#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <cstdint>

#include "../../Driver/Shared/ioctl.h"

class driver_interface
{
public:
	///-------------------------------------------------------------------------------------------------
	/// <summary>Default constructor. Opens a handle to the kernel driver device.</summary>
	///-------------------------------------------------------------------------------------------------

	driver_interface()
		: m_handle( INVALID_HANDLE_VALUE )
		, m_pid( 0 )
	{
		m_handle = CreateFileW(
			OSMIUM_WIN32_DEVICE,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr
		);
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Destructor. Closes the driver handle if open.</summary>
	///-------------------------------------------------------------------------------------------------

	~driver_interface()
	{
		if( this->m_handle && this->m_handle != INVALID_HANDLE_VALUE )
			CloseHandle( this->m_handle );
	}

	/* Non-copyable, movable */
	driver_interface( const driver_interface& ) = delete;
	driver_interface& operator=( const driver_interface& ) = delete;

	driver_interface( driver_interface&& other ) noexcept
		: m_handle( other.m_handle )
		, m_pid( other.m_pid )
	{
		other.m_handle = INVALID_HANDLE_VALUE;
		other.m_pid = 0;
	}

	driver_interface& operator=( driver_interface&& other ) noexcept
	{
		if( this != &other )
		{
			if( this->m_handle && this->m_handle != INVALID_HANDLE_VALUE )
				CloseHandle( this->m_handle );

			this->m_handle = other.m_handle;
			this->m_pid = other.m_pid;
			other.m_handle = INVALID_HANDLE_VALUE;
			other.m_pid = 0;
		}
		return *this;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Checks if the driver handle is valid and communication is possible.</summary>
	///
	/// <returns>True if connected to the driver, false otherwise.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool is_connected() const noexcept
	{
		return this->m_handle != nullptr && this->m_handle != INVALID_HANDLE_VALUE;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Attaches to a target process by process ID.</summary>
	///
	/// <param name="pid">The process ID of the target process.</param>
	///-------------------------------------------------------------------------------------------------

	void attach( DWORD pid ) noexcept
	{
		this->m_pid = pid;
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

		const auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
		if( !snapshot || snapshot == INVALID_HANDLE_VALUE )
			return false;

		PROCESSENTRY32W pe32 = {};
		pe32.dwSize = sizeof( PROCESSENTRY32W );

		if( Process32FirstW( snapshot, &pe32 ) )
		{
			do
			{
				if( std::wstring( pe32.szExeFile ) == process_name )
				{
					this->m_pid = pe32.th32ProcessID;
					CloseHandle( snapshot );
					return true;
				}
			}
			while( Process32NextW( snapshot, &pe32 ) );
		}

		CloseHandle( snapshot );
		return false;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the currently attached process ID.</summary>
	///
	/// <returns>The process ID, or 0 if not attached.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] DWORD get_pid() const noexcept
	{
		return this->m_pid;
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
		if( !this->is_connected() || !buffer || size == 0 )
			return false;

		MEMORY_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( this->m_pid );
		request.Address   = static_cast< ULONG64 >( address );
		request.Buffer    = reinterpret_cast< ULONG64 >( buffer );
		request.Size      = static_cast< ULONG64 >( size );

		MEMORY_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			this->m_handle,
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
		if( !this->is_connected() || !buffer || size == 0 )
			return false;

		MEMORY_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( this->m_pid );
		request.Address   = static_cast< ULONG64 >( address );
		request.Buffer    = reinterpret_cast< ULONG64 >( const_cast< void* >( buffer ) );
		request.Size      = static_cast< ULONG64 >( size );

		MEMORY_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			this->m_handle,
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
		if( !this->is_connected() )
			return 0;

		if( pid == 0 )
			pid = this->m_pid;

		PROCESS_BASE_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( pid );

		PROCESS_BASE_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			this->m_handle,
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
	/// <param name="pid">The process ID. If 0, uses the currently attached PID.</param>
	/// <param name="module_name">The module name (e.g. L"ntdll.dll").</param>
	/// <param name="out_size">Optional pointer to receive the module size.</param>
	///
	/// <returns>The module base address, or 0 on failure.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::uintptr_t get_module_base( const std::wstring& module_name, DWORD pid = 0, size_t* out_size = nullptr )
	{
		if( !this->is_connected() || module_name.empty() )
			return 0;

		if( pid == 0 )
			pid = this->m_pid;

		MODULE_BASE_REQUEST request = {};
		request.ProcessId = static_cast< ULONG64 >( pid );

		/* Copy the module name, ensuring null termination */
		const auto copy_len = min( module_name.size(), MAX_MODULE_NAME_LENGTH - 1 );
		memcpy( request.ModuleName, module_name.c_str(), copy_len * sizeof( WCHAR ) );
		request.ModuleName[copy_len] = L'\0';

		MODULE_BASE_RESPONSE response = {};
		DWORD bytes_returned = 0;

		const auto success = DeviceIoControl(
			this->m_handle,
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

private:
	HANDLE m_handle;
	DWORD  m_pid;
};
