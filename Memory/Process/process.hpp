#pragma once
#include <Windows.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <ranges>

#ifdef _WIN64
#include "../Image_x64/image_x64.hpp"
#else
#include "../Image_x86/image_x86.hpp"
#endif

#include "../Hook/hook.hpp"

class process
{
public:

	process() :
		m_handle( INVALID_HANDLE_VALUE ),
		m_hwnd( HWND() ),
		m_pid( DWORD() )
		//m_images( {} ),
		//m_hooks( {} )
	{}


	~process()
	{
		// make sure no handle is leaked when leaving
		if (this->m_handle)
			CloseHandle(this->m_handle);

		// make sure no memory will be leaked, by unhooking existent hooks
		if( !this->m_hooks.empty() )
			for( const auto & hk : this->m_hooks )
				this->destroy_hook_x86( hk->get_hook_address() );
	}


	[[nodiscard]] HANDLE get_process_handle() const noexcept
	{
		return this->m_handle;
	}


	[[nodiscard]] HWND get_window_handle() const noexcept
	{
		return this->m_hwnd;
	}


	[[nodiscard]] DWORD get_process_id() const noexcept
	{
		return this->m_pid;
	}


	[[nodiscard]] bool is_process_ready() const noexcept
	{
		return this->m_handle != INVALID_HANDLE_VALUE && this->m_hwnd != nullptr && this->m_pid >= 0;
	}


	template < typename T >
	T read( const std::uintptr_t address, size_t size_of_read = sizeof( T ) )
	{
		T buffer;
		ReadProcessMemory( this->m_handle, reinterpret_cast< LPCVOID >( address ), &buffer, size_of_read, nullptr );
		return buffer;
	}

	[[nodiscard]] inline std::string read_ascii_null_terminated_string( const std::uintptr_t address )
	{
		std::string ret = {};

		auto stringptr = address;

		char c = {};

		while( ( c = this->read< char >( stringptr++ ) ) != '\0' )
			if ( c >= 32 && c < 127 )
				ret += c;
			else
				return "OSMIUM_NO_ASCII";

		return ret;
	}


	template < typename T >
	bool write(std::uintptr_t address, T value)
	{
		return WriteProcessMemory(
			this->m_handle,
			reinterpret_cast<LPVOID>(address),
			&value,
			sizeof(value),
			nullptr
		) != 0;
	}

	[[nodiscard]] DWORD change_protection_of_memory_block( const std::uintptr_t address, const size_t size, const DWORD protection ) const
	{
		DWORD buffer = 0;

		if ( !VirtualProtectEx( this->m_handle, reinterpret_cast< LPVOID >( address ), size, protection, &buffer ) )
			return NULL;

		return buffer;
	}

	template < typename T >
	bool write_to_protected_memory( std::uintptr_t address, T value, size_t size = sizeof( T ) )
	{
		if( !this->is_process_ready() )
			return false;

		DWORD buffer = 0;

		if( !VirtualProtectEx( this->m_handle, reinterpret_cast< LPVOID >( address ), size, PAGE_EXECUTE_READWRITE, &buffer ) )
			return false;

		if( WriteProcessMemory( this->m_handle, reinterpret_cast< LPVOID >( address ), &value, sizeof( value ), nullptr ) == 0 )
			return false;
		
		return VirtualProtectEx( this->m_handle, reinterpret_cast< LPVOID >( address ), size, buffer, &buffer ) != 0;
	}

	[[nodiscard]] inline LPVOID allocate_rwx_page_in_process( const size_t page_size = 4096 ) const
	{
		const auto ret = VirtualAllocEx( 
			this->m_handle, 
			nullptr, 
			page_size, 
			MEM_COMMIT | MEM_RESERVE, 
			PAGE_EXECUTE_READWRITE );

		return ret;
	}

	[[nodiscard]] inline LPVOID allocate_page_in_process( const DWORD page_protection, const size_t page_size = 4096 ) const
	{
		const auto ret = VirtualAllocEx(
			this->m_handle,
			nullptr,
			page_size,
			MEM_COMMIT | MEM_RESERVE,
			page_protection );

		return ret;
	}

	[[nodiscard]] bool refresh_image_map(const DWORD process_id = 0);

	[[nodiscard]] bool setup_process(const std::wstring& process_identifier, const bool is_process_name = true );

	[[nodiscard]] bool setup_process( const DWORD process_id );


	[[nodiscard]] std::uintptr_t get_image_base(const std::wstring& image_name) const noexcept
	{
		try
		{
			return this->m_images.at(image_name).get()->get_image_base();
		}
		catch (std::exception& exception)
		{
			UNREFERENCED_PARAMETER(exception);
			return std::uintptr_t();
		}
	}


	[[nodiscard]] size_t get_image_size(const std::wstring& image_name) const noexcept
	{
		try
		{
			return this->m_images.at(image_name).get()->get_image_size();
		}
		catch (std::exception& exception)
		{
			UNREFERENCED_PARAMETER(exception);
			return size_t();
		}
	}

	[[nodiscard]] bool does_image_exist_in_map(const std::wstring& image_name) const noexcept
	{
		try
		{
			const auto temp = this->m_images.at(image_name).get();

			return true;
		}
		catch (std::exception& exception)
		{
			UNREFERENCED_PARAMETER(exception);

			return false;
		}
	}

#ifdef _WIN64
	[[nodiscard]] image_x64* get_image_ptr_by_name( const std::wstring& image_name ) const noexcept
#else
	[[nodiscard]] image_x86* get_image_ptr_by_name( const std::wstring& image_name ) const noexcept
#endif
	{
		if (!this->does_image_exist_in_map(image_name))
			return nullptr;

		return this->m_images.at(image_name).get();
	}

#ifdef _WIN64
	[[nodiscard]] image_x64* get_first_image_ptr() const noexcept
#else
	[[nodiscard]] image_x86* get_first_image_ptr() const noexcept
#endif
	{
		if( this->m_images.empty() )
			return nullptr;

		return this->m_images.begin()->second.get();
	}

	[[nodiscard]] size_t get_map_size() const noexcept
	{
		return this->m_images.size();
	}

	[[nodiscard]] double get_map_size_in_mbytes() const noexcept
	{
		if ( this->m_images.empty() )
			return double();

		auto size = 0.0;

		constexpr auto divider = 1024.0 * 1024.0;

		for ( const auto& image : this->m_images | std::views::values )
			size += image->get_image_size() / divider;

		return size;
	}

	void clear_image_map() noexcept
	{
		if (!this->m_images.empty())
			this->m_images.clear();
	}

	void print_images() const
	{
		printf("[#] Image-Name | Image-Base | Image-Size | Is-Executable\n");

		for (auto& [image_name, image_ptr] : this->m_images)
			printf(
#ifdef _WIN64
				"[+] %-25ls | 0x%llX | 0x%llX | %d.\n",
#else
				"[+] %-32ls | 0x%08X | 0x%08X | %d.\n",
#endif
				image_name.c_str(),
				image_ptr->get_image_base(),
				image_ptr->get_image_size(),
				image_ptr->is_executable()
			);
		printf("\n\n");
	}

	void print_images(const size_t num_of_images) const
	{
		if (this->m_images.empty() || num_of_images >= this->m_images.size())
			return;

		printf("[#] Image-Name | Image-Base | Image-Size | Is-Executable\n");

		size_t counter = 0;

		for (auto& [image_name, image_ptr] : this->m_images)
		{
			if (counter == num_of_images)
				return;

			printf(
#ifdef _WIN64
				"[+] %-25ls | 0x%llX | 0x%llX | %d.\n",
#else
				"[+] %-32ls | 0x%08X | 0x%08X | %d.\n",
#endif
				image_name.c_str(),
				image_ptr->get_image_base(),
				image_ptr->get_image_size(),
				image_ptr->is_executable()
			);

			counter++;
		}
	}


	bool patch_bytes(const byte_vector& bytes, std::uintptr_t address, size_t size);


	bool patch_bytes(const std::byte bytes[], std::uintptr_t address, size_t size);


	bool nop_bytes(std::uintptr_t address, size_t size);

	[[nodiscard]] bool read_image(byte_vector* dest_vec, const std::wstring& image_name) const;

	[[nodiscard]] bool create_hook_x86( const std::uintptr_t start_address, const size_t size, const std::vector< uint8_t >& shellcode );

	[[nodiscard]] bool destroy_hook_x86( const std::uintptr_t start_address );

	[[nodiscard]] inline size_t get_size_of_hooks() const noexcept
	{
		return this->m_hooks.size();
	}

	[[nodiscard]] inline hook* get_hook_ptr_by_address(const std::uintptr_t start_address_of_hook) const
	{
		for (const auto& hook : this->m_hooks)
			if (hook->get_hook_address() == start_address_of_hook)
				return hook.get();

		return nullptr;
	}

	[[nodiscard]] inline auto get_hooks_ptr() noexcept
	{
		return &this->m_hooks;
	}


private:
	HANDLE m_handle;

	HWND m_hwnd;

	DWORD m_pid;

#ifdef _WIN64
	std::unordered_map< std::wstring, std::unique_ptr< image_x64 > > m_images;
#else
	std::unordered_map< std::wstring, std::unique_ptr< image_x86 > > m_images;
#endif

	std::vector< std::unique_ptr< hook > > m_hooks;
};
