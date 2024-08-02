#pragma once
#include <Windows.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <ranges>
#include <winternl.h>

#ifdef _WIN64
#include "../Image_x64/image_x64.hpp"
#else
#include "../Image_x86/image_x86.hpp"
#endif

#include "../Hook/hook.hpp"
#include "../SharedMemoryInstance/sharedmemoryinstance.hpp"
#include "../RegisterDumper/registercontext.hpp"

class process
{
public:
	///-------------------------------------------------------------------------------------------------
	/// <summary>Default constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	process()
		: m_handle( INVALID_HANDLE_VALUE )
	  , m_hwnd( HWND() )
	  , m_pid( DWORD() ) {}

	///-------------------------------------------------------------------------------------------------
	/// <summary>The default destructor, it will also close the process handle, destroy every active hook and free their allocated memory.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	~process()
	{
		this->shutdown();

		if( this->m_handle )
			CloseHandle( this->m_handle );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	This function should be called, when it's expected that the destructor won't be called on exiting. Will free any used resources, so no memory leaks should appear after that. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <returns>	True if it succeeds, false if it fails. </returns>
	///-------------------------------------------------------------------------------------------------

	bool shutdown()
	{
		// make sure no memory will be leaked, by destroying all registered contexts 
		// first you should clear all registered contexts because their hooks and shared memory instances
		// will be also destroyed.
		// if you destroy the hooks or the sh instances first the destroy function of the register contexts will fail
		// resulting in unwanten behaviour  
		if( !this->m_register_dumper.empty() )
			for( const auto& reg_ctx : this->m_register_dumper )
				if( !this->destroy_register_dumper_x86( reg_ctx->get_dumped_address() ) )
					return false;

		// make sure no memory will be leaked, by unhooking existent hooks
		if( !this->m_hooks.empty() )
			for( const auto& hk : this->m_hooks )
				if( !this->destroy_hook_x86( hk->get_hook_address() ) )
					return false;

		// make sure no memory will be leaked, by destroying all named shared memory instances
		if( !this->m_sh_instances.empty() )
			for( const auto& sh_inst : this->m_sh_instances )
				if( !this->destroy_shared_memory_instance_x86( sh_inst->get_object_name() ) )
					return false;

		// clear the whole image map from the target process
		if ( !this->m_images.empty() )
			this->m_images.clear();

		return true;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets process handle.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The process handle.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] HANDLE get_process_handle() const noexcept
	{
		return this->m_handle;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets window handle.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The window handle.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] HWND get_window_handle() const noexcept
	{
		return this->m_hwnd;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets process id.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The process id of the target process.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] DWORD get_process_id() const noexcept
	{
		return this->m_pid;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Checks if the process is ready to use.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if process ready, false if not.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool is_process_ready() const noexcept
	{
		return this->m_handle != INVALID_HANDLE_VALUE && this->m_hwnd != nullptr && this->m_pid >= 0;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Reads memory from the target process.</summary>
	///
	/// <typeparam name="T">	Generic type parameter.</typeparam>
	/// <param name="address">	   	The address which you want to read.</param>
	/// <param name="size_of_read">	(Optional) Size which will be read from the address.</param>
	///
	/// <returns>A buffer with datatype T, read from the memory address.</returns>
	///-------------------------------------------------------------------------------------------------

	template< typename T >
	T read( const std::uintptr_t address, size_t size_of_read = sizeof( T ) )
	{
		T buffer;
		ReadProcessMemory( this->m_handle, reinterpret_cast< LPCVOID >( address ), &buffer, size_of_read, nullptr );
		return buffer;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Reads ASCII null terminated string from the target process.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="address">	The address which will be read from.</param>
	///
	/// <returns>The ASCII null terminated string.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::string read_ascii_null_terminated_string( const std::uintptr_t address )
	{
		std::string ret = {};

		auto stringptr = address;

		char c = {};

		while( ( c = this->read< char >( stringptr++ ) ) != '\0' )
			if( c >= 32 && c < 127 )
				ret += c;
			else
				return "OSMIUM_NO_ASCII";

		return ret;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Writes memory to the target process.</summary>
	///
	/// <typeparam name="T">	Generic type parameter.</typeparam>
	/// <param name="address">	The address which should be written to.</param>
	/// <param name="value">  	The value which should be written to the memory address.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	template< typename T >
	bool write( std::uintptr_t address, T value )
	{
		return WriteProcessMemory(
			this->m_handle,
			reinterpret_cast< LPVOID >( address ),
			&value,
			sizeof( value ),
			nullptr
		) != 0;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Change the protection of a memory block.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="address">   	The address which protection will be changed.</param>
	/// <param name="size">		 	The number of bytes which get their protection changed.</param>
	/// <param name="protection">	The new protection which will be applied to the memory block.</param>
	///
	/// <returns>The old protection from the memory block, needed for restoring the old protection.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] DWORD change_protection_of_memory_block( const std::uintptr_t address, const size_t size,
	                                                       const DWORD protection ) const
	{
		DWORD buffer = 0;

		if( !VirtualProtectEx( this->m_handle, reinterpret_cast< LPVOID >( address ), size, protection, &buffer ) )
			return NULL;

		return buffer;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Writes to protected memory.</summary>
	///
	/// <typeparam name="T">	Generic type parameter.</typeparam>
	/// <param name="address">	The address which will be written to.</param>
	/// <param name="value">  	The value which will be written to the address.</param>
	/// <param name="size">   	(Optional) The number of bytes which their protection will get temporarily changed.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	template< typename T >
	bool write_to_protected_memory( std::uintptr_t address, T value, size_t size = sizeof( T ) )
	{
		if( !this->is_process_ready() )
			return false;

		DWORD buffer = 0;

		if( !VirtualProtectEx(
			this->m_handle,
			reinterpret_cast< LPVOID >( address ),
			size,
			PAGE_EXECUTE_READWRITE,
			&buffer
		) )
			return false;

		if( WriteProcessMemory(
			this->m_handle,
			reinterpret_cast< LPVOID >( address ),
			&value,
			sizeof( value ),
			nullptr
		) == 0 )
			return false;

		return VirtualProtectEx( this->m_handle, reinterpret_cast< LPVOID >( address ), size, buffer, &buffer ) != 0;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Allocate an rwx page in the target process.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="page_size">	(Optional) Size of the page [in bytes].</param>
	///
	/// <returns>The pointer to the freshly allocated page or if it fails it will return a null pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] LPVOID allocate_rwx_page_in_process( const size_t page_size = 4096 ) const
	{
		const auto ret = VirtualAllocEx(
			this->m_handle,
			nullptr,
			page_size,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		return ret;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Allocate a memory page with specific protection in the target process.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="page_protection">	The page protection which will be applied to the new allocated memory page.</param>
	/// <param name="page_size">	  	(Optional) Size of the page [in bytes].</param>
	///
	/// <returns>The pointer to the freshly allocated page or if it fails it will return a null pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] LPVOID allocate_page_in_process( const DWORD page_protection, const size_t page_size = 4096 ) const
	{
		const auto ret = VirtualAllocEx(
			this->m_handle,
			nullptr,
			page_size,
			MEM_COMMIT | MEM_RESERVE,
			page_protection
		);

		return ret;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Refreshes the internal image map by re-dumping all images in the target process and caching them locally.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool refresh_image_map();

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets up the process instance with an process identifier (window title, process name). </summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="process_identifier">	Identifier for the process, can be window title or process name.</param>
	/// <param name="is_process_name">   	(Optional) True if is process name, false if the process identifier is a window title.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool setup_process( const std::wstring& process_identifier, bool is_process_name = true );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets up the process instance with an process id of the target process.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="process_id">	The process id of the target process.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool setup_process( DWORD process_id );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the image base of an dumped image by looking in the internal unordered_map.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="image_name">	Name of the image.</param>
	///
	/// <returns>The image base if the image was found or 0 if the image does not exist.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::uintptr_t get_image_base( const std::wstring& image_name ) const noexcept
	{
		try
		{
			return this->m_images.at( image_name ).get()->get_image_base();
		}
		catch( std::exception& exception )
		{
			UNREFERENCED_PARAMETER( exception );
			return std::uintptr_t();
		}
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the image size of an dumped image by looking in the internal unordered_map.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="image_name">	Name of the image.</param>
	///
	/// <returns>The image size if the image was found or 0 if the image does not exist.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] size_t get_image_size( const std::wstring& image_name ) const noexcept
	{
		try
		{
			return this->m_images.at( image_name ).get()->get_image_size();
		}
		catch( std::exception& exception )
		{
			UNREFERENCED_PARAMETER( exception );
			return size_t();
		}
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Checks if the image exists in the internal image map, tells if the image was dumped.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="image_name">	Name of the image.</param>
	///
	/// <returns>True if the image was dumped/ does exists and false if does not exists/ was not dumped.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool does_image_exist_in_map( const std::wstring& image_name ) const noexcept
	{
		try
		{
			const auto temp = this->m_images.at( image_name ).get();

			return true;
		}
		catch( std::exception& exception )
		{
			UNREFERENCED_PARAMETER( exception );

			return false;
		}
	}

#ifdef _WIN64

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets x64 image pointer by name.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="image_name">	Name of the image.</param>
	///
	/// <returns>Null if it fails, else the image pointer by name.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] image_x64* get_image_ptr_by_name( const std::wstring& image_name ) const noexcept
#else

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets x86 image pointer by name.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="image_name">	Name of the image.</param>
	///
	/// <returns>Null if it fails, else the image pointer by name.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] image_x86* get_image_ptr_by_name( const std::wstring& image_name ) const noexcept
#endif
	{
		if( !this->does_image_exist_in_map( image_name ) )
			return nullptr;

		return this->m_images.at( image_name ).get();
	}

#ifdef _WIN64

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the first x64 image pointer.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>Null if it fails, else the first image pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] image_x64* get_first_image_ptr() const noexcept
#else

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the first x86 image pointer.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>Null if it fails, else the first image pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] image_x86* get_first_image_ptr() const noexcept
#endif
	{
		if( this->m_images.empty() )
			return nullptr;

		return this->m_images.begin()->second.get();
	}

	[[nodiscard]] inline auto get_images_ptr() const noexcept
	{
		return &this->m_images;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the size of the internal image map, it tells how many images were dumped.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The map size.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] size_t get_map_size() const noexcept
	{
		return this->m_images.size();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the size of the internal image map in megabytes.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The map size in megabytes.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] double get_map_size_in_mbytes() const noexcept
	{
		if( this->m_images.empty() )
			return double();

		auto size = 0.0;

		constexpr auto divider = 1024.0 * 1024.0;

		for( const auto& image : this->m_images | std::views::values )
			size += image->get_image_size() / divider;

		return size;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Clears the image map.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	void clear_image_map() noexcept
	{
		if( !this->m_images.empty() )
			this->m_images.clear();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Prints all dumped images in a nice summary with some info about them.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	void print_images() const
	{
		printf( "[#] Image-Name | Image-Base | Image-Size | Is-Executable\n" );

		for( auto& [ image_name, image_ptr ] : this->m_images )
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
		printf( "\n\n" );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Prints a specific count of dumped images in a nice summary with some info about them.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="num_of_images">	Number of images which should be printed.</param>
	///-------------------------------------------------------------------------------------------------

	void print_images( const size_t num_of_images ) const
	{
		if( this->m_images.empty() || num_of_images >= this->m_images.size() )
			return;

		printf( "[#] Image-Name | Image-Base | Image-Size | Is-Executable\n" );

		size_t counter = 0;

		for( auto& [ image_name, image_ptr ] : this->m_images )
		{
			if( counter == num_of_images )
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

	///-------------------------------------------------------------------------------------------------
	/// <summary>Patch bytes in the target process with a given vector of bytes.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="bytes">  	The vector of bytes.</param>
	/// <param name="address">	The address which will be patched.</param>
	/// <param name="size">   	The number of bytes which will be overwritten.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	bool patch_bytes( const byte_vector& bytes, std::uintptr_t address, size_t size );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Patch bytes in the target process with a given array of bytes.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="bytes">  	The array of bytes.</param>
	/// <param name="address">	The address which will be patched.</param>
	/// <param name="size">   	The number of bytes which will be overwritten.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	bool patch_bytes( const std::byte bytes[ ], std::uintptr_t address, size_t size );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Overwrites bytes with NOP's inside the target process.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="address">	The address where the bytes will be overwritten with NOP (0x90).</param>
	/// <param name="size">   	The number of bytes which will be overwritten.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	bool nop_bytes( std::uintptr_t address, size_t size );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Reads an image from the target process to an vector of bytes.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="dest_vec">  	[in,out] If non-null, destination vector.</param>
	/// <param name="image_name">	Name of the image.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool read_image( byte_vector* dest_vec, const std::wstring& image_name ) const;

	///-------------------------------------------------------------------------------------------------
	/// <summary>Creates an mid function x86 hook inside of the target process by allocating a rwx page, copying the given shellcode to it and patching the given address with an JMP to the allocated page. Also adds a new hook instance into the local hook vector.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="start_address">	The start address where the mid function hook will be placed.</param>
	/// <param name="size">				The number of bytes the mid function hook should overwrite, needs to be atleast 5 bytes (JMP + ADDRESS).</param>
	/// <param name="shellcode">		The shellcode of your hook which should get executed.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool create_hook_x86( std::uintptr_t start_address, size_t size,
	                                    const std::vector< uint8_t >& shellcode );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Destroys the x86 hook inside the target process by restoring the old bytes and freeing the allocated memory page inside the target process.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="start_address">	The start address of the mid function hook.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool destroy_hook_x86( std::uintptr_t start_address );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets size of current hooks inside the target process.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The number of current hooks inside of the target process.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] size_t get_size_of_hooks() const noexcept
	{
		return this->m_hooks.size();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets pointer to the related hook instance by the start address of the mid function hook.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="start_address_of_hook">	The start address of the mid function hook.</param>
	///
	/// <returns>Null if it fails, else the hook pointer by address.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] hook* get_hook_ptr_by_address( const std::uintptr_t start_address_of_hook ) const
	{
		for( const auto& hook : this->m_hooks )
			if( hook->get_hook_address() == start_address_of_hook )
				return hook.get();

		return nullptr;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the pointer to the vector where all hooks are stored.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The pointer to the vector where all hooks are stored.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] auto get_hooks_ptr() noexcept
	{
		return &this->m_hooks;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Executes the given shellcode via remote thread (allocated memory page has RWX rights) inside the target process and waits until the thread terminates. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <param name="shellcode">	The shellcode which will be executed. </param>
	///
	/// <returns>	True if it succeeds, false if it fails. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool execute_shellcode_in_process( const std::vector< uint8_t >& shellcode ) const;

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Creates and installs a named shared memory instance with a given object name, file size HIGH and LOW. With the pointer from the shared memory instance you will be able to do IPC via Named Shared Memory. All new instances will be hold inside the instances vector. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <param name="object_name">   	Name of the object. </param>
	/// <param name="file_size_high">	The file size high. </param>
	/// <param name="file_size_low"> 	The file size low. </param>
	///
	/// <returns>	True if it succeeds, false if it fails. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool create_shared_memory_instance_x86( const std::string& object_name, DWORD file_size_high,
	                                                      DWORD file_size_low );

	///-------------------------------------------------------------------------------------------------
	/// <summary>
	/// 	Destroys the shared memory instance described by object_name and removes the instance from the instances vector.
	/// </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <param name="object_name">	Name of the object. </param>
	///
	/// <returns>	True if it succeeds, false if it fails. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool destroy_shared_memory_instance_x86( const std::string& object_name );

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Gets shared memory instance pointer by object name. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <param name="object_name">	Name of the object. </param>
	///
	/// <returns>	Null if it fails, else the shared memory instance pointer. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] shared_memory_instance* get_shared_memory_instance_by_object_name(
		const std::string& object_name ) const
	{
		for( const auto& inst : this->m_sh_instances )
			if( inst->get_object_name() == object_name )
				return inst.get();
		return nullptr;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Gets the pointer to the vector whre all shared memory instances are stored. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <returns>	The pointer of the vector where all shared memory instances are stored. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] auto get_shared_memory_instances_ptr() noexcept
	{
		return &this->m_sh_instances;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Creates a new registercontext for the given address and stores it's new instance inside the internal vector for the registercontext's. Also all registercontext's are started by default. </summary>
	///
	/// <remarks>	cragson, 23/12/2022. </remarks>
	///
	/// <param name="dumped_address">	The address where the register should be dumped from. </param>
	/// <param name="hook_size">	 	(Optional) Size of the hook in bytes. </param>
	///
	/// <returns>	True if it succeeds, false if it fails. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool create_register_dumper_x86( std::uintptr_t dumped_address, size_t hook_size = 5 );

	///-------------------------------------------------------------------------------------------------
	/// <summary>
	/// 	Destroys a registercontext instance by unhooking it and destroying the shared memory instance, also erases it from the interal vector for the registercontext's.
	/// </summary>
	///
	/// <remarks>	cragson, 23/12/2022. </remarks>
	///
	/// <param name="dumped_address">	The dumped address of the registercontext which should be destroyed. </param>
	///
	/// <returns>	True if it succeeds, false if it fails. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool destroy_register_dumper_x86( std::uintptr_t dumped_address );

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Sets the registercontext with the given address active and starting the dumping. </summary>
	///
	/// <remarks>	cragson, 23/12/2022. </remarks>
	///
	/// <param name="dumped_address">	The dumped address of the registercontext which should be started. </param>
	///
	/// <returns>	True if it succeeds, false if it fails. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool start_register_dumper_x86( std::uintptr_t dumped_address );

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Sets the registercontext with the given address inactive and stop the dumping. </summary>
	///
	/// <remarks>	cragson, 23/12/2022. </remarks>
	///
	/// <param name="dumped_address">	The dumped address of the registercontext which should be stopped. </param>
	///
	/// <returns>	True if it succeeds, false if it fails. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool stop_register_dumper_x86( std::uintptr_t dumped_address );

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Checks if a registercontext exists with a given address and which is active. </summary>
	///
	/// <remarks>	cragson, 23/12/2022. </remarks>
	///
	/// <param name="dumped_address">	The dumped address of the registercontext. </param>
	///
	/// <returns>	True if a registercontext exists for the given address and is active, false if not. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] auto is_active_register_dumper_x86( const std::uintptr_t dumped_address ) const noexcept
	{
		return std::ranges::find_if(
			this->m_register_dumper.begin(),
			this->m_register_dumper.end(),
			[&dumped_address]( const std::unique_ptr< registercontext >& re )
			{
				return re->get_dumped_address() == dumped_address && re->is_dumper_active();
			}
		) != this->m_register_dumper.end();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Retrieves the pointer to the registercontext class of a given dumped address which belongs to the registercontext. </summary>
	///
	/// <remarks>	cragson, 23/12/2022. </remarks>
	///
	/// <param name="dumped_address">	The dumped address of the registercontext. </param>
	///
	/// <returns>	Nullpointer if it fails, else the registercontext pointer. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] registercontext* get_register_dumper_x86_ptr( const std::uintptr_t dumped_address ) const noexcept
	{
		const auto ret = std::ranges::find_if(
			this->m_register_dumper.begin(),
			this->m_register_dumper.end(),
			[&dumped_address]( const std::unique_ptr< registercontext >& re )
			{
				return re->get_dumped_address() == dumped_address && re->is_dumper_active();
			}
		);

		return ret != this->m_register_dumper.end() ? ret->get() : nullptr;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Retrieves the pointer to the register_data class of a registercontext by searching for the given dumped address in the internal vector of registercontext's. </summary>
	///
	/// <remarks>	cragson, 23/12/2022. </remarks>
	///
	/// <param name="dumped_address">	The dumped address of the registercontext. </param>
	///
	/// <returns>	Nullpointer if it fails, else the register_data pointer. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] register_data* get_data_from_registers_x86( const std::uintptr_t dumped_address ) const noexcept
	{
		const auto ret = std::ranges::find_if(
			this->m_register_dumper.begin(),
			this->m_register_dumper.end(),
			[&dumped_address]( const std::unique_ptr< registercontext >& re )
			{
				return re->get_dumped_address() == dumped_address && re->is_dumper_active();
			}
		);

		return ret != this->m_register_dumper.end() ? ret->get()->get_registers_data() : nullptr;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Injects a external dll into another process, utilizing the LoadLibrary technique. </summary>
	///
	/// <remarks>	cragson, 09/07/2024. </remarks>
	///
	/// <param name="dll_path">	The full path of the dll, which will be injected. </param>
	///
	/// <returns>	True if it injected successfully and false if it fails. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool inject_dll_load_library(const std::string& dll_path);

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Retreives a pointer to the PEB of the target process. </summary>
	///
	/// <remarks>	cragson, 19/07/2024. </remarks>
	///
	/// <returns>	The peb pointer. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::uintptr_t get_peb_ptr();

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Dumps the PEB out of the memory from the target process. </summary>
	///
	/// <remarks>	cragson, 19/07/2024. </remarks>
	///
	/// <returns>	The peb structure. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] PEB get_peb();

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Reads the image base address member of the PEB struct from the target process. </summary>
	///
	/// <remarks>	cragson, 19/07/2024. </remarks>
	///
	/// <returns>	The peb image base address. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::uintptr_t get_peb_image_base_address() noexcept;

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Walks the InMemoryOrderModuleList of the PEB of the target process and stores all loaded module information in a vector. </summary>
	///
	/// <remarks>	cragson, 19/07/2024. </remarks>
	///
	/// <returns>	The std::vector of module information from InMemoryOrderModuleList inside the PEB. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::vector< std::tuple< std::string, std::uintptr_t, size_t > > get_modules_from_peb();

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

	std::vector< std::unique_ptr< shared_memory_instance > > m_sh_instances;

	std::vector< std::unique_ptr< registercontext > > m_register_dumper;
};
