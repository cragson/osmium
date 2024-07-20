#include "process.hpp"
#include <TlHelp32.h>
#include <algorithm>

struct window_cb_args
{
	DWORD target_pid;
	HWND target_hwnd;
};

BOOL CALLBACK hwnd_cb( HWND hWnd, LPARAM lparam )
{
	DWORD pid = DWORD();

	GetWindowThreadProcessId( hWnd, &pid );

	const auto args = reinterpret_cast< window_cb_args* >( lparam );

	if( pid == args->target_pid )
	{
		args->target_hwnd = hWnd;

		return FALSE;
	}

	return TRUE;
};

bool process::refresh_image_map()
{
	MODULEENTRY32 me32 = { sizeof( MODULEENTRY32 ) };

	const auto snapshot_handle = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->m_pid );
	if( !snapshot_handle || snapshot_handle == INVALID_HANDLE_VALUE )
		return false;

	// after successfully retrieving my snapshot handle, I clear the map - to get rid of the old images + information
	this->m_images.clear();

	if( Module32First( snapshot_handle, &me32 ) )
	{
		do
		{
			// check first if the image name already exists, as a key, in the map
			// if so, just skip the certain image
			if( this->m_images.contains( me32.szModule ) )
				continue;

			const auto image_base = reinterpret_cast< std::uintptr_t >( me32.modBaseAddr );
			const auto image_size = static_cast< size_t >( me32.modBaseSize );

			// create a new object for the image name, which is the key for the map
#ifdef _WIN64
			this->m_images[me32.szModule] = std::make_unique< image_x64 >( image_base, image_size );
#else
			this->m_images[ me32.szModule ] = std::make_unique< image_x86 >( image_base, image_size );
#endif
			// now dump the image from memory and write it into the specific byte_vector
			// if the image could not be read, like RPM sets 299 as the error code
			// the image will be removed from the map
			// smart ptr should take care of collecting the garbage
			if( !this->read_image( this->m_images[ me32.szModule ]->get_byte_vector_ptr(), me32.szModule ) )
				this->m_images.erase( me32.szModule );
		}
		while( Module32Next( snapshot_handle, &me32 ) );
	}

	// make sure to close the handle 
	CloseHandle( snapshot_handle );

	return true;
}


bool process::setup_process( const std::wstring& process_identifier, const bool is_process_name )
{
	if( process_identifier.empty() )
		return false;

	auto window_handle = HWND();
	auto buffer = DWORD();
	auto proc_handle = INVALID_HANDLE_VALUE;

	// if the given process identifier is not a process name but a window title 
	// try to retrieve a window handle, the process id and a handle to the process with specific rights.
	if( !is_process_name )
	{
		window_handle = FindWindowW( nullptr, process_identifier.c_str() );
		if( !window_handle )
			return false;

		if( !GetWindowThreadProcessId( window_handle, &buffer ) )
			return false;

		proc_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, buffer );
		if( !proc_handle )
			return false;
	}
	// if the process identifier is a process name
	// use it for retrieving the process id first
	else
	{
		// Some quick note: Cz the project is lacking some proper documentation I want to describe the behaviour of the method here a bit better
		// I want to iterate above the different process entries and search for the first entry which matches my identifier
		// I take the PID from the first match and retrieve the window and process handle from it
		const auto snapshot_handle = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );
		if( !snapshot_handle )
			return false;

		auto pe32 = PROCESSENTRY32();
		pe32.dwSize = sizeof( PROCESSENTRY32 );

		if( Process32First( snapshot_handle, &pe32 ) )
		{
			do
			{
				if( const auto wprocess_name = std::wstring( pe32.szExeFile ); wprocess_name == process_identifier )
				{
					buffer = pe32.th32ProcessID;

					break;
				}
			}
			while( Process32Next( snapshot_handle, &pe32 ) );
		}
		else
			return false;

		// now I got the pid and I need to open a handle to the process
		proc_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, buffer );
		if( !proc_handle )
			return false;

		// prevent leaking the handle
		CloseHandle( snapshot_handle );

		// The last needed thing is the window handle
		window_cb_args args = { buffer, HWND() };

		EnumWindows( hwnd_cb, reinterpret_cast< LPARAM >( &args ) );

		if( !args.target_hwnd )
			return false;

		// Now I can go out of the else block and just let the values be set
		window_handle = args.target_hwnd;
	}

	// set now the correct data
	// Because refresh_image_map will call RPM which uses m_handle
	this->m_hwnd = window_handle;
	this->m_pid = buffer;
	this->m_handle = proc_handle;

	// Before I set the retrieved data, I want to safe information about every image in the process
	// So I iterate over every image loaded into the certain process and store them :)
	if( !this->refresh_image_map() )
	{
		// because I need the correct handle in this function, I need to take care of the case where the handle is correct but images cannot be dumped
		// so clear the retrieved data about the process here, if the function fails
		this->m_hwnd = nullptr;
		this->m_pid = 0;
		this->m_handle = INVALID_HANDLE_VALUE;

		return false;
	}

	return true;
}


bool process::setup_process( const DWORD process_id )
{
	// try to open a handle to the process 
	const auto handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, process_id );

	if( !handle )
		return false;

	// now I got the valid handle, I try to receive a handle to the main window of the process
	window_cb_args args = { process_id, HWND() };

	EnumWindows( hwnd_cb, reinterpret_cast< LPARAM >( &args ) );

	if( !args.target_hwnd )
		return false;

	// set now the correct data
	this->m_hwnd = args.target_hwnd;

	this->m_pid = process_id;

	this->m_handle = handle;

	// Before I set the retrieved data, I want to safe information about every image in the process
	// So I iterate over every image loaded into the certain process and store them :)
	if( !this->refresh_image_map() )
	{
		// because I need the correct handle in this function, I need to take care of the case where the handle is correct but images cannot be dumped
		// so clear the retrieved data about the process here, if the function fails
		this->m_hwnd = nullptr;
		this->m_pid = 0;
		this->m_handle = INVALID_HANDLE_VALUE;

		return false;
	}

	return true;
}

bool process::patch_bytes( const byte_vector& bytes, const std::uintptr_t address, const size_t size )
{
	if( bytes.empty() || !address || !size || bytes.size() > size )
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

	for( size_t i = 0; i < size; i++ )
		this->write< byte >( address + i, 0x90 );

	for( size_t i = 0; i < bytes.size(); i++ )
		this->write< std::byte >( address + i, bytes.at( i ) );

	if( !VirtualProtectEx( this->m_handle, reinterpret_cast< LPVOID >( address ), size, buffer, &buffer ) )
		return false;

	return true;
}


bool process::patch_bytes( const std::byte bytes[ ], const std::uintptr_t address, const size_t size )
{
	if( !address || !size )
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

	for( size_t i = 0; i < size; i++ )
		this->write< std::byte >( address + i, bytes[ i ] );

	if( !VirtualProtectEx( this->m_handle, reinterpret_cast< LPVOID >( address ), size, buffer, &buffer ) )
		return false;

	return true;
}


bool process::nop_bytes( const std::uintptr_t address, const size_t size )
{
	if( !address || !size )
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

	for( size_t i = 0; i < size; i++ )
		this->write< byte >( address + i, 0x90 );

	if( !VirtualProtectEx( this->m_handle, reinterpret_cast< LPVOID >( address ), size, buffer, &buffer ) )
		return false;

	return true;
}

bool process::read_image( byte_vector* dest_vec, const std::wstring& image_name ) const
{
	if( !dest_vec || image_name.empty() || !this->does_image_exist_in_map( image_name ) )
		return false;

	// here should no exception occur, because I checked above if the image exists in the map
	const auto image = this->m_images.at( image_name ).get();

	// clear the vector and make sure the vector has the correct size
	dest_vec->clear();
	dest_vec->resize( image->get_image_size() );

	return ReadProcessMemory(
		this->m_handle,
		reinterpret_cast< LPCVOID >( image->get_image_base() ),
		dest_vec->data(),
		image->get_image_size(),
		nullptr
	) != 0;
}

bool process::create_hook_x86( const std::uintptr_t start_address, const size_t size,
                               const std::vector< uint8_t >& shellcode )
{
	if( start_address < 0 || size < 5 || shellcode.empty() )
		return false;

	// allocate a read-write-execute memory page in the target process
	const auto rwx_page = this->allocate_rwx_page_in_process( shellcode.size() > 4096 ? shellcode.size() : 4096 );

	if( !rwx_page )
		return false;

	// copy now the shellcode into the allocated memory page in the target process
	if( !WriteProcessMemory(
		this->m_handle,
		rwx_page,
		&shellcode.front(),
		shellcode.size(),
		nullptr
	) )
		return false;

	// calculate now the jump address back after the hook
	const DWORD jmp_back_addr = ( start_address + size ) - ( reinterpret_cast< std::uintptr_t >( rwx_page ) + shellcode.
		size() + 5 );

	// Place now the jmp instruction + address into the allocated page, which will jmp back to the hooked function (after the jmp to the hook)
	if( !this->write< uint8_t >( reinterpret_cast< std::uintptr_t >( rwx_page ) + shellcode.size(), 0xE9 ) )
		return false;

	if( !this->write< DWORD >( reinterpret_cast< std::uintptr_t >( rwx_page ) + shellcode.size() + 1, jmp_back_addr ) )
		return false;

	// the new memory page was allocated, the hook bytes were copied into it and the jmp back to the hooked function was done
	// now the original function needs to be hooked
	// buf before hooking I need to save the original bytes of the hooked function, which will be overwritten by the JMP instruction
	std::vector< uint8_t > original_bytes;

	// allocate space for the vector which will contain the original bytes
	original_bytes.resize( size );

	// read now the original bytes
	if( !ReadProcessMemory(
		this->m_handle,
		reinterpret_cast< LPCVOID >( start_address ),
		original_bytes.data(),
		size,
		nullptr
	) )
		return false;

	// change now the page protection of the hooked function
	DWORD buffer = 0;

	if( !VirtualProtectEx(
		this->m_handle,
		reinterpret_cast< LPVOID >( start_address ),
		size,
		PAGE_EXECUTE_READWRITE,
		&buffer
	) )
		return false;

	// before I write my hook I want to make sure all bytes, which will be overwritten are NOPed
	// because if the hook size is not equal with the size of the jmp + address I will have left over bytes which will do me dirty
	if( size > 5 )
	{
		for( auto idx = 0; idx < size; idx++ )
			this->write< uint8_t >( start_address + idx, 0x90 );
	}

	// write now the JMP instruction + the address to the hook function where the shellcode lies
	if( !this->write< uint8_t >( start_address, 0xE9 ) )
		return false;

	// calculate now the jump adress to the allocated memory from the hooked function
	const DWORD jmp_to_hook = ( reinterpret_cast< std::uintptr_t >( rwx_page ) ) - ( start_address + 5 );

	// write now the jump address after the jmp instruction in the hooked function
	if( !this->write< DWORD >( start_address + 1, jmp_to_hook ) )
		return false;

	// set now the old page protection, where the hooked function lies
	if( !VirtualProtectEx(
		this->m_handle,
		reinterpret_cast< LPVOID >( start_address ),
		size,
		buffer,
		&buffer
	) )
		return false;

	// now hopefully was all this done:
	// rwx memory page allocated
	// shellcode copied to memory page
	// jmp placed with address that points right after the jmp in the hooked function
	// target function was hooked with jmp which points to the rwx page

	// So after that procedure I am able to create a hook instance with the needed information
	auto _hook = std::make_unique< hook >(
		start_address,
		reinterpret_cast< std::uintptr_t >( rwx_page ),
		size,
		shellcode,
		original_bytes
	);

	// add now the hook to the process vector
	this->m_hooks.push_back( std::move( _hook ) );

	return true;
}

bool process::destroy_hook_x86( const std::uintptr_t start_address )
{
	if( start_address < 0 )
		return false;

	// iterate over all placed hooks and check if the address of the hooked function exists
	for( const auto& hk : this->m_hooks )
		if( hk->get_hook_address() == start_address )
		{
			// before I go on, I want to make sure that the hook size is equal to the size of the vector which contains the original bytes
			// this important because I will write them back with the size of the vector to make sure all bytes are copied
			if( hk->get_hook_size() != hk->get_original_bytes_ptr()->size() )
				return false;

			DWORD buffer = 0;

			// change the page protection to restore the original bytes
			if( !VirtualProtectEx(
				this->m_handle,
				reinterpret_cast< LPVOID >( start_address ),
				hk->get_hook_size(),
				PAGE_EXECUTE_READWRITE,
				&buffer
			) )
				return false;

			// write now the original bytes
			if( !WriteProcessMemory(
				this->m_handle,
				reinterpret_cast< LPVOID >( start_address ),
				hk->get_original_bytes_ptr()->data(),
				hk->get_original_bytes_ptr()->size(),
				nullptr
			) )
				return false;

			// restore the old page protection now
			if( !VirtualProtectEx(
				this->m_handle,
				reinterpret_cast< LPVOID >( start_address ),
				hk->get_hook_size(),
				buffer,
				&buffer
			) )
				return false;

			// now I need to free the allocated memory
			if( !VirtualFreeEx(
				this->m_handle,
				reinterpret_cast< LPVOID >( hk->get_allocated_page_address() ),
				NULL,
				MEM_RELEASE
			) )
				return false;

			// need to remove the hook element now from the vector
			this->m_hooks.erase( std::ranges::find( this->m_hooks.begin(), this->m_hooks.end(), hk ) );

			// now I restored the old bytes, free'd the allocated memory and removed the hook instance from the vector
			// the world should be fine again
			return true;
		}

	return false;
}

bool process::execute_shellcode_in_process( const std::vector< uint8_t >& shellcode ) const
{
	// no shellcode? no execution for you
	if( shellcode.empty() )
		return false;

	// allocate memory in process for the shellcode
	const auto page = this->allocate_rwx_page_in_process( shellcode.size() );

	if( !page )
		return false;

	// copy now the shellcode to the freshly allocated memory page
	if( !WriteProcessMemory(
		this->m_handle,
		page,
		shellcode.data(),
		shellcode.size(),
		nullptr
	) )
		return false;

	// create now a thread inside the process, which executes the shellcode
	const auto ret = CreateRemoteThread(
		this->m_handle,
		nullptr,
		NULL,
		reinterpret_cast< LPTHREAD_START_ROUTINE >( page ),
		nullptr,
		NULL,
		nullptr
	);

	if( !ret )
		return false;

	// Wait until thread finish it's execution
	WaitForSingleObject( ret, INFINITE );

	// close now the thread handle
	if( !CloseHandle( ret ) )
		return false;

	// free now the allocated memory page for the shellcode
	if( !VirtualFreeEx(
		this->m_handle,
		page,
		NULL,
		MEM_RELEASE
	) )
		return false;

	// Now everything should be fine again

	return true;
}

bool process::create_shared_memory_instance_x86( const std::string& object_name, const DWORD file_size_high,
                                                 const DWORD file_size_low )
{
	// i don't want empty object names here, hausrecht und so
	if( object_name.empty() )
		return false;

	// check if object name is already in instance vector
	for( const auto& inst : this->m_sh_instances )
		if( inst->get_object_name() == object_name )
			return false;

	const auto kernel32 = GetModuleHandleA( "Kernel32" );

	if( !kernel32 )
		return false;

	const auto fnCreateFileMappingA = GetProcAddress( kernel32, "CreateFileMappingA" );

	if( !fnCreateFileMappingA )
		return false;

	const auto fnMapViewOfFile = GetProcAddress( kernel32, "MapViewOfFile" );

	if( !fnMapViewOfFile )
		return false;

	// allocate now a memory page for the saved data and the string of the global object inside the process
	const auto save_data_ptr = this->allocate_page_in_process( PAGE_READWRITE, 8 + object_name.size() );

	if( !save_data_ptr )
		return false;

	const auto name_ptr = reinterpret_cast< std::uintptr_t >( save_data_ptr ) + 8;

	// write now the object name string into the process
	if( !WriteProcessMemory(
		this->m_handle,
		reinterpret_cast< LPVOID >( name_ptr ),
		object_name.data(),
		object_name.size(),
		nullptr
	) )
		return false;

	std::vector< uint8_t > install_sh =
	{
		0xBA, 0xEF, 0xBE, 0xAD, 0xDE,			// mov edx, DEADBEEF	; EDX = CreateFileMappingA Address
		0xBF, 0xEF, 0xBE, 0xAD, 0xDE,			// mov edi, DEADBEEF	; EDI = MapViewOfFile Address
		0xBB, 0xEF, 0xBE, 0xAD, 0xDE,			// mov ebx, DEADBEEF	; Address of global object name string
		0x53,									// push ebx
		0xBB, 0xEF, 0xBE, 0xAD, 0xDE,			// mov ebx, DEADBEEF	; max size LOW
		0x53,									// push ebx
		0xBB, 0xEF, 0xBE, 0xAD, 0xDE,			// mov ebx, DEADBEEF	; max size HIGH
		0x53,									// push ebx
		0x6A, 0x04,								// push 04				; PAGE_READWRITE
		0x6A, 0x00,								// push 00
		0x68, 0xFF, 0xFF, 0xFF, 0xFF,			// push FFFFFFFF
		0xFF, 0xD2,								// call edx				; CreateFileMappingA()
		0x83, 0xF8, 0x00,						// cmp eax,0
		0x74, 0x23,								// je 
		0x8B, 0xC8,								// mov ecx, eax			; ECX = handle to mapping object
		0xBB, 0xEF, 0xBE, 0xAD, 0xDE,			// mov ebx, DEADBEEF	; max size low
		0x53,									// push ebx
		0x6A, 0x00,								// push 00
		0x6A, 0x00,								// push 00
		0x68, 0x1F, 0x00, 0x0F, 0x00,			// push 000F001F		; FILE_MAP_ALL_ACCESS
		0x50,									// push eax
		0xFF, 0xD7,								// call edi				; MapViewOfFile()
		0x83, 0xF8, 0x00,						// cmp eax,0
		0x74, 0x0A,								// je 
		0xBB, 0xEF, 0xBE, 0xAD, 0xDE,			// mov ebx, DEADBEEF	; address where return values are backup'ed
		0x89, 0x0B,								// mov [ebx], ecx		; handle to mapping object
		0x89, 0x43, 0x04,						// mov [ebx+04], eax	; starting address of mapped view
		0xC3									// ret 
	};

	// set address of CreateFileMappingA
	*reinterpret_cast< std::uintptr_t* >( &install_sh[ 1 ] ) = reinterpret_cast< std::uintptr_t >(
		fnCreateFileMappingA );

	// set address of MapViewOfFile
	*reinterpret_cast< std::uintptr_t* >( &install_sh[ 6 ] ) = reinterpret_cast< std::uintptr_t >( fnMapViewOfFile );

	// set address of the global object name string
	*reinterpret_cast< std::uintptr_t* >( &install_sh[ 11 ] ) = name_ptr;

	// set maximum size low word of view offset
	*reinterpret_cast< DWORD* >( &install_sh[ 17 ] ) = file_size_low;

	// set maximum size high word of view offset
	*reinterpret_cast< DWORD* >( &install_sh[ 23 ] ) = file_size_high;

	// set maximum size low word of view offset
	*reinterpret_cast< DWORD* >( &install_sh[ 47 ] ) = file_size_low;

	// set now the allocated page ptr for the saved data
	*reinterpret_cast< std::uintptr_t* >( &install_sh[ 70 ] ) = reinterpret_cast< std::uintptr_t >( save_data_ptr );


	// execute now the installation shellcode
	if( !this->execute_shellcode_in_process( install_sh ) )
		return false;

	// read now the saved data from the allocated memory page
	const auto object_handle = this->read< HANDLE >( reinterpret_cast< std::uintptr_t >( save_data_ptr ) );

	if( !object_handle )
		return false;

	// read now the starting address of the mapped view fro the allocated memory page
	const auto view_address = this->read< std::uintptr_t >( reinterpret_cast< std::uintptr_t >( save_data_ptr ) + 4 );

	if( !view_address )
		return false;

	// now create the second part of the shared memory in this process

	// open the file mapping to the global object
	const auto file_handle = OpenFileMappingA( FILE_MAP_ALL_ACCESS, FALSE, object_name.c_str() );

	if( !file_handle )
		return false;

	// now map the view of the mapped file into our address space
	const auto view_ptr = MapViewOfFile(
		file_handle,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		file_size_high == 0 ? file_size_low : file_size_high & file_size_low
	);

	if( !view_ptr )
		return false;

	// create now the shared memory instance
	auto sh_mem = std::make_unique< shared_memory_instance >(
		object_name,
		file_handle,
		view_ptr,
		reinterpret_cast< void* >( view_address ),
		object_handle,
		!file_size_high ? file_size_low : file_size_high & file_size_low
	);

	// add it to the internal vector for shared memory instances
	this->m_sh_instances.push_back( std::move( sh_mem ) );

	// now free the allocated memory page for the saved data
	if( !VirtualFreeEx(
		this->m_handle,
		save_data_ptr,
		0,
		MEM_RELEASE
	) )
		return false;

	return true;
}

bool process::destroy_shared_memory_instance_x86( const std::string& object_name )
{
	if( object_name.empty() )
		return false;

	// check if object name exists in instance vector
	for( const auto& sh_inst : this->m_sh_instances )
	{
		if( sh_inst->get_object_name() == object_name )
		{
			// Get now the addresses of the needed winapi functions

			const auto kernel32 = GetModuleHandleA( "Kernel32" );

			if( !kernel32 )
				return false;

			const auto fnUnmapViewOfFile = GetProcAddress( kernel32, "UnmapViewOfFile" );

			if( !fnUnmapViewOfFile )
				return false;

			const auto fnCloseHandle = GetProcAddress( kernel32, "CloseHandle" );

			if( !fnCloseHandle )
				return false;

			// prepare now the shellcode

			std::vector< uint8_t > uninstall_sh =
			{
				0xBE, 0xEF, 0xBE, 0xAD, 0xDE,			// mov esi,DEADBEEF			; Address of UnmapViewOfFile
				0xBF, 0xEF, 0xBE, 0xAD, 0xDE,			// mov edi,DEADBEEF			; Address of CloseHandle
				0xB8, 0xEF, 0xDB, 0xEA, 0x0D,			// mov eax,0DEADBEF			; pBuf ptr
				0x50,									// push eax
				0xFF, 0xD6,								// call esi					; UnmapViewOfFile()
				0xB8, 0xEF, 0xBE, 0xAD, 0xDE,			// mov eax,DEADBEEF			; hMapFile handle
				0x50,									// push eax
				0xFF, 0xD7,								// call edi					; CloseHandle()
				0xC3									// ret 

			};

			// set address of UnmapViewOfFile
			*reinterpret_cast< std::uintptr_t* >( &uninstall_sh[ 1 ] ) = reinterpret_cast< std::uintptr_t >(
				fnUnmapViewOfFile );

			// set address of CloseHandle
			*reinterpret_cast< std::uintptr_t* >( &uninstall_sh[ 6 ] ) = reinterpret_cast< std::uintptr_t >(
				fnCloseHandle );

			// set now the pBuf pointer
			*reinterpret_cast< std::uintptr_t* >( &uninstall_sh[ 11 ] ) = reinterpret_cast< std::uintptr_t >( sh_inst->
				get_process_buffer_ptr() );

			// set now the hMapFile handle
			*reinterpret_cast< HANDLE* >( &uninstall_sh[ 19 ] ) = sh_inst->get_file_mapping_object_handle();

			// execute now the shellcode inside the process

			if( !this->execute_shellcode_in_process( uninstall_sh ) )
				return false;

			// now I need to unmap the view also from this process
			if( !UnmapViewOfFile( sh_inst->get_buffer_ptr< LPCVOID >() ) )
				return false;

			// also I need to close handle of the mapping file
			if( !CloseHandle( sh_inst->get_file_mapping_object_handle() ) )
				return false;

			// also I need to remove the shared memory instance ptr form the vector
			this->m_sh_instances.erase(
				std::ranges::find( this->m_sh_instances.begin(), this->m_sh_instances.end(), sh_inst )
			);

			// now everything should be fine 

			return true;
		}
	}
	return false;
}

bool process::create_register_dumper_x86( const std::uintptr_t dumped_address, const size_t hook_size )
{
	// if the address where the dumper will be placed is invalid
	if( dumped_address <= 0 )
		return false;

	// if a register context already exists with the given address
	if(
		std::ranges::any_of(
			this->m_register_dumper.begin(),
			this->m_register_dumper.end(),
			[&dumped_address]( const std::unique_ptr< registercontext >& re )
			{
				return re->get_dumped_address() == dumped_address;
			}
		)
	)
		return false;

	// create the custom object name for the register context
	const auto obj_name = std::vformat( "osmium-dumpctx-{:X}", std::make_format_args( dumped_address ) );

	// maybe a bit too paranoid but better safe than sorry
	if( obj_name.empty() )
		return false;

	// create the shared memory for the regdumper, with enough bytes to fit into the registers_data class
	if( !this->create_shared_memory_instance_x86( obj_name, NULL, sizeof( register_data ) ) )
		return false;

	// now after the shared memory instance was successfully created
	// let's place the hook which will dump all registers data into the shared memory

	std::vector< uint8_t > install_sh =
	{
		0xA3, 0xEF, 0xBE, 0xAD, 0xDE,			// 0000  mov [DEADBEEF],    eax
		0x89, 0x1D, 0xF3, 0xBE, 0xAD, 0xDE,		// 0005  mov [DEADBEEF+4],  ebx
		0x89, 0x0D, 0xF7, 0xBE, 0xAD, 0xDE,		// 000B  mov [DEADBEEF+8],  ecx
		0x89, 0x15, 0xFB, 0xBE, 0xAD, 0xDE,		// 0011  mov [DEADBEEF+C],  edx
		0x89, 0x25, 0xFF, 0xBE, 0xAD, 0xDE,		// 0017  mov [DEADBEEF+10], esp
		0x89, 0x2D, 0x03, 0xBF, 0xAD, 0xDE,		// 001D  mov [DEADBEEF+14], ebp
		0x89, 0x35, 0x07, 0xBF, 0xAD, 0xDE,		// 0023  mov [DEADBEEF+18], esi
		0x89, 0x3D, 0x0B, 0xBF, 0xAD, 0xDE		// 0029  mov [DEADBEEF+1C], edi
	};

	// get now the - hopefully - freshly created shared memory instance
	const auto sh_inst = this->get_shared_memory_instance_by_object_name( obj_name );

	// must be valid because nothing works without it
	if( sh_inst == nullptr )
		return false;

	// get now the address of the shared memory inside the target process
	const auto target_sh_ptr = reinterpret_cast< std::uintptr_t >( sh_inst->get_process_buffer_ptr() );

	// make sure the target process buffer pointer is valid
	if( !target_sh_ptr )
		return false;

	// prepare now the addresses where the registers will be written to

	// GPRs
	for( auto i = 0; i < 8; i++ )
	{
		if( i == 0 )
			*reinterpret_cast< std::uintptr_t* >( &install_sh[ 1 ] ) = target_sh_ptr;
		else
			*reinterpret_cast< std::uintptr_t* >( &install_sh[ 7 + 6 * ( i - 1 ) ] ) = target_sh_ptr + i * sizeof(
				uint32_t );
	}

	// Read now the original bytes from memory
	std::vector< uint8_t > original_bytes;
	original_bytes.resize( hook_size );

	if( !ReadProcessMemory(
		this->m_handle,
		reinterpret_cast< LPCVOID >( dumped_address ),
		original_bytes.data(),
		hook_size,
		nullptr
	) )
		return false;

	// append them now to the shellcode
	install_sh.insert( install_sh.end(), original_bytes.begin(), original_bytes.end() );

	// now place the hook at the address which should be dumped
	if( !this->create_hook_x86( dumped_address, hook_size, install_sh ) )
		return false;

	// At this point the following should be done
	// 1. Created a shared memory instance for the new register context
	// 2. Prepared the dumping shellcode with the proper pointer from the new shared memory instance
	// 3. Created and placed the hook at the given address, where the registers should be dumped

	// Create now the smart ptr with the proper instance
	auto ctx = std::make_unique< registercontext >( sh_inst, dumped_address, hook_size );

	// Enable the register_context, so the dumping will already happen
	ctx->enable_dumper();

	// Append now the fresh register context to the internal vector
	this->m_register_dumper.push_back( std::move( ctx ) );

	return true;
}

bool process::destroy_register_dumper_x86( const std::uintptr_t dumped_address )
{
	// If the address where the dumper will be placed is invalid
	if( dumped_address <= 0 )
		return false;

	// Try to find the registercontext for the given address
	const auto& existing_ctx = std::ranges::find_if(
		this->m_register_dumper.begin(),
		this->m_register_dumper.end(),
		[&dumped_address]( const std::unique_ptr< registercontext >& re )
		{
			return re->get_dumped_address() == dumped_address;
		}
	);

	// If no registercontext was found, return false
	if( existing_ctx == this->m_register_dumper.end() )
		return false;

	// If the registercontext is still active, stop it before destroying it
	// If it couldn't be stopped, return false
	if( existing_ctx->get()->is_dumper_active() )
		if( !this->stop_register_dumper_x86( dumped_address ) )
			return false;

	// Unhook the placed hook now
	if( !this->destroy_hook_x86( dumped_address ) )
		return false;

	// Craft now the object name from the existing shared memory instance
	const auto obj_name = std::vformat( "osmium-dumpctx-{:X}", std::make_format_args( dumped_address ) );

	// Maybe a bit too paranoid but better safe than sorry
	if( obj_name.empty() )
		return false;

	// Destroy now the existing shared memory instance
	if( !this->destroy_shared_memory_instance_x86( obj_name ) )
		return false;

	// Erase now the registercontext from the internal vector
	this->m_register_dumper.erase(
		std::ranges::find( this->m_register_dumper.begin(), this->m_register_dumper.end(), *existing_ctx )
	);

	// Now everything should be properly cleaned and fine again :-)

	return true;
}

bool process::start_register_dumper_x86( const std::uintptr_t dumped_address )
{
	// If no register context exists with the given dumped address, return false
	if( const auto not_exists = std::ranges::none_of(
		this->m_register_dumper,
		[&dumped_address]( const std::unique_ptr< registercontext >& re )
		{
			return re->get_dumped_address() == dumped_address;
		}
	) )
		return false;

	// Try finding a registercontext for the given address
	const auto& existing_ctx = std::ranges::find_if(
		this->m_register_dumper,
		[&dumped_address]( const std::unique_ptr< registercontext >& re )
		{
			return re->get_dumped_address() == dumped_address;
		}
	);

	// Check if the given address belongs to a existing registercontext
	// If the context doesn't exist, return false
	if( existing_ctx == this->m_register_dumper.end() )
		return false;

	// If a registercontext exists with the given address and is already active, return false
	// A already active context can not be started again
	if( existing_ctx->get()->is_dumper_active() )
		return false;

	// Craft now the object name from the existing shared memory instance
	const auto obj_name = std::vformat( "osmium-dumpctx-{:X}", std::make_format_args( dumped_address ) );

	// Now prepare the shellcode for the hook
	std::vector< uint8_t > start_sh =
	{
		0xA3, 0xEF, 0xBE, 0xAD, 0xDE,			// 0000  mov [DEADBEEF],    eax
		0x89, 0x1D, 0xF3, 0xBE, 0xAD, 0xDE,		// 0005  mov [DEADBEEF+4],  ebx
		0x89, 0x0D, 0xF7, 0xBE, 0xAD, 0xDE,		// 000B  mov [DEADBEEF+8],  ecx
		0x89, 0x15, 0xFB, 0xBE, 0xAD, 0xDE,		// 0011  mov [DEADBEEF+C],  edx
		0x89, 0x25, 0xFF, 0xBE, 0xAD, 0xDE,		// 0017  mov [DEADBEEF+10], esp
		0x89, 0x2D, 0x03, 0xBF, 0xAD, 0xDE,		// 001D  mov [DEADBEEF+14], ebp
		0x89, 0x35, 0x07, 0xBF, 0xAD, 0xDE,		// 0023  mov [DEADBEEF+18], esi
		0x89, 0x3D, 0x0B, 0xBF, 0xAD, 0xDE		// 0029  mov [DEADBEEF+1C], edi
	};

	// Get now the - hopefully - freshly created shared memory instance
	const auto sh_inst = this->get_shared_memory_instance_by_object_name( obj_name );

	// Must be valid because nothing works without it
	if( sh_inst == nullptr )
		return false;

	// Get now the address of the shared memory inside the target process
	const auto target_sh_ptr = reinterpret_cast< std::uintptr_t >( sh_inst->get_process_buffer_ptr() );

	// Make sure the target process buffer pointer is valid
	if( !target_sh_ptr )
		return false;

	// Prepare now the addresses where the registers will be written to

	// GPRs
	for( auto i = 0; i < 8; i++ )
	{
		if( i == 0 )
			*reinterpret_cast< std::uintptr_t* >( &start_sh[ 1 ] ) = target_sh_ptr;
		else
			*reinterpret_cast< std::uintptr_t* >( &start_sh[ 7 + 6 * ( i - 1 ) ] ) = target_sh_ptr + i * sizeof(
				uint32_t );
	}

	// Read now the original bytes from memory
	std::vector< uint8_t > original_bytes;
	original_bytes.resize( existing_ctx->get()->get_hook_size() );

	if( !ReadProcessMemory(
		this->m_handle,
		reinterpret_cast< LPCVOID >( dumped_address ),
		original_bytes.data(),
		existing_ctx->get()->get_hook_size(),
		nullptr
	) )
		return false;

	// append them now to the shellcode
	start_sh.insert( start_sh.end(), original_bytes.begin(), original_bytes.end() );

	// Now place the hook at the address which should be dumped
	if( !this->create_hook_x86( dumped_address, existing_ctx->get()->get_hook_size(), start_sh ) )
		return false;

	// Finally set the register context active
	existing_ctx->get()->enable_dumper();

	return true;
}

bool process::stop_register_dumper_x86( const std::uintptr_t dumped_address )
{
	// Try to find a registercontext instance for the given address
	const auto& existing_ctx = std::ranges::find_if(
		this->m_register_dumper.begin(),
		this->m_register_dumper.end(),
		[&dumped_address]( const std::unique_ptr< registercontext >& re )
		{
			return re->get_dumped_address() == dumped_address;
		}
	);

	// If no registercontext with given address exists, return false
	if( existing_ctx == this->m_register_dumper.end() )
		return false;

	// If a registercontext exists with the given address and is not active, return false
	if( !existing_ctx->get()->is_dumper_active() )
		return false;

	// Destroy now the placed hook
	if( !this->destroy_hook_x86( dumped_address ) )
		return false;

	// disable now the dumper
	existing_ctx->get()->disable_dumper();

	return true;
}

bool process::inject_dll_load_library(const std::string& dll_path)
{
	// Allocate memory which will hold the dll path
	const auto mem_dll = this->allocate_page_in_process(PAGE_READWRITE, dll_path.size() + 1);

	if (!mem_dll)
		return false;

	// Write the DLL path to the allocated memory
	if (!WriteProcessMemory(this->get_process_handle(), mem_dll, dll_path.c_str(), dll_path.size() + 1, NULL))
		return false;

	// Get a handle to the library where the needed function pointer is located at
	const auto module_handle = GetModuleHandleA("kernel32.dll");

	if (!module_handle)
		return false;

	// Get the address of LoadLibraryA in kernel32.dll
	const auto loadlib_a = (LPVOID)GetProcAddress(module_handle, "LoadLibraryA");
	if (!loadlib_a)
		return false;

	// Create a remote thread that calls LoadLibraryA with our DLL path as its argument
	const auto remote_thread = CreateRemoteThread(this->get_process_handle(), NULL, NULL, (LPTHREAD_START_ROUTINE)loadlib_a, mem_dll, NULL, NULL);
	if (!remote_thread)
		return false;

	// Wait for the remote thread to complete
	WaitForSingleObject(remote_thread, INFINITE);

	// Clean up
	VirtualFreeEx(this->get_process_handle(), mem_dll, NULL, MEM_RELEASE);

	return true;
}

std::uintptr_t process::get_peb_ptr()
{
	typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
		IN  HANDLE ProcessHandle,
		IN  PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN  ULONG ProcessInformationLength,
		OUT PULONG ReturnLength    OPTIONAL
		);

	const auto ntdll = LoadLibraryA("ntdll.dll");
	if (ntdll == NULL)
		return {};

	const auto fn_NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

	PROCESS_BASIC_INFORMATION pbi = {};

	const auto ret = fn_NtQueryInformationProcess( this->m_handle, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

	if (!NT_SUCCESS(ret) || !pbi.PebBaseAddress)
		return {};

	return reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress);
}

PEB process::get_peb()
{
	const auto peb_ptr = this->get_peb_ptr();

	if (!peb_ptr)
		return {};

	return this->read< PEB >( peb_ptr );
}

std::uintptr_t process::get_peb_image_base_address() noexcept
{
	const auto peb = this->get_peb();

	return peb.Reserved3[1] != nullptr ? reinterpret_cast<std::uintptr_t>(peb.Reserved3[1]) : std::uintptr_t();

	return std::uintptr_t();
}

std::vector<std::tuple<std::string, std::uintptr_t, size_t>> process::get_modules_from_peb()
{
	std::vector<std::tuple<std::string, std::uintptr_t, size_t>> ret = {};

	const auto peb = this->get_peb();

	PEB_LDR_DATA ldr = {};

	if (!ReadProcessMemory(this->m_handle, peb.Ldr, &ldr, sizeof(ldr), nullptr))
		return ret;

	const auto ldr_head = ldr.InMemoryOrderModuleList.Flink;
	auto ldr_current = ldr_head;

	do
	{
		const auto ldr_data_current = this->read< LDR_DATA_TABLE_ENTRY >(
			reinterpret_cast<std::uintptr_t>(ldr_current) - sizeof(LIST_ENTRY)
		);

		const auto path_size = ldr_data_current.FullDllName.Length / sizeof(wchar_t);

		std::vector< wchar_t > full_dll_name = {};
		full_dll_name.resize(path_size);

		if (!ReadProcessMemory(
			this->m_handle, 
			ldr_data_current.FullDllName.Buffer, 
			full_dll_name.data(), 
			ldr_data_current.FullDllName.Length, 
			nullptr)
			)
			break;

		full_dll_name.emplace_back(L'\0');

		const auto image_name_w = std::wstring(full_dll_name.data());

		const auto image_name_a = std::string(image_name_w.begin(), image_name_w.end());

		const auto image_base = reinterpret_cast<std::uintptr_t>(ldr_data_current.DllBase);
		const auto image_size = reinterpret_cast<size_t>(ldr_data_current.Reserved3[1]);

		if (image_base && image_size)
		{
			ret.emplace_back(
				image_name_a,
				image_base,
				image_size
			);
		}

		const auto ldr_temp = this->read< LIST_ENTRY >(reinterpret_cast<std::uintptr_t>(ldr_current));

		ldr_current = ldr_temp.Flink;
		
	} while (ldr_current != ldr_head);

	return ret;
}
