#include "process.hpp"
#include <TlHelp32.h>

struct window_cb_args
{
	DWORD target_pid;
	HWND target_hwnd;
};

BOOL CALLBACK hwnd_cb(HWND hWnd, LPARAM lparam)
{
	DWORD pid = DWORD();

	GetWindowThreadProcessId(hWnd, &pid);

	const auto args = reinterpret_cast<window_cb_args*>(lparam);

	if (pid == args->target_pid)
	{
		args->target_hwnd = hWnd;

		return FALSE;
	}

	return TRUE;
};

bool process::refresh_image_map(const DWORD process_id)
{
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };

	const auto snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, process_id);
	if (!snapshot_handle)
		return false;

	// after successfully retrieving my snapshot handle, I clear the map - to get rid of the old images + information
	this->m_images.clear();

	if (Module32First(snapshot_handle, &me32))
	{
		do
		{
			// check first if the image name already exists, as a key, in the map
			// if so, just skip the certain image
			if (this->m_images.find(me32.szModule) != this->m_images.end())
				continue;

			const auto image_base = reinterpret_cast<std::uintptr_t>(me32.modBaseAddr);
			const auto image_size = static_cast<size_t>(me32.modBaseSize);

			// create a new object for the image name, which is the key for the map
#ifdef _WIN64
			this->m_images[me32.szModule] = std::make_unique< image_x64 >( image_base, image_size );
#else
			this->m_images[me32.szModule] = std::make_unique< image_x86 >( image_base, image_size );
#endif
			// now dump the image from memory and write it into the specific byte_vector
			// if the image could not be read, like RPM sets 299 as the error code
			// the image will be removed from the map
			// smart ptr should take care of collecting the garbage
			if (!this->read_image(this->m_images[me32.szModule]->get_byte_vector_ptr(), me32.szModule))
				this->m_images.erase(me32.szModule);

		} while (Module32Next(snapshot_handle, &me32));
	}

	// make sure to close the handle 
	CloseHandle(snapshot_handle);

	return true;
}


bool process::setup_process(const std::wstring& process_identifier, const bool is_process_name)
{
	if (process_identifier.empty())
		return false;

	auto window_handle = HWND();
	auto buffer = DWORD();
	auto proc_handle = INVALID_HANDLE_VALUE;

	// if the given process identifier is not a process name but a window title 
	// try to retrieve a window handle, the process id and a handle to the process with specific rights.
	if( !is_process_name )
	{
		window_handle = FindWindowW( nullptr, process_identifier.c_str() );
		if ( !window_handle )
			return false;

		if ( !GetWindowThreadProcessId( window_handle, &buffer ) )
			return false;

		proc_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, buffer );
		if ( !proc_handle )
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
			} while( Process32Next( snapshot_handle, &pe32 ) );
		}
		else
			return false;

		// now I got the pid and I need to open a handle to the process
		proc_handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, buffer );
		if ( !proc_handle )
			return false;

		// The last needed thing is the window handle
		window_cb_args args = { buffer, HWND() };

		EnumWindows( hwnd_cb, reinterpret_cast< LPARAM >( &args ) );

		if ( !args.target_hwnd )
			return false;

		// Now I can go out of the else block and just let the values be set
	}

	// set now the correct data
	// Because refresh_image_map will call RPM which uses m_handle
	this->m_hwnd = window_handle;
	this->m_pid = buffer;
	this->m_handle = proc_handle;

	// Before I set the retrieved data, I want to safe information about every image in the process
	// So I iterate over every image loaded into the certain process and store them :)
	if ( !this->refresh_image_map( buffer ) )
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
	if ( !this->refresh_image_map( process_id ) )
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

bool process::patch_bytes(const byte_vector& bytes, const std::uintptr_t address, const size_t size)
{
	if (bytes.empty() || !address || !size || bytes.size() > size)
		return false;
	DWORD buffer = 0;
	if (!VirtualProtectEx(
		this->m_handle,
		reinterpret_cast<LPVOID>(address),
		size,
		PAGE_EXECUTE_READWRITE,
		&buffer
	))
		return false;
	for (size_t i = 0; i < size; i++)
		this->write< byte >(address + i, 0x90);
	for (size_t i = 0; i < bytes.size(); i++)
		this->write< std::byte >(address + i, bytes.at(i));
	if (!VirtualProtectEx(this->m_handle, reinterpret_cast<LPVOID>(address), size, buffer, &buffer))
		return false;
	return true;
}


bool process::patch_bytes(const std::byte bytes[], const std::uintptr_t address, const size_t size)
{
	if (!address || !size)
		return false;
	DWORD buffer = 0;
	if (!VirtualProtectEx(
		this->m_handle,
		reinterpret_cast<LPVOID>(address),
		size,
		PAGE_EXECUTE_READWRITE,
		&buffer
	))
		return false;
	for (size_t i = 0; i < size; i++)
		this->write< std::byte >(address + i, bytes[i]);
	if (!VirtualProtectEx(this->m_handle, reinterpret_cast<LPVOID>(address), size, buffer, &buffer))
		return false;
	return true;
}


bool process::nop_bytes(const std::uintptr_t address, const size_t size)
{
	if (!address || !size)
		return false;
	DWORD buffer = 0;
	if (!VirtualProtectEx(
		this->m_handle,
		reinterpret_cast<LPVOID>(address),
		size,
		PAGE_EXECUTE_READWRITE,
		&buffer
	))
		return false;
	for (size_t i = 0; i < size; i++)
		this->write< byte >(address + i, 0x90);
	if (!VirtualProtectEx(this->m_handle, reinterpret_cast<LPVOID>(address), size, buffer, &buffer))
		return false;
	return true;
}

bool process::read_image(byte_vector* dest_vec, const std::wstring& image_name)
{
	if (!dest_vec || image_name.empty() || !this->does_image_exist_in_map(image_name))
		return false;

	// here should no exception occur, because I checked above if the image exists in the map
	const auto image = this->m_images.at(image_name).get();

	// clear the vector and make sure the vector has the correct size
	dest_vec->clear();
	dest_vec->resize(image->get_image_size());

	return ReadProcessMemory(this->m_handle, reinterpret_cast<LPCVOID>(image->get_image_base()), dest_vec->data(), image->get_image_size(), nullptr) != 0;
}
