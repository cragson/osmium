#include "process.hpp"
#include <TlHelp32.h>

bool process::refresh_image_map(const DWORD process_id)
{
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };

	const auto snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, process_id);
	if (!snapshot_handle)
		return false;

	// after successfully retrieving my snapshot handle, I clear the map - to get rid of the old images + information
	// no memory leak should occur because I wrapped my imageinfo_t structs in a smart ptr
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
			this->m_images[me32.szModule] = std::make_unique< image_x64 >(image_base, image_size);

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

bool process::setup_process(const std::wstring& window_name)
{
	// First try to retrieve a window handle, the process id and a handle to the process with specific rights.
	if (window_name.empty())
		return false;

	const auto window_handle = FindWindowW(nullptr, window_name.c_str());
	if (!window_handle)
		return false;

	DWORD buffer = 0;
	if (!GetWindowThreadProcessId(window_handle, &buffer))
		return false;

	const auto proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, buffer);
	if (!proc_handle)
		return false;

	// set now the correct data
	// Because refresh_image_map will call RPM which uses m_handle
	// if the call 
	this->m_hwnd = window_handle;
	this->m_pid = buffer;
	this->m_handle = proc_handle;

	// Before I set the retrieved data, I want to safe information about every image in the process
	// So I iterate over every image loaded into the certain process and store them :)
	if (!this->refresh_image_map(buffer))
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
