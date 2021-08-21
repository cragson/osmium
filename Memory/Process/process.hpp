#pragma once
#include <Windows.h>
#include <string>
#include <memory>
#include <unordered_map>
#include "../image_x64/image_x64.hpp"

class process
{
public:
	process()
	{
		this->m_handle = INVALID_HANDLE_VALUE;
		this->m_hwnd = nullptr;
		this->m_pid = 0;
	}


	~process()
	{
		if (this->m_handle)
			CloseHandle(this->m_handle);
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
	T read(std::uintptr_t address, size_t size_of_read = sizeof(T))
	{
		T buffer;
		ReadProcessMemory(this->m_handle, reinterpret_cast<LPCVOID>(address), &buffer, size_of_read, nullptr);
		return buffer;
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


	[[nodiscard]] bool refresh_image_map(const DWORD process_id = 0);

	[[nodiscard]] bool setup_process(const std::wstring& window_name);


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

	[[nodiscard]] image_x64* get_image_ptr_by_name(const std::wstring& image_name) const noexcept
	{
		if (!this->does_image_exist_in_map(image_name))
			return nullptr;

		return this->m_images.at(image_name).get();
	}


	[[nodiscard]] size_t get_map_size() const noexcept
	{
		return this->m_images.size();
	}

	[[nodiscard]] double get_map_size_in_mbytes() const noexcept
	{
		if (this->m_images.empty())
			return double();

		auto size = 0.0;

		constexpr auto divider = 1024.0 * 1024.0;

		for (const auto& image : this->m_images)
			size += static_cast<double>(image.second->get_image_size() / divider);

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

		for (auto& image : this->m_images)
			printf(
				"[+] %-25ls | 0x%llX | 0x%llX | %d.\n",
				image.first.c_str(),
				image.second->get_image_base(),
				image.second->get_image_size(),
				image.second->is_executable()
			);
		printf("\n\n");
	}

	void print_images(const size_t num_of_images) const
	{
		if (this->m_images.empty() || num_of_images >= this->m_images.size())
			return;

		printf("[#] Image-Name | Image-Base | Image-Size | Is-Executable\n");

		size_t counter = 0;

		for (auto& image : this->m_images)
		{
			if (counter == num_of_images)
				return;

			printf(
				"[+] %-25ls | 0x%llX | 0x%llX | %d.\n",
				image.first.c_str(),
				image.second->get_image_base(),
				image.second->get_image_size(),
				image.second->is_executable()
			);

			counter++;
		}
	}


	bool patch_bytes(const byte_vector& bytes, std::uintptr_t address, size_t size);


	bool patch_bytes(const std::byte bytes[], std::uintptr_t address, size_t size);


	bool nop_bytes(std::uintptr_t address, size_t size);

	[[nodiscard]] bool read_image(byte_vector* dest_vec, const std::wstring& image_name);


private:
	HANDLE m_handle;

	HWND m_hwnd;

	DWORD m_pid;

	std::unordered_map< std::wstring, std::unique_ptr< image_x64 > > m_images;
};
