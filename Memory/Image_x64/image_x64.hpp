#pragma once

#include <cstdint>
#include <string>
#include <Windows.h>
#include "../../Includings/custom_data_types.hpp"

class image_x64
{

public:

	image_x64()
	{
		this->m_base = std::uintptr_t();

		this->m_size = size_t();

		this->m_bytes = byte_vector();
	}

	image_x64(const std::uintptr_t image_base, const size_t image_size)
	{
		this->m_base = image_base;

		this->m_size = image_size;

		this->m_bytes = byte_vector();
		this->m_bytes.reserve(image_size);
	}

	[[nodiscard]] inline std::uintptr_t get_image_base() const noexcept
	{
		return this->m_base;
	}

	[[nodiscard]] inline size_t get_image_size() const noexcept
	{
		return this->m_size;
	}

	[[nodiscard]] inline bool is_byte_vector_empty() const noexcept
	{
		return this->m_bytes.empty();
	}

	[[nodiscard]] inline byte_vector* get_byte_vector_ptr() noexcept
	{
		return &this->m_bytes;
	}

	[[nodiscard]] inline std::byte* get_ref_to_first_byte() noexcept
	{
		// make sure that the vector isn't empty, so no exception can occur
		if (this->m_bytes.empty())
			return nullptr;

		return &this->m_bytes.front();
	}

	[[nodiscard]] inline bool is_executable() const noexcept
	{
		if (this->m_bytes.size() < 2)
			return false;

		// how does this even work with using "constexpr"?
		// If you have a answer to my question, I would be very happy if you write me a quick mail - thanks! :)
		constexpr uint16_t MZ_SIGNATURE = 0x5A4D;

		return std::memcmp(reinterpret_cast<LPCVOID>(&this->m_bytes.at(0)), reinterpret_cast<LPCVOID>(&MZ_SIGNATURE), sizeof(std::byte) * 2) == 0;
	}

	[[nodiscard]] std::uintptr_t find_pattern(const std::wstring& pattern, const bool should_be_relative = true);

	///-------------------------------------------------------------------------------------------------
	/// <summary> This function is used for dereferencing the bytes from the byte_vector. </summary>
	///
	/// <typeparam name="T">	The type which will determine the return type and the size of the memcpy. </typeparam>
	/// <param name="address">	The address which will be deferenced, make sure this isn't relative but absolute (image base + offset). </param>
	/// <param name="size">   	(Optional) The size which will be used in the std::memcpy call. </param>
	///
	/// <returns> A Buffer of the determined type, holding the specific bytes at the given address of the image. </returns>
	///-------------------------------------------------------------------------------------------------

	template< typename T >
	[[nodiscard]] inline T deref_address(const std::uintptr_t address, const size_t size = sizeof(T))
	{
		// make sure address is in range of the image
		if (address < this->m_base || address > this->m_base + this->m_size)
			return T();

		T buffer = T();

		memcpy(&buffer, reinterpret_cast<LPCVOID>(&this->m_bytes.at(address - this->m_base)), size);

		return buffer;
	}

private:
	std::uintptr_t m_base;

	size_t m_size;

	byte_vector m_bytes;
};
