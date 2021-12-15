#pragma once

#include <cstdint>
#include <string>
#include <Windows.h>
#include <format>

#include "../../Includings/custom_data_types.hpp"

class image_x86
{

public:

	image_x86()
	{
		this->m_base = std::uintptr_t();

		this->m_size = size_t();

		this->m_bytes = byte_vector();
	}

	image_x86(const std::uintptr_t image_base, const size_t image_size)
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

	[[nodiscard]] std::uintptr_t find_pattern(const std::wstring& pattern, const bool should_be_relative = true );

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
	[[nodiscard]] inline T deref_address( const std::uintptr_t address, const size_t size = sizeof( T ) )
	{
		// make sure address is in range of the image
		if ( address < this->m_base || address > this->m_base + this->m_size )
			return T();

		T buffer = T();

		memcpy( &buffer, reinterpret_cast< LPCVOID >( &this->m_bytes.at( address - this->m_base ) ), size );

		return buffer;
	}

	void print_memory_region( const std::uintptr_t start_addr, const size_t size, const bool is_absolute_addr )
	{
		if ( start_addr < 0 || start_addr > this->m_base + this->m_size )
			return;

		std::string left_side = {};
		std::string right_side = {};

		for ( uint32_t idx = 0; idx < size; idx += 16 )
		{
			// now loop through the buffer and prepare both sides
			for ( uint32_t j = 0; j < 16; j++ )
			{
				const auto current_byte = ( is_absolute_addr ) ? this->m_bytes.at( start_addr + idx + j - this->m_base ) : this->m_bytes.at( start_addr + idx + j );
				
				// prepare left side, which is the hex bytes
				if ( j != 15 )
					left_side += std::format( "{:02X} ", std::to_integer< uint8_t >( current_byte ) );
				else
					left_side += std::format( "{:02X}", std::to_integer< uint8_t >( current_byte ) );
				
				// prepare right side, which should be ascii chars etc
				const auto rs_value = std::to_integer< uint8_t >( current_byte );
				
				right_side += std::format( "{} ", ( rs_value >= 33 && rs_value < 127 ) ? static_cast< char >( rs_value ) : static_cast< char >( 46 ) );
			}

			// print now the current line and a newline
			printf( "%-25s | %s\n", left_side.c_str(), right_side.c_str() );

			// reset now both side strings
			left_side = "";
			right_side = "";
		}
	}


private:
	std::uintptr_t m_base;

	size_t m_size;

	byte_vector m_bytes;
};
