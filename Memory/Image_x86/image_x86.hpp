#pragma once

#include <cstdint>
#include <string>
#include <Windows.h>
#include <format>

#include "../../Includings/custom_data_types.hpp"

class image_x86
{

public:

	///-------------------------------------------------------------------------------------------------
	/// <summary>Default constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	image_x86()
	{
		this->m_base = std::uintptr_t();

		this->m_size = size_t();

		this->m_bytes = byte_vector();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="image_base">	The image base.</param>
	/// <param name="image_size">	Size of the image.</param>
	///-------------------------------------------------------------------------------------------------

	image_x86(const std::uintptr_t image_base, const size_t image_size)
	{
		this->m_base = image_base;

		this->m_size = image_size;

		this->m_bytes = byte_vector();
		this->m_bytes.reserve(image_size);
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets image base.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The image base.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline std::uintptr_t get_image_base() const noexcept
	{
		return this->m_base;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets image size.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The image size.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline size_t get_image_size() const noexcept
	{
		return this->m_size;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Queries if the byte vector is empty.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if the byte vector is empty, false if not.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline bool is_byte_vector_empty() const noexcept
	{
		return this->m_bytes.empty();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets a pointer to the byte vector, where all bytes from the dumped image are stored.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>Null if it fails, else the byte vector pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline byte_vector* get_byte_vector_ptr() noexcept
	{
		return &this->m_bytes;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets pointer to first byte of the byte vector, where all bytes from the dumped image are stored.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>Null if it fails, else the pointer to first byte of the byte vector.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline std::byte* get_ref_to_first_byte() noexcept
	{
		// make sure that the vector isn't empty, so no exception can occur
		if (this->m_bytes.empty())
			return nullptr;

		return &this->m_bytes.front();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Checks if the dumped image is an executable, by checking if the MZ signature is valid.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if executable, false if not.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline bool is_executable() const noexcept
	{
		if (this->m_bytes.size() < 2)
			return false;

		// how does this even work with using "constexpr"?
		// If you have a answer to my question, I would be very happy if you write me a quick mail - thanks! :)
		constexpr uint16_t MZ_SIGNATURE = 0x5A4D;

		return std::memcmp(reinterpret_cast<LPCVOID>(&this->m_bytes.at(0)), reinterpret_cast<LPCVOID>(&MZ_SIGNATURE), sizeof(std::byte) * 2) == 0;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Searches for an byte pattern in the vector of bytes from the dumped image.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="pattern">			 	Specifies the pattern.</param>
	/// <param name="should_be_relative">	(Optional) True if the result address should be relative.</param>
	///
	/// <returns>The first found pattern match address.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::uintptr_t find_pattern(const std::wstring& pattern, const bool should_be_relative = true );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Searches for all byte pattern occurences inside the dumped image.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="pattern">			 	Specifies the pattern.</param>
	/// <param name="should_be_relative">	(Optional) True if the result addresses should be relative.</param>
	///
	/// <returns>An vector of addresses where the byte pattern could be matched inside the dumped image.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::vector< std::uintptr_t > find_all_pattern_occurences( const std::wstring& pattern, const bool should_be_relative = true );

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

	///-------------------------------------------------------------------------------------------------
	/// <summary>Reads an nullterminated string from an address inside the image.</summary>
	///
	/// <remarks>cragson, 12/17/21.</remarks>
	///
	/// <param name="address">	  	The address of the string inside the image.</param>
	/// <param name="is_relative">	(Optional) If the address is absolute (base+offset) or is relative (offset). By default this parameter is false.</param>
	///
	/// <returns>The string read from the address.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline std::string read_string_from_address( const std::uintptr_t address, const bool is_relative = false )
	{
		if( address < this->m_base || address > this->m_base + this->m_size )
			return "OSMIUM_INVALID_ADDRESS";

		std::string ret = {};

		char c = {};

		auto stringptr = is_relative
		? this->deref_address< std::uintptr_t >( address )
		: this->deref_address< std::uintptr_t >( address - this->m_base );

		while( ( c = this->deref_address< char >( stringptr++ ) ) != '\0'  )
			ret += c;

		return ret;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>This functions prints a hexdump of the memory region to the console.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="start_addr">	   	The start address of the dump.</param>
	/// <param name="size">			   	The number of bytes, which should be dumped.</param>
	/// <param name="is_absolute_addr">	True if the address on the left should be absolute, false if not.</param>
	///-------------------------------------------------------------------------------------------------

	void print_memory_region( const std::uintptr_t start_addr, const size_t size, const bool is_absolute_addr ) const
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
					left_side += std::vformat( "{:02X} ", std::make_format_args( std::to_integer< uint8_t >( current_byte ) ) );
				else
					left_side += std::vformat( "{:02X}", std::make_format_args( std::to_integer< uint8_t >( current_byte ) ) );
				
				// prepare right side, which should be ascii chars etc
				const auto rs_value = std::to_integer< uint8_t >( current_byte );
				
				right_side += std::vformat( "{} ", std::make_format_args( rs_value >= 33 && rs_value < 127 ? static_cast< char >( rs_value ) : static_cast< char >( 46 ) ) );
			}

			// print now the current line and a newline
			printf( "0x%0X | %-32s | %s\n", start_addr + idx, left_side.c_str(), right_side.c_str() );

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
