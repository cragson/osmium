#pragma once

#include <format>
#include <cstdint>
#include <string>
#include <Windows.h>
#include "../../Includings/custom_data_types.hpp"

class image_x64
{

public:

	///-------------------------------------------------------------------------------------------------
	/// <summary>Default constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	image_x64()
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

	image_x64(const std::uintptr_t image_base, const size_t image_size)
	{
		this->m_base = image_base;

		this->m_size = image_size;

		this->m_bytes = byte_vector();
		this->m_bytes.resize(image_size);
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
	/// <summary>	Gets dos header pointer of the current image. </summary>
	///
	/// <remarks>	cragson, 09/07/2024. </remarks>
	///
	/// <returns>	The dos header pointer. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline PIMAGE_DOS_HEADER get_dos_header_ptr() noexcept
	{
		if (this->m_bytes.size() < sizeof(IMAGE_DOS_HEADER))
			return nullptr;

		const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(this->m_bytes.data());

		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		return dos_header;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Gets NT headers pointer of the current image. </summary>
	///
	/// <remarks>	cragson, 09/07/2024. </remarks>
	///
	/// <returns>	The NT headers pointer. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline PIMAGE_NT_HEADERS get_nt_headers_ptr() noexcept
	{
		const auto dos_header = this->get_dos_header_ptr();

		if (!dos_header)
			return nullptr;

		if (this->m_bytes.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
			return nullptr;

		const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(this->m_bytes.data() + dos_header->e_lfanew);

		if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		return nt_headers;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Gets import descriptor of the current image. </summary>
	///
	/// <remarks>	cragson, 09/07/2024. </remarks>
	///
	/// <returns>	The import descriptor pointer. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline PIMAGE_IMPORT_DESCRIPTOR get_import_descriptor() noexcept
	{
		const auto nt_headers = this->get_nt_headers_ptr();

		if (!nt_headers)
			return nullptr;

		return reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(this->m_bytes.data() + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Parses the Import Address Table (IAT) of the current image and retrieves the imports. </summary>
	///
	/// <remarks>	cragson, 09/07/2024. </remarks>
	///
	/// <returns>	Returns an std::vector with the image name, function name and function ptr of all entries in the IAT. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline auto get_imports() noexcept
	{
		std::vector< std::tuple< std::string, std::string, std::uintptr_t > > ret = {};

		auto id = this->get_import_descriptor();

		if (!id)
			return ret;

		while (id->Name)
		{
			const auto module_name = std::string(reinterpret_cast<char*>(this->m_bytes.data() + id->Name));

			if (module_name.empty())
			{
				++id;

				continue;
			}

			auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(this->m_bytes.data() + id->FirstThunk);

			auto orig_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(this->m_bytes.data() + id->OriginalFirstThunk);

			while (thunk->u1.AddressOfData)
			{
				std::string import_name = {};

				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					// weird fix for handling incorrect values in orig_thunk like e.g.: 0x8000000000000008, 0x8000000000000005 etc.
					// need to do more research what this means and why this happens
					if (orig_thunk->u1.Ordinal && !(orig_thunk->u1.Ordinal & 0x8000000000000000))
						import_name = std::to_string(IMAGE_ORDINAL(orig_thunk->u1.Ordinal));
				}
				else
				{
					// weird fix for handling incorrect values in orig_thunk like e.g.: 0x8000000000000008, 0x8000000000000005 etc.
					if( orig_thunk->u1.AddressOfData && !(orig_thunk->u1.AddressOfData & 0x8000000000000000))
						import_name = std::string(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(this->m_bytes.data() + orig_thunk->u1.AddressOfData)->Name);
				}

				if( !import_name.empty())
					ret.emplace_back(
						module_name, 
						import_name,
						thunk->u1.Function
					);

				++thunk;
				++orig_thunk;
			}
			++id;
		}

		return ret;
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

	///-------------------------------------------------------------------------------------------------
	/// <summary>This functions prints a hexdump of the memory region to the console.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="start_addr">	   	The start address of the dump.</param>
	/// <param name="size">			   	The number of bytes, which should be dumped.</param>
	/// <param name="is_absolute_addr">	True if the address on the left should be absolute, false if not.</param>
	///-------------------------------------------------------------------------------------------------

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
					left_side += std::format( "{:02X} ", static_cast< uint8_t >( current_byte ) );
				else
					left_side += std::format( "{:02X}", static_cast< uint8_t >( current_byte ) );

				// prepare right side, which should be ascii chars etc
				const auto rs_value = static_cast< uint8_t >( current_byte );

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
