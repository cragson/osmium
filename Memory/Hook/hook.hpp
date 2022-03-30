#pragma once

#include <cstdint>

#include <vector>

class hook
{

public:

	///-------------------------------------------------------------------------------------------------
	/// <summary>Default constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	hook() :
		m_start_address( std::uintptr_t() ),
		m_allocated_page_address( std::uintptr_t() ),
		m_hook_size( size_t() ),
		m_shellcode( {} ),
		m_original_bytes( {} )
	{}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="start">		The start address where the hook will be placed.</param>
	/// <param name="page">			The address of the allocated memory page, needed for freeing it later.</param>
	/// <param name="size">			The number of bytes which were overwritten.</param>
	/// <param name="shellcode">	The shellcode as a vector of bytes.</param>
	/// <param name="original"> 	The original bytes, which were overwritten by the hook instructions, as a vector of bytes.</param>
	///-------------------------------------------------------------------------------------------------

	hook( 
		const std::uintptr_t start,
		const std::uintptr_t page,
		const size_t size, 
		const std::vector< uint8_t >& shellcode, 
		const std::vector< uint8_t >& original 
	) :
		m_start_address( start ),
		m_allocated_page_address( page ),
		m_hook_size( size ),
		m_shellcode( shellcode ),
		m_original_bytes( original )
	{}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the hook address, where the mid function hook was placed inside the target process.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The hook address.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline std::uintptr_t get_hook_address() const noexcept
	{
		return this->m_start_address;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the address of the allocated page inside the target process, where the shellcode was placed.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The address of the allocated page.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline std::uintptr_t get_allocated_page_address() const noexcept
	{
		return this->m_allocated_page_address;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the size of the hook in bytes, also tells how many bytes were overwritten in the original function.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The size of the hook in bytes.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline size_t get_hook_size() const noexcept
	{
		return this->m_hook_size;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets a pointer to the shellcode, which is an vector of bytes.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The pointer to the shellcode.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline auto get_shellcode_ptr() noexcept
	{
		return &this->m_shellcode;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets a pointer to the original bytes, which is an vector of bytes.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The original bytes pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline auto get_original_bytes_ptr() noexcept
	{
		return &this->m_original_bytes;
	}

protected:

	std::uintptr_t m_start_address;
	std::uintptr_t m_allocated_page_address;

	size_t m_hook_size;

	std::vector< uint8_t > m_shellcode;
	std::vector< uint8_t > m_original_bytes;
};