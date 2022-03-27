#pragma once

#include <cstdint>

#include <vector>

class hook
{

public:

	hook() :
		m_start_address( std::uintptr_t() ),
		m_allocated_page_address( std::uintptr_t() ),
		m_hook_size( size_t() ),
		m_shellcode( {} ),
		m_original_bytes( {} )
	{}

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

	[[nodiscard]] inline std::uintptr_t get_hook_address() const noexcept
	{
		return this->m_start_address;
	}

	[[nodiscard]] inline std::uintptr_t get_allocated_page_address() const noexcept
	{
		return this->m_allocated_page_address;
	}

	[[nodiscard]] inline size_t get_hook_size() const noexcept
	{
		return this->m_hook_size;
	}

	[[nodiscard]] inline auto get_shellcode_ptr() noexcept
	{
		return &this->m_shellcode;
	}

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