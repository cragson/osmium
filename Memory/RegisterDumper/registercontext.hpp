#pragma once

#include <cstdint>

#include "../SharedMemoryInstance/sharedmemoryinstance.hpp"

class register_data
{
public:

	// I don't want anyone to write into the struct as this would produce undefined behaviour
	// Because the dumper will write into the shared memory which a user could also might write to into the exact moment to it
	register_data& operator=(const register_data&) = delete;

	union EAX
	{
		uint32_t eax;
		uint16_t ax;
		uint8_t a[2];
	}EAX;

	union EBX
	{
		uint32_t ebx;
		uint16_t bx;
		uint8_t b[2];
	}EBX;

	union ECX
	{
		uint32_t ecx;
		uint16_t cx;
		uint8_t c[2];
	}ECX;

	union EDX
	{
		uint32_t edx;
		uint16_t dx;
		uint8_t d[2];
	}EDX;

	union ESP
	{
		uint32_t esp;
		uint16_t sp;
	}ESP;

	union EBP
	{
		uint32_t ebp;
		uint16_t bp;
	}EBP;

	union ESI
	{
		uint32_t esi;
		uint16_t si;
	}ESI;

	union EDI
	{
		uint32_t edi;
		uint16_t di;
	}EDI;

	//float st0, st1, st2, st3, st4, st5, st6, st7;

	//float xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
};

// TODO: add documentation
class registercontext
{
public:

	registercontext() = delete;

	explicit registercontext( shared_memory_instance* sh_ptr, const std::uintptr_t dumped_address, const size_t hook_size ) 
	{
		if (sh_ptr == nullptr)
			throw std::exception("Shared memory instance pointer is nullptr!");

		this->m_pShInstance = sh_ptr;

		this->m_bActive = false;

		this->m_iDumpedAddress = dumped_address;

		this->m_iHookSize = hook_size;
	}

	[[nodiscard]] inline auto get_shared_memory_instance_ptr() const noexcept
	{
		return this->m_pShInstance;
	}

	[[nodiscard]] inline auto get_registers_data() const noexcept
	{
		return static_cast< register_data* >( this->m_pShInstance->get_buffer_ptr() );
	}

	[[nodiscard]] inline auto is_dumper_active() const noexcept
	{
		return this->m_bActive;
	}

	[[nodiscard]] inline auto get_dumped_address() const noexcept
	{
		return this->m_iDumpedAddress;
	}

	[[nodiscard]] inline auto get_hook_size() const noexcept
	{
		return this->m_iHookSize;
	}

	inline void enable_dumper() noexcept
	{
		this->m_bActive = true;
	}

	inline void disable_dumper() noexcept
	{
		this->m_bActive = false;
	}

	inline void toggle_dumper() noexcept
	{
		this->m_bActive = !this->m_bActive;
	}

private:
	shared_memory_instance* m_pShInstance;

	bool m_bActive;

	std::uintptr_t m_iDumpedAddress;

	size_t m_iHookSize;
};