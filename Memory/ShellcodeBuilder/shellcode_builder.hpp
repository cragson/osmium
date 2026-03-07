#pragma once

#include <cstdint>
#include <vector>
#include <stdexcept>

/*
 * Lightweight x86/x64 shellcode builder.
 *
 * Encodes common instructions directly — no external dependencies
 * (capstone, keystone, etc.) required.  Uses a fluent builder pattern
 * so calls can be chained:
 *
 *   auto code = shellcode::x64()
 *       .push_reg( shellcode::RAX )
 *       .mov_reg_imm( shellcode::RAX, 0x00007FF600000000 )
 *       .call_reg( shellcode::RAX )
 *       .pop_reg( shellcode::RAX )
 *       .ret()
 *       .build();
 */

namespace shellcode
{
	/* -----------------------------------------------------------------------
	 * Register identifiers (encoding index matches ModRM/SIB numbering)
	 * ----------------------------------------------------------------------- */

	enum reg32 : uint8_t
	{
		EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI
	};

	enum reg64 : uint8_t
	{
		RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
		R8, R9, R10, R11, R12, R13, R14, R15
	};

	/* -----------------------------------------------------------------------
	 * x86 builder (32-bit)
	 * ----------------------------------------------------------------------- */

	class x86
	{
		std::vector< uint8_t > m_buf;

	public:
		/* Emit raw bytes */
		x86& raw( const std::vector< uint8_t >& bytes )
		{
			m_buf.insert( m_buf.end(), bytes.begin(), bytes.end() );
			return *this;
		}

		x86& raw( uint8_t byte )
		{
			m_buf.push_back( byte );
			return *this;
		}

		/* NOP */
		x86& nop()
		{
			m_buf.push_back( 0x90 );
			return *this;
		}

		/* INT3 (breakpoint) */
		x86& int3()
		{
			m_buf.push_back( 0xCC );
			return *this;
		}

		/* RET */
		x86& ret()
		{
			m_buf.push_back( 0xC3 );
			return *this;
		}

		/* PUSH reg32 */
		x86& push_reg( reg32 r )
		{
			m_buf.push_back( 0x50 + r );
			return *this;
		}

		/* POP reg32 */
		x86& pop_reg( reg32 r )
		{
			m_buf.push_back( 0x58 + r );
			return *this;
		}

		/* PUSHAD (push all general-purpose registers) */
		x86& pushad()
		{
			m_buf.push_back( 0x60 );
			return *this;
		}

		/* POPAD (pop all general-purpose registers) */
		x86& popad()
		{
			m_buf.push_back( 0x61 );
			return *this;
		}

		/* PUSHFD (push EFLAGS) */
		x86& pushfd()
		{
			m_buf.push_back( 0x9C );
			return *this;
		}

		/* POPFD (pop EFLAGS) */
		x86& popfd()
		{
			m_buf.push_back( 0x9D );
			return *this;
		}

		/* MOV reg32, imm32 */
		x86& mov_reg_imm( reg32 r, uint32_t imm )
		{
			m_buf.push_back( 0xB8 + r );
			push_le32( imm );
			return *this;
		}

		/* MOV reg32, reg32 */
		x86& mov_reg_reg( reg32 dst, reg32 src )
		{
			m_buf.push_back( 0x89 );
			m_buf.push_back( modrm( 3, src, dst ) );
			return *this;
		}

		/* XOR reg32, reg32 (commonly used to zero a register) */
		x86& xor_reg_reg( reg32 dst, reg32 src )
		{
			m_buf.push_back( 0x31 );
			m_buf.push_back( modrm( 3, src, dst ) );
			return *this;
		}

		/* ADD reg32, imm32 */
		x86& add_reg_imm( reg32 r, uint32_t imm )
		{
			if( imm <= 0x7F )
			{
				m_buf.push_back( 0x83 );
				m_buf.push_back( modrm( 3, 0, r ) );
				m_buf.push_back( static_cast< uint8_t >( imm ) );
			}
			else
			{
				if( r == EAX )
				{
					m_buf.push_back( 0x05 );
				}
				else
				{
					m_buf.push_back( 0x81 );
					m_buf.push_back( modrm( 3, 0, r ) );
				}
				push_le32( imm );
			}
			return *this;
		}

		/* SUB reg32, imm32 */
		x86& sub_reg_imm( reg32 r, uint32_t imm )
		{
			if( imm <= 0x7F )
			{
				m_buf.push_back( 0x83 );
				m_buf.push_back( modrm( 3, 5, r ) );
				m_buf.push_back( static_cast< uint8_t >( imm ) );
			}
			else
			{
				if( r == EAX )
				{
					m_buf.push_back( 0x2D );
				}
				else
				{
					m_buf.push_back( 0x81 );
					m_buf.push_back( modrm( 3, 5, r ) );
				}
				push_le32( imm );
			}
			return *this;
		}

		/* CALL reg32 (indirect) */
		x86& call_reg( reg32 r )
		{
			m_buf.push_back( 0xFF );
			m_buf.push_back( modrm( 3, 2, r ) );
			return *this;
		}

		/* JMP reg32 (indirect) */
		x86& jmp_reg( reg32 r )
		{
			m_buf.push_back( 0xFF );
			m_buf.push_back( modrm( 3, 4, r ) );
			return *this;
		}

		/* CALL rel32 (relative to current position) */
		x86& call_rel( int32_t offset )
		{
			m_buf.push_back( 0xE8 );
			push_le32( static_cast< uint32_t >( offset ) );
			return *this;
		}

		/* JMP rel32 (relative to current position) */
		x86& jmp_rel( int32_t offset )
		{
			m_buf.push_back( 0xE9 );
			push_le32( static_cast< uint32_t >( offset ) );
			return *this;
		}

		/* MOV [reg32], reg32 — store to memory pointed by register */
		x86& mov_mem_reg( reg32 base, reg32 src )
		{
			m_buf.push_back( 0x89 );
			m_buf.push_back( modrm( 0, src, base ) );
			return *this;
		}

		/* MOV reg32, [reg32] — load from memory pointed by register */
		x86& mov_reg_mem( reg32 dst, reg32 base )
		{
			m_buf.push_back( 0x8B );
			m_buf.push_back( modrm( 0, dst, base ) );
			return *this;
		}

		/* PUSH imm32 */
		x86& push_imm( uint32_t imm )
		{
			m_buf.push_back( 0x68 );
			push_le32( imm );
			return *this;
		}

		/* Return the assembled bytes */
		[[nodiscard]] std::vector< uint8_t > build() const
		{
			return m_buf;
		}

		/* Return current size */
		[[nodiscard]] size_t size() const noexcept
		{
			return m_buf.size();
		}

	private:
		static uint8_t modrm( uint8_t mod, uint8_t reg, uint8_t rm )
		{
			return ( ( mod & 3 ) << 6 ) | ( ( reg & 7 ) << 3 ) | ( rm & 7 );
		}

		void push_le32( uint32_t v )
		{
			m_buf.push_back( static_cast< uint8_t >( v ) );
			m_buf.push_back( static_cast< uint8_t >( v >> 8 ) );
			m_buf.push_back( static_cast< uint8_t >( v >> 16 ) );
			m_buf.push_back( static_cast< uint8_t >( v >> 24 ) );
		}
	};

	/* -----------------------------------------------------------------------
	 * x64 builder (64-bit)
	 * ----------------------------------------------------------------------- */

	class x64
	{
		std::vector< uint8_t > m_buf;

	public:
		/* Emit raw bytes */
		x64& raw( const std::vector< uint8_t >& bytes )
		{
			m_buf.insert( m_buf.end(), bytes.begin(), bytes.end() );
			return *this;
		}

		x64& raw( uint8_t byte )
		{
			m_buf.push_back( byte );
			return *this;
		}

		/* NOP */
		x64& nop()
		{
			m_buf.push_back( 0x90 );
			return *this;
		}

		/* INT3 (breakpoint) */
		x64& int3()
		{
			m_buf.push_back( 0xCC );
			return *this;
		}

		/* RET */
		x64& ret()
		{
			m_buf.push_back( 0xC3 );
			return *this;
		}

		/* PUSH reg64 (R8-R15 use REX.B prefix) */
		x64& push_reg( reg64 r )
		{
			emit_rex_b( r );
			m_buf.push_back( 0x50 + ( r & 7 ) );
			return *this;
		}

		/* POP reg64 */
		x64& pop_reg( reg64 r )
		{
			emit_rex_b( r );
			m_buf.push_back( 0x58 + ( r & 7 ) );
			return *this;
		}

		/* MOV reg64, imm64 (REX.W + B8+r + imm64) */
		x64& mov_reg_imm( reg64 r, uint64_t imm )
		{
			m_buf.push_back( rex_w( 0, 0, r ) );
			m_buf.push_back( 0xB8 + ( r & 7 ) );
			push_le64( imm );
			return *this;
		}

		/* MOV reg64, imm32 (zero-extended, REX.W + C7 /0) */
		x64& mov_reg_imm32( reg64 r, uint32_t imm )
		{
			m_buf.push_back( rex_w( 0, 0, r ) );
			m_buf.push_back( 0xC7 );
			m_buf.push_back( modrm( 3, 0, r & 7 ) );
			push_le32( imm );
			return *this;
		}

		/* MOV reg64, reg64 */
		x64& mov_reg_reg( reg64 dst, reg64 src )
		{
			m_buf.push_back( rex_w( 0, src, dst ) );
			m_buf.push_back( 0x89 );
			m_buf.push_back( modrm( 3, src & 7, dst & 7 ) );
			return *this;
		}

		/* XOR reg64, reg64 */
		x64& xor_reg_reg( reg64 dst, reg64 src )
		{
			m_buf.push_back( rex_w( 0, src, dst ) );
			m_buf.push_back( 0x31 );
			m_buf.push_back( modrm( 3, src & 7, dst & 7 ) );
			return *this;
		}

		/* ADD reg64, imm32 (sign-extended) */
		x64& add_reg_imm( reg64 r, int32_t imm )
		{
			if( imm >= -128 && imm <= 127 )
			{
				m_buf.push_back( rex_w( 0, 0, r ) );
				m_buf.push_back( 0x83 );
				m_buf.push_back( modrm( 3, 0, r & 7 ) );
				m_buf.push_back( static_cast< uint8_t >( imm ) );
			}
			else
			{
				m_buf.push_back( rex_w( 0, 0, r ) );
				if( ( r & 7 ) == 0 && r < R8 )
				{
					m_buf.push_back( 0x05 );
				}
				else
				{
					m_buf.push_back( 0x81 );
					m_buf.push_back( modrm( 3, 0, r & 7 ) );
				}
				push_le32( static_cast< uint32_t >( imm ) );
			}
			return *this;
		}

		/* SUB reg64, imm32 (sign-extended) */
		x64& sub_reg_imm( reg64 r, int32_t imm )
		{
			if( imm >= -128 && imm <= 127 )
			{
				m_buf.push_back( rex_w( 0, 0, r ) );
				m_buf.push_back( 0x83 );
				m_buf.push_back( modrm( 3, 5, r & 7 ) );
				m_buf.push_back( static_cast< uint8_t >( imm ) );
			}
			else
			{
				m_buf.push_back( rex_w( 0, 0, r ) );
				if( ( r & 7 ) == 0 && r < R8 )
				{
					m_buf.push_back( 0x2D );
				}
				else
				{
					m_buf.push_back( 0x81 );
					m_buf.push_back( modrm( 3, 5, r & 7 ) );
				}
				push_le32( static_cast< uint32_t >( imm ) );
			}
			return *this;
		}

		/* CALL reg64 (indirect) */
		x64& call_reg( reg64 r )
		{
			if( r >= R8 )
				m_buf.push_back( 0x41 );
			m_buf.push_back( 0xFF );
			m_buf.push_back( modrm( 3, 2, r & 7 ) );
			return *this;
		}

		/* JMP reg64 (indirect) */
		x64& jmp_reg( reg64 r )
		{
			if( r >= R8 )
				m_buf.push_back( 0x41 );
			m_buf.push_back( 0xFF );
			m_buf.push_back( modrm( 3, 4, r & 7 ) );
			return *this;
		}

		/* CALL rel32 */
		x64& call_rel( int32_t offset )
		{
			m_buf.push_back( 0xE8 );
			push_le32( static_cast< uint32_t >( offset ) );
			return *this;
		}

		/* JMP rel32 */
		x64& jmp_rel( int32_t offset )
		{
			m_buf.push_back( 0xE9 );
			push_le32( static_cast< uint32_t >( offset ) );
			return *this;
		}

		/* MOV [reg64], reg64 — store to memory */
		x64& mov_mem_reg( reg64 base, reg64 src )
		{
			m_buf.push_back( rex_w( 0, src, base ) );
			m_buf.push_back( 0x89 );
			m_buf.push_back( modrm( 0, src & 7, base & 7 ) );
			return *this;
		}

		/* MOV reg64, [reg64] — load from memory */
		x64& mov_reg_mem( reg64 dst, reg64 base )
		{
			m_buf.push_back( rex_w( 0, dst, base ) );
			m_buf.push_back( 0x8B );
			m_buf.push_back( modrm( 0, dst & 7, base & 7 ) );
			return *this;
		}

		/* LEA reg64, [RIP + disp32] */
		x64& lea_rip( reg64 dst, int32_t disp )
		{
			m_buf.push_back( rex_w( 0, dst, 0 ) );
			m_buf.push_back( 0x8D );
			m_buf.push_back( modrm( 0, dst & 7, 5 ) );
			push_le32( static_cast< uint32_t >( disp ) );
			return *this;
		}

		/* SUB RSP, imm8 (shadow space / stack alignment) */
		x64& sub_rsp_imm8( uint8_t imm )
		{
			m_buf.push_back( 0x48 );
			m_buf.push_back( 0x83 );
			m_buf.push_back( 0xEC );
			m_buf.push_back( imm );
			return *this;
		}

		/* ADD RSP, imm8 */
		x64& add_rsp_imm8( uint8_t imm )
		{
			m_buf.push_back( 0x48 );
			m_buf.push_back( 0x83 );
			m_buf.push_back( 0xC4 );
			m_buf.push_back( imm );
			return *this;
		}

		/* Return the assembled bytes */
		[[nodiscard]] std::vector< uint8_t > build() const
		{
			return m_buf;
		}

		/* Return current size */
		[[nodiscard]] size_t size() const noexcept
		{
			return m_buf.size();
		}

	private:
		static uint8_t modrm( uint8_t mod, uint8_t reg, uint8_t rm )
		{
			return ( ( mod & 3 ) << 6 ) | ( ( reg & 7 ) << 3 ) | ( rm & 7 );
		}

		/* REX.W prefix: W=1, R=reg>>3, X=0, B=rm>>3 */
		static uint8_t rex_w( uint8_t x, uint8_t reg, uint8_t rm )
		{
			return 0x48 | ( ( reg >> 3 ) << 2 ) | ( ( x >> 3 ) << 1 ) | ( rm >> 3 );
		}

		/* Emit REX.B only if register index >= 8 (R8-R15) */
		void emit_rex_b( reg64 r )
		{
			if( r >= R8 )
				m_buf.push_back( 0x41 );
		}

		void push_le32( uint32_t v )
		{
			m_buf.push_back( static_cast< uint8_t >( v ) );
			m_buf.push_back( static_cast< uint8_t >( v >> 8 ) );
			m_buf.push_back( static_cast< uint8_t >( v >> 16 ) );
			m_buf.push_back( static_cast< uint8_t >( v >> 24 ) );
		}

		void push_le64( uint64_t v )
		{
			push_le32( static_cast< uint32_t >( v ) );
			push_le32( static_cast< uint32_t >( v >> 32 ) );
		}
	};

} // namespace shellcode
