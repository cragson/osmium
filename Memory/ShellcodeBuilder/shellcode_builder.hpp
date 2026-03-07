#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

/*
 * Lightweight x86/x64 shellcode builder.
 *
 * Encodes common instructions directly — no external dependencies
 * (capstone, keystone, etc.) required.  Uses a fluent builder pattern
 * so calls can be chained:
 *
 *   auto code = shellcode::x64()
 *       .push_reg( shellcode::reg64::RAX )
 *       .mov_reg_imm( shellcode::reg64::RAX, 0x00007FF600000000 )
 *       .call_reg( shellcode::reg64::RAX )
 *       .pop_reg( shellcode::reg64::RAX )
 *       .ret()
 *       .build();
 */

namespace shellcode
{
    /* -----------------------------------------------------------------------
     * Register identifiers (encoding index matches ModRM/SIB numbering)
     * ----------------------------------------------------------------------- */

    enum class reg32 : uint8_t
    {
        EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI
    };

    enum class reg64 : uint8_t
    {
        RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
        R8, R9, R10, R11, R12, R13, R14, R15
    };

    /* XMM registers for x86 SSE (XMM0-XMM7) */
    enum class xmm32 : uint8_t
    {
        XMM0 = 0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7
    };

    /* XMM registers for x64 SSE (XMM0-XMM15) */
    enum class xmm64 : uint8_t
    {
        XMM0 = 0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
        XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15
    };

    /* Helper to extract the numeric index from a scoped register enum */
    template< typename R >
    static constexpr uint8_t reg_index( R r ) noexcept
    {
        return static_cast< uint8_t >( r );
    }

    /* -----------------------------------------------------------------------
     * CRTP base class — shared logic for x86 and x64 builders
     * ----------------------------------------------------------------------- */

    template< typename Derived >
    class builder_base
    {
    public:
        struct label { size_t id; };
        struct fixup { size_t offset; size_t label_id; };

    protected:
        std::vector< uint8_t > m_buf;
        std::vector< fixup > m_fixups;
        size_t m_next_label = 0;
        std::vector< size_t > m_label_positions; // indexed by label id

        Derived& self() noexcept
        {
            return static_cast< Derived& >( *this );
        }

        /* ModRM byte: mod(2) | reg(3) | rm(3) */
        static constexpr uint8_t modrm( uint8_t mod, uint8_t reg, uint8_t rm )
        {
            return ( ( mod & 3 ) << 6 ) | ( ( reg & 7 ) << 3 ) | ( rm & 7 );
        }

        /* Push a 32-bit value in little-endian order */
        void push_le32( uint32_t v )
        {
            m_buf.push_back( static_cast< uint8_t >( v ) );
            m_buf.push_back( static_cast< uint8_t >( v >> 8 ) );
            m_buf.push_back( static_cast< uint8_t >( v >> 16 ) );
            m_buf.push_back( static_cast< uint8_t >( v >> 24 ) );
        }

        /* Emit ModRM + optional SIB/disp for indirect [base] addressing.
         * Handles the EBP/RBP (mod=1 disp8=0) and ESP/RSP (SIB 0x24) special cases.
         * reg_field is the /r or register field (bits 5:3 of ModRM). */
        void emit_modrm_indirect( uint8_t reg_field, uint8_t base )
        {
            if( ( base & 7 ) == 5 )
            {
                /* EBP/RBP/R13: mod=0 rm=5 encodes [disp32]/[RIP+disp32], use mod=1 disp8=0 */
                m_buf.push_back( modrm( 1, reg_field & 7, base & 7 ) );
                m_buf.push_back( 0x00 );
            }
            else if( ( base & 7 ) == 4 )
            {
                /* ESP/RSP/R12: mod=0 rm=4 encodes SIB follows, emit SIB 0x24 */
                m_buf.push_back( modrm( 0, reg_field & 7, base & 7 ) );
                m_buf.push_back( 0x24 );
            }
            else
            {
                m_buf.push_back( modrm( 0, reg_field & 7, base & 7 ) );
            }
        }

        /* Resolve all label fixups in the given buffer */
        void resolve_fixups( std::vector< uint8_t >& buf ) const
        {
            for( auto const& f : m_fixups )
            {
                auto target = m_label_positions[f.label_id];
                if( target == SIZE_MAX )
                {
                    /* Unbound label — emit zero displacement rather than garbage */
                    continue;
                }
                auto rel = static_cast< int32_t >( target - ( f.offset + 4 ) );
                auto v = static_cast< uint32_t >( rel );
                buf[f.offset]     = static_cast< uint8_t >( v );
                buf[f.offset + 1] = static_cast< uint8_t >( v >> 8 );
                buf[f.offset + 2] = static_cast< uint8_t >( v >> 16 );
                buf[f.offset + 3] = static_cast< uint8_t >( v >> 24 );
            }
        }

    public:
        /* Emit raw bytes */
        Derived& raw( std::vector< uint8_t > const& bytes )
        {
            m_buf.insert( m_buf.end(), bytes.begin(), bytes.end() );
            return self();
        }

        /* Emit a single raw byte */
        Derived& raw( uint8_t byte )
        {
            m_buf.push_back( byte );
            return self();
        }

        /* NOP */
        Derived& nop()
        {
            m_buf.push_back( 0x90 );
            return self();
        }

        /* INT3 (breakpoint) */
        Derived& int3()
        {
            m_buf.push_back( 0xCC );
            return self();
        }

        /* RET */
        Derived& ret()
        {
            m_buf.push_back( 0xC3 );
            return self();
        }

        /* Return the assembled bytes (copy, with fixups resolved) */
        [[nodiscard]] std::vector< uint8_t > build() const &
        {
            auto result = m_buf;
            resolve_fixups( result );
            return result;
        }

        /* Return the assembled bytes (move — use on temporaries, with fixups resolved) */
        [[nodiscard]] std::vector< uint8_t > build() &&
        {
            resolve_fixups( m_buf );
            return std::move( m_buf );
        }

        /* Return current buffer size */
        [[nodiscard]] size_t size() const noexcept
        {
            return m_buf.size();
        }

        /* Return current write offset (alias for size) */
        [[nodiscard]] size_t offset() const noexcept
        {
            return m_buf.size();
        }

        /* Patch a 32-bit little-endian value at a given position */
        Derived& patch( size_t pos, uint32_t value )
        {
            if( pos + 4 > m_buf.size() )
            {
                return self();
            }
            m_buf[pos]     = static_cast< uint8_t >( value );
            m_buf[pos + 1] = static_cast< uint8_t >( value >> 8 );
            m_buf[pos + 2] = static_cast< uint8_t >( value >> 16 );
            m_buf[pos + 3] = static_cast< uint8_t >( value >> 24 );
            return self();
        }

        /* ------- Label / fixup system ------- */

        /* Create a new label (unbound) */
        label make_label()
        {
            auto id = m_next_label++;
            m_label_positions.push_back( SIZE_MAX ); // unbound sentinel
            return { id };
        }

        /* Bind a label to the current position */
        Derived& bind( label lbl )
        {
            m_label_positions[lbl.id] = m_buf.size();
            return self();
        }

        /* JMP rel32 to a label (resolved at build time) */
        Derived& jmp_to( label lbl )
        {
            m_buf.push_back( 0xE9 );
            m_fixups.push_back( { m_buf.size(), lbl.id } );
            push_le32( 0 ); // placeholder
            return self();
        }

        /* CALL rel32 to a label (resolved at build time) */
        Derived& call_to( label lbl )
        {
            m_buf.push_back( 0xE8 );
            m_fixups.push_back( { m_buf.size(), lbl.id } );
            push_le32( 0 ); // placeholder
            return self();
        }

        /* ------- Conditional jumps (Jcc near: 0F 8x rel32 to label) ------- */

        /* Jcc near (0F 8x rel32) to label */
        Derived& jcc( uint8_t cc, label lbl )
        {
            m_buf.push_back( 0x0F );
            m_buf.push_back( cc );
            m_fixups.push_back( { m_buf.size(), lbl.id } );
            push_le32( 0 ); // placeholder
            return self();
        }

        Derived& je( label lbl )  { return jcc( 0x84, lbl ); }
        Derived& jne( label lbl ) { return jcc( 0x85, lbl ); }
        Derived& jz( label lbl )  { return jcc( 0x84, lbl ); }  // alias for je
        Derived& jnz( label lbl ) { return jcc( 0x85, lbl ); }  // alias for jne
        Derived& jb( label lbl )  { return jcc( 0x82, lbl ); }  // below (unsigned <)
        Derived& jae( label lbl ) { return jcc( 0x83, lbl ); }  // above or equal (unsigned >=)
        Derived& ja( label lbl )  { return jcc( 0x87, lbl ); }  // above (unsigned >)
        Derived& jbe( label lbl ) { return jcc( 0x86, lbl ); }  // below or equal (unsigned <=)
        Derived& jl( label lbl )  { return jcc( 0x8C, lbl ); }  // less (signed <)
        Derived& jge( label lbl ) { return jcc( 0x8D, lbl ); }  // greater or equal (signed >=)
        Derived& jg( label lbl )  { return jcc( 0x8F, lbl ); }  // greater (signed >)
        Derived& jle( label lbl ) { return jcc( 0x8E, lbl ); }  // less or equal (signed <=)
        Derived& js( label lbl )  { return jcc( 0x88, lbl ); }  // sign
        Derived& jns( label lbl ) { return jcc( 0x89, lbl ); }  // not sign
    };

    /* -----------------------------------------------------------------------
     * x86 builder (32-bit)
     * ----------------------------------------------------------------------- */

    class x86 : public builder_base< x86 >
    {
    public:
        /* PUSH reg32 */
        x86& push_reg( reg32 r )
        {
            this->m_buf.push_back( 0x50 + reg_index( r ) );
            return *this;
        }

        /* POP reg32 */
        x86& pop_reg( reg32 r )
        {
            this->m_buf.push_back( 0x58 + reg_index( r ) );
            return *this;
        }

        /* PUSHAD (push all general-purpose registers) */
        x86& pushad()
        {
            this->m_buf.push_back( 0x60 );
            return *this;
        }

        /* POPAD (pop all general-purpose registers) */
        x86& popad()
        {
            this->m_buf.push_back( 0x61 );
            return *this;
        }

        /* PUSHFD (push EFLAGS) */
        x86& pushfd()
        {
            this->m_buf.push_back( 0x9C );
            return *this;
        }

        /* POPFD (pop EFLAGS) */
        x86& popfd()
        {
            this->m_buf.push_back( 0x9D );
            return *this;
        }

        /* MOV reg32, imm32 */
        x86& mov_reg_imm( reg32 r, uint32_t imm )
        {
            this->m_buf.push_back( 0xB8 + reg_index( r ) );
            this->push_le32( imm );
            return *this;
        }

        /* MOV reg32, reg32 */
        x86& mov_reg_reg( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x89 );
            this->m_buf.push_back( this->modrm( 3, reg_index( src ), reg_index( dst ) ) );
            return *this;
        }

        /* XOR reg32, reg32 (commonly used to zero a register) */
        x86& xor_reg_reg( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x31 );
            this->m_buf.push_back( this->modrm( 3, reg_index( src ), reg_index( dst ) ) );
            return *this;
        }

        /* ADD reg32, imm32 */
        x86& add_reg_imm( reg32 r, uint32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm <= 0x7F )
            {
                this->m_buf.push_back( 0x83 );
                this->m_buf.push_back( this->modrm( 3, 0, ri ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                if( r == reg32::EAX )
                {
                    this->m_buf.push_back( 0x05 );
                }
                else
                {
                    this->m_buf.push_back( 0x81 );
                    this->m_buf.push_back( this->modrm( 3, 0, ri ) );
                }
                this->push_le32( imm );
            }
            return *this;
        }

        /* SUB reg32, imm32 */
        x86& sub_reg_imm( reg32 r, uint32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm <= 0x7F )
            {
                this->m_buf.push_back( 0x83 );
                this->m_buf.push_back( this->modrm( 3, 5, ri ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                if( r == reg32::EAX )
                {
                    this->m_buf.push_back( 0x2D );
                }
                else
                {
                    this->m_buf.push_back( 0x81 );
                    this->m_buf.push_back( this->modrm( 3, 5, ri ) );
                }
                this->push_le32( imm );
            }
            return *this;
        }

        /* CALL reg32 (indirect) */
        x86& call_reg( reg32 r )
        {
            this->m_buf.push_back( 0xFF );
            this->m_buf.push_back( this->modrm( 3, 2, reg_index( r ) ) );
            return *this;
        }

        /* JMP reg32 (indirect) */
        x86& jmp_reg( reg32 r )
        {
            this->m_buf.push_back( 0xFF );
            this->m_buf.push_back( this->modrm( 3, 4, reg_index( r ) ) );
            return *this;
        }

        /* CALL rel32 (relative to end of instruction) */
        x86& call_rel( int32_t offset )
        {
            this->m_buf.push_back( 0xE8 );
            this->push_le32( static_cast< uint32_t >( offset ) );
            return *this;
        }

        /* JMP rel32 (relative to end of instruction) */
        x86& jmp_rel( int32_t offset )
        {
            this->m_buf.push_back( 0xE9 );
            this->push_le32( static_cast< uint32_t >( offset ) );
            return *this;
        }

        /* MOV [reg32], reg32 — store to memory pointed by register */
        x86& mov_mem_reg( reg32 base, reg32 src )
        {
            this->m_buf.push_back( 0x89 );
            this->emit_modrm_indirect( reg_index( src ), reg_index( base ) );
            return *this;
        }

        /* MOV reg32, [reg32] — load from memory pointed by register */
        x86& mov_reg_mem( reg32 dst, reg32 base )
        {
            this->m_buf.push_back( 0x8B );
            this->emit_modrm_indirect( reg_index( dst ), reg_index( base ) );
            return *this;
        }

        /* PUSH imm32 */
        x86& push_imm( uint32_t imm )
        {
            this->m_buf.push_back( 0x68 );
            this->push_le32( imm );
            return *this;
        }

        /* TEST reg32, reg32 */
        x86& test_reg_reg( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x85 );
            this->m_buf.push_back( this->modrm( 3, reg_index( src ), reg_index( dst ) ) );
            return *this;
        }

        /* CMP reg32, imm32 */
        x86& cmp_reg_imm( reg32 r, uint32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm <= 0x7F )
            {
                this->m_buf.push_back( 0x83 );
                this->m_buf.push_back( this->modrm( 3, 7, ri ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                if( r == reg32::EAX )
                {
                    this->m_buf.push_back( 0x3D );
                }
                else
                {
                    this->m_buf.push_back( 0x81 );
                    this->m_buf.push_back( this->modrm( 3, 7, ri ) );
                }
                this->push_le32( imm );
            }
            return *this;
        }

        /* CMP reg32, reg32 */
        x86& cmp_reg_reg( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x39 );
            this->m_buf.push_back( this->modrm( 3, reg_index( src ), reg_index( dst ) ) );
            return *this;
        }

        /* SYSENTER */
        x86& sysenter()
        {
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0x34 );
            return *this;
        }

        /* INT 0x2E (legacy syscall mechanism) */
        x86& int_2e()
        {
            this->m_buf.push_back( 0xCD );
            this->m_buf.push_back( 0x2E );
            return *this;
        }

        /* ------- Arithmetic / logic instructions ------- */

        /* AND reg32, reg32 */
        x86& and_reg_reg( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x21 );
            this->m_buf.push_back( this->modrm( 3, reg_index( src ), reg_index( dst ) ) );
            return *this;
        }

        /* AND reg32, imm32 */
        x86& and_reg_imm( reg32 r, uint32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm <= 0x7F )
            {
                this->m_buf.push_back( 0x83 );
                this->m_buf.push_back( this->modrm( 3, 4, ri ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                if( r == reg32::EAX )
                {
                    this->m_buf.push_back( 0x25 );
                }
                else
                {
                    this->m_buf.push_back( 0x81 );
                    this->m_buf.push_back( this->modrm( 3, 4, ri ) );
                }
                this->push_le32( imm );
            }
            return *this;
        }

        /* OR reg32, reg32 */
        x86& or_reg_reg( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x09 );
            this->m_buf.push_back( this->modrm( 3, reg_index( src ), reg_index( dst ) ) );
            return *this;
        }

        /* OR reg32, imm32 */
        x86& or_reg_imm( reg32 r, uint32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm <= 0x7F )
            {
                this->m_buf.push_back( 0x83 );
                this->m_buf.push_back( this->modrm( 3, 1, ri ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                if( r == reg32::EAX )
                {
                    this->m_buf.push_back( 0x0D );
                }
                else
                {
                    this->m_buf.push_back( 0x81 );
                    this->m_buf.push_back( this->modrm( 3, 1, ri ) );
                }
                this->push_le32( imm );
            }
            return *this;
        }

        /* NOT reg32 (F7 /2) */
        x86& not_reg( reg32 r )
        {
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 2, reg_index( r ) ) );
            return *this;
        }

        /* NEG reg32 (F7 /3) */
        x86& neg_reg( reg32 r )
        {
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 3, reg_index( r ) ) );
            return *this;
        }

        /* SHL reg32, imm8 (C1 /4) */
        x86& shl_reg_imm( reg32 r, uint8_t imm )
        {
            this->m_buf.push_back( 0xC1 );
            this->m_buf.push_back( this->modrm( 3, 4, reg_index( r ) ) );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* SHL reg32, CL (D3 /4) */
        x86& shl_reg_cl( reg32 r )
        {
            this->m_buf.push_back( 0xD3 );
            this->m_buf.push_back( this->modrm( 3, 4, reg_index( r ) ) );
            return *this;
        }

        /* SHR reg32, imm8 (C1 /5) */
        x86& shr_reg_imm( reg32 r, uint8_t imm )
        {
            this->m_buf.push_back( 0xC1 );
            this->m_buf.push_back( this->modrm( 3, 5, reg_index( r ) ) );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* SHR reg32, CL (D3 /5) */
        x86& shr_reg_cl( reg32 r )
        {
            this->m_buf.push_back( 0xD3 );
            this->m_buf.push_back( this->modrm( 3, 5, reg_index( r ) ) );
            return *this;
        }

        /* SAR reg32, imm8 (C1 /7) */
        x86& sar_reg_imm( reg32 r, uint8_t imm )
        {
            this->m_buf.push_back( 0xC1 );
            this->m_buf.push_back( this->modrm( 3, 7, reg_index( r ) ) );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* SAR reg32, CL (D3 /7) */
        x86& sar_reg_cl( reg32 r )
        {
            this->m_buf.push_back( 0xD3 );
            this->m_buf.push_back( this->modrm( 3, 7, reg_index( r ) ) );
            return *this;
        }

        /* ROL reg32, imm8 (C1 /0) */
        x86& rol_reg_imm( reg32 r, uint8_t imm )
        {
            this->m_buf.push_back( 0xC1 );
            this->m_buf.push_back( this->modrm( 3, 0, reg_index( r ) ) );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* ROR reg32, imm8 (C1 /1) */
        x86& ror_reg_imm( reg32 r, uint8_t imm )
        {
            this->m_buf.push_back( 0xC1 );
            this->m_buf.push_back( this->modrm( 3, 1, reg_index( r ) ) );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* MUL reg32 — unsigned multiply EDX:EAX = EAX * r (F7 /4) */
        x86& mul_reg( reg32 r )
        {
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 4, reg_index( r ) ) );
            return *this;
        }

        /* IMUL reg32 — signed multiply EDX:EAX = EAX * r (F7 /5) */
        x86& imul_reg( reg32 r )
        {
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 5, reg_index( r ) ) );
            return *this;
        }

        /* IMUL reg32, reg32 — two-operand signed multiply (0F AF) */
        x86& imul_reg_reg( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xAF );
            this->m_buf.push_back( this->modrm( 3, reg_index( dst ), reg_index( src ) ) );
            return *this;
        }

        /* IMUL reg32, imm32 — reg = reg * imm (69 /r) */
        x86& imul_reg_imm( reg32 r, int32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm >= -128 && imm <= 127 )
            {
                this->m_buf.push_back( 0x6B );
                this->m_buf.push_back( this->modrm( 3, ri, ri ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                this->m_buf.push_back( 0x69 );
                this->m_buf.push_back( this->modrm( 3, ri, ri ) );
                this->push_le32( static_cast< uint32_t >( imm ) );
            }
            return *this;
        }

        /* DIV reg32 — unsigned divide EDX:EAX / r (F7 /6) */
        x86& div_reg( reg32 r )
        {
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 6, reg_index( r ) ) );
            return *this;
        }

        /* IDIV reg32 — signed divide EDX:EAX / r (F7 /7) */
        x86& idiv_reg( reg32 r )
        {
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 7, reg_index( r ) ) );
            return *this;
        }

        /* INC reg32 (40+r) */
        x86& inc_reg( reg32 r )
        {
            this->m_buf.push_back( 0x40 + reg_index( r ) );
            return *this;
        }

        /* DEC reg32 (48+r) */
        x86& dec_reg( reg32 r )
        {
            this->m_buf.push_back( 0x48 + reg_index( r ) );
            return *this;
        }

        /* XCHG reg32, reg32 (87 or 90+r short form for EAX) */
        x86& xchg_reg_reg( reg32 dst, reg32 src )
        {
            if( dst == reg32::EAX )
            {
                this->m_buf.push_back( 0x90 + reg_index( src ) );
            }
            else if( src == reg32::EAX )
            {
                this->m_buf.push_back( 0x90 + reg_index( dst ) );
            }
            else
            {
                this->m_buf.push_back( 0x87 );
                this->m_buf.push_back( this->modrm( 3, reg_index( src ), reg_index( dst ) ) );
            }
            return *this;
        }

        /* CDQ — sign-extend EAX into EDX:EAX (99) */
        x86& cdq()
        {
            this->m_buf.push_back( 0x99 );
            return *this;
        }

        /* MOVZX reg32, reg8 (0F B6) */
        x86& movzx_reg_reg8( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xB6 );
            this->m_buf.push_back( this->modrm( 3, reg_index( dst ), reg_index( src ) ) );
            return *this;
        }

        /* MOVZX reg32, reg16 (0F B7) */
        x86& movzx_reg_reg16( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xB7 );
            this->m_buf.push_back( this->modrm( 3, reg_index( dst ), reg_index( src ) ) );
            return *this;
        }

        /* MOVSX reg32, reg8 (0F BE) */
        x86& movsx_reg_reg8( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xBE );
            this->m_buf.push_back( this->modrm( 3, reg_index( dst ), reg_index( src ) ) );
            return *this;
        }

        /* MOVSX reg32, reg16 (0F BF) */
        x86& movsx_reg_reg16( reg32 dst, reg32 src )
        {
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xBF );
            this->m_buf.push_back( this->modrm( 3, reg_index( dst ), reg_index( src ) ) );
            return *this;
        }

        /* BSWAP reg32 (0F C8+r) */
        x86& bswap_reg( reg32 r )
        {
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xC8 + reg_index( r ) );
            return *this;
        }

        /* LEA reg32, [reg32 + disp32] (8D mod=2) */
        x86& lea_reg_disp( reg32 dst, reg32 base, int32_t disp )
        {
            auto const di = reg_index( dst );
            auto const bi = reg_index( base );
            this->m_buf.push_back( 0x8D );
            if( ( bi & 7 ) == 4 )
            {
                /* ESP: need SIB byte */
                this->m_buf.push_back( this->modrm( 2, di, bi ) );
                this->m_buf.push_back( 0x24 );
            }
            else
            {
                this->m_buf.push_back( this->modrm( 2, di, bi ) );
            }
            this->push_le32( static_cast< uint32_t >( disp ) );
            return *this;
        }

        /* ------- SSE instructions ------- */

    private:
        /* Emit SSE register-to-register: [prefix] 0F op ModRM(3,dst,src) */
        void emit_sse_rr( uint8_t prefix, uint8_t op, uint8_t dst, uint8_t src )
        {
            if( prefix ) this->m_buf.push_back( prefix );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( op );
            this->m_buf.push_back( this->modrm( 3, dst, src ) );
        }

        /* Emit SSE register + [memory]: [prefix] 0F op ModRM+SIB/disp */
        void emit_sse_rm( uint8_t prefix, uint8_t op, uint8_t xmm_field, uint8_t base )
        {
            if( prefix ) this->m_buf.push_back( prefix );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( op );
            this->emit_modrm_indirect( xmm_field, base );
        }

    public:
        /* --- Movement --- */

        /* MOVAPS xmm, xmm (0F 28) */
        x86& movaps_xmm_xmm( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x28, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MOVAPS xmm, [reg32] (0F 28) */
        x86& movaps_xmm_mem( xmm32 dst, reg32 base )
        {
            emit_sse_rm( 0, 0x28, reg_index( dst ), reg_index( base ) );
            return *this;
        }

        /* MOVAPS [reg32], xmm (0F 29) */
        x86& movaps_mem_xmm( reg32 base, xmm32 src )
        {
            emit_sse_rm( 0, 0x29, reg_index( src ), reg_index( base ) );
            return *this;
        }

        /* MOVUPS xmm, xmm (0F 10) */
        x86& movups_xmm_xmm( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x10, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MOVUPS xmm, [reg32] (0F 10) */
        x86& movups_xmm_mem( xmm32 dst, reg32 base )
        {
            emit_sse_rm( 0, 0x10, reg_index( dst ), reg_index( base ) );
            return *this;
        }

        /* MOVUPS [reg32], xmm (0F 11) */
        x86& movups_mem_xmm( reg32 base, xmm32 src )
        {
            emit_sse_rm( 0, 0x11, reg_index( src ), reg_index( base ) );
            return *this;
        }

        /* MOVSS xmm, xmm (F3 0F 10) */
        x86& movss_xmm_xmm( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF3, 0x10, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MOVSS xmm, [reg32] (F3 0F 10) */
        x86& movss_xmm_mem( xmm32 dst, reg32 base )
        {
            emit_sse_rm( 0xF3, 0x10, reg_index( dst ), reg_index( base ) );
            return *this;
        }

        /* MOVSS [reg32], xmm (F3 0F 11) */
        x86& movss_mem_xmm( reg32 base, xmm32 src )
        {
            emit_sse_rm( 0xF3, 0x11, reg_index( src ), reg_index( base ) );
            return *this;
        }

        /* MOVSD xmm, xmm (F2 0F 10) */
        x86& movsd_xmm_xmm( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF2, 0x10, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MOVSD xmm, [reg32] (F2 0F 10) */
        x86& movsd_xmm_mem( xmm32 dst, reg32 base )
        {
            emit_sse_rm( 0xF2, 0x10, reg_index( dst ), reg_index( base ) );
            return *this;
        }

        /* MOVSD [reg32], xmm (F2 0F 11) */
        x86& movsd_mem_xmm( reg32 base, xmm32 src )
        {
            emit_sse_rm( 0xF2, 0x11, reg_index( src ), reg_index( base ) );
            return *this;
        }

        /* --- Scalar float arithmetic (F3 prefix) --- */

        /* ADDSS xmm, xmm (F3 0F 58) */
        x86& addss( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF3, 0x58, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* SUBSS xmm, xmm (F3 0F 5C) */
        x86& subss( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF3, 0x5C, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MULSS xmm, xmm (F3 0F 59) */
        x86& mulss( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF3, 0x59, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* DIVSS xmm, xmm (F3 0F 5E) */
        x86& divss( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF3, 0x5E, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* --- Scalar double arithmetic (F2 prefix) --- */

        /* ADDSD xmm, xmm (F2 0F 58) */
        x86& addsd( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF2, 0x58, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* SUBSD xmm, xmm (F2 0F 5C) */
        x86& subsd( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF2, 0x5C, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MULSD xmm, xmm (F2 0F 59) */
        x86& mulsd( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF2, 0x59, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* DIVSD xmm, xmm (F2 0F 5E) */
        x86& divsd( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF2, 0x5E, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* --- Packed float arithmetic (no prefix) --- */

        /* ADDPS xmm, xmm (0F 58) */
        x86& addps( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x58, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* SUBPS xmm, xmm (0F 5C) */
        x86& subps( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x5C, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MULPS xmm, xmm (0F 59) */
        x86& mulps( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x59, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* DIVPS xmm, xmm (0F 5E) */
        x86& divps( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x5E, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* --- Packed bitwise (no prefix) --- */

        /* XORPS xmm, xmm (0F 57) */
        x86& xorps( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x57, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* ORPS xmm, xmm (0F 56) */
        x86& orps( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x56, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* ANDPS xmm, xmm (0F 54) */
        x86& andps( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x54, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* --- Compare --- */

        /* COMISS xmm, xmm (0F 2F) */
        x86& comiss( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x2F, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* UCOMISS xmm, xmm (0F 2E) */
        x86& ucomiss( xmm32 dst, xmm32 src )
        {
            emit_sse_rr( 0, 0x2E, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* --- Conversions --- */

        /* CVTSI2SS xmm, reg32 (F3 0F 2A) */
        x86& cvtsi2ss( xmm32 dst, reg32 src )
        {
            emit_sse_rr( 0xF3, 0x2A, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* CVTSS2SI reg32, xmm (F3 0F 2D) */
        x86& cvtss2si( reg32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF3, 0x2D, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* CVTSI2SD xmm, reg32 (F2 0F 2A) */
        x86& cvtsi2sd( xmm32 dst, reg32 src )
        {
            emit_sse_rr( 0xF2, 0x2A, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* CVTSD2SI reg32, xmm (F2 0F 2D) */
        x86& cvtsd2si( reg32 dst, xmm32 src )
        {
            emit_sse_rr( 0xF2, 0x2D, reg_index( dst ), reg_index( src ) );
            return *this;
        }
    };

    /* -----------------------------------------------------------------------
     * x64 builder (64-bit)
     * ----------------------------------------------------------------------- */

    class x64 : public builder_base< x64 >
    {
    public:
        /* PUSH reg64 (R8-R15 use REX.B prefix) */
        x64& push_reg( reg64 r )
        {
            emit_rex_b( r );
            this->m_buf.push_back( 0x50 + ( reg_index( r ) & 7 ) );
            return *this;
        }

        /* POP reg64 */
        x64& pop_reg( reg64 r )
        {
            emit_rex_b( r );
            this->m_buf.push_back( 0x58 + ( reg_index( r ) & 7 ) );
            return *this;
        }

        /* MOV reg64, imm64 (REX.W + B8+r + imm64) */
        x64& mov_reg_imm( reg64 r, uint64_t imm )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xB8 + ( ri & 7 ) );
            push_le64( imm );
            return *this;
        }

        /* MOV reg64, imm32 (sign-extended to 64 bits, REX.W + C7 /0) */
        x64& mov_reg_imm32( reg64 r, uint32_t imm )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xC7 );
            this->m_buf.push_back( this->modrm( 3, 0, ri & 7 ) );
            this->push_le32( imm );
            return *this;
        }

        /* MOV reg64, reg64 */
        x64& mov_reg_reg( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, si, di ) );
            this->m_buf.push_back( 0x89 );
            this->m_buf.push_back( this->modrm( 3, si & 7, di & 7 ) );
            return *this;
        }

        /* XOR reg64, reg64 */
        x64& xor_reg_reg( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, si, di ) );
            this->m_buf.push_back( 0x31 );
            this->m_buf.push_back( this->modrm( 3, si & 7, di & 7 ) );
            return *this;
        }

        /* ADD reg64, imm32 (sign-extended) */
        x64& add_reg_imm( reg64 r, int32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm >= -128 && imm <= 127 )
            {
                this->m_buf.push_back( rex_w( 0, 0, ri ) );
                this->m_buf.push_back( 0x83 );
                this->m_buf.push_back( this->modrm( 3, 0, ri & 7 ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                this->m_buf.push_back( rex_w( 0, 0, ri ) );
                if( ( ri & 7 ) == 0 && r < reg64::R8 )
                {
                    this->m_buf.push_back( 0x05 );
                }
                else
                {
                    this->m_buf.push_back( 0x81 );
                    this->m_buf.push_back( this->modrm( 3, 0, ri & 7 ) );
                }
                this->push_le32( static_cast< uint32_t >( imm ) );
            }
            return *this;
        }

        /* SUB reg64, imm32 (sign-extended) */
        x64& sub_reg_imm( reg64 r, int32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm >= -128 && imm <= 127 )
            {
                this->m_buf.push_back( rex_w( 0, 0, ri ) );
                this->m_buf.push_back( 0x83 );
                this->m_buf.push_back( this->modrm( 3, 5, ri & 7 ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                this->m_buf.push_back( rex_w( 0, 0, ri ) );
                if( ( ri & 7 ) == 0 && r < reg64::R8 )
                {
                    this->m_buf.push_back( 0x2D );
                }
                else
                {
                    this->m_buf.push_back( 0x81 );
                    this->m_buf.push_back( this->modrm( 3, 5, ri & 7 ) );
                }
                this->push_le32( static_cast< uint32_t >( imm ) );
            }
            return *this;
        }

        /* CALL reg64 (indirect) */
        x64& call_reg( reg64 r )
        {
            if( r >= reg64::R8 )
            {
                this->m_buf.push_back( 0x41 );
            }
            this->m_buf.push_back( 0xFF );
            this->m_buf.push_back( this->modrm( 3, 2, reg_index( r ) & 7 ) );
            return *this;
        }

        /* JMP reg64 (indirect) */
        x64& jmp_reg( reg64 r )
        {
            if( r >= reg64::R8 )
            {
                this->m_buf.push_back( 0x41 );
            }
            this->m_buf.push_back( 0xFF );
            this->m_buf.push_back( this->modrm( 3, 4, reg_index( r ) & 7 ) );
            return *this;
        }

        /* CALL rel32 (relative to end of instruction) */
        x64& call_rel( int32_t offset )
        {
            this->m_buf.push_back( 0xE8 );
            this->push_le32( static_cast< uint32_t >( offset ) );
            return *this;
        }

        /* JMP rel32 (relative to end of instruction) */
        x64& jmp_rel( int32_t offset )
        {
            this->m_buf.push_back( 0xE9 );
            this->push_le32( static_cast< uint32_t >( offset ) );
            return *this;
        }

        /* MOV [reg64], reg64 — store to memory */
        x64& mov_mem_reg( reg64 base, reg64 src )
        {
            auto const bi = reg_index( base );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, si, bi ) );
            this->m_buf.push_back( 0x89 );
            this->emit_modrm_indirect( si, bi );
            return *this;
        }

        /* MOV reg64, [reg64] — load from memory */
        x64& mov_reg_mem( reg64 dst, reg64 base )
        {
            auto const di = reg_index( dst );
            auto const bi = reg_index( base );
            this->m_buf.push_back( rex_w( 0, di, bi ) );
            this->m_buf.push_back( 0x8B );
            this->emit_modrm_indirect( di, bi );
            return *this;
        }

        /* LEA reg64, [RIP + disp32] */
        x64& lea_rip( reg64 dst, int32_t disp )
        {
            auto const di = reg_index( dst );
            this->m_buf.push_back( rex_w( 0, di, 0 ) );
            this->m_buf.push_back( 0x8D );
            this->m_buf.push_back( this->modrm( 0, di & 7, 5 ) );
            this->push_le32( static_cast< uint32_t >( disp ) );
            return *this;
        }

        /* SUB RSP, imm8 (shadow space / stack alignment) */
        x64& sub_rsp_imm8( uint8_t imm )
        {
            this->m_buf.push_back( 0x48 );
            this->m_buf.push_back( 0x83 );
            this->m_buf.push_back( 0xEC );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* ADD RSP, imm8 */
        x64& add_rsp_imm8( uint8_t imm )
        {
            this->m_buf.push_back( 0x48 );
            this->m_buf.push_back( 0x83 );
            this->m_buf.push_back( 0xC4 );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* TEST reg64, reg64 */
        x64& test_reg_reg( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, si, di ) );
            this->m_buf.push_back( 0x85 );
            this->m_buf.push_back( this->modrm( 3, si & 7, di & 7 ) );
            return *this;
        }

        /* CMP reg64, imm32 (sign-extended) */
        x64& cmp_reg_imm( reg64 r, int32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm >= -128 && imm <= 127 )
            {
                this->m_buf.push_back( rex_w( 0, 0, ri ) );
                this->m_buf.push_back( 0x83 );
                this->m_buf.push_back( this->modrm( 3, 7, ri & 7 ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                this->m_buf.push_back( rex_w( 0, 0, ri ) );
                if( ( ri & 7 ) == 0 && r < reg64::R8 )
                {
                    this->m_buf.push_back( 0x3D );
                }
                else
                {
                    this->m_buf.push_back( 0x81 );
                    this->m_buf.push_back( this->modrm( 3, 7, ri & 7 ) );
                }
                this->push_le32( static_cast< uint32_t >( imm ) );
            }
            return *this;
        }

        /* CMP reg64, reg64 */
        x64& cmp_reg_reg( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, si, di ) );
            this->m_buf.push_back( 0x39 );
            this->m_buf.push_back( this->modrm( 3, si & 7, di & 7 ) );
            return *this;
        }

        /* PUSH imm32 (sign-extended to 64 bits) */
        x64& push_imm( int32_t imm )
        {
            this->m_buf.push_back( 0x68 );
            this->push_le32( static_cast< uint32_t >( imm ) );
            return *this;
        }

        /* PUSHFQ (push RFLAGS) */
        x64& pushfq()
        {
            this->m_buf.push_back( 0x9C );
            return *this;
        }

        /* POPFQ (pop RFLAGS) */
        x64& popfq()
        {
            this->m_buf.push_back( 0x9D );
            return *this;
        }

        /* SYSCALL (0F 05) */
        x64& syscall()
        {
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0x05 );
            return *this;
        }

        /* ------- Arithmetic / logic instructions ------- */

        /* AND reg64, reg64 */
        x64& and_reg_reg( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, si, di ) );
            this->m_buf.push_back( 0x21 );
            this->m_buf.push_back( this->modrm( 3, si & 7, di & 7 ) );
            return *this;
        }

        /* AND reg64, imm32 (sign-extended) */
        x64& and_reg_imm( reg64 r, int32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm >= -128 && imm <= 127 )
            {
                this->m_buf.push_back( rex_w( 0, 0, ri ) );
                this->m_buf.push_back( 0x83 );
                this->m_buf.push_back( this->modrm( 3, 4, ri & 7 ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                this->m_buf.push_back( rex_w( 0, 0, ri ) );
                if( ( ri & 7 ) == 0 && r < reg64::R8 )
                {
                    this->m_buf.push_back( 0x25 );
                }
                else
                {
                    this->m_buf.push_back( 0x81 );
                    this->m_buf.push_back( this->modrm( 3, 4, ri & 7 ) );
                }
                this->push_le32( static_cast< uint32_t >( imm ) );
            }
            return *this;
        }

        /* OR reg64, reg64 */
        x64& or_reg_reg( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, si, di ) );
            this->m_buf.push_back( 0x09 );
            this->m_buf.push_back( this->modrm( 3, si & 7, di & 7 ) );
            return *this;
        }

        /* OR reg64, imm32 (sign-extended) */
        x64& or_reg_imm( reg64 r, int32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm >= -128 && imm <= 127 )
            {
                this->m_buf.push_back( rex_w( 0, 0, ri ) );
                this->m_buf.push_back( 0x83 );
                this->m_buf.push_back( this->modrm( 3, 1, ri & 7 ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                this->m_buf.push_back( rex_w( 0, 0, ri ) );
                if( ( ri & 7 ) == 0 && r < reg64::R8 )
                {
                    this->m_buf.push_back( 0x0D );
                }
                else
                {
                    this->m_buf.push_back( 0x81 );
                    this->m_buf.push_back( this->modrm( 3, 1, ri & 7 ) );
                }
                this->push_le32( static_cast< uint32_t >( imm ) );
            }
            return *this;
        }

        /* NOT reg64 (REX.W + F7 /2) */
        x64& not_reg( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 2, ri & 7 ) );
            return *this;
        }

        /* NEG reg64 (REX.W + F7 /3) */
        x64& neg_reg( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 3, ri & 7 ) );
            return *this;
        }

        /* SHL reg64, imm8 (REX.W + C1 /4) */
        x64& shl_reg_imm( reg64 r, uint8_t imm )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xC1 );
            this->m_buf.push_back( this->modrm( 3, 4, ri & 7 ) );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* SHL reg64, CL (REX.W + D3 /4) */
        x64& shl_reg_cl( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xD3 );
            this->m_buf.push_back( this->modrm( 3, 4, ri & 7 ) );
            return *this;
        }

        /* SHR reg64, imm8 (REX.W + C1 /5) */
        x64& shr_reg_imm( reg64 r, uint8_t imm )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xC1 );
            this->m_buf.push_back( this->modrm( 3, 5, ri & 7 ) );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* SHR reg64, CL (REX.W + D3 /5) */
        x64& shr_reg_cl( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xD3 );
            this->m_buf.push_back( this->modrm( 3, 5, ri & 7 ) );
            return *this;
        }

        /* SAR reg64, imm8 (REX.W + C1 /7) */
        x64& sar_reg_imm( reg64 r, uint8_t imm )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xC1 );
            this->m_buf.push_back( this->modrm( 3, 7, ri & 7 ) );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* SAR reg64, CL (REX.W + D3 /7) */
        x64& sar_reg_cl( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xD3 );
            this->m_buf.push_back( this->modrm( 3, 7, ri & 7 ) );
            return *this;
        }

        /* ROL reg64, imm8 (REX.W + C1 /0) */
        x64& rol_reg_imm( reg64 r, uint8_t imm )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xC1 );
            this->m_buf.push_back( this->modrm( 3, 0, ri & 7 ) );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* ROR reg64, imm8 (REX.W + C1 /1) */
        x64& ror_reg_imm( reg64 r, uint8_t imm )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xC1 );
            this->m_buf.push_back( this->modrm( 3, 1, ri & 7 ) );
            this->m_buf.push_back( imm );
            return *this;
        }

        /* MUL reg64 — unsigned multiply RDX:RAX = RAX * r (REX.W + F7 /4) */
        x64& mul_reg( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 4, ri & 7 ) );
            return *this;
        }

        /* IMUL reg64 — signed multiply RDX:RAX = RAX * r (REX.W + F7 /5) */
        x64& imul_reg( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 5, ri & 7 ) );
            return *this;
        }

        /* IMUL reg64, reg64 — two-operand signed multiply (REX.W + 0F AF) */
        x64& imul_reg_reg( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, di, si ) );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xAF );
            this->m_buf.push_back( this->modrm( 3, di & 7, si & 7 ) );
            return *this;
        }

        /* IMUL reg64, imm32 — reg = reg * imm (REX.W + 69 /r) */
        x64& imul_reg_imm( reg64 r, int32_t imm )
        {
            auto const ri = reg_index( r );
            if( imm >= -128 && imm <= 127 )
            {
                this->m_buf.push_back( rex_w( 0, ri, ri ) );
                this->m_buf.push_back( 0x6B );
                this->m_buf.push_back( this->modrm( 3, ri & 7, ri & 7 ) );
                this->m_buf.push_back( static_cast< uint8_t >( imm ) );
            }
            else
            {
                this->m_buf.push_back( rex_w( 0, ri, ri ) );
                this->m_buf.push_back( 0x69 );
                this->m_buf.push_back( this->modrm( 3, ri & 7, ri & 7 ) );
                this->push_le32( static_cast< uint32_t >( imm ) );
            }
            return *this;
        }

        /* DIV reg64 — unsigned divide RDX:RAX / r (REX.W + F7 /6) */
        x64& div_reg( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 6, ri & 7 ) );
            return *this;
        }

        /* IDIV reg64 — signed divide RDX:RAX / r (REX.W + F7 /7) */
        x64& idiv_reg( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xF7 );
            this->m_buf.push_back( this->modrm( 3, 7, ri & 7 ) );
            return *this;
        }

        /* INC reg64 (REX.W + FF /0) — cannot use 40+r in x64 (REX prefix range) */
        x64& inc_reg( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xFF );
            this->m_buf.push_back( this->modrm( 3, 0, ri & 7 ) );
            return *this;
        }

        /* DEC reg64 (REX.W + FF /1) — cannot use 48+r in x64 (REX prefix range) */
        x64& dec_reg( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0xFF );
            this->m_buf.push_back( this->modrm( 3, 1, ri & 7 ) );
            return *this;
        }

        /* XCHG reg64, reg64 (REX.W + 87 or 90+r short form for RAX) */
        x64& xchg_reg_reg( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            if( dst == reg64::RAX && src != reg64::RAX )
            {
                this->m_buf.push_back( rex_w( 0, 0, si ) );
                this->m_buf.push_back( 0x90 + ( si & 7 ) );
            }
            else if( src == reg64::RAX && dst != reg64::RAX )
            {
                this->m_buf.push_back( rex_w( 0, 0, di ) );
                this->m_buf.push_back( 0x90 + ( di & 7 ) );
            }
            else
            {
                this->m_buf.push_back( rex_w( 0, si, di ) );
                this->m_buf.push_back( 0x87 );
                this->m_buf.push_back( this->modrm( 3, si & 7, di & 7 ) );
            }
            return *this;
        }

        /* CQO — sign-extend RAX into RDX:RAX (REX.W + 99) */
        x64& cqo()
        {
            this->m_buf.push_back( 0x48 );
            this->m_buf.push_back( 0x99 );
            return *this;
        }

        /* CDQ — sign-extend EAX into EDX:EAX (99, no REX.W) */
        x64& cdq()
        {
            this->m_buf.push_back( 0x99 );
            return *this;
        }

        /* MOVSXD reg64, reg32 — sign-extend 32-bit to 64-bit (REX.W + 63) */
        x64& movsxd( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, di, si ) );
            this->m_buf.push_back( 0x63 );
            this->m_buf.push_back( this->modrm( 3, di & 7, si & 7 ) );
            return *this;
        }

        /* MOVZX reg64, reg8 (REX.W + 0F B6) */
        x64& movzx_reg_reg8( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, di, si ) );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xB6 );
            this->m_buf.push_back( this->modrm( 3, di & 7, si & 7 ) );
            return *this;
        }

        /* MOVZX reg64, reg16 (REX.W + 0F B7) */
        x64& movzx_reg_reg16( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, di, si ) );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xB7 );
            this->m_buf.push_back( this->modrm( 3, di & 7, si & 7 ) );
            return *this;
        }

        /* MOVSX reg64, reg8 (REX.W + 0F BE) */
        x64& movsx_reg_reg8( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, di, si ) );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xBE );
            this->m_buf.push_back( this->modrm( 3, di & 7, si & 7 ) );
            return *this;
        }

        /* MOVSX reg64, reg16 (REX.W + 0F BF) */
        x64& movsx_reg_reg16( reg64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( rex_w( 0, di, si ) );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xBF );
            this->m_buf.push_back( this->modrm( 3, di & 7, si & 7 ) );
            return *this;
        }

        /* BSWAP reg64 (REX.W + 0F C8+r) */
        x64& bswap_reg( reg64 r )
        {
            auto const ri = reg_index( r );
            this->m_buf.push_back( rex_w( 0, 0, ri ) );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0xC8 + ( ri & 7 ) );
            return *this;
        }

        /* LEA reg64, [reg64 + disp32] (REX.W + 8D mod=2) */
        x64& lea_reg_disp( reg64 dst, reg64 base, int32_t disp )
        {
            auto const di = reg_index( dst );
            auto const bi = reg_index( base );
            this->m_buf.push_back( rex_w( 0, di, bi ) );
            this->m_buf.push_back( 0x8D );
            if( ( bi & 7 ) == 4 )
            {
                /* RSP/R12: need SIB byte */
                this->m_buf.push_back( this->modrm( 2, di & 7, bi & 7 ) );
                this->m_buf.push_back( 0x24 );
            }
            else
            {
                this->m_buf.push_back( this->modrm( 2, di & 7, bi & 7 ) );
            }
            this->push_le32( static_cast< uint32_t >( disp ) );
            return *this;
        }

        /* ------- SSE instructions ------- */

    private:
        /* REX.W prefix: W=1, R=reg>>3, X=0, B=rm>>3 */
        static constexpr uint8_t rex_w( uint8_t x, uint8_t reg, uint8_t rm )
        {
            return 0x48 | ( ( reg >> 3 ) << 2 ) | ( ( x >> 3 ) << 1 ) | ( rm >> 3 );
        }

        /* Emit REX.B only if register index >= 8 (R8-R15) */
        void emit_rex_b( reg64 r )
        {
            if( r >= reg64::R8 )
            {
                this->m_buf.push_back( 0x41 );
            }
        }

        /* Push a 64-bit value in little-endian order */
        void push_le64( uint64_t v )
        {
            this->push_le32( static_cast< uint32_t >( v ) );
            this->push_le32( static_cast< uint32_t >( v >> 32 ) );
        }

        /* REX byte for SSE (no W bit): only R and B for extended registers */
        static constexpr uint8_t rex_sse( uint8_t reg, uint8_t rm )
        {
            return 0x40 | ( ( reg >> 3 ) << 2 ) | ( rm >> 3 );
        }

        /* Emit REX for SSE if any operand uses an extended register (index >= 8) */
        void emit_rex_sse( uint8_t reg, uint8_t rm )
        {
            if( reg >= 8 || rm >= 8 )
            {
                this->m_buf.push_back( rex_sse( reg, rm ) );
            }
        }

        /* Emit SSE reg-to-reg: [prefix] [REX] 0F op ModRM(3,dst,src) */
        void emit_sse_rr( uint8_t prefix, uint8_t op, uint8_t dst, uint8_t src )
        {
            if( prefix ) this->m_buf.push_back( prefix );
            emit_rex_sse( dst, src );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( op );
            this->m_buf.push_back( this->modrm( 3, dst & 7, src & 7 ) );
        }

        /* Emit SSE register + [memory]: [prefix] [REX] 0F op ModRM+SIB/disp */
        void emit_sse_rm( uint8_t prefix, uint8_t op, uint8_t xmm_field, uint8_t base )
        {
            if( prefix ) this->m_buf.push_back( prefix );
            emit_rex_sse( xmm_field, base );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( op );
            this->emit_modrm_indirect( xmm_field, base );
        }

    public:
        /* --- Movement --- */

        /* MOVAPS xmm, xmm (0F 28) */
        x64& movaps_xmm_xmm( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x28, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MOVAPS xmm, [reg64] (0F 28) */
        x64& movaps_xmm_mem( xmm64 dst, reg64 base )
        {
            emit_sse_rm( 0, 0x28, reg_index( dst ), reg_index( base ) );
            return *this;
        }

        /* MOVAPS [reg64], xmm (0F 29) */
        x64& movaps_mem_xmm( reg64 base, xmm64 src )
        {
            emit_sse_rm( 0, 0x29, reg_index( src ), reg_index( base ) );
            return *this;
        }

        /* MOVUPS xmm, xmm (0F 10) */
        x64& movups_xmm_xmm( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x10, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MOVUPS xmm, [reg64] (0F 10) */
        x64& movups_xmm_mem( xmm64 dst, reg64 base )
        {
            emit_sse_rm( 0, 0x10, reg_index( dst ), reg_index( base ) );
            return *this;
        }

        /* MOVUPS [reg64], xmm (0F 11) */
        x64& movups_mem_xmm( reg64 base, xmm64 src )
        {
            emit_sse_rm( 0, 0x11, reg_index( src ), reg_index( base ) );
            return *this;
        }

        /* MOVSS xmm, xmm (F3 0F 10) */
        x64& movss_xmm_xmm( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0xF3, 0x10, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MOVSS xmm, [reg64] (F3 0F 10) */
        x64& movss_xmm_mem( xmm64 dst, reg64 base )
        {
            emit_sse_rm( 0xF3, 0x10, reg_index( dst ), reg_index( base ) );
            return *this;
        }

        /* MOVSS [reg64], xmm (F3 0F 11) */
        x64& movss_mem_xmm( reg64 base, xmm64 src )
        {
            emit_sse_rm( 0xF3, 0x11, reg_index( src ), reg_index( base ) );
            return *this;
        }

        /* MOVSD xmm, xmm (F2 0F 10) */
        x64& movsd_xmm_xmm( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0xF2, 0x10, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MOVSD xmm, [reg64] (F2 0F 10) */
        x64& movsd_xmm_mem( xmm64 dst, reg64 base )
        {
            emit_sse_rm( 0xF2, 0x10, reg_index( dst ), reg_index( base ) );
            return *this;
        }

        /* MOVSD [reg64], xmm (F2 0F 11) */
        x64& movsd_mem_xmm( reg64 base, xmm64 src )
        {
            emit_sse_rm( 0xF2, 0x11, reg_index( src ), reg_index( base ) );
            return *this;
        }

        /* --- Scalar float arithmetic (F3 prefix) --- */

        /* ADDSS xmm, xmm (F3 0F 58) */
        x64& addss( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0xF3, 0x58, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* SUBSS xmm, xmm (F3 0F 5C) */
        x64& subss( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0xF3, 0x5C, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MULSS xmm, xmm (F3 0F 59) */
        x64& mulss( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0xF3, 0x59, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* DIVSS xmm, xmm (F3 0F 5E) */
        x64& divss( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0xF3, 0x5E, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* --- Scalar double arithmetic (F2 prefix) --- */

        /* ADDSD xmm, xmm (F2 0F 58) */
        x64& addsd( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0xF2, 0x58, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* SUBSD xmm, xmm (F2 0F 5C) */
        x64& subsd( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0xF2, 0x5C, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MULSD xmm, xmm (F2 0F 59) */
        x64& mulsd( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0xF2, 0x59, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* DIVSD xmm, xmm (F2 0F 5E) */
        x64& divsd( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0xF2, 0x5E, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* --- Packed float arithmetic (no prefix) --- */

        /* ADDPS xmm, xmm (0F 58) */
        x64& addps( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x58, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* SUBPS xmm, xmm (0F 5C) */
        x64& subps( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x5C, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* MULPS xmm, xmm (0F 59) */
        x64& mulps( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x59, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* DIVPS xmm, xmm (0F 5E) */
        x64& divps( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x5E, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* --- Packed bitwise (no prefix) --- */

        /* XORPS xmm, xmm (0F 57) */
        x64& xorps( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x57, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* ORPS xmm, xmm (0F 56) */
        x64& orps( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x56, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* ANDPS xmm, xmm (0F 54) */
        x64& andps( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x54, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* --- Compare --- */

        /* COMISS xmm, xmm (0F 2F) */
        x64& comiss( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x2F, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* UCOMISS xmm, xmm (0F 2E) */
        x64& ucomiss( xmm64 dst, xmm64 src )
        {
            emit_sse_rr( 0, 0x2E, reg_index( dst ), reg_index( src ) );
            return *this;
        }

        /* --- Conversions (manually encoded for REX.W with 64-bit GPR) --- */

        /* CVTSI2SS xmm, reg64 (F3 REX.W 0F 2A) */
        x64& cvtsi2ss( xmm64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( 0xF3 );
            this->m_buf.push_back( rex_w( 0, di, si ) );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0x2A );
            this->m_buf.push_back( this->modrm( 3, di & 7, si & 7 ) );
            return *this;
        }

        /* CVTSS2SI reg64, xmm (F3 REX.W 0F 2D) */
        x64& cvtss2si( reg64 dst, xmm64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( 0xF3 );
            this->m_buf.push_back( rex_w( 0, di, si ) );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0x2D );
            this->m_buf.push_back( this->modrm( 3, di & 7, si & 7 ) );
            return *this;
        }

        /* CVTSI2SD xmm, reg64 (F2 REX.W 0F 2A) */
        x64& cvtsi2sd( xmm64 dst, reg64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( 0xF2 );
            this->m_buf.push_back( rex_w( 0, di, si ) );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0x2A );
            this->m_buf.push_back( this->modrm( 3, di & 7, si & 7 ) );
            return *this;
        }

        /* CVTSD2SI reg64, xmm (F2 REX.W 0F 2D) */
        x64& cvtsd2si( reg64 dst, xmm64 src )
        {
            auto const di = reg_index( dst );
            auto const si = reg_index( src );
            this->m_buf.push_back( 0xF2 );
            this->m_buf.push_back( rex_w( 0, di, si ) );
            this->m_buf.push_back( 0x0F );
            this->m_buf.push_back( 0x2D );
            this->m_buf.push_back( this->modrm( 3, di & 7, si & 7 ) );
            return *this;
        }
    };

} // namespace shellcode
