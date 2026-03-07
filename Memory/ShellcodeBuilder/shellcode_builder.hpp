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
            auto const bi = reg_index( base );
            auto const si = reg_index( src );
            this->m_buf.push_back( 0x89 );
            if( ( bi & 7 ) == 5 )
            {
                /* EBP: mod=0 rm=5 encodes [disp32], use mod=1 disp8=0 instead */
                this->m_buf.push_back( this->modrm( 1, si, bi ) );
                this->m_buf.push_back( 0x00 );
            }
            else if( ( bi & 7 ) == 4 )
            {
                /* ESP: mod=0 rm=4 encodes SIB follows, emit SIB 0x24 */
                this->m_buf.push_back( this->modrm( 0, si, bi ) );
                this->m_buf.push_back( 0x24 );
            }
            else
            {
                this->m_buf.push_back( this->modrm( 0, si, bi ) );
            }
            return *this;
        }

        /* MOV reg32, [reg32] — load from memory pointed by register */
        x86& mov_reg_mem( reg32 dst, reg32 base )
        {
            auto const di = reg_index( dst );
            auto const bi = reg_index( base );
            this->m_buf.push_back( 0x8B );
            if( ( bi & 7 ) == 5 )
            {
                /* EBP: mod=0 rm=5 encodes [disp32], use mod=1 disp8=0 instead */
                this->m_buf.push_back( this->modrm( 1, di, bi ) );
                this->m_buf.push_back( 0x00 );
            }
            else if( ( bi & 7 ) == 4 )
            {
                /* ESP: mod=0 rm=4 encodes SIB follows, emit SIB 0x24 */
                this->m_buf.push_back( this->modrm( 0, di, bi ) );
                this->m_buf.push_back( 0x24 );
            }
            else
            {
                this->m_buf.push_back( this->modrm( 0, di, bi ) );
            }
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
            if( ( bi & 7 ) == 5 )
            {
                /* RBP/R13: mod=0 rm=5 encodes [RIP+disp32], use mod=1 disp8=0 */
                this->m_buf.push_back( this->modrm( 1, si & 7, bi & 7 ) );
                this->m_buf.push_back( 0x00 );
            }
            else if( ( bi & 7 ) == 4 )
            {
                /* RSP/R12: mod=0 rm=4 encodes SIB follows, emit SIB 0x24 */
                this->m_buf.push_back( this->modrm( 0, si & 7, bi & 7 ) );
                this->m_buf.push_back( 0x24 );
            }
            else
            {
                this->m_buf.push_back( this->modrm( 0, si & 7, bi & 7 ) );
            }
            return *this;
        }

        /* MOV reg64, [reg64] — load from memory */
        x64& mov_reg_mem( reg64 dst, reg64 base )
        {
            auto const di = reg_index( dst );
            auto const bi = reg_index( base );
            this->m_buf.push_back( rex_w( 0, di, bi ) );
            this->m_buf.push_back( 0x8B );
            if( ( bi & 7 ) == 5 )
            {
                /* RBP/R13: mod=0 rm=5 encodes [RIP+disp32], use mod=1 disp8=0 */
                this->m_buf.push_back( this->modrm( 1, di & 7, bi & 7 ) );
                this->m_buf.push_back( 0x00 );
            }
            else if( ( bi & 7 ) == 4 )
            {
                /* RSP/R12: mod=0 rm=4 encodes SIB follows, emit SIB 0x24 */
                this->m_buf.push_back( this->modrm( 0, di & 7, bi & 7 ) );
                this->m_buf.push_back( 0x24 );
            }
            else
            {
                this->m_buf.push_back( this->modrm( 0, di & 7, bi & 7 ) );
            }
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
    };

} // namespace shellcode
