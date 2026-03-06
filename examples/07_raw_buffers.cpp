#include <print>
#include <cstdint>
#include <memory>
#include <vector>
#include <string>
#include <string_view>
#include "../Memory/DriverInterface/driver_interface.hpp"

static std::wstring to_wide( std::string_view s )
{
	return { s.begin(), s.end() };
}

static void print_help( std::string_view prog )
{
	std::print( R"({0} - Read or write raw byte buffers in a target process via the kernel driver.

Description:
  Attaches to a target process and reads a raw byte buffer from the
  given address, displayed as a hex dump. Optionally writes a sequence
  of hex bytes before reading.

Usage:
  {0} <process_name> <address> <size>                       Read bytes
  {0} <process_name> <address> --write <hex_bytes>          Write bytes
  {0} --help

Arguments:
  process_name    Name of the target process (e.g. target.exe)
  address         Virtual address (hex, e.g. 0x7FF6A000)
  size            Number of bytes to read (decimal)
  --write         Write hex bytes (space-separated, e.g. 90 90 90 CC)

Examples:
  {0} target.exe 0x7FF6A000 64
  {0} target.exe 0x7FF6A000 256
  {0} target.exe 0x7FF6A100 --write 90 90 90 90 90
)", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 4 || std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" )
	{
		print_help( argv[0] );
		return ( argc > 1 && ( std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" ) ) ? 0 : 1;
	}

	const auto process_name = to_wide( argv[1] );
	const auto address = static_cast< std::uintptr_t >( std::stoull( argv[2], nullptr, 16 ) );

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		std::println( "[!] Could not connect to the driver!" );
		return 1;
	}

	if( !driver->attach( process_name ) )
	{
		std::println( "[!] Could not find process '{}'!", argv[1] );
		return 1;
	}

	std::println( "[+] Attached to {} (PID: {})", argv[1], driver->get_pid() );

	if( std::string_view{ argv[3] } == "--write" )
	{
		if( argc < 5 )
		{
			std::println( "[!] --write requires at least one hex byte." );
			return 1;
		}

		std::vector< uint8_t > bytes;
		for( int i = 4; i < argc; i++ )
			bytes.push_back( static_cast< uint8_t >( std::stoul( argv[i], nullptr, 16 ) ) );

		if( driver->write_buffer( address, bytes.data(), bytes.size() ) )
			std::println( "[+] Wrote {} bytes to 0x{:X}", bytes.size(), address );
		else
		{
			std::println( "[!] Write failed!" );
			return 1;
		}
	}
	else
	{
		const auto size = static_cast< size_t >( std::stoul( argv[3] ) );

		if( size == 0 || size > 0x10000 )
		{
			std::println( "[!] Invalid size (must be 1..65536)." );
			return 1;
		}

		std::vector< uint8_t > buffer( size );

		if( !driver->read_buffer( address, buffer.data(), buffer.size() ) )
		{
			std::println( "[!] Read failed!" );
			return 1;
		}

		std::println( "[+] Hex dump of {} bytes at 0x{:X}:", size, address );

		for( size_t i = 0; i < size; i += 16 )
		{
			std::print( "  {:X}  ", address + i );

			for( size_t j = 0; j < 16; j++ )
			{
				if( i + j < size )
					std::print( "{:02X} ", buffer[i + j] );
				else
					std::print( "   " );

				if( j == 7 ) std::print( " " );
			}

			std::print( " |" );
			for( size_t j = 0; j < 16 && i + j < size; j++ )
			{
				const auto c = static_cast< char >( buffer[i + j] );
				std::print( "{}", ( c >= 0x20 && c < 0x7F ) ? c : '.' );
			}
			std::println( "|" );
		}
	}

	return 0;
}
