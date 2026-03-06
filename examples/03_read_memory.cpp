#include <print>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include "../Memory/DriverInterface/driver_interface.hpp"

static std::wstring to_wide( std::string_view s )
{
	return { s.begin(), s.end() };
}

static void print_help( std::string_view prog )
{
	std::print( R"({0} - Read typed values from a target process via the kernel driver.

Description:
  Attaches to a target process and reads a value at the given address.
  The value is interpreted as float, int32, and pointer simultaneously
  so you can inspect memory without knowing the exact type upfront.

Usage:
  {0} <process_name> <address>
  {0} --help

Arguments:
  process_name    Name of the target process (e.g. target.exe)
  address         Virtual address to read from (hex, e.g. 0x7FF6A000)

Examples:
  {0} target.exe 0xDEADAFFE
  {0} notepad.exe 7FF6A0001000
)", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 3 || std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" )
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
	std::println( "[+] Reading from address 0x{:X}:", address );

	const auto as_float = driver->read< float >( address );
	const auto as_int32 = driver->read< int32_t >( address );
	const auto as_ptr   = driver->read< std::uintptr_t >( address );

	std::println( "    as float:   {:.6f}", as_float );
	std::println( "    as int32:   {} (0x{:X})", as_int32, as_int32 );
	std::println( "    as pointer: 0x{:X}", as_ptr );

	return 0;
}
