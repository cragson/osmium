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
	std::print( R"({0} - Write a typed value to a target process via the kernel driver.

Description:
  Attaches to a target process and writes a value at the given address.
  Supports float, int32, and byte types. The driver automatically uses
  MDL-based writes for read-only pages, so no VirtualProtectEx is needed.

Usage:
  {0} <process_name> <address> <value> [--type float|int32|byte]
  {0} --help

Arguments:
  process_name    Name of the target process (e.g. target.exe)
  address         Virtual address to write to (hex, e.g. 0x7FF6A000)
  value           The value to write (decimal for int/byte, decimal for float)
  --type          Value type: float, int32 (default), or byte

Examples:
  {0} target.exe 0xDEADAFFE 1337
  {0} target.exe 0xDEADAFFE 100.0 --type float
  {0} target.exe 0xDEADAFFE 0x90 --type byte
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
	const auto value_str = std::string_view{ argv[3] };

	auto type = std::string_view{ "int32" };
	for( int i = 4; i < argc - 1; i++ )
	{
		if( std::string_view{ argv[i] } == "--type" )
			type = argv[i + 1];
	}

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

	bool ok = false;

	if( type == "float" )
	{
		const auto val = std::stof( std::string{ value_str } );
		ok = driver->write< float >( address, val );
		if( ok ) std::println( "[+] Wrote float {:.6f} to 0x{:X}", val, address );
	}
	else if( type == "byte" )
	{
		const auto val = static_cast< uint8_t >( std::stoul( std::string{ value_str }, nullptr, 0 ) );
		ok = driver->write< uint8_t >( address, val );
		if( ok ) std::println( "[+] Wrote byte 0x{:02X} to 0x{:X}", val, address );
	}
	else
	{
		const auto val = std::stoi( std::string{ value_str }, nullptr, 0 );
		ok = driver->write< int32_t >( address, static_cast< int32_t >( val ) );
		if( ok ) std::println( "[+] Wrote int32 {} to 0x{:X}", val, address );
	}

	if( !ok )
		std::println( "[!] Write failed!" );

	return ok ? 0 : 1;
}
