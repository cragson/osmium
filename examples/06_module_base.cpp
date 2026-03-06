#include <print>
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
	std::print( R"({0} - Get the base address and size of loaded modules via the kernel driver.

Description:
  Attaches to a target process and resolves the base address and size
  of one or more loaded modules by walking the PEB module list from
  kernel mode. Handles both native x64 and WoW64 processes.

Usage:
  {0} <process_name> <module_name> [module_name2 ...]
  {0} --help

Arguments:
  process_name    Name of the target process (e.g. target.exe)
  module_name     Name of the module to look up (e.g. ntdll.dll)
                  Multiple module names can be specified.

Examples:
  {0} notepad.exe ntdll.dll
  {0} target.exe ntdll.dll kernel32.dll user32.dll
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

	for( int i = 2; i < argc; i++ )
	{
		const auto module_name = to_wide( argv[i] );
		size_t module_size = 0;

		const auto base = driver->get_module_base( module_name, 0, &module_size );

		if( base )
			std::println( "[+] {:<20} -> 0x{:X} (size: 0x{:X})", argv[i], base, module_size );
		else
			std::println( "[!] {:<20} -> not found", argv[i] );
	}

	return 0;
}
