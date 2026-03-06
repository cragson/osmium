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
	std::print( R"({0} - Get the base address of a process via the kernel driver.

Description:
  Attaches to a target process and retrieves its main executable base
  address using PsGetProcessSectionBaseAddress in kernel mode. This
  does not require an open handle to the target process.

Usage:
  {0} <process_name>
  {0} --help

Arguments:
  process_name    Name of the target process (e.g. notepad.exe)

Examples:
  {0} notepad.exe
  {0} explorer.exe
)", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" )
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

	const auto base = driver->get_process_base();

	if( !base )
	{
		std::println( "[!] Could not get process base address!" );
		return 1;
	}

	std::println( "[+] Base address: 0x{:X}", base );

	return 0;
}
