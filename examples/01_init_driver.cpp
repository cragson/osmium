#include <print>
#include <memory>
#include <string_view>
#include "../Memory/DriverInterface/driver_interface.hpp"

static void print_help( std::string_view prog )
{
	std::print( R"({0} - Test connection to the osmium kernel driver.

Description:
  Opens a handle to the loaded kernel driver and verifies that
  communication is working. No arguments are required.

Usage:
  {0}
  {0} --help

Prerequisites:
  The kernel driver must be loaded before running this example:
    sc create OsmiumDrv type= kernel binPath= C:\path\to\driver.sys
    sc start OsmiumDrv
)", prog );
}

int main( int argc, char* argv[] )
{
	if( argc > 1 && ( std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" ) )
	{
		print_help( argv[0] );
		return 0;
	}

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		std::println( "[!] Could not connect to the driver, make sure it's loaded!" );
		return 1;
	}

	std::println( "[+] Connected to kernel driver!" );
	return 0;
}
