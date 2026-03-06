#include <cstdio>
#include <cstring>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

void print_help( const char* prog )
{
	printf( "%s - Test connection to the osmium kernel driver.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Opens a handle to the loaded kernel driver and verifies that\n" );
	printf( "  communication is working. No arguments are required.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s\n", prog );
	printf( "  %s --help\n", prog );
	printf( "\n" );
	printf( "Prerequisites:\n" );
	printf( "  The kernel driver must be loaded before running this example:\n" );
	printf( "    sc create OsmiumDrv type= kernel binPath= C:\\path\\to\\driver.sys\n" );
	printf( "    sc start OsmiumDrv\n" );
}

int main( int argc, char* argv[] )
{
	if( argc > 1 && ( strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 ) )
	{
		print_help( argv[0] );
		return 0;
	}

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		printf( "[!] Could not connect to the driver, make sure it's loaded!\n" );
		return 1;
	}

	printf( "[+] Connected to kernel driver!\n" );
	return 0;
}
