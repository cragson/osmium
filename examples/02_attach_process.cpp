#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include "../Memory/DriverInterface/driver_interface.hpp"

static std::wstring to_wide( const char* s )
{
	std::wstring ws;
	while( *s ) ws += static_cast< wchar_t >( *s++ );
	return ws;
}

void print_help( const char* prog )
{
	printf( "%s - Attach to a target process via the kernel driver.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Connects to the kernel driver and attaches to a target process\n" );
	printf( "  by name or PID, then prints the resolved PID.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <process_name>     Attach by process name\n", prog );
	printf( "  %s --pid <pid>        Attach by process ID\n", prog );
	printf( "  %s --help             Show this help\n", prog );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s notepad.exe\n", prog );
	printf( "  %s --pid 1337\n", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 )
	{
		print_help( argv[0] );
		return argc < 2 ? 1 : 0;
	}

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		printf( "[!] Could not connect to the driver!\n" );
		return 1;
	}

	if( strcmp( argv[1], "--pid" ) == 0 )
	{
		if( argc < 3 )
		{
			printf( "[!] --pid requires a process ID argument.\n" );
			return 1;
		}

		const auto pid = static_cast< DWORD >( strtoul( argv[2], nullptr, 10 ) );
		driver->attach( pid );
		printf( "[+] Attached to PID: %u\n", pid );
	}
	else
	{
		const auto name = to_wide( argv[1] );

		if( !driver->attach( name ) )
		{
			printf( "[!] Could not find process '%s'!\n", argv[1] );
			return 1;
		}

		printf( "[+] Attached to %s (PID: %u)\n", argv[1], driver->get_pid() );
	}

	return 0;
}
