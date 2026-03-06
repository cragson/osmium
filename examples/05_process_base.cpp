#include <cstdio>
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
	printf( "%s - Get the base address of a process via the kernel driver.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Attaches to a target process and retrieves its main executable base\n" );
	printf( "  address using PsGetProcessSectionBaseAddress in kernel mode. This\n" );
	printf( "  does not require an open handle to the target process.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <process_name>\n", prog );
	printf( "  %s --help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  process_name    Name of the target process (e.g. notepad.exe)\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s notepad.exe\n", prog );
	printf( "  %s explorer.exe\n", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 )
	{
		print_help( argv[0] );
		return argc > 1 && ( strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 ) ? 0 : 1;
	}

	const auto process_name = to_wide( argv[1] );

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		printf( "[!] Could not connect to the driver!\n" );
		return 1;
	}

	if( !driver->attach( process_name ) )
	{
		printf( "[!] Could not find process '%s'!\n", argv[1] );
		return 1;
	}

	printf( "[+] Attached to %s (PID: %u)\n", argv[1], driver->get_pid() );

	const auto base = driver->get_process_base();

	if( !base )
	{
		printf( "[!] Could not get process base address!\n" );
		return 1;
	}

	printf( "[+] Base address: 0x%llX\n", static_cast< unsigned long long >( base ) );

	return 0;
}
