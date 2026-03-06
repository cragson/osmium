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
	printf( "%s - Get the base address and size of loaded modules via the kernel driver.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Attaches to a target process and resolves the base address and size\n" );
	printf( "  of one or more loaded modules by walking the PEB module list from\n" );
	printf( "  kernel mode. Handles both native x64 and WoW64 processes.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <process_name> <module_name> [module_name2 ...]\n", prog );
	printf( "  %s --help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  process_name    Name of the target process (e.g. target.exe)\n" );
	printf( "  module_name     Name of the module to look up (e.g. ntdll.dll)\n" );
	printf( "                  Multiple module names can be specified.\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s notepad.exe ntdll.dll\n", prog );
	printf( "  %s target.exe ntdll.dll kernel32.dll user32.dll\n", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 3 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 )
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

	for( int i = 2; i < argc; i++ )
	{
		const auto module_name = to_wide( argv[i] );
		size_t module_size = 0;

		const auto base = driver->get_module_base( module_name, 0, &module_size );

		if( base )
			printf( "[+] %-20s -> 0x%llX (size: 0x%llX)\n", argv[i],
				static_cast< unsigned long long >( base ),
				static_cast< unsigned long long >( module_size ) );
		else
			printf( "[!] %-20s -> not found\n", argv[i] );
	}

	return 0;
}
