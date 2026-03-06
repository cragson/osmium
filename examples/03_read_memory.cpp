#include <cstdio>
#include <cstdlib>
#include <cstdint>
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
	printf( "%s - Read typed values from a target process via the kernel driver.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Attaches to a target process and reads a value at the given address.\n" );
	printf( "  The value is interpreted as float, int32, and pointer simultaneously\n" );
	printf( "  so you can inspect memory without knowing the exact type upfront.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <process_name> <address>\n", prog );
	printf( "  %s --help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  process_name    Name of the target process (e.g. target.exe)\n" );
	printf( "  address         Virtual address to read from (hex, e.g. 0x7FF6A000)\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s target.exe 0xDEADAFFE\n", prog );
	printf( "  %s notepad.exe 7FF6A0001000\n", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 3 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 )
	{
		print_help( argv[0] );
		return argc > 1 && ( strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 ) ? 0 : 1;
	}

	const auto process_name = to_wide( argv[1] );
	const auto address = static_cast< std::uintptr_t >( strtoull( argv[2], nullptr, 16 ) );

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
	printf( "[+] Reading from address 0x%llX:\n", static_cast< unsigned long long >( address ) );

	const auto as_float = driver->read< float >( address );
	const auto as_int32 = driver->read< int32_t >( address );
	const auto as_ptr   = driver->read< std::uintptr_t >( address );

	printf( "    as float:   %.6f\n", as_float );
	printf( "    as int32:   %d (0x%X)\n", as_int32, as_int32 );
	printf( "    as pointer: 0x%llX\n", static_cast< unsigned long long >( as_ptr ) );

	return 0;
}
