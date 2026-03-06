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
	printf( "%s - Write a typed value to a target process via the kernel driver.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Attaches to a target process and writes a value at the given address.\n" );
	printf( "  Supports float, int32, and byte types. The driver automatically uses\n" );
	printf( "  MDL-based writes for read-only pages, so no VirtualProtectEx is needed.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <process_name> <address> <value> [--type float|int32|byte]\n", prog );
	printf( "  %s --help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  process_name    Name of the target process (e.g. target.exe)\n" );
	printf( "  address         Virtual address to write to (hex, e.g. 0x7FF6A000)\n" );
	printf( "  value           The value to write (decimal for int/byte, decimal for float)\n" );
	printf( "  --type          Value type: float, int32 (default), or byte\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s target.exe 0xDEADAFFE 1337\n", prog );
	printf( "  %s target.exe 0xDEADAFFE 100.0 --type float\n", prog );
	printf( "  %s target.exe 0xDEADAFFE 0x90 --type byte\n", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 4 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 )
	{
		print_help( argv[0] );
		return argc > 1 && ( strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 ) ? 0 : 1;
	}

	const auto process_name = to_wide( argv[1] );
	const auto address = static_cast< std::uintptr_t >( strtoull( argv[2], nullptr, 16 ) );
	const char* value_str = argv[3];

	const char* type = "int32";
	for( int i = 4; i < argc - 1; i++ )
	{
		if( strcmp( argv[i], "--type" ) == 0 )
			type = argv[i + 1];
	}

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

	bool ok = false;

	if( strcmp( type, "float" ) == 0 )
	{
		const auto val = static_cast< float >( atof( value_str ) );
		ok = driver->write< float >( address, val );
		if( ok ) printf( "[+] Wrote float %.6f to 0x%llX\n", val, static_cast< unsigned long long >( address ) );
	}
	else if( strcmp( type, "byte" ) == 0 )
	{
		const auto val = static_cast< uint8_t >( strtoul( value_str, nullptr, 0 ) );
		ok = driver->write< uint8_t >( address, val );
		if( ok ) printf( "[+] Wrote byte 0x%02X to 0x%llX\n", val, static_cast< unsigned long long >( address ) );
	}
	else
	{
		const auto val = static_cast< int32_t >( strtol( value_str, nullptr, 0 ) );
		ok = driver->write< int32_t >( address, val );
		if( ok ) printf( "[+] Wrote int32 %d to 0x%llX\n", val, static_cast< unsigned long long >( address ) );
	}

	if( !ok )
		printf( "[!] Write failed!\n" );

	return ok ? 0 : 1;
}
