#include <cstdio>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
		return 1;

	// Enumerate all process creation callbacks
	if( auto callbacks = driver->enum_callbacks( CALLBACK_TYPE_PROCESS ) )
	{
		printf( "[+] Found %llu process callbacks:\n", callbacks->size() );

		for( const auto& cb : *callbacks )
			printf( "    [%u] 0x%llX\n", cb.index, cb.address );
	}

	// Remove all process creation callbacks
	if( auto removed = driver->remove_all_callbacks( CALLBACK_TYPE_PROCESS ) )
		printf( "[+] Removed %u process callbacks.\n", *removed );

	// Remove all thread creation callbacks
	if( auto removed = driver->remove_all_callbacks( CALLBACK_TYPE_THREAD ) )
		printf( "[+] Removed %u thread callbacks.\n", *removed );

	// Remove all image load callbacks
	if( auto removed = driver->remove_all_callbacks( CALLBACK_TYPE_IMAGE ) )
		printf( "[+] Removed %u image callbacks.\n", *removed );

	// Or remove a single callback by index
	if( driver->remove_callback( CALLBACK_TYPE_PROCESS, 3 ) )
		printf( "[+] Removed callback at index 3.\n" );

	return 0;
}
