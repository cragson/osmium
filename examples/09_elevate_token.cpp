#include <cstdio>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
		return 1;

	// Elevate the current process to SYSTEM
	if( driver->elevate_token( GetCurrentProcessId() ) )
		printf( "[+] Elevated to NT AUTHORITY\\SYSTEM!\n" );

	// Or elevate a specific PID
	if( driver->elevate_token( 1337 ) )
		printf( "[+] PID 1337 elevated to SYSTEM!\n" );

	return 0;
}
