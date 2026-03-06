#include <cstdio>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
		return 1;

	// Attach by process name
	if( !driver->attach( L"target.exe" ) )
	{
		printf( "[!] Could not find the target process!\n" );
		return 1;
	}

	printf( "[+] Attached to target.exe with PID: %d\n", driver->get_pid() );

	// Or attach by PID directly if you already know it
	// driver->attach( 1337 );

	return 0;
}
