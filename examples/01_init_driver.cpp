#include <cstdio>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		printf( "[!] Could not connect to the driver, make sure it's loaded!\n" );
		return 1;
	}

	printf( "[+] Connected to kernel driver!\n" );
	return 0;
}
