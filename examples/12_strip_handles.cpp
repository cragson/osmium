#include <cstdio>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
		return 1;

	driver->attach( L"implant.exe" );

	if( auto stripped = driver->strip_handles() )
		printf( "[+] Closed %u handles held by other processes.\n", *stripped );
	else
		printf( "[!] Failed to strip handles.\n" );

	return 0;
}
