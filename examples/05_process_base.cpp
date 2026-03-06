#include <cstdio>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
		return 1;

	if( !driver->attach( L"target.exe" ) )
		return 1;

	const auto base = driver->get_process_base();

	if( !base )
	{
		printf( "[!] Could not get process base address!\n" );
		return 1;
	}

	printf( "[+] target.exe base: 0x%llX\n", base );

	return 0;
}
