#include <cstdio>
#include <cstdint>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
		return 1;

	if( !driver->attach( L"target.exe" ) )
		return 1;

	const auto health = driver->read< float >( 0xDEADAFFE );

	const auto ammo = driver->read< int32_t >( 0xDEADAFFE + 0x10 );

	const auto ptr = driver->read< std::uintptr_t >( 0xDEADAFFE + 0x20 );

	printf( "[+] Health: %.2f | Ammo: %d | Ptr: 0x%llX\n", health, ammo, ptr );

	return 0;
}
