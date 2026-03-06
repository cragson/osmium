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

	// Write a float value
	if( driver->write< float >( 0xDEADAFFE, 100.0f ) )
		printf( "[+] Wrote health successfully!\n" );

	// Write an integer
	driver->write< int32_t >( 0xDEADAFFE + 0x10, 999 );

	// Write a byte (e.g. NOP a check)
	driver->write< uint8_t >( 0xDEADAFFE + 0x50, 0x90 );

	return 0;
}
