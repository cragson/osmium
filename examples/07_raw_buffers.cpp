#include <cstdio>
#include <cstdint>
#include <memory>
#include <vector>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
		return 1;

	if( !driver->attach( L"target.exe" ) )
		return 1;

	// Read 256 bytes from the target
	std::vector< uint8_t > buffer( 256 );

	if( driver->read_buffer( 0xDEADAFFE, buffer.data(), buffer.size() ) )
		printf( "[+] Read %llu bytes from target!\n", buffer.size() );

	// Write a NOP sled (e.g. patching out a check)
	std::vector< uint8_t > nops( 5, 0x90 );

	if( driver->write_buffer( 0xDEADAFFE + 0x100, nops.data(), nops.size() ) )
		printf( "[+] Patched %llu bytes in target!\n", nops.size() );

	return 0;
}
