#include <cstdio>
#include <cstdint>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	// Create the driver interface (opens handle to the loaded driver)
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		printf( "[!] Driver not loaded! Load it first:\n" );
		printf( "    sc create OsmiumDrv type= kernel binPath= C:\\path\\to\\driver.sys\n" );
		printf( "    sc start OsmiumDrv\n" );
		return 1;
	}

	printf( "[+] Connected to kernel driver.\n" );

	// Attach to the target process by name
	if( !driver->attach( L"target.exe" ) )
	{
		printf( "[!] Could not find target.exe!\n" );
		return 1;
	}

	printf( "[+] Attached to target.exe (PID: %d)\n", driver->get_pid() );

	// Get the process base address
	const auto base = driver->get_process_base();
	printf( "[+] Process base: 0x%llX\n", base );

	// Get a module base address
	size_t mod_size = 0;
	const auto ntdll = driver->get_module_base( L"ntdll.dll", 0, &mod_size );
	printf( "[+] ntdll.dll: 0x%llX (0x%llX bytes)\n", ntdll, mod_size );

	// Read some values from the target process
	const auto value = driver->read< int32_t >( base + 0x1000 );
	printf( "[+] Read value: %d\n", value );

	// Write a value to the target process
	if( driver->write< int32_t >( base + 0x1000, 1337 ) )
		printf( "[+] Wrote 1337 to target!\n" );

	// The driver_interface destructor will close the handle automatically
	return 0;
}
