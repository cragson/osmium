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

	size_t module_size = 0;

	const auto ntdll_base = driver->get_module_base( L"ntdll.dll", 0, &module_size );

	if( ntdll_base )
		printf( "[+] ntdll.dll -> 0x%llX (size: 0x%llX)\n", ntdll_base, module_size );

	const auto kernel32_base = driver->get_module_base( L"kernel32.dll" );

	if( kernel32_base )
		printf( "[+] kernel32.dll -> 0x%llX\n", kernel32_base );

	return 0;
}
