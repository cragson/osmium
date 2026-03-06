#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include "../Memory/DriverInterface/driver_interface.hpp"

static std::wstring to_wide( const char* s )
{
	std::wstring ws;
	while( *s ) ws += static_cast< wchar_t >( *s++ );
	return ws;
}

void print_help( const char* prog )
{
	printf( "%s - Full end-to-end driver interface demonstration.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  A complete example showing the typical workflow with the osmium\n" );
	printf( "  kernel driver: connect, attach to a process, resolve the process\n" );
	printf( "  base and a module base, then read and write a value at an offset\n" );
	printf( "  from the process base. This is the driver-backed equivalent of\n" );
	printf( "  using the osmium process class for memory operations.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <process_name> [offset] [write_value]\n", prog );
	printf( "  %s --help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  process_name    Name of the target process (e.g. target.exe)\n" );
	printf( "  offset          Hex offset from process base to read (default: 0x1000)\n" );
	printf( "  write_value     Decimal int32 value to write at the offset (optional)\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s notepad.exe\n", prog );
	printf( "  %s target.exe 0x2000\n", prog );
	printf( "  %s target.exe 0x1000 1337\n", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 )
	{
		print_help( argv[0] );
		return argc > 1 && ( strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 ) ? 0 : 1;
	}

	const auto process_name = to_wide( argv[1] );
	const auto offset = ( argc >= 3 )
		? static_cast< std::uintptr_t >( strtoull( argv[2], nullptr, 16 ) )
		: static_cast< std::uintptr_t >( 0x1000 );

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
	if( !driver->attach( process_name ) )
	{
		printf( "[!] Could not find %s!\n", argv[1] );
		return 1;
	}

	printf( "[+] Attached to %s (PID: %u)\n", argv[1], driver->get_pid() );

	// Get the process base address
	const auto base = driver->get_process_base();
	printf( "[+] Process base: 0x%llX\n", static_cast< unsigned long long >( base ) );

	// Get a module base address
	size_t mod_size = 0;
	const auto ntdll = driver->get_module_base( L"ntdll.dll", 0, &mod_size );
	printf( "[+] ntdll.dll: 0x%llX (0x%llX bytes)\n",
		static_cast< unsigned long long >( ntdll ),
		static_cast< unsigned long long >( mod_size ) );

	// Read a value from the target process
	const auto read_addr = base + offset;
	const auto value = driver->read< int32_t >( read_addr );
	printf( "[+] Read int32 at base+0x%llX: %d (0x%X)\n",
		static_cast< unsigned long long >( offset ), value, value );

	// Optionally write a value
	if( argc >= 4 )
	{
		const auto write_val = static_cast< int32_t >( strtol( argv[3], nullptr, 0 ) );

		if( driver->write< int32_t >( read_addr, write_val ) )
			printf( "[+] Wrote %d to base+0x%llX\n", write_val,
				static_cast< unsigned long long >( offset ) );
		else
			printf( "[!] Write failed!\n" );
	}

	// The driver_interface destructor will close the handle automatically
	return 0;
}
