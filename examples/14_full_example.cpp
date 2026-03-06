#include <print>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include "../Memory/DriverInterface/driver_interface.hpp"

static std::wstring to_wide( std::string_view s )
{
	return { s.begin(), s.end() };
}

static void print_help( std::string_view prog )
{
	std::print( R"({0} - Full end-to-end driver interface demonstration.

Description:
  A complete example showing the typical workflow with the osmium
  kernel driver: connect, attach to a process, resolve the process
  base and a module base, then read and write a value at an offset
  from the process base. This is the driver-backed equivalent of
  using the osmium process class for memory operations.

Usage:
  {0} <process_name> [offset] [write_value]
  {0} --help

Arguments:
  process_name    Name of the target process (e.g. target.exe)
  offset          Hex offset from process base to read (default: 0x1000)
  write_value     Decimal int32 value to write at the offset (optional)

Examples:
  {0} notepad.exe
  {0} target.exe 0x2000
  {0} target.exe 0x1000 1337
)", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" )
	{
		print_help( argv[0] );
		return ( argc > 1 && ( std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" ) ) ? 0 : 1;
	}

	const auto process_name = to_wide( argv[1] );
	const auto offset = ( argc >= 3 )
		? static_cast< std::uintptr_t >( std::stoull( argv[2], nullptr, 16 ) )
		: static_cast< std::uintptr_t >( 0x1000 );

	// Create the driver interface (opens handle to the loaded driver)
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		std::println( "[!] Driver not loaded! Load it first:" );
		std::println( "    sc create OsmiumDrv type= kernel binPath= C:\\path\\to\\driver.sys" );
		std::println( "    sc start OsmiumDrv" );
		return 1;
	}

	std::println( "[+] Connected to kernel driver." );

	// Attach to the target process by name
	if( !driver->attach( process_name ) )
	{
		std::println( "[!] Could not find {}!", argv[1] );
		return 1;
	}

	std::println( "[+] Attached to {} (PID: {})", argv[1], driver->get_pid() );

	// Get the process base address
	const auto base = driver->get_process_base();
	std::println( "[+] Process base: 0x{:X}", base );

	// Get a module base address
	size_t mod_size = 0;
	const auto ntdll = driver->get_module_base( L"ntdll.dll", 0, &mod_size );
	std::println( "[+] ntdll.dll: 0x{:X} (0x{:X} bytes)", ntdll, mod_size );

	// Read a value from the target process
	const auto read_addr = base + offset;
	const auto value = driver->read< int32_t >( read_addr );
	std::println( "[+] Read int32 at base+0x{:X}: {} (0x{:X})", offset, value, value );

	// Optionally write a value
	if( argc >= 4 )
	{
		const auto write_val = std::stoi( argv[3], nullptr, 0 );

		if( driver->write< int32_t >( read_addr, static_cast< int32_t >( write_val ) ) )
			std::println( "[+] Wrote {} to base+0x{:X}", write_val, offset );
		else
			std::println( "[!] Write failed!" );
	}

	// The driver_interface destructor will close the handle automatically
	return 0;
}
