#include <print>
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
	std::print( R"({0} - Attach to a target process via the kernel driver.

Description:
  Connects to the kernel driver and attaches to a target process
  by name or PID, then prints the resolved PID.

Usage:
  {0} <process_name>     Attach by process name
  {0} --pid <pid>        Attach by process ID
  {0} --help             Show this help

Examples:
  {0} notepad.exe
  {0} --pid 1337
)", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" )
	{
		print_help( argv[0] );
		return argc < 2 ? 1 : 0;
	}

	const auto arg1 = std::string_view{ argv[1] };
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		std::println( "[!] Could not connect to the driver!" );
		return 1;
	}

	if( arg1 == "--pid" )
	{
		if( argc < 3 )
		{
			std::println( "[!] --pid requires a process ID argument." );
			return 1;
		}

		const auto pid = static_cast< DWORD >( std::stoul( argv[2] ) );
		driver->attach( pid );
		std::println( "[+] Attached to PID: {}", pid );
	}
	else
	{
		const auto name = to_wide( arg1 );

		if( !driver->attach( name ) )
		{
			std::println( "[!] Could not find process '{}'!", arg1 );
			return 1;
		}

		std::println( "[+] Attached to {} (PID: {})", arg1, driver->get_pid() );
	}

	return 0;
}
