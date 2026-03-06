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
	std::print( R"({0} - Strip all external handles to a process.

Description:
  Closes all handles to a process that are held by other processes.
  This prevents other processes (including EDRs) from inspecting or
  manipulating the target via handle-based APIs like ReadProcessMemory,
  NtQueryInformationProcess, etc.

Usage:
  {0} <process_name>     Strip handles by process name
  {0} --pid <pid>        Strip handles by process ID
  {0} --help             Show this help

Arguments:
  process_name    Name of the target process (e.g. implant.exe)
  --pid <pid>     Process ID (decimal)

Examples:
  {0} implant.exe
  {0} --pid 4200
)", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" )
	{
		print_help( argv[0] );
		return ( argc > 1 && ( std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" ) ) ? 0 : 1;
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

		driver->attach( static_cast< DWORD >( std::stoul( argv[2] ) ) );
	}
	else
	{
		if( !driver->attach( to_wide( arg1 ) ) )
		{
			std::println( "[!] Could not find process '{}'!", arg1 );
			return 1;
		}
	}

	std::println( "[+] Target PID: {}", driver->get_pid() );

	if( auto stripped = driver->strip_handles() )
		std::println( "[+] Closed {} handles held by other processes.", *stripped );
	else
	{
		std::println( "[!] Failed to strip handles." );
		return 1;
	}

	return 0;
}
