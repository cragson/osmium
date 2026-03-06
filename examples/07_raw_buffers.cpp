#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>
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
	printf( "%s - Read or write raw byte buffers in a target process via the kernel driver.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Attaches to a target process and reads a raw byte buffer from the\n" );
	printf( "  given address, displayed as a hex dump. Optionally writes a sequence\n" );
	printf( "  of hex bytes before reading.\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <process_name> <address> <size>                       Read bytes\n", prog );
	printf( "  %s <process_name> <address> --write <hex_bytes>          Write bytes\n", prog );
	printf( "  %s --help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  process_name    Name of the target process (e.g. target.exe)\n" );
	printf( "  address         Virtual address (hex, e.g. 0x7FF6A000)\n" );
	printf( "  size            Number of bytes to read (decimal)\n" );
	printf( "  --write         Write hex bytes (space-separated, e.g. 90 90 90 CC)\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s target.exe 0x7FF6A000 64\n", prog );
	printf( "  %s target.exe 0x7FF6A000 256\n", prog );
	printf( "  %s target.exe 0x7FF6A100 --write 90 90 90 90 90\n", prog );
}

int main( int argc, char* argv[] )
{
	if( argc < 4 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 )
	{
		print_help( argv[0] );
		return argc > 1 && ( strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 ) ? 0 : 1;
	}

	const auto process_name = to_wide( argv[1] );
	const auto address = static_cast< std::uintptr_t >( strtoull( argv[2], nullptr, 16 ) );

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		printf( "[!] Could not connect to the driver!\n" );
		return 1;
	}

	if( !driver->attach( process_name ) )
	{
		printf( "[!] Could not find process '%s'!\n", argv[1] );
		return 1;
	}

	printf( "[+] Attached to %s (PID: %u)\n", argv[1], driver->get_pid() );

	if( strcmp( argv[3], "--write" ) == 0 )
	{
		if( argc < 5 )
		{
			printf( "[!] --write requires at least one hex byte.\n" );
			return 1;
		}

		std::vector< uint8_t > bytes;
		for( int i = 4; i < argc; i++ )
			bytes.push_back( static_cast< uint8_t >( strtoul( argv[i], nullptr, 16 ) ) );

		if( driver->write_buffer( address, bytes.data(), bytes.size() ) )
			printf( "[+] Wrote %llu bytes to 0x%llX\n",
				static_cast< unsigned long long >( bytes.size() ),
				static_cast< unsigned long long >( address ) );
		else
		{
			printf( "[!] Write failed!\n" );
			return 1;
		}
	}
	else
	{
		const auto size = static_cast< size_t >( strtoul( argv[3], nullptr, 10 ) );

		if( size == 0 || size > 0x10000 )
		{
			printf( "[!] Invalid size (must be 1..65536).\n" );
			return 1;
		}

		std::vector< uint8_t > buffer( size );

		if( !driver->read_buffer( address, buffer.data(), buffer.size() ) )
		{
			printf( "[!] Read failed!\n" );
			return 1;
		}

		printf( "[+] Hex dump of %llu bytes at 0x%llX:\n",
			static_cast< unsigned long long >( size ),
			static_cast< unsigned long long >( address ) );

		for( size_t i = 0; i < size; i += 16 )
		{
			printf( "  %llX  ", static_cast< unsigned long long >( address + i ) );

			for( size_t j = 0; j < 16; j++ )
			{
				if( i + j < size )
					printf( "%02X ", buffer[i + j] );
				else
					printf( "   " );

				if( j == 7 ) printf( " " );
			}

			printf( " |" );
			for( size_t j = 0; j < 16 && i + j < size; j++ )
			{
				const auto c = buffer[i + j];
				printf( "%c", ( c >= 0x20 && c < 0x7F ) ? c : '.' );
			}
			printf( "|\n" );
		}
	}

	return 0;
}
