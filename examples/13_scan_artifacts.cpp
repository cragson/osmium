#include <cstdio>
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

static const char* artifact_type_name( ULONG type )
{
	switch( type )
	{
	case ARTIFACT_TYPE_PREFETCH:  return "Prefetch";
	case ARTIFACT_TYPE_SHIMCACHE: return "ShimCache";
	case ARTIFACT_TYPE_BAM:       return "BAM";
	case ARTIFACT_TYPE_AMCACHE:   return "AmCache";
	default: return "Unknown";
	}
}

void print_help( const char* prog )
{
	printf( "%s - Scan for forensic execution artifacts of an executable.\n", prog );
	printf( "\n" );
	printf( "Description:\n" );
	printf( "  Scans for execution traces left by a given executable across four\n" );
	printf( "  forensic sources from kernel mode:\n" );
	printf( "    - Prefetch files in C:\\Windows\\Prefetch\n" );
	printf( "    - ShimCache (AppCompatCache) entries in the registry\n" );
	printf( "    - BAM (Background Activity Moderator) registry entries per user SID\n" );
	printf( "    - AmCache hive file presence\n" );
	printf( "  All findings are also logged via kernel DbgPrint (visible in WinDbg).\n" );
	printf( "\n" );
	printf( "Usage:\n" );
	printf( "  %s <executable_name>                       Scan all artifact types\n", prog );
	printf( "  %s <executable_name> --types <type_list>   Scan specific types\n", prog );
	printf( "  %s --help\n", prog );
	printf( "\n" );
	printf( "Arguments:\n" );
	printf( "  executable_name    Filename to search for (e.g. implant.exe)\n" );
	printf( "  --types            Comma-separated list of artifact types to scan:\n" );
	printf( "                       prefetch, shimcache, bam, amcache\n" );
	printf( "                     If omitted, all types are scanned.\n" );
	printf( "\n" );
	printf( "Examples:\n" );
	printf( "  %s implant.exe\n", prog );
	printf( "  %s payload.exe --types prefetch,shimcache\n", prog );
	printf( "  %s malware.exe --types bam,amcache\n", prog );
}

static ULONG parse_types( const char* s )
{
	ULONG mask = 0;
	std::string token;
	std::string input( s );

	for( size_t i = 0; i <= input.size(); i++ )
	{
		if( i == input.size() || input[i] == ',' )
		{
			if( token == "prefetch" )       mask |= ARTIFACT_TYPE_PREFETCH;
			else if( token == "shimcache" ) mask |= ARTIFACT_TYPE_SHIMCACHE;
			else if( token == "bam" )       mask |= ARTIFACT_TYPE_BAM;
			else if( token == "amcache" )   mask |= ARTIFACT_TYPE_AMCACHE;
			else if( !token.empty() )
				printf( "[!] Unknown artifact type '%s', ignoring.\n", token.c_str() );

			token.clear();
		}
		else
		{
			token += input[i];
		}
	}

	return mask;
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 )
	{
		print_help( argv[0] );
		return argc > 1 && ( strcmp( argv[1], "--help" ) == 0 || strcmp( argv[1], "-h" ) == 0 ) ? 0 : 1;
	}

	const auto exe_name = to_wide( argv[1] );

	ULONG artifact_types = ARTIFACT_TYPE_ALL;
	for( int i = 2; i < argc - 1; i++ )
	{
		if( strcmp( argv[i], "--types" ) == 0 )
		{
			artifact_types = parse_types( argv[i + 1] );
			if( artifact_types == 0 )
			{
				printf( "[!] No valid artifact types specified.\n" );
				return 1;
			}
		}
	}

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		printf( "[!] Could not connect to the driver!\n" );
		return 1;
	}

	printf( "[+] Scanning for artifacts of '%s'", argv[1] );
	if( artifact_types != ARTIFACT_TYPE_ALL )
	{
		printf( " (types:" );
		if( artifact_types & ARTIFACT_TYPE_PREFETCH )  printf( " prefetch" );
		if( artifact_types & ARTIFACT_TYPE_SHIMCACHE ) printf( " shimcache" );
		if( artifact_types & ARTIFACT_TYPE_BAM )       printf( " bam" );
		if( artifact_types & ARTIFACT_TYPE_AMCACHE )   printf( " amcache" );
		printf( ")" );
	}
	printf( "\n" );

	if( auto artifacts = driver->scan_artifacts( exe_name, artifact_types ) )
	{
		if( artifacts->empty() )
		{
			printf( "[+] No forensic artifacts found.\n" );
		}
		else
		{
			printf( "[+] Found %llu forensic artifacts:\n",
				static_cast< unsigned long long >( artifacts->size() ) );

			for( const auto& a : *artifacts )
				wprintf( L"    [%-9S] %s\n", artifact_type_name( a.type ), a.path.c_str() );
		}
	}
	else
	{
		printf( "[!] Artifact scan failed.\n" );
		return 1;
	}

	return 0;
}
