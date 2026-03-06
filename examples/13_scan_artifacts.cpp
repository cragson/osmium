#include <cstdio>
#include <print>
#include <memory>
#include <string>
#include <string_view>
#include "../Memory/DriverInterface/driver_interface.hpp"

static std::wstring to_wide( std::string_view s )
{
	return { s.begin(), s.end() };
}

static std::string to_narrow( const std::wstring& ws )
{
	return { ws.begin(), ws.end() };
}

static std::string_view artifact_type_name( ULONG type )
{
	switch( type )
	{
	case ARTIFACT_TYPE_PREFETCH:   return "Prefetch";
	case ARTIFACT_TYPE_SHIMCACHE:  return "ShimCache";
	case ARTIFACT_TYPE_BAM:        return "BAM";
	case ARTIFACT_TYPE_AMCACHE:    return "AmCache";
	case ARTIFACT_TYPE_USERASSIST: return "UserAssist";
	case ARTIFACT_TYPE_MUICACHE:   return "MUICache";
	case ARTIFACT_TYPE_RECENTAPPS: return "RecentApps";
	case ARTIFACT_TYPE_RUNMRU:     return "RunMRU";
	case ARTIFACT_TYPE_SRUM:       return "SRUM";
	case ARTIFACT_TYPE_TIMELINE:   return "Timeline";
	case ARTIFACT_TYPE_JUMPLISTS:  return "JumpLists";
	case ARTIFACT_TYPE_RECENTDOCS: return "RecentDocs";
	case ARTIFACT_TYPE_EVTLOG:     return "EvtLog";
	case ARTIFACT_TYPE_WER:        return "WER";
	case ARTIFACT_TYPE_SUPERFETCH: return "Superfetch";
	default: return "Unknown";
	}
}

static void print_help( std::string_view prog )
{
	std::print( R"({0} - Scan for forensic execution artifacts of an executable.

Description:
  Scans for execution traces left by a given executable across 15
  forensic sources from kernel mode:
    - Prefetch files in C:\Windows\Prefetch
    - ShimCache (AppCompatCache) entries in the registry
    - BAM (Background Activity Moderator) registry entries per user SID
    - AmCache hive file presence
    - UserAssist (ROT13-encoded execution history per user)
    - MUICache (application display name cache per user)
    - RecentApps (Windows Search recent apps per user)
    - RunMRU (Run dialog history per user)
    - SRUM (System Resource Usage Monitor database)
    - Timeline / ActivitiesCache (Windows Timeline database per user)
    - Jump Lists (automatic destinations per user)
    - RecentDocs (.lnk shortcut files per user)
    - Event Logs (Security, Sysmon, Application .evtx files)
    - WER (Windows Error Reporting crash reports)
    - Superfetch (SysMain AgAppLaunch database)
  All findings are also logged via kernel DbgPrint (visible in WinDbg).

Usage:
  {0} <executable_name>                       Scan all artifact types
  {0} <executable_name> --types <type_list>   Scan specific types
  {0} --help

Arguments:
  executable_name    Filename to search for (e.g. implant.exe)
  --types            Comma-separated list of artifact types to scan:
                       prefetch, shimcache, bam, amcache, userassist,
                       muicache, recentapps, runmru, srum, timeline,
                       jumplists, recentdocs, evtlog, wer, superfetch
                     If omitted, all types are scanned.

Examples:
  {0} implant.exe
  {0} payload.exe --types prefetch,shimcache
  {0} malware.exe --types bam,amcache,userassist,muicache
)", prog );
}

static ULONG parse_types( std::string_view input )
{
	ULONG mask = 0;
	std::string_view remaining = input;

	while( !remaining.empty() )
	{
		const auto pos = remaining.find( ',' );
		const auto token = remaining.substr( 0, pos );
		remaining = ( pos == std::string_view::npos ) ? std::string_view{} : remaining.substr( pos + 1 );

		if( token == "prefetch" )        mask |= ARTIFACT_TYPE_PREFETCH;
		else if( token == "shimcache" )  mask |= ARTIFACT_TYPE_SHIMCACHE;
		else if( token == "bam" )        mask |= ARTIFACT_TYPE_BAM;
		else if( token == "amcache" )    mask |= ARTIFACT_TYPE_AMCACHE;
		else if( token == "userassist" ) mask |= ARTIFACT_TYPE_USERASSIST;
		else if( token == "muicache" )   mask |= ARTIFACT_TYPE_MUICACHE;
		else if( token == "recentapps" ) mask |= ARTIFACT_TYPE_RECENTAPPS;
		else if( token == "runmru" )     mask |= ARTIFACT_TYPE_RUNMRU;
		else if( token == "srum" )       mask |= ARTIFACT_TYPE_SRUM;
		else if( token == "timeline" )   mask |= ARTIFACT_TYPE_TIMELINE;
		else if( token == "jumplists" )  mask |= ARTIFACT_TYPE_JUMPLISTS;
		else if( token == "recentdocs" ) mask |= ARTIFACT_TYPE_RECENTDOCS;
		else if( token == "evtlog" )     mask |= ARTIFACT_TYPE_EVTLOG;
		else if( token == "wer" )        mask |= ARTIFACT_TYPE_WER;
		else if( token == "superfetch" ) mask |= ARTIFACT_TYPE_SUPERFETCH;
		else if( !token.empty() )
			std::println( "[!] Unknown artifact type '{}', ignoring.", token );
	}

	return mask;
}

int main( int argc, char* argv[] )
{
	if( argc < 2 || std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" )
	{
		print_help( argv[0] );
		return ( argc > 1 && ( std::string_view{ argv[1] } == "--help" || std::string_view{ argv[1] } == "-h" ) ) ? 0 : 1;
	}

	const auto exe_name = to_wide( argv[1] );

	ULONG artifact_types = ARTIFACT_TYPE_ALL;
	for( int i = 2; i < argc - 1; i++ )
	{
		if( std::string_view{ argv[i] } == "--types" )
		{
			artifact_types = parse_types( argv[i + 1] );
			if( artifact_types == 0 )
			{
				std::println( "[!] No valid artifact types specified." );
				return 1;
			}
		}
	}

	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
	{
		std::println( "[!] Could not connect to the driver!" );
		return 1;
	}

	std::print( "[+] Scanning for artifacts of '{}'", argv[1] );
	if( artifact_types != ARTIFACT_TYPE_ALL )
	{
		std::print( " (types:" );
		if( artifact_types & ARTIFACT_TYPE_PREFETCH )   std::print( " prefetch" );
		if( artifact_types & ARTIFACT_TYPE_SHIMCACHE )  std::print( " shimcache" );
		if( artifact_types & ARTIFACT_TYPE_BAM )        std::print( " bam" );
		if( artifact_types & ARTIFACT_TYPE_AMCACHE )    std::print( " amcache" );
		if( artifact_types & ARTIFACT_TYPE_USERASSIST ) std::print( " userassist" );
		if( artifact_types & ARTIFACT_TYPE_MUICACHE )   std::print( " muicache" );
		if( artifact_types & ARTIFACT_TYPE_RECENTAPPS ) std::print( " recentapps" );
		if( artifact_types & ARTIFACT_TYPE_RUNMRU )     std::print( " runmru" );
		if( artifact_types & ARTIFACT_TYPE_SRUM )       std::print( " srum" );
		if( artifact_types & ARTIFACT_TYPE_TIMELINE )   std::print( " timeline" );
		if( artifact_types & ARTIFACT_TYPE_JUMPLISTS )  std::print( " jumplists" );
		if( artifact_types & ARTIFACT_TYPE_RECENTDOCS ) std::print( " recentdocs" );
		if( artifact_types & ARTIFACT_TYPE_EVTLOG )     std::print( " evtlog" );
		if( artifact_types & ARTIFACT_TYPE_WER )        std::print( " wer" );
		if( artifact_types & ARTIFACT_TYPE_SUPERFETCH ) std::print( " superfetch" );
		std::print( ")" );
	}
	std::println( "" );

	if( auto artifacts = driver->scan_artifacts( exe_name, artifact_types ) )
	{
		if( artifacts->empty() )
		{
			std::println( "[+] No forensic artifacts found." );
		}
		else
		{
			std::println( "[+] Found {} forensic artifacts:", artifacts->size() );

			for( const auto& a : *artifacts )
				std::println( "    [{:<10}] {}", artifact_type_name( a.type ), to_narrow( a.path ) );
		}
	}
	else
	{
		std::println( "[!] Artifact scan failed." );
		return 1;
	}

	return 0;
}
