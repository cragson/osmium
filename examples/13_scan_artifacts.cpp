#include <cstdio>
#include <memory>
#include "../Memory/DriverInterface/driver_interface.hpp"

int main()
{
	const auto driver = std::make_unique< driver_interface >();

	if( !driver->is_connected() )
		return 1;

	// Scan for all artifact types
	if( auto artifacts = driver->scan_artifacts( L"implant.exe" ) )
	{
		printf( "[+] Found %llu forensic artifacts:\n", artifacts->size() );

		for( const auto& a : *artifacts )
			wprintf( L"    [type: %u] %s\n", a.type, a.path.c_str() );
	}
	else
	{
		printf( "[!] Artifact scan failed.\n" );
	}

	// Scan only Prefetch and ShimCache
	if( auto artifacts = driver->scan_artifacts( L"implant.exe",
		ARTIFACT_TYPE_PREFETCH | ARTIFACT_TYPE_SHIMCACHE ) )
	{
		for( const auto& a : *artifacts )
			wprintf( L"    %s\n", a.path.c_str() );
	}

	return 0;
}
