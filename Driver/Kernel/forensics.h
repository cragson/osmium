#pragma once

#include <ntifs.h>
#include "../Shared/ioctl.h"

/*
 * Forensic artifact scanner.
 *
 * KmScanForensicArtifacts: Scans for execution traces left by a given
 *                          executable across multiple forensic sources
 *                          (Prefetch, ShimCache, BAM, AmCache).
 *                          Results are logged via DbgPrint and returned
 *                          to the caller.
 */

NTSTATUS KmScanForensicArtifacts(
	IN  PCWSTR          ExecutableName,
	IN  ULONG           ArtifactTypes,
	OUT PARTIFACT_ENTRY Entries,
	IN  ULONG           MaxEntries,
	OUT PULONG          FoundCount
);
