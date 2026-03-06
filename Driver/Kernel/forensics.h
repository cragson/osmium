#pragma once

#include <ntifs.h>
#include "../Shared/ioctl.h"

/*
 * Forensic artifact scanner.
 *
 * KmScanForensicArtifacts: Scans for execution traces left by a given
 *                          executable across 15 forensic sources:
 *                            Prefetch, ShimCache, BAM, AmCache,
 *                            UserAssist, MUICache, RecentApps, RunMRU,
 *                            SRUM, Timeline/ActivitiesCache, Jump Lists,
 *                            RecentDocs, Event Logs, WER, Superfetch.
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
