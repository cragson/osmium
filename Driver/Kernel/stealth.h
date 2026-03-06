#pragma once

#include <ntifs.h>
#include "../Shared/ioctl.h"

/*
 * Stealth routines for hiding usermode components from detection.
 *
 * KmHideProcessThreads:      Unlinks all threads from the process's ThreadListHead.
 * KmEnumerateNotifyCallbacks: Enumerates registered Ps/image notify callbacks.
 * KmRemoveNotifyCallback:     Removes a single callback by type and array index.
 * KmStripProcessHandles:      Closes handles to a process held by other processes.
 */

NTSTATUS KmHideProcessThreads(
	IN  HANDLE  ProcessId,
	OUT PULONG  ThreadsHidden
);

NTSTATUS KmEnumerateNotifyCallbacks(
	IN  ULONG           CallbackType,
	OUT PCALLBACK_ENTRY  Entries,
	IN  ULONG           MaxEntries,
	OUT PULONG           ReturnedEntries
);

NTSTATUS KmRemoveNotifyCallback(
	IN ULONG CallbackType,
	IN ULONG Index
);

NTSTATUS KmStripProcessHandles(
	IN  HANDLE ProcessId,
	OUT PULONG HandlesStripped
);
