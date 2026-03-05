#pragma once

#include <ntifs.h>

/*
 * Kernel-mode memory read/write operations.
 *
 * KmReadProcessMemory:  Attach to target, copy bytes out via RtlCopyMemory (SEH-protected).
 * KmWriteProcessMemory: Attach to target, copy bytes in. Falls back to MDL mapping for read-only pages.
 */

NTSTATUS KmReadProcessMemory(
	IN  PEPROCESS TargetProcess,
	IN  PVOID     SourceAddress,
	OUT PVOID     DestinationBuffer,
	IN  SIZE_T    Size,
	OUT PSIZE_T   BytesCopied
);

NTSTATUS KmWriteProcessMemory(
	IN  PEPROCESS TargetProcess,
	IN  PVOID     TargetAddress,
	IN  PVOID     SourceBuffer,
	IN  SIZE_T    Size,
	OUT PSIZE_T   BytesCopied
);
