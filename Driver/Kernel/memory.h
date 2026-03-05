#pragma once

#include <ntifs.h>

/*
 * Kernel-mode memory read/write operations.
 *
 * KmReadProcessMemory:  Cross-process read via MmCopyVirtualMemory.
 * KmWriteProcessMemory: Cross-process write via MmCopyVirtualMemory, MDL fallback for read-only pages.
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
