#pragma once

#include <ntifs.h>

/*
 * Code injection routines.
 *
 * KmHijackCallbackTable:  Overwrites a PEB.KernelCallbackTable entry.
 * KmQueueKernelApc:       Queues a user-mode APC to a target thread.
 * KmInjectDll:            Allocates memory + writes DLL path + queues APC to LdrLoadDll.
 */

NTSTATUS KmHijackCallbackTable(
	IN  HANDLE  ProcessId,
	IN  ULONG   TableIndex,
	IN  ULONG64 NewFunction,
	OUT PULONG64 PreviousFunction
);

NTSTATUS KmQueueKernelApc(
	IN HANDLE  ProcessId,
	IN ULONG64 ThreadId,
	IN ULONG64 ApcRoutine,
	IN ULONG64 ApcArgument
);

NTSTATUS KmInjectDll(
	IN  HANDLE  ProcessId,
	IN  PCWSTR  DllPath,
	OUT PULONG64 AllocatedAddress
);
