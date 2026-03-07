#pragma once

#include <ntifs.h>

/*
 * Process tamper routines.
 *
 * KmSpoofParentPid:       Writes a new parent PID to EPROCESS.InheritedFromUniqueProcessId.
 * KmBypassPPL:            Zeros the PS_PROTECTION byte in EPROCESS.
 * KmToggleTokenPrivilege:  Enables or disables a specific privilege in the process token.
 * KmInitializeTamperOffsets: Resolves dynamic EPROCESS/TOKEN offsets at driver load time.
 */

NTSTATUS KmInitializeTamperOffsets( VOID );

NTSTATUS KmSpoofParentPid(
	IN  HANDLE  ProcessId,
	IN  ULONG64 NewParentPid,
	OUT PULONG64 PreviousParentPid
);

NTSTATUS KmBypassPPL(
	IN  HANDLE  ProcessId,
	OUT PULONG64 PreviousProtection
);

NTSTATUS KmToggleTokenPrivilege(
	IN  HANDLE  ProcessId,
	IN  ULONG64 PrivilegeLuid,
	IN  BOOLEAN Enable,
	OUT PULONG64 PreviousState
);
