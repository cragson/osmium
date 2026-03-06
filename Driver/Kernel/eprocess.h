#pragma once

#include <ntifs.h>

/*
 * EPROCESS manipulation routines.
 *
 * KmInitializeEprocessOffsets: Dynamically resolves EPROCESS field offsets at load time.
 * KmHideProcess:              Unlinks a process from ActiveProcessLinks (DKOM).
 * KmElevateProcessToken:      Copies the SYSTEM token to a target process.
 */

NTSTATUS KmInitializeEprocessOffsets( VOID );

NTSTATUS KmHideProcess(
	IN HANDLE ProcessId
);

NTSTATUS KmElevateProcessToken(
	IN HANDLE ProcessId
);
