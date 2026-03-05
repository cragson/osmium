#pragma once

#include <ntddk.h>

/*
 * Kernel-mode process information helpers.
 *
 * KmGetProcessBaseAddress: Returns the image base of the main executable.
 * KmGetModuleBaseByName:   Walks PEB→Ldr→InMemoryOrderModuleList for a named module.
 */

NTSTATUS KmGetProcessBaseAddress(
	IN  HANDLE   ProcessId,
	OUT PULONG64 BaseAddress
);

NTSTATUS KmGetModuleBaseByName(
	IN  HANDLE   ProcessId,
	IN  PCWSTR   ModuleName,
	OUT PULONG64 BaseAddress,
	OUT PULONG64 ModuleSize
);
