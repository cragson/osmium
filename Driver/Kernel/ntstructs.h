#pragma once

#include <ntifs.h>

/* -----------------------------------------------------------------------
 * Forward declaration: MmCopyVirtualMemory
 * Exported by ntoskrnl.exe but not declared in the WDK headers.
 * ----------------------------------------------------------------------- */
NTSTATUS NTAPI MmCopyVirtualMemory(
	IN PEPROCESS       SourceProcess,
	IN PVOID           SourceAddress,
	IN PEPROCESS       TargetProcess,
	OUT PVOID          TargetAddress,
	IN SIZE_T          BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T        ReturnSize
);

/* -----------------------------------------------------------------------
 * PEB / LDR structures for module enumeration
 *
 * We define our own because the WDK does not expose full PEB internals.
 * These must match the OS layout — validated against Windows 10/11 x64.
 * ----------------------------------------------------------------------- */

/* 64-bit UNICODE_STRING (native) */
typedef struct _KM_UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
} KM_UNICODE_STRING, *PKM_UNICODE_STRING;

/* 32-bit UNICODE_STRING (WoW64) */
typedef struct _KM_UNICODE_STRING32
{
	USHORT   Length;
	USHORT   MaximumLength;
	ULONG    Buffer;         /* 32-bit pointer */
} KM_UNICODE_STRING32, *PKM_UNICODE_STRING32;

/* -----------------------------------------------------------------------
 * 64-bit PEB structures
 * ----------------------------------------------------------------------- */
typedef struct _KM_PEB_LDR_DATA
{
	ULONG      Length;
	BOOLEAN    Initialized;
	PVOID      SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} KM_PEB_LDR_DATA, *PKM_PEB_LDR_DATA;

typedef struct _KM_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY         InLoadOrderLinks;
	LIST_ENTRY         InMemoryOrderLinks;
	LIST_ENTRY         InInitializationOrderLinks;
	PVOID              DllBase;
	PVOID              EntryPoint;
	ULONG              SizeOfImage;
	KM_UNICODE_STRING  FullDllName;
	KM_UNICODE_STRING  BaseDllName;
} KM_LDR_DATA_TABLE_ENTRY, *PKM_LDR_DATA_TABLE_ENTRY;

typedef struct _KM_PEB
{
	UCHAR               InheritedAddressSpace;
	UCHAR               ReadImageFileExecOptions;
	UCHAR               BeingDebugged;
	UCHAR               BitField;
	UCHAR               Padding0[4];
	PVOID               Mutant;
	PVOID               ImageBaseAddress;
	PKM_PEB_LDR_DATA    Ldr;
	/* We only need up to Ldr for module enumeration */
} KM_PEB, *PKM_PEB;

/* -----------------------------------------------------------------------
 * 32-bit (WoW64) PEB structures
 * ----------------------------------------------------------------------- */
typedef struct _KM_PEB_LDR_DATA32
{
	ULONG          Length;
	UCHAR          Initialized;
	ULONG          SsHandle;
	LIST_ENTRY32   InLoadOrderModuleList;
	LIST_ENTRY32   InMemoryOrderModuleList;
	LIST_ENTRY32   InInitializationOrderModuleList;
} KM_PEB_LDR_DATA32, *PKM_PEB_LDR_DATA32;

typedef struct _KM_LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32         InLoadOrderLinks;
	LIST_ENTRY32         InMemoryOrderLinks;
	LIST_ENTRY32         InInitializationOrderLinks;
	ULONG                DllBase;
	ULONG                EntryPoint;
	ULONG                SizeOfImage;
	KM_UNICODE_STRING32  FullDllName;
	KM_UNICODE_STRING32  BaseDllName;
} KM_LDR_DATA_TABLE_ENTRY32, *PKM_LDR_DATA_TABLE_ENTRY32;

typedef struct _KM_PEB32
{
	UCHAR                InheritedAddressSpace;
	UCHAR                ReadImageFileExecOptions;
	UCHAR                BeingDebugged;
	UCHAR                BitField;
	ULONG                Mutant;
	ULONG                ImageBaseAddress;
	ULONG                Ldr;            /* pointer to PEB_LDR_DATA32 */
} KM_PEB32, *PKM_PEB32;

/* -----------------------------------------------------------------------
 * Undocumented but exported Ps routines
 * ----------------------------------------------------------------------- */
NTKERNELAPI PVOID    NTAPI PsGetProcessSectionBaseAddress(IN PEPROCESS Process);
NTKERNELAPI PPEB     NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI PVOID    NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);
