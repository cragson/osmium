#include "process.h"
#include "ntstructs.h"

/*
 * KmGetProcessBaseAddress
 *
 * Uses the documented PsGetProcessSectionBaseAddress to retrieve the
 * main image base of a process. No PEB walking required.
 */
NTSTATUS KmGetProcessBaseAddress(
	IN  HANDLE   ProcessId,
	OUT PULONG64 BaseAddress
)
{
	PEPROCESS Process = NULL;
	NTSTATUS  Status;
	PVOID     Base;

	if ( !BaseAddress )
		return STATUS_INVALID_PARAMETER;

	*BaseAddress = 0;

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	Base = PsGetProcessSectionBaseAddress( Process );

	*BaseAddress = (ULONG64)(ULONG_PTR)Base;

	ObDereferenceObject( Process );

	return Base ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/*
 * KmGetModuleBaseByName64
 *
 * Internal: walks the 64-bit PEB→Ldr→InMemoryOrderModuleList.
 * Must be called while attached to the target process context.
 */
static NTSTATUS KmGetModuleBaseByName64(
	IN  PEPROCESS Process,
	IN  PCWSTR    ModuleName,
	OUT PULONG64  BaseAddress,
	OUT PULONG64  ModuleSize
)
{
	PPEB               Peb;
	KM_PEB             PebData;
	KM_PEB_LDR_DATA   LdrData;
	PLIST_ENTRY        Head;
	PLIST_ENTRY        Current;
	KAPC_STATE         ApcState;
	NTSTATUS           Status = STATUS_NOT_FOUND;

	Peb = PsGetProcessPeb( Process );
	if ( !Peb )
		return STATUS_NOT_FOUND;

	KeStackAttachProcess( Process, &ApcState );

	__try
	{
		/* Read PEB */
		RtlCopyMemory( &PebData, Peb, sizeof( KM_PEB ) );

		if ( !PebData.Ldr )
		{
			Status = STATUS_NOT_FOUND;
			__leave;
		}

		/* Read LDR_DATA */
		RtlCopyMemory( &LdrData, PebData.Ldr, sizeof( KM_PEB_LDR_DATA ) );

		Head = &PebData.Ldr->InMemoryOrderModuleList;
		Current = LdrData.InMemoryOrderModuleList.Flink;

		while ( Current != Head )
		{
			KM_LDR_DATA_TABLE_ENTRY Entry;
			PVOID EntryAddress;

			/* InMemoryOrderLinks is the second LIST_ENTRY in the structure */
			EntryAddress = CONTAINING_RECORD( Current, KM_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );

			RtlCopyMemory( &Entry, EntryAddress, sizeof( KM_LDR_DATA_TABLE_ENTRY ) );

			if ( Entry.BaseDllName.Buffer && Entry.BaseDllName.Length > 0 )
			{
				WCHAR NameBuffer[260];
				USHORT CopyLen = Entry.BaseDllName.Length;
				if ( CopyLen > sizeof( NameBuffer ) - sizeof( WCHAR ) )
					CopyLen = sizeof( NameBuffer ) - sizeof( WCHAR );

				RtlZeroMemory( NameBuffer, sizeof( NameBuffer ) );
				RtlCopyMemory( NameBuffer, Entry.BaseDllName.Buffer, CopyLen );

				if ( _wcsicmp( NameBuffer, ModuleName ) == 0 )
				{
					*BaseAddress = (ULONG64)(ULONG_PTR)Entry.DllBase;
					*ModuleSize  = (ULONG64)Entry.SizeOfImage;
					Status = STATUS_SUCCESS;
					__leave;
				}
			}

			Current = Entry.InMemoryOrderLinks.Flink;
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		Status = GetExceptionCode();
	}

	KeUnstackDetachProcess( &ApcState );

	return Status;
}

/*
 * KmGetModuleBaseByName32
 *
 * Internal: walks the 32-bit (WoW64) PEB→Ldr→InMemoryOrderModuleList.
 * Must be called while NOT already attached (will attach internally).
 */
static NTSTATUS KmGetModuleBaseByName32(
	IN  PEPROCESS Process,
	IN  PCWSTR    ModuleName,
	OUT PULONG64  BaseAddress,
	OUT PULONG64  ModuleSize
)
{
	PVOID              Wow64Peb;
	KM_PEB32           PebData32;
	KM_PEB_LDR_DATA32 LdrData32;
	ULONG              Head32;
	ULONG              Current32;
	KAPC_STATE         ApcState;
	NTSTATUS           Status = STATUS_NOT_FOUND;

	Wow64Peb = PsGetProcessWow64Process( Process );
	if ( !Wow64Peb )
		return STATUS_NOT_FOUND;

	KeStackAttachProcess( Process, &ApcState );

	__try
	{
		RtlCopyMemory( &PebData32, Wow64Peb, sizeof( KM_PEB32 ) );

		if ( !PebData32.Ldr )
		{
			Status = STATUS_NOT_FOUND;
			__leave;
		}

		RtlCopyMemory( &LdrData32, (PVOID)(ULONG_PTR)PebData32.Ldr, sizeof( KM_PEB_LDR_DATA32 ) );

		/* Head is the address of InMemoryOrderModuleList inside the LDR_DATA in the target */
		Head32 = PebData32.Ldr + FIELD_OFFSET( KM_PEB_LDR_DATA32, InMemoryOrderModuleList );
		Current32 = LdrData32.InMemoryOrderModuleList.Flink;

		while ( Current32 != Head32 && Current32 != 0 )
		{
			KM_LDR_DATA_TABLE_ENTRY32 Entry32;
			ULONG EntryAddress32;
			WCHAR NameBuffer[260];

			/* InMemoryOrderLinks is the second LIST_ENTRY32 in the structure */
			EntryAddress32 = Current32 - FIELD_OFFSET( KM_LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks );

			RtlCopyMemory( &Entry32, (PVOID)(ULONG_PTR)EntryAddress32, sizeof( KM_LDR_DATA_TABLE_ENTRY32 ) );

			if ( Entry32.BaseDllName.Buffer && Entry32.BaseDllName.Length > 0 )
			{
				USHORT CopyLen = Entry32.BaseDllName.Length;
				if ( CopyLen > sizeof( NameBuffer ) - sizeof( WCHAR ) )
					CopyLen = sizeof( NameBuffer ) - sizeof( WCHAR );

				RtlZeroMemory( NameBuffer, sizeof( NameBuffer ) );
				RtlCopyMemory( NameBuffer, (PVOID)(ULONG_PTR)Entry32.BaseDllName.Buffer, CopyLen );

				if ( _wcsicmp( NameBuffer, ModuleName ) == 0 )
				{
					*BaseAddress = (ULONG64)Entry32.DllBase;
					*ModuleSize  = (ULONG64)Entry32.SizeOfImage;
					Status = STATUS_SUCCESS;
					__leave;
				}
			}

			/* Advance: read the Flink from the current InMemoryOrderLinks */
			{
				LIST_ENTRY32 Links32;
				RtlCopyMemory( &Links32, (PVOID)(ULONG_PTR)Current32, sizeof( LIST_ENTRY32 ) );
				Current32 = Links32.Flink;
			}
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		Status = GetExceptionCode();
	}

	KeUnstackDetachProcess( &ApcState );

	return Status;
}

/*
 * KmGetModuleBaseByName
 *
 * Public entry point. Resolves the process, checks if WoW64, then
 * delegates to the appropriate 32-bit or 64-bit walker.
 */
NTSTATUS KmGetModuleBaseByName(
	IN  HANDLE   ProcessId,
	IN  PCWSTR   ModuleName,
	OUT PULONG64 BaseAddress,
	OUT PULONG64 ModuleSize
)
{
	PEPROCESS Process = NULL;
	NTSTATUS  Status;

	if ( !ModuleName || !BaseAddress || !ModuleSize )
		return STATUS_INVALID_PARAMETER;

	*BaseAddress = 0;
	*ModuleSize  = 0;

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	/* Check for WoW64 (32-bit process on 64-bit OS) first */
	if ( PsGetProcessWow64Process( Process ) != NULL )
	{
		Status = KmGetModuleBaseByName32( Process, ModuleName, BaseAddress, ModuleSize );
	}
	else
	{
		Status = KmGetModuleBaseByName64( Process, ModuleName, BaseAddress, ModuleSize );
	}

	ObDereferenceObject( Process );

	return Status;
}
