#include "memory.h"
#include "ntstructs.h"

/*
 * KmReadProcessMemory
 *
 * Uses MmCopyVirtualMemory to copy from the target process address space
 * into the calling process's buffer. No KeStackAttachProcess needed —
 * MmCopyVirtualMemory handles cross-process copies internally.
 */
NTSTATUS KmReadProcessMemory(
	IN  PEPROCESS TargetProcess,
	IN  PVOID     SourceAddress,
	OUT PVOID     DestinationBuffer,
	IN  SIZE_T    Size,
	OUT PSIZE_T   BytesCopied
)
{
	if ( !TargetProcess || !SourceAddress || !DestinationBuffer || Size == 0 )
		return STATUS_INVALID_PARAMETER;

	if ( BytesCopied )
		*BytesCopied = 0;

	return MmCopyVirtualMemory(
		TargetProcess,
		SourceAddress,
		PsGetCurrentProcess(),
		DestinationBuffer,
		Size,
		KernelMode,
		BytesCopied
	);
}

/*
 * KmWriteProcessMemoryMdl
 *
 * Internal: MDL-based write for read-only pages in the target process.
 * Attaches to the target to lock and map the pages into system space,
 * then detaches before copying so the caller's source buffer is valid.
 */
static NTSTATUS KmWriteProcessMemoryMdl(
	IN  PEPROCESS TargetProcess,
	IN  PVOID     TargetAddress,
	IN  PVOID     SourceBuffer,
	IN  SIZE_T    Size
)
{
	PMDL       Mdl = NULL;
	PVOID      Mapped = NULL;
	KAPC_STATE ApcState;
	NTSTATUS   Status = STATUS_SUCCESS;

	/* Attach to target so MDL operations resolve the correct physical pages */
	KeStackAttachProcess( TargetProcess, &ApcState );

	Mdl = IoAllocateMdl( TargetAddress, (ULONG)Size, FALSE, FALSE, NULL );
	if ( !Mdl )
	{
		KeUnstackDetachProcess( &ApcState );
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	__try
	{
		MmProbeAndLockPages( Mdl, KernelMode, IoReadAccess );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		IoFreeMdl( Mdl );
		KeUnstackDetachProcess( &ApcState );
		return GetExceptionCode();
	}

	Mapped = MmMapLockedPagesSpecifyCache(
		Mdl,
		KernelMode,
		MmNonCached,
		NULL,
		FALSE,
		NormalPagePriority
	);

	if ( !Mapped )
	{
		MmUnlockPages( Mdl );
		IoFreeMdl( Mdl );
		KeUnstackDetachProcess( &ApcState );
		return STATUS_NONE_MAPPED;
	}

	/* Re-protect the mapped region as read-write */
	Status = MmProtectMdlSystemAddress( Mdl, PAGE_READWRITE );
	if ( !NT_SUCCESS( Status ) )
	{
		MmUnmapLockedPages( Mapped, Mdl );
		MmUnlockPages( Mdl );
		IoFreeMdl( Mdl );
		KeUnstackDetachProcess( &ApcState );
		return Status;
	}

	/*
	 * Detach from target — the MDL mapping is in system address space
	 * and remains valid in any process context. This makes SourceBuffer
	 * (a user-mode address in the calling process) accessible again.
	 */
	KeUnstackDetachProcess( &ApcState );

	__try
	{
		RtlCopyMemory( Mapped, SourceBuffer, Size );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		Status = GetExceptionCode();
	}

	MmUnmapLockedPages( Mapped, Mdl );
	MmUnlockPages( Mdl );
	IoFreeMdl( Mdl );

	return Status;
}

/*
 * KmWriteProcessMemory
 *
 * Writes to target process memory. Tries MmCopyVirtualMemory first (fast path).
 * If that fails (e.g. read-only page), falls back to MDL-based mapping.
 */
NTSTATUS KmWriteProcessMemory(
	IN  PEPROCESS TargetProcess,
	IN  PVOID     TargetAddress,
	IN  PVOID     SourceBuffer,
	IN  SIZE_T    Size,
	OUT PSIZE_T   BytesCopied
)
{
	NTSTATUS Status;

	if ( !TargetProcess || !TargetAddress || !SourceBuffer || Size == 0 )
		return STATUS_INVALID_PARAMETER;

	if ( BytesCopied )
		*BytesCopied = 0;

	/* Fast path: MmCopyVirtualMemory */
	Status = MmCopyVirtualMemory(
		PsGetCurrentProcess(),
		SourceBuffer,
		TargetProcess,
		TargetAddress,
		Size,
		KernelMode,
		BytesCopied
	);

	if ( NT_SUCCESS( Status ) )
		return Status;

	/* Slow path: MDL-based write for protected pages */
	Status = KmWriteProcessMemoryMdl( TargetProcess, TargetAddress, SourceBuffer, Size );

	if ( NT_SUCCESS( Status ) && BytesCopied )
		*BytesCopied = Size;

	return Status;
}
