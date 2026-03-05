#include "memory.h"
#include "ntstructs.h"

/* Generic pool tag — avoids obvious strings */
#define POOL_TAG_MDL 'lDmN'

/*
 * KmReadProcessMemory
 *
 * Attaches to the target process context, copies memory out via RtlCopyMemory.
 * All accesses are SEH-protected to handle invalid/paged-out addresses gracefully.
 */
NTSTATUS KmReadProcessMemory(
	IN  PEPROCESS TargetProcess,
	IN  PVOID     SourceAddress,
	OUT PVOID     DestinationBuffer,
	IN  SIZE_T    Size,
	OUT PSIZE_T   BytesCopied
)
{
	KAPC_STATE ApcState;
	NTSTATUS   Status = STATUS_SUCCESS;

	if ( !TargetProcess || !SourceAddress || !DestinationBuffer || Size == 0 )
		return STATUS_INVALID_PARAMETER;

	if ( BytesCopied )
		*BytesCopied = 0;

	KeStackAttachProcess( TargetProcess, &ApcState );

	__try
	{
		ProbeForRead( SourceAddress, Size, 1 );
		RtlCopyMemory( DestinationBuffer, SourceAddress, Size );

		if ( BytesCopied )
			*BytesCopied = Size;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		Status = GetExceptionCode();
	}

	KeUnstackDetachProcess( &ApcState );

	return Status;
}

/*
 * KmWriteProcessMemoryDirect
 *
 * Internal: tries a direct RtlCopyMemory write while attached.
 * Returns STATUS_SUCCESS or an exception code.
 */
static NTSTATUS KmWriteProcessMemoryDirect(
	IN  PVOID  TargetAddress,
	IN  PVOID  SourceBuffer,
	IN  SIZE_T Size
)
{
	NTSTATUS Status = STATUS_SUCCESS;

	__try
	{
		ProbeForWrite( TargetAddress, Size, 1 );
		RtlCopyMemory( TargetAddress, SourceBuffer, Size );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		Status = GetExceptionCode();
	}

	return Status;
}

/*
 * KmWriteProcessMemoryMdl
 *
 * Internal: MDL-based write for read-only pages.
 * Allocates an MDL, locks the pages, maps them as read-write in system space, then copies.
 */
static NTSTATUS KmWriteProcessMemoryMdl(
	IN  PVOID  TargetAddress,
	IN  PVOID  SourceBuffer,
	IN  SIZE_T Size
)
{
	PMDL   Mdl = NULL;
	PVOID  Mapped = NULL;
	NTSTATUS Status = STATUS_SUCCESS;

	Mdl = IoAllocateMdl( TargetAddress, (ULONG)Size, FALSE, FALSE, NULL );
	if ( !Mdl )
		return STATUS_INSUFFICIENT_RESOURCES;

	__try
	{
		MmProbeAndLockPages( Mdl, KernelMode, IoReadAccess );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		IoFreeMdl( Mdl );
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
		return STATUS_NONE_MAPPED;
	}

	/* Re-protect the mapped region as read-write */
	Status = MmProtectMdlSystemAddress( Mdl, PAGE_READWRITE );
	if ( !NT_SUCCESS( Status ) )
	{
		MmUnmapLockedPages( Mapped, Mdl );
		MmUnlockPages( Mdl );
		IoFreeMdl( Mdl );
		return Status;
	}

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
 * Attaches to target, attempts direct write first.
 * If that fails (read-only page), falls back to MDL-based mapping.
 */
NTSTATUS KmWriteProcessMemory(
	IN  PEPROCESS TargetProcess,
	IN  PVOID     TargetAddress,
	IN  PVOID     SourceBuffer,
	IN  SIZE_T    Size,
	OUT PSIZE_T   BytesCopied
)
{
	KAPC_STATE ApcState;
	NTSTATUS   Status;

	if ( !TargetProcess || !TargetAddress || !SourceBuffer || Size == 0 )
		return STATUS_INVALID_PARAMETER;

	if ( BytesCopied )
		*BytesCopied = 0;

	KeStackAttachProcess( TargetProcess, &ApcState );

	/* Try direct write first */
	Status = KmWriteProcessMemoryDirect( TargetAddress, SourceBuffer, Size );

	if ( !NT_SUCCESS( Status ) )
	{
		/* Fall back to MDL-based write for protected pages */
		Status = KmWriteProcessMemoryMdl( TargetAddress, SourceBuffer, Size );
	}

	KeUnstackDetachProcess( &ApcState );

	if ( NT_SUCCESS( Status ) && BytesCopied )
		*BytesCopied = Size;

	return Status;
}
