#include "memory.h"
#include "ntstructs.h"

/* Generic pool tags */
#define POOL_TAG_READ  'RdmK'
#define POOL_TAG_WRITE 'WrmK'

/*
 * KmReadProcessMemory
 *
 * Reads from the target process using a kernel intermediate buffer.
 * 1. Allocate NonPagedPool buffer (valid in any address space context).
 * 2. Attach to target, copy from source into kernel buffer, detach.
 * 3. Copy from kernel buffer into the caller's destination buffer.
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
	PVOID      KernelBuffer;

	if ( !TargetProcess || !SourceAddress || !DestinationBuffer || Size == 0 )
		return STATUS_INVALID_PARAMETER;

	if ( BytesCopied )
		*BytesCopied = 0;

	KernelBuffer = ExAllocatePoolWithTag( NonPagedPool, Size, POOL_TAG_READ );
	if ( !KernelBuffer )
		return STATUS_INSUFFICIENT_RESOURCES;

	/* Step 1: attach to target, read into kernel buffer */
	KeStackAttachProcess( TargetProcess, &ApcState );

	__try
	{
		ProbeForRead( SourceAddress, Size, 1 );
		RtlCopyMemory( KernelBuffer, SourceAddress, Size );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		Status = GetExceptionCode();
	}

	KeUnstackDetachProcess( &ApcState );

	/* Step 2: back in caller context — copy kernel buffer to user buffer */
	if ( NT_SUCCESS( Status ) )
	{
		__try
		{
			RtlCopyMemory( DestinationBuffer, KernelBuffer, Size );

			if ( BytesCopied )
				*BytesCopied = Size;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER )
		{
			Status = GetExceptionCode();
		}
	}

	ExFreePoolWithTag( KernelBuffer, POOL_TAG_READ );

	return Status;
}

/*
 * KmWriteProcessMemoryDirect
 *
 * Internal: tries a direct RtlCopyMemory write while attached.
 * SourceBuffer must be a kernel address (valid in any context).
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
 * SourceBuffer must be a kernel address (valid in any context).
 * Must be called while attached to the target process.
 */
static NTSTATUS KmWriteProcessMemoryMdl(
	IN  PVOID  TargetAddress,
	IN  PVOID  SourceBuffer,
	IN  SIZE_T Size
)
{
	PMDL     Mdl = NULL;
	PVOID    Mapped = NULL;
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

	/* Both Mapped and SourceBuffer are kernel addresses — always valid */
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
 * Writes to target process memory using a kernel intermediate buffer.
 * 1. Copy caller's source data into a kernel buffer (caller context).
 * 2. Attach to target, write from kernel buffer (valid in any context).
 * 3. Direct write first, MDL fallback for read-only pages.
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
	PVOID      KernelBuffer;

	if ( !TargetProcess || !TargetAddress || !SourceBuffer || Size == 0 )
		return STATUS_INVALID_PARAMETER;

	if ( BytesCopied )
		*BytesCopied = 0;

	KernelBuffer = ExAllocatePoolWithTag( NonPagedPool, Size, POOL_TAG_WRITE );
	if ( !KernelBuffer )
		return STATUS_INSUFFICIENT_RESOURCES;

	/* Step 1: copy source data from caller into kernel buffer */
	__try
	{
		RtlCopyMemory( KernelBuffer, SourceBuffer, Size );
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		ExFreePoolWithTag( KernelBuffer, POOL_TAG_WRITE );
		return GetExceptionCode();
	}

	/* Step 2: attach to target, write from kernel buffer */
	KeStackAttachProcess( TargetProcess, &ApcState );

	/* Try direct write first */
	Status = KmWriteProcessMemoryDirect( TargetAddress, KernelBuffer, Size );

	if ( !NT_SUCCESS( Status ) )
	{
		/* Fall back to MDL-based write for protected pages */
		Status = KmWriteProcessMemoryMdl( TargetAddress, KernelBuffer, Size );
	}

	KeUnstackDetachProcess( &ApcState );

	ExFreePoolWithTag( KernelBuffer, POOL_TAG_WRITE );

	if ( NT_SUCCESS( Status ) && BytesCopied )
		*BytesCopied = Size;

	return Status;
}
