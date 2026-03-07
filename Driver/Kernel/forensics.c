#include "forensics.h"
#include <ntddk.h>
#include <ntstrsafe.h>

#if DBG
#define FLOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
	"[ndis6] " fmt "\n", __VA_ARGS__)
#else
#define FLOG(fmt, ...) ((void)0)
#endif

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

/*
 * WidePrefixMatch — case-insensitive prefix comparison for wide chars.
 * StringChars / PrefixChars are character counts, NOT byte counts.
 */
static BOOLEAN WidePrefixMatch(
	IN PCWSTR String,
	IN ULONG  StringChars,
	IN PCWSTR Prefix,
	IN ULONG  PrefixChars
)
{
	ULONG j;

	if ( PrefixChars > StringChars )
		return FALSE;

	for ( j = 0; j < PrefixChars; j++ )
	{
		WCHAR s = String[j];
		WCHAR p = Prefix[j];

		if ( s >= L'A' && s <= L'Z' ) s += 0x20;
		if ( p >= L'A' && p <= L'Z' ) p += 0x20;

		if ( s != p )
			return FALSE;
	}

	return TRUE;
}

/*
 * WideSubstringMatch — case-insensitive substring search.
 */
static BOOLEAN WideSubstringMatch(
	IN PCWSTR Haystack,
	IN ULONG  HaystackChars,
	IN PCWSTR Needle,
	IN ULONG  NeedleChars
)
{
	ULONG i;

	if ( NeedleChars == 0 || NeedleChars > HaystackChars )
		return FALSE;

	for ( i = 0; i <= HaystackChars - NeedleChars; i++ )
	{
		if ( WidePrefixMatch( &Haystack[i], HaystackChars - i,
			Needle, NeedleChars ) )
			return TRUE;
	}

	return FALSE;
}

/*
 * Rot13DecodeWide — Decode ROT13 on ASCII letters in a wide string (in-place).
 * UserAssist encodes registry value names with ROT13.
 */
static VOID Rot13DecodeWide(
	IN OUT PWSTR String,
	IN     ULONG Chars
)
{
	ULONG i;

	for ( i = 0; i < Chars; i++ )
	{
		WCHAR c = String[i];

		if ( c >= L'A' && c <= L'Z' )
			String[i] = ( WCHAR )( ( ( c - L'A' + 13 ) % 26 ) + L'A' );
		else if ( c >= L'a' && c <= L'z' )
			String[i] = ( WCHAR )( ( ( c - L'a' + 13 ) % 26 ) + L'a' );
	}
}

/*
 * ScanFileForName — Generic binary file scanner.
 * Opens a file, reads in 64KB chunks (with 512-byte overlap for boundary
 * matches), and uses WideSubstringMatch on each chunk.  Returns TRUE if
 * the executable name was found anywhere in the file.
 */
static BOOLEAN ScanFileForName(
	IN PCWSTR FilePath,
	IN PCWSTR ExecutableName,
	IN ULONG  NameLen
)
{
	UNICODE_STRING     Path;
	OBJECT_ATTRIBUTES  ObjAttr;
	HANDLE             FileHandle = NULL;
	IO_STATUS_BLOCK    IoStatus;
	NTSTATUS           Status;
	PVOID              Buffer = NULL;
	BOOLEAN            Found  = FALSE;
	LARGE_INTEGER      Offset;
	ULONG              BytesRead;

	#define SCAN_CHUNK_SIZE    (64 * 1024)
	#define SCAN_OVERLAP       512

	RtlInitUnicodeString( &Path, FilePath );
	InitializeObjectAttributes( &ObjAttr, &Path,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwCreateFile(
		&FileHandle,
		FILE_READ_DATA | SYNCHRONIZE,
		&ObjAttr,
		&IoStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL, 0
	);

	if ( !NT_SUCCESS( Status ) )
		return FALSE;

	Buffer = ExAllocatePool2( POOL_FLAG_PAGED, SCAN_CHUNK_SIZE, 'NdBf' );
	if ( !Buffer )
	{
		ZwClose( FileHandle );
		return FALSE;
	}

	Offset.QuadPart = 0;

	while ( !Found )
	{
		Status = ZwReadFile(
			FileHandle, NULL, NULL, NULL,
			&IoStatus,
			Buffer, SCAN_CHUNK_SIZE,
			&Offset, NULL
		);

		if ( !NT_SUCCESS( Status ) )
			break;

		BytesRead = (ULONG)IoStatus.Information;
		if ( BytesRead < NameLen * sizeof( WCHAR ) )
			break;

		if ( WideSubstringMatch(
			(PCWSTR)Buffer,
			BytesRead / sizeof( WCHAR ),
			ExecutableName, NameLen ) )
		{
			Found = TRUE;
		}

		if ( BytesRead < SCAN_CHUNK_SIZE )
			break;

		/* Overlap to catch matches spanning chunk boundaries */
		Offset.QuadPart += SCAN_CHUNK_SIZE - SCAN_OVERLAP;
	}

	ExFreePoolWithTag( Buffer, 'NdBf' );
	ZwClose( FileHandle );

	return Found;

	#undef SCAN_CHUNK_SIZE
	#undef SCAN_OVERLAP
}

/*
 * ForEachUserSid callback signature.
 */
typedef VOID ( *PFN_USER_SID_CALLBACK )(
	IN PCWSTR           SidString,
	IN ULONG            SidChars,
	IN PVOID            Context
);

/*
 * ForEachUserSid — Enumerates subkeys of \Registry\User, calling the
 * callback for each real user SID (skips well-known service SIDs,
 * .DEFAULT, and *_Classes shadow keys).
 */
static VOID ForEachUserSid(
	IN PFN_USER_SID_CALLBACK Callback,
	IN PVOID                 Context
)
{
	UNICODE_STRING    KeyPath;
	OBJECT_ATTRIBUTES ObjAttr;
	HANDLE            HkuHandle = NULL;
	NTSTATUS          Status;
	ULONG             Index;
	PVOID             Buffer;
	ULONG             ResultLength;

	RtlInitUnicodeString( &KeyPath, L"\\Registry\\User" );
	InitializeObjectAttributes( &ObjAttr, &KeyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwOpenKey( &HkuHandle, KEY_READ, &ObjAttr );
	if ( !NT_SUCCESS( Status ) )
		return;

	Buffer = ExAllocatePool2( POOL_FLAG_PAGED, 1024, 'NdBf' );
	if ( !Buffer )
	{
		ZwClose( HkuHandle );
		return;
	}

	for ( Index = 0; ; Index++ )
	{
		PKEY_BASIC_INFORMATION KeyInfo;
		WCHAR                  SidBuf[128];
		ULONG                  Chars;

		Status = ZwEnumerateKey( HkuHandle, Index, KeyBasicInformation,
			Buffer, 1024, &ResultLength );
		if ( !NT_SUCCESS( Status ) )
			break;

		KeyInfo = (PKEY_BASIC_INFORMATION)Buffer;
		Chars   = KeyInfo->NameLength / sizeof( WCHAR );

		if ( Chars >= 128 )
			continue;

		RtlCopyMemory( SidBuf, KeyInfo->Name, Chars * sizeof( WCHAR ) );
		SidBuf[Chars] = L'\0';

		/* Skip well-known SIDs and shadow keys */
		if ( _wcsicmp( SidBuf, L".DEFAULT" ) == 0 )
			continue;
		if ( _wcsicmp( SidBuf, L"S-1-5-18" ) == 0 )
			continue;
		if ( _wcsicmp( SidBuf, L"S-1-5-19" ) == 0 )
			continue;
		if ( _wcsicmp( SidBuf, L"S-1-5-20" ) == 0 )
			continue;
		if ( Chars > 8 && _wcsicmp( SidBuf + Chars - 8, L"_Classes" ) == 0 )
			continue;

		Callback( SidBuf, Chars, Context );
	}

	ExFreePoolWithTag( Buffer, 'NdBf' );
	ZwClose( HkuHandle );
}

/*
 * ResolveProfilePath — Reads ProfileImagePath from the ProfileList registry
 * for a given SID. Returns an NT path like \??\C:\Users\username.
 */
static BOOLEAN ResolveProfilePath(
	IN  PCWSTR SidString,
	OUT PWSTR  NtPath,
	IN  ULONG  NtPathChars
)
{
	WCHAR              KeyBuf[256];
	UNICODE_STRING     KeyPath;
	OBJECT_ATTRIBUTES  ObjAttr;
	HANDLE             KeyHandle = NULL;
	NTSTATUS           Status;
	UNICODE_STRING     ValueName;
	ULONG              ResultLength = 0;
	PKEY_VALUE_PARTIAL_INFORMATION ValueInfo = NULL;
	BOOLEAN            Ok = FALSE;

	RtlStringCchPrintfW( KeyBuf, 256,
		L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\"
		L"CurrentVersion\\ProfileList\\%ws", SidString );
	RtlInitUnicodeString( &KeyPath, KeyBuf );
	InitializeObjectAttributes( &ObjAttr, &KeyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwOpenKey( &KeyHandle, KEY_READ, &ObjAttr );
	if ( !NT_SUCCESS( Status ) )
		return FALSE;

	RtlInitUnicodeString( &ValueName, L"ProfileImagePath" );

	Status = ZwQueryValueKey( KeyHandle, &ValueName, KeyValuePartialInformation,
		NULL, 0, &ResultLength );
	if ( Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW )
	{
		ZwClose( KeyHandle );
		return FALSE;
	}

	ValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
		POOL_FLAG_PAGED, ResultLength, 'NdBf' );
	if ( !ValueInfo )
	{
		ZwClose( KeyHandle );
		return FALSE;
	}

	Status = ZwQueryValueKey( KeyHandle, &ValueName, KeyValuePartialInformation,
		ValueInfo, ResultLength, &ResultLength );

	if ( NT_SUCCESS( Status ) && ( ValueInfo->Type == REG_EXPAND_SZ || ValueInfo->Type == REG_SZ ) )
	{
		PCWSTR RawPath = (PCWSTR)ValueInfo->Data;
		ULONG  RawChars = ValueInfo->DataLength / sizeof( WCHAR );

		/* Strip trailing null if present */
		if ( RawChars > 0 && RawPath[RawChars - 1] == L'\0' )
			RawChars--;

		/* Convert %SystemDrive%\... or C:\... to NT path \??\C:\... */
		if ( RawChars > 13 && _wcsnicmp( RawPath, L"%SystemDrive%", 13 ) == 0 )
		{
			RtlStringCchPrintfW( NtPath, NtPathChars,
				L"\\??\\C:%ws", RawPath + 13 );
		}
		else if ( RawChars >= 2 && RawPath[1] == L':' )
		{
			RtlStringCchPrintfW( NtPath, NtPathChars,
				L"\\??\\%ws", RawPath );
		}
		else
		{
			/* Unknown format — use as-is */
			ULONG CopyChars = RawChars;
			if ( CopyChars >= NtPathChars )
				CopyChars = NtPathChars - 1;
			RtlCopyMemory( NtPath, RawPath, CopyChars * sizeof( WCHAR ) );
			NtPath[CopyChars] = L'\0';
		}

		Ok = TRUE;
	}

	ExFreePoolWithTag( ValueInfo, 'NdBf' );
	ZwClose( KeyHandle );

	return Ok;
}

/* -----------------------------------------------------------------------
 * Prefetch file scanning
 *
 * Enumerates C:\Windows\Prefetch for files matching <ExeName>-*.pf
 * ----------------------------------------------------------------------- */
static NTSTATUS ScanPrefetchArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	UNICODE_STRING              DirPath;
	OBJECT_ATTRIBUTES           ObjAttr;
	HANDLE                      DirHandle = NULL;
	IO_STATUS_BLOCK             IoStatus;
	NTSTATUS                    Status;
	PVOID                       Buffer = NULL;
	BOOLEAN                     FirstQuery = TRUE;
	ULONG                       NameLen;
	PFILE_DIRECTORY_INFORMATION DirInfo;

	NameLen = (ULONG)wcslen( ExecutableName );

	RtlInitUnicodeString( &DirPath, L"\\??\\C:\\Windows\\Prefetch" );
	InitializeObjectAttributes( &ObjAttr, &DirPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwCreateFile(
		&DirHandle,
		FILE_LIST_DIRECTORY | SYNCHRONIZE,
		&ObjAttr,
		&IoStatus,
		NULL,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	if ( !NT_SUCCESS( Status ) )
	{
		FLOG( "Prefetch directory not accessible: 0x%08X", Status );
		return Status;
	}

	Buffer = ExAllocatePool2( POOL_FLAG_PAGED, 4096, 'NdBf' );
	if ( !Buffer )
	{
		ZwClose( DirHandle );
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	while ( *Count < MaxEntries )
	{
		ULONG FileNameChars;

		Status = ZwQueryDirectoryFile(
			DirHandle, NULL, NULL, NULL,
			&IoStatus,
			Buffer, 4096,
			FileDirectoryInformation,
			TRUE,    /* ReturnSingleEntry */
			NULL,    /* FileName filter */
			FirstQuery
		);

		FirstQuery = FALSE;

		if ( !NT_SUCCESS( Status ) )
			break;

		DirInfo = (PFILE_DIRECTORY_INFORMATION)Buffer;
		FileNameChars = DirInfo->FileNameLength / sizeof( WCHAR );

		/* Prefetch files are named: EXECUTABLE.EXE-XXXXXXXX.pf
		 * Check if filename starts with the executable name */
		if ( WidePrefixMatch( DirInfo->FileName, FileNameChars,
			ExecutableName, NameLen ) )
		{
			WCHAR NameBuf[MAX_ARTIFACT_PATH];
			ULONG CopyChars = FileNameChars;

			if ( CopyChars >= MAX_ARTIFACT_PATH )
				CopyChars = MAX_ARTIFACT_PATH - 1;

			RtlCopyMemory( NameBuf, DirInfo->FileName, CopyChars * sizeof( WCHAR ) );
			NameBuf[CopyChars] = L'\0';

			FLOG( "PREFETCH artifact: C:\\Windows\\Prefetch\\%ws", NameBuf );

			Entries[*Count].Type = ARTIFACT_TYPE_PREFETCH;
			RtlStringCchPrintfW(
				Entries[*Count].Path,
				MAX_ARTIFACT_PATH,
				L"C:\\Windows\\Prefetch\\%ws",
				NameBuf
			);

			/* Deletion would happen here:
			 * UNICODE_STRING DelPath;
			 * OBJECT_ATTRIBUTES DelAttr;
			 * WCHAR DelBuf[300];
			 * RtlStringCchPrintfW( DelBuf, 300,
			 *     L"\\??\\C:\\Windows\\Prefetch\\%ws", NameBuf );
			 * RtlInitUnicodeString( &DelPath, DelBuf );
			 * InitializeObjectAttributes( &DelAttr, &DelPath,
			 *     OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );
			 * ZwDeleteFile( &DelAttr );
			 */

			( *Count )++;
		}
	}

	ExFreePoolWithTag( Buffer, 'NdBf' );
	ZwClose( DirHandle );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * ShimCache (AppCompatCache) scanning
 *
 * Reads the AppCompatCache registry blob and searches for the
 * executable name as a Unicode substring.
 * ----------------------------------------------------------------------- */
static NTSTATUS ScanShimCacheArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	UNICODE_STRING                  KeyPath;
	OBJECT_ATTRIBUTES               ObjAttr;
	HANDLE                          KeyHandle = NULL;
	NTSTATUS                        Status;
	UNICODE_STRING                  ValueName;
	ULONG                           ResultLength = 0;
	PKEY_VALUE_PARTIAL_INFORMATION  ValueInfo = NULL;
	ULONG                           NameLen;

	NameLen = (ULONG)wcslen( ExecutableName );

	RtlInitUnicodeString( &KeyPath,
		L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\"
		L"Session Manager\\AppCompatCache" );
	InitializeObjectAttributes( &ObjAttr, &KeyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwOpenKey( &KeyHandle, KEY_READ, &ObjAttr );
	if ( !NT_SUCCESS( Status ) )
	{
		FLOG( "AppCompatCache key not accessible: 0x%08X", Status );
		return Status;
	}

	RtlInitUnicodeString( &ValueName, L"AppCompatCache" );

	/* Query size first */
	Status = ZwQueryValueKey( KeyHandle, &ValueName, KeyValuePartialInformation,
		NULL, 0, &ResultLength );
	if ( Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW )
	{
		ZwClose( KeyHandle );
		return STATUS_NOT_FOUND;
	}

	ValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
		POOL_FLAG_PAGED, ResultLength, 'NdBf' );
	if ( !ValueInfo )
	{
		ZwClose( KeyHandle );
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Status = ZwQueryValueKey( KeyHandle, &ValueName, KeyValuePartialInformation,
		ValueInfo, ResultLength, &ResultLength );

	if ( NT_SUCCESS( Status ) && *Count < MaxEntries )
	{
		/* Scan the binary blob for the executable name as Unicode text.
		 * ShimCache format varies by Windows version — raw scanning is the
		 * most portable approach. */
		PUCHAR  Data       = ValueInfo->Data;
		ULONG   DataLen    = ValueInfo->DataLength;
		ULONG   SearchBytes = NameLen * (ULONG)sizeof( WCHAR );
		ULONG   i;
		BOOLEAN Found = FALSE;

		for ( i = 0; i + SearchBytes <= DataLen && !Found; i += 2 )
		{
			if ( WidePrefixMatch( (PCWSTR)( Data + i ),
				( DataLen - i ) / sizeof( WCHAR ),
				ExecutableName, NameLen ) )
			{
				FLOG( "SHIMCACHE artifact: '%ws' found in AppCompatCache at offset 0x%X",
					ExecutableName, i );

				Entries[*Count].Type = ARTIFACT_TYPE_SHIMCACHE;
				RtlStringCchPrintfW(
					Entries[*Count].Path,
					MAX_ARTIFACT_PATH,
					L"HKLM\\SYSTEM\\...\\AppCompatCache [offset 0x%X]",
					i
				);

				/* Clearing would happen here:
				 * — Rewrite blob without this entry, or delete the value:
				 * ZwDeleteValueKey( KeyHandle, &ValueName );
				 */

				Found = TRUE;
				( *Count )++;
			}
		}

		if ( !Found )
			FLOG( "SHIMCACHE: no artifact found for '%ws'", ExecutableName );
	}

	ExFreePoolWithTag( ValueInfo, 'NdBf' );
	ZwClose( KeyHandle );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * BAM (Background Activity Moderator) scanning
 *
 * Enumerates BAM\State\UserSettings\<SID> values for paths
 * containing the executable name.
 * ----------------------------------------------------------------------- */
static NTSTATUS ScanBamArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	UNICODE_STRING    KeyPath;
	OBJECT_ATTRIBUTES ObjAttr;
	HANDLE            BamHandle = NULL;
	NTSTATUS          Status;
	ULONG             SidIndex;
	ULONG             ResultLength;
	PVOID             KeyInfoBuffer = NULL;
	ULONG             NameLen;

	NameLen = (ULONG)wcslen( ExecutableName );

	RtlInitUnicodeString( &KeyPath,
		L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\"
		L"bam\\State\\UserSettings" );
	InitializeObjectAttributes( &ObjAttr, &KeyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwOpenKey( &BamHandle, KEY_READ, &ObjAttr );
	if ( !NT_SUCCESS( Status ) )
	{
		FLOG( "BAM key not found (may not exist on this OS): 0x%08X", Status );
		return Status;
	}

	KeyInfoBuffer = ExAllocatePool2( POOL_FLAG_PAGED, 1024, 'NdBf' );
	if ( !KeyInfoBuffer )
	{
		ZwClose( BamHandle );
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	for ( SidIndex = 0; *Count < MaxEntries; SidIndex++ )
	{
		PKEY_BASIC_INFORMATION SidKeyInfo;
		HANDLE                 SidHandle = NULL;
		OBJECT_ATTRIBUTES      SidAttr;
		UNICODE_STRING         SidKeyName;
		PVOID                  ValBuffer = NULL;
		ULONG                  ValIndex;

		Status = ZwEnumerateKey( BamHandle, SidIndex, KeyBasicInformation,
			KeyInfoBuffer, 1024, &ResultLength );
		if ( !NT_SUCCESS( Status ) )
			break;

		SidKeyInfo = (PKEY_BASIC_INFORMATION)KeyInfoBuffer;
		SidKeyName.Buffer        = SidKeyInfo->Name;
		SidKeyName.Length        = (USHORT)SidKeyInfo->NameLength;
		SidKeyName.MaximumLength = SidKeyName.Length;

		InitializeObjectAttributes( &SidAttr, &SidKeyName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, BamHandle, NULL );

		Status = ZwOpenKey( &SidHandle, KEY_READ, &SidAttr );
		if ( !NT_SUCCESS( Status ) )
			continue;

		ValBuffer = ExAllocatePool2( POOL_FLAG_PAGED, 2048, 'NdBf' );
		if ( !ValBuffer )
		{
			ZwClose( SidHandle );
			continue;
		}

		/* Enumerate values — each value name is a device path like
		 * \Device\HarddiskVolume3\path\to\executable.exe */
		for ( ValIndex = 0; *Count < MaxEntries; ValIndex++ )
		{
			PKEY_VALUE_BASIC_INFORMATION ValInfo;
			ULONG ValNameChars;

			Status = ZwEnumerateValueKey( SidHandle, ValIndex,
				KeyValueBasicInformation, ValBuffer, 2048, &ResultLength );
			if ( !NT_SUCCESS( Status ) )
				break;

			ValInfo = (PKEY_VALUE_BASIC_INFORMATION)ValBuffer;
			ValNameChars = ValInfo->NameLength / sizeof( WCHAR );

			if ( WideSubstringMatch( ValInfo->Name, ValNameChars,
				ExecutableName, NameLen ) )
			{
				WCHAR PathBuf[MAX_ARTIFACT_PATH];
				ULONG CopyChars = ValNameChars;

				if ( CopyChars >= MAX_ARTIFACT_PATH )
					CopyChars = MAX_ARTIFACT_PATH - 1;

				RtlCopyMemory( PathBuf, ValInfo->Name, CopyChars * sizeof( WCHAR ) );
				PathBuf[CopyChars] = L'\0';

				FLOG( "BAM artifact: %ws", PathBuf );

				Entries[*Count].Type = ARTIFACT_TYPE_BAM;
				RtlStringCchCopyW( Entries[*Count].Path, MAX_ARTIFACT_PATH, PathBuf );

				/* Deletion would happen here:
				 * UNICODE_STRING DelName;
				 * DelName.Buffer = ValInfo->Name;
				 * DelName.Length = (USHORT)ValInfo->NameLength;
				 * DelName.MaximumLength = DelName.Length;
				 * ZwDeleteValueKey( SidHandle, &DelName );
				 */

				( *Count )++;
			}
		}

		ExFreePoolWithTag( ValBuffer, 'NdBf' );
		ZwClose( SidHandle );
	}

	ExFreePoolWithTag( KeyInfoBuffer, 'NdBf' );
	ZwClose( BamHandle );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * AmCache scanning
 *
 * Scans the Amcache.hve binary hive for the executable name as a
 * Unicode substring, using the generic ScanFileForName helper.
 * ----------------------------------------------------------------------- */
static NTSTATUS ScanAmCacheArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	ULONG NameLen;

	if ( *Count >= MaxEntries )
		return STATUS_SUCCESS;

	NameLen = (ULONG)wcslen( ExecutableName );

	if ( ScanFileForName(
		L"\\??\\C:\\Windows\\appcompat\\Programs\\Amcache.hve",
		ExecutableName, NameLen ) )
	{
		FLOG( "AMCACHE artifact: Amcache.hve contains '%ws'", ExecutableName );

		Entries[*Count].Type = ARTIFACT_TYPE_AMCACHE;
		RtlStringCchCopyW(
			Entries[*Count].Path, MAX_ARTIFACT_PATH,
			L"C:\\Windows\\appcompat\\Programs\\Amcache.hve"
		);

		( *Count )++;
	}

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * UserAssist scanning
 *
 * Enumerates HKU\<SID>\...\UserAssist\{GUID}\Count for each user.
 * Value names are ROT13-encoded paths; we decode and match.
 * ----------------------------------------------------------------------- */

typedef struct _USERASSIST_CTX
{
	PCWSTR          ExecutableName;
	ULONG           NameLen;
	PARTIFACT_ENTRY Entries;
	ULONG           MaxEntries;
	PULONG          Count;
} USERASSIST_CTX, *PUSERASSIST_CTX;

static VOID UserAssistSidCallback(
	IN PCWSTR SidString,
	IN ULONG  SidChars,
	IN PVOID  Context
)
{
	PUSERASSIST_CTX Ctx = (PUSERASSIST_CTX)Context;
	WCHAR              KeyBuf[300];
	UNICODE_STRING     KeyPath;
	OBJECT_ATTRIBUTES  ObjAttr;
	HANDLE             UaHandle = NULL;
	NTSTATUS           Status;
	ULONG              GuidIdx;
	PVOID              KeyInfoBuf;
	ULONG              ResultLength;

	UNREFERENCED_PARAMETER( SidChars );

	RtlStringCchPrintfW( KeyBuf, 300,
		L"\\Registry\\User\\%ws\\Software\\Microsoft\\Windows\\"
		L"CurrentVersion\\Explorer\\UserAssist", SidString );
	RtlInitUnicodeString( &KeyPath, KeyBuf );
	InitializeObjectAttributes( &ObjAttr, &KeyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwOpenKey( &UaHandle, KEY_READ, &ObjAttr );
	if ( !NT_SUCCESS( Status ) )
		return;

	KeyInfoBuf = ExAllocatePool2( POOL_FLAG_PAGED, 1024, 'NdBf' );
	if ( !KeyInfoBuf )
	{
		ZwClose( UaHandle );
		return;
	}

	/* Enumerate GUID subkeys */
	for ( GuidIdx = 0; *Ctx->Count < Ctx->MaxEntries; GuidIdx++ )
	{
		PKEY_BASIC_INFORMATION GuidInfo;
		UNICODE_STRING         GuidName;
		OBJECT_ATTRIBUTES      GuidAttr;
		HANDLE                 GuidHandle = NULL;
		UNICODE_STRING         CountName;
		OBJECT_ATTRIBUTES      CountAttr;
		HANDLE                 CountHandle = NULL;
		ULONG                  ValIdx;
		PVOID                  ValBuf;

		Status = ZwEnumerateKey( UaHandle, GuidIdx, KeyBasicInformation,
			KeyInfoBuf, 1024, &ResultLength );
		if ( !NT_SUCCESS( Status ) )
			break;

		GuidInfo = (PKEY_BASIC_INFORMATION)KeyInfoBuf;
		GuidName.Buffer        = GuidInfo->Name;
		GuidName.Length        = (USHORT)GuidInfo->NameLength;
		GuidName.MaximumLength = GuidName.Length;

		InitializeObjectAttributes( &GuidAttr, &GuidName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, UaHandle, NULL );

		Status = ZwOpenKey( &GuidHandle, KEY_READ, &GuidAttr );
		if ( !NT_SUCCESS( Status ) )
			continue;

		RtlInitUnicodeString( &CountName, L"Count" );
		InitializeObjectAttributes( &CountAttr, &CountName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, GuidHandle, NULL );

		Status = ZwOpenKey( &CountHandle, KEY_READ, &CountAttr );
		ZwClose( GuidHandle );

		if ( !NT_SUCCESS( Status ) )
			continue;

		ValBuf = ExAllocatePool2( POOL_FLAG_PAGED, 2048, 'NdBf' );
		if ( !ValBuf )
		{
			ZwClose( CountHandle );
			continue;
		}

		for ( ValIdx = 0; *Ctx->Count < Ctx->MaxEntries; ValIdx++ )
		{
			PKEY_VALUE_BASIC_INFORMATION ValInfo;
			ULONG  ValNameChars;
			WCHAR  Decoded[MAX_ARTIFACT_PATH];
			ULONG  CopyChars;

			Status = ZwEnumerateValueKey( CountHandle, ValIdx,
				KeyValueBasicInformation, ValBuf, 2048, &ResultLength );
			if ( !NT_SUCCESS( Status ) )
				break;

			ValInfo = (PKEY_VALUE_BASIC_INFORMATION)ValBuf;
			ValNameChars = ValInfo->NameLength / sizeof( WCHAR );

			CopyChars = ValNameChars;
			if ( CopyChars >= MAX_ARTIFACT_PATH )
				CopyChars = MAX_ARTIFACT_PATH - 1;

			RtlCopyMemory( Decoded, ValInfo->Name, CopyChars * sizeof( WCHAR ) );
			Decoded[CopyChars] = L'\0';

			Rot13DecodeWide( Decoded, CopyChars );

			if ( WideSubstringMatch( Decoded, CopyChars,
				Ctx->ExecutableName, Ctx->NameLen ) )
			{
				FLOG( "USERASSIST artifact: %ws", Decoded );

				Ctx->Entries[*Ctx->Count].Type = ARTIFACT_TYPE_USERASSIST;
				RtlStringCchPrintfW(
					Ctx->Entries[*Ctx->Count].Path,
					MAX_ARTIFACT_PATH,
					L"HKU\\%ws\\...\\UserAssist\\Count: %ws",
					SidString, Decoded
				);
				( *Ctx->Count )++;
			}
		}

		ExFreePoolWithTag( ValBuf, 'NdBf' );
		ZwClose( CountHandle );
	}

	ExFreePoolWithTag( KeyInfoBuf, 'NdBf' );
	ZwClose( UaHandle );
}

static NTSTATUS ScanUserAssistArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	USERASSIST_CTX Ctx;

	Ctx.ExecutableName = ExecutableName;
	Ctx.NameLen        = (ULONG)wcslen( ExecutableName );
	Ctx.Entries        = Entries;
	Ctx.MaxEntries     = MaxEntries;
	Ctx.Count          = Count;

	ForEachUserSid( UserAssistSidCallback, &Ctx );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * MUICache scanning
 *
 * Enumerates HKU\<SID>\...\Shell\MuiCache values for paths
 * containing the executable name.
 * ----------------------------------------------------------------------- */

typedef struct _MUICACHE_CTX
{
	PCWSTR          ExecutableName;
	ULONG           NameLen;
	PARTIFACT_ENTRY Entries;
	ULONG           MaxEntries;
	PULONG          Count;
} MUICACHE_CTX, *PMUICACHE_CTX;

static VOID MuiCacheSidCallback(
	IN PCWSTR SidString,
	IN ULONG  SidChars,
	IN PVOID  Context
)
{
	PMUICACHE_CTX     Ctx = (PMUICACHE_CTX)Context;
	WCHAR              KeyBuf[300];
	UNICODE_STRING     KeyPath;
	OBJECT_ATTRIBUTES  ObjAttr;
	HANDLE             McHandle = NULL;
	NTSTATUS           Status;
	PVOID              ValBuf;
	ULONG              ValIdx;
	ULONG              ResultLength;

	UNREFERENCED_PARAMETER( SidChars );

	RtlStringCchPrintfW( KeyBuf, 300,
		L"\\Registry\\User\\%ws\\Software\\Classes\\Local Settings\\"
		L"Software\\Microsoft\\Windows\\Shell\\MuiCache", SidString );
	RtlInitUnicodeString( &KeyPath, KeyBuf );
	InitializeObjectAttributes( &ObjAttr, &KeyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwOpenKey( &McHandle, KEY_READ, &ObjAttr );
	if ( !NT_SUCCESS( Status ) )
		return;

	ValBuf = ExAllocatePool2( POOL_FLAG_PAGED, 2048, 'NdBf' );
	if ( !ValBuf )
	{
		ZwClose( McHandle );
		return;
	}

	for ( ValIdx = 0; *Ctx->Count < Ctx->MaxEntries; ValIdx++ )
	{
		PKEY_VALUE_BASIC_INFORMATION ValInfo;
		ULONG ValNameChars;

		Status = ZwEnumerateValueKey( McHandle, ValIdx,
			KeyValueBasicInformation, ValBuf, 2048, &ResultLength );
		if ( !NT_SUCCESS( Status ) )
			break;

		ValInfo = (PKEY_VALUE_BASIC_INFORMATION)ValBuf;
		ValNameChars = ValInfo->NameLength / sizeof( WCHAR );

		if ( WideSubstringMatch( ValInfo->Name, ValNameChars,
			Ctx->ExecutableName, Ctx->NameLen ) )
		{
			WCHAR PathBuf[MAX_ARTIFACT_PATH];
			ULONG CopyChars = ValNameChars;

			if ( CopyChars >= MAX_ARTIFACT_PATH )
				CopyChars = MAX_ARTIFACT_PATH - 1;

			RtlCopyMemory( PathBuf, ValInfo->Name, CopyChars * sizeof( WCHAR ) );
			PathBuf[CopyChars] = L'\0';

			FLOG( "MUICACHE artifact: %ws", PathBuf );

			Ctx->Entries[*Ctx->Count].Type = ARTIFACT_TYPE_MUICACHE;
			RtlStringCchPrintfW(
				Ctx->Entries[*Ctx->Count].Path,
				MAX_ARTIFACT_PATH,
				L"HKU\\%ws\\...\\MuiCache: %ws",
				SidString, PathBuf
			);
			( *Ctx->Count )++;
		}
	}

	ExFreePoolWithTag( ValBuf, 'NdBf' );
	ZwClose( McHandle );
}

static NTSTATUS ScanMuiCacheArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	MUICACHE_CTX Ctx;

	Ctx.ExecutableName = ExecutableName;
	Ctx.NameLen        = (ULONG)wcslen( ExecutableName );
	Ctx.Entries        = Entries;
	Ctx.MaxEntries     = MaxEntries;
	Ctx.Count          = Count;

	ForEachUserSid( MuiCacheSidCallback, &Ctx );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * RecentApps scanning
 *
 * Enumerates HKU\<SID>\...\Search\RecentApps\{GUID} subkeys and
 * reads the AppId value to match against the executable name.
 * ----------------------------------------------------------------------- */

typedef struct _RECENTAPPS_CTX
{
	PCWSTR          ExecutableName;
	ULONG           NameLen;
	PARTIFACT_ENTRY Entries;
	ULONG           MaxEntries;
	PULONG          Count;
} RECENTAPPS_CTX, *PRECENTAPPS_CTX;

static VOID RecentAppsSidCallback(
	IN PCWSTR SidString,
	IN ULONG  SidChars,
	IN PVOID  Context
)
{
	PRECENTAPPS_CTX   Ctx = (PRECENTAPPS_CTX)Context;
	WCHAR              KeyBuf[300];
	UNICODE_STRING     KeyPath;
	OBJECT_ATTRIBUTES  ObjAttr;
	HANDLE             RaHandle = NULL;
	NTSTATUS           Status;
	PVOID              KeyInfoBuf;
	ULONG              GuidIdx;
	ULONG              ResultLength;

	UNREFERENCED_PARAMETER( SidChars );

	RtlStringCchPrintfW( KeyBuf, 300,
		L"\\Registry\\User\\%ws\\Software\\Microsoft\\Windows\\"
		L"CurrentVersion\\Search\\RecentApps", SidString );
	RtlInitUnicodeString( &KeyPath, KeyBuf );
	InitializeObjectAttributes( &ObjAttr, &KeyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwOpenKey( &RaHandle, KEY_READ, &ObjAttr );
	if ( !NT_SUCCESS( Status ) )
		return;

	KeyInfoBuf = ExAllocatePool2( POOL_FLAG_PAGED, 1024, 'NdBf' );
	if ( !KeyInfoBuf )
	{
		ZwClose( RaHandle );
		return;
	}

	for ( GuidIdx = 0; *Ctx->Count < Ctx->MaxEntries; GuidIdx++ )
	{
		PKEY_BASIC_INFORMATION GuidInfo;
		UNICODE_STRING         GuidName;
		OBJECT_ATTRIBUTES      GuidAttr;
		HANDLE                 GuidHandle = NULL;
		UNICODE_STRING         AppIdName;
		ULONG                  AppIdLen = 0;
		PKEY_VALUE_PARTIAL_INFORMATION AppIdInfo = NULL;

		Status = ZwEnumerateKey( RaHandle, GuidIdx, KeyBasicInformation,
			KeyInfoBuf, 1024, &ResultLength );
		if ( !NT_SUCCESS( Status ) )
			break;

		GuidInfo = (PKEY_BASIC_INFORMATION)KeyInfoBuf;
		GuidName.Buffer        = GuidInfo->Name;
		GuidName.Length        = (USHORT)GuidInfo->NameLength;
		GuidName.MaximumLength = GuidName.Length;

		InitializeObjectAttributes( &GuidAttr, &GuidName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, RaHandle, NULL );

		Status = ZwOpenKey( &GuidHandle, KEY_READ, &GuidAttr );
		if ( !NT_SUCCESS( Status ) )
			continue;

		RtlInitUnicodeString( &AppIdName, L"AppId" );

		Status = ZwQueryValueKey( GuidHandle, &AppIdName,
			KeyValuePartialInformation, NULL, 0, &AppIdLen );
		if ( Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW )
		{
			ZwClose( GuidHandle );
			continue;
		}

		AppIdInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
			POOL_FLAG_PAGED, AppIdLen, 'NdBf' );
		if ( !AppIdInfo )
		{
			ZwClose( GuidHandle );
			continue;
		}

		Status = ZwQueryValueKey( GuidHandle, &AppIdName,
			KeyValuePartialInformation, AppIdInfo, AppIdLen, &AppIdLen );

		if ( NT_SUCCESS( Status ) && AppIdInfo->Type == REG_SZ )
		{
			PCWSTR AppIdStr  = (PCWSTR)AppIdInfo->Data;
			ULONG  AppIdChars = AppIdInfo->DataLength / sizeof( WCHAR );

			if ( AppIdChars > 0 && AppIdStr[AppIdChars - 1] == L'\0' )
				AppIdChars--;

			if ( WideSubstringMatch( AppIdStr, AppIdChars,
				Ctx->ExecutableName, Ctx->NameLen ) )
			{
				WCHAR GuidBuf[64];
				ULONG GuidChars = GuidInfo->NameLength / sizeof( WCHAR );

				if ( GuidChars >= 64 )
					GuidChars = 63;
				RtlCopyMemory( GuidBuf, GuidInfo->Name, GuidChars * sizeof( WCHAR ) );
				GuidBuf[GuidChars] = L'\0';

				FLOG( "RECENTAPPS artifact: %ws in %ws", AppIdStr, GuidBuf );

				Ctx->Entries[*Ctx->Count].Type = ARTIFACT_TYPE_RECENTAPPS;
				RtlStringCchPrintfW(
					Ctx->Entries[*Ctx->Count].Path,
					MAX_ARTIFACT_PATH,
					L"HKU\\%ws\\...\\RecentApps\\%ws",
					SidString, GuidBuf
				);
				( *Ctx->Count )++;
			}
		}

		ExFreePoolWithTag( AppIdInfo, 'NdBf' );
		ZwClose( GuidHandle );
	}

	ExFreePoolWithTag( KeyInfoBuf, 'NdBf' );
	ZwClose( RaHandle );
}

static NTSTATUS ScanRecentAppsArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	RECENTAPPS_CTX Ctx;

	Ctx.ExecutableName = ExecutableName;
	Ctx.NameLen        = (ULONG)wcslen( ExecutableName );
	Ctx.Entries        = Entries;
	Ctx.MaxEntries     = MaxEntries;
	Ctx.Count          = Count;

	ForEachUserSid( RecentAppsSidCallback, &Ctx );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * RunMRU scanning
 *
 * Enumerates HKU\<SID>\...\Explorer\RunMRU values (named a, b, c, ...)
 * which contain commands typed into the Run dialog.
 * ----------------------------------------------------------------------- */

typedef struct _RUNMRU_CTX
{
	PCWSTR          ExecutableName;
	ULONG           NameLen;
	PARTIFACT_ENTRY Entries;
	ULONG           MaxEntries;
	PULONG          Count;
} RUNMRU_CTX, *PRUNMRU_CTX;

static VOID RunMruSidCallback(
	IN PCWSTR SidString,
	IN ULONG  SidChars,
	IN PVOID  Context
)
{
	PRUNMRU_CTX       Ctx = (PRUNMRU_CTX)Context;
	WCHAR              KeyBuf[300];
	UNICODE_STRING     KeyPath;
	OBJECT_ATTRIBUTES  ObjAttr;
	HANDLE             MruHandle = NULL;
	NTSTATUS           Status;
	PVOID              ValBuf;
	ULONG              ValIdx;
	ULONG              ResultLength;

	UNREFERENCED_PARAMETER( SidChars );

	RtlStringCchPrintfW( KeyBuf, 300,
		L"\\Registry\\User\\%ws\\Software\\Microsoft\\Windows\\"
		L"CurrentVersion\\Explorer\\RunMRU", SidString );
	RtlInitUnicodeString( &KeyPath, KeyBuf );
	InitializeObjectAttributes( &ObjAttr, &KeyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwOpenKey( &MruHandle, KEY_READ, &ObjAttr );
	if ( !NT_SUCCESS( Status ) )
		return;

	ValBuf = ExAllocatePool2( POOL_FLAG_PAGED, 2048, 'NdBf' );
	if ( !ValBuf )
	{
		ZwClose( MruHandle );
		return;
	}

	for ( ValIdx = 0; *Ctx->Count < Ctx->MaxEntries; ValIdx++ )
	{
		PKEY_VALUE_FULL_INFORMATION ValInfo;
		ULONG  ValNameChars;
		PCWSTR ValData;
		ULONG  ValDataChars;

		Status = ZwEnumerateValueKey( MruHandle, ValIdx,
			KeyValueFullInformation, ValBuf, 2048, &ResultLength );
		if ( !NT_SUCCESS( Status ) )
			break;

		ValInfo = (PKEY_VALUE_FULL_INFORMATION)ValBuf;
		ValNameChars = ValInfo->NameLength / sizeof( WCHAR );

		/* Skip the MRUList value (ordering index) */
		if ( ValNameChars == 7 &&
			_wcsnicmp( ValInfo->Name, L"MRUList", 7 ) == 0 )
			continue;

		if ( ValInfo->Type != REG_SZ || ValInfo->DataLength < sizeof( WCHAR ) )
			continue;

		ValData = (PCWSTR)( (PUCHAR)ValInfo + ValInfo->DataOffset );
		ValDataChars = ValInfo->DataLength / sizeof( WCHAR );

		/* Strip trailing null and \1 terminator */
		while ( ValDataChars > 0 &&
			( ValData[ValDataChars - 1] == L'\0' || ValData[ValDataChars - 1] == L'\1' ) )
			ValDataChars--;

		if ( WideSubstringMatch( ValData, ValDataChars,
			Ctx->ExecutableName, Ctx->NameLen ) )
		{
			WCHAR DataBuf[MAX_ARTIFACT_PATH];
			ULONG CopyChars = ValDataChars;

			if ( CopyChars >= MAX_ARTIFACT_PATH )
				CopyChars = MAX_ARTIFACT_PATH - 1;

			RtlCopyMemory( DataBuf, ValData, CopyChars * sizeof( WCHAR ) );
			DataBuf[CopyChars] = L'\0';

			FLOG( "RUNMRU artifact: %ws", DataBuf );

			Ctx->Entries[*Ctx->Count].Type = ARTIFACT_TYPE_RUNMRU;
			RtlStringCchPrintfW(
				Ctx->Entries[*Ctx->Count].Path,
				MAX_ARTIFACT_PATH,
				L"HKU\\%ws\\...\\RunMRU: %ws",
				SidString, DataBuf
			);
			( *Ctx->Count )++;
		}
	}

	ExFreePoolWithTag( ValBuf, 'NdBf' );
	ZwClose( MruHandle );
}

static NTSTATUS ScanRunMruArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	RUNMRU_CTX Ctx;

	Ctx.ExecutableName = ExecutableName;
	Ctx.NameLen        = (ULONG)wcslen( ExecutableName );
	Ctx.Entries        = Entries;
	Ctx.MaxEntries     = MaxEntries;
	Ctx.Count          = Count;

	ForEachUserSid( RunMruSidCallback, &Ctx );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * SRUM (System Resource Usage Monitor) scanning
 *
 * Scans the SRUDB.dat binary file for the executable name.
 * ----------------------------------------------------------------------- */
static NTSTATUS ScanSrumArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	ULONG NameLen;

	if ( *Count >= MaxEntries )
		return STATUS_SUCCESS;

	NameLen = (ULONG)wcslen( ExecutableName );

	if ( ScanFileForName(
		L"\\??\\C:\\Windows\\System32\\sru\\SRUDB.dat",
		ExecutableName, NameLen ) )
	{
		FLOG( "SRUM artifact: SRUDB.dat contains '%ws'", ExecutableName );

		Entries[*Count].Type = ARTIFACT_TYPE_SRUM;
		RtlStringCchCopyW(
			Entries[*Count].Path, MAX_ARTIFACT_PATH,
			L"C:\\Windows\\System32\\sru\\SRUDB.dat"
		);
		( *Count )++;
	}

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Event Log scanning
 *
 * Scans Security, Sysmon, and Application .evtx files for the
 * executable name.
 * ----------------------------------------------------------------------- */
static NTSTATUS ScanEventLogArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	static const PCWSTR EvtxFiles[] = {
		L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
		L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
		L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\Application.evtx"
	};
	static const PCWSTR EvtxDisplay[] = {
		L"Security.evtx",
		L"Sysmon%4Operational.evtx",
		L"Application.evtx"
	};
	ULONG NameLen;
	ULONG i;

	NameLen = (ULONG)wcslen( ExecutableName );

	for ( i = 0; i < 3 && *Count < MaxEntries; i++ )
	{
		if ( ScanFileForName( EvtxFiles[i], ExecutableName, NameLen ) )
		{
			FLOG( "EVTLOG artifact: %ws contains '%ws'",
				EvtxDisplay[i], ExecutableName );

			Entries[*Count].Type = ARTIFACT_TYPE_EVTLOG;
			RtlStringCchPrintfW(
				Entries[*Count].Path, MAX_ARTIFACT_PATH,
				L"C:\\Windows\\System32\\winevt\\Logs\\%ws",
				EvtxDisplay[i]
			);
			( *Count )++;
		}
	}

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Superfetch (SysMain) scanning
 *
 * Scans AgAppLaunch.db for the executable name.
 * ----------------------------------------------------------------------- */
static NTSTATUS ScanSuperfetchArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	ULONG NameLen;

	if ( *Count >= MaxEntries )
		return STATUS_SUCCESS;

	NameLen = (ULONG)wcslen( ExecutableName );

	if ( ScanFileForName(
		L"\\??\\C:\\Windows\\Prefetch\\AgAppLaunch.db",
		ExecutableName, NameLen ) )
	{
		FLOG( "SUPERFETCH artifact: AgAppLaunch.db contains '%ws'", ExecutableName );

		Entries[*Count].Type = ARTIFACT_TYPE_SUPERFETCH;
		RtlStringCchCopyW(
			Entries[*Count].Path, MAX_ARTIFACT_PATH,
			L"C:\\Windows\\Prefetch\\AgAppLaunch.db"
		);
		( *Count )++;
	}

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Timeline / ActivitiesCache scanning
 *
 * For each user profile, scans ActivitiesCache.db under
 * AppData\Local\ConnectedDevicesPlatform\<subdir>\.
 * ----------------------------------------------------------------------- */

typedef struct _TIMELINE_CTX
{
	PCWSTR          ExecutableName;
	ULONG           NameLen;
	PARTIFACT_ENTRY Entries;
	ULONG           MaxEntries;
	PULONG          Count;
} TIMELINE_CTX, *PTIMELINE_CTX;

static VOID TimelineSidCallback(
	IN PCWSTR SidString,
	IN ULONG  SidChars,
	IN PVOID  Context
)
{
	PTIMELINE_CTX     Ctx = (PTIMELINE_CTX)Context;
	WCHAR              ProfilePath[260];
	WCHAR              DirBuf[300];
	UNICODE_STRING     DirPath;
	OBJECT_ATTRIBUTES  DirAttr;
	HANDLE             DirHandle = NULL;
	IO_STATUS_BLOCK    IoStatus;
	NTSTATUS           Status;
	PVOID              Buffer;
	BOOLEAN            FirstQuery = TRUE;

	UNREFERENCED_PARAMETER( SidChars );

	if ( !ResolveProfilePath( SidString, ProfilePath, 260 ) )
		return;

	RtlStringCchPrintfW( DirBuf, 300,
		L"%ws\\AppData\\Local\\ConnectedDevicesPlatform", ProfilePath );
	RtlInitUnicodeString( &DirPath, DirBuf );
	InitializeObjectAttributes( &DirAttr, &DirPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwCreateFile(
		&DirHandle,
		FILE_LIST_DIRECTORY | SYNCHRONIZE,
		&DirAttr, &IoStatus, NULL,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	if ( !NT_SUCCESS( Status ) )
		return;

	Buffer = ExAllocatePool2( POOL_FLAG_PAGED, 4096, 'NdBf' );
	if ( !Buffer )
	{
		ZwClose( DirHandle );
		return;
	}

	while ( *Ctx->Count < Ctx->MaxEntries )
	{
		PFILE_DIRECTORY_INFORMATION DirInfo;
		WCHAR  SubDirName[128];
		ULONG  SubChars;
		WCHAR  DbPath[400];

		Status = ZwQueryDirectoryFile(
			DirHandle, NULL, NULL, NULL,
			&IoStatus, Buffer, 4096,
			FileDirectoryInformation, TRUE, NULL, FirstQuery );
		FirstQuery = FALSE;

		if ( !NT_SUCCESS( Status ) )
			break;

		DirInfo = (PFILE_DIRECTORY_INFORMATION)Buffer;

		/* Skip . and .. and non-directories */
		if ( !( DirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY ) )
			continue;

		SubChars = DirInfo->FileNameLength / sizeof( WCHAR );
		if ( SubChars >= 128 )
			continue;
		if ( SubChars <= 2 && DirInfo->FileName[0] == L'.' )
			continue;

		RtlCopyMemory( SubDirName, DirInfo->FileName, SubChars * sizeof( WCHAR ) );
		SubDirName[SubChars] = L'\0';

		RtlStringCchPrintfW( DbPath, 400,
			L"%ws\\%ws\\ActivitiesCache.db", DirBuf, SubDirName );

		if ( ScanFileForName( DbPath, Ctx->ExecutableName, Ctx->NameLen ) )
		{
			FLOG( "TIMELINE artifact: ActivitiesCache.db in %ws", SubDirName );

			Ctx->Entries[*Ctx->Count].Type = ARTIFACT_TYPE_TIMELINE;
			/* Convert NT path back to display path */
			RtlStringCchPrintfW(
				Ctx->Entries[*Ctx->Count].Path,
				MAX_ARTIFACT_PATH,
				L"ConnectedDevicesPlatform\\%ws\\ActivitiesCache.db",
				SubDirName
			);
			( *Ctx->Count )++;
		}
	}

	ExFreePoolWithTag( Buffer, 'NdBf' );
	ZwClose( DirHandle );
}

static NTSTATUS ScanTimelineArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	TIMELINE_CTX Ctx;

	Ctx.ExecutableName = ExecutableName;
	Ctx.NameLen        = (ULONG)wcslen( ExecutableName );
	Ctx.Entries        = Entries;
	Ctx.MaxEntries     = MaxEntries;
	Ctx.Count          = Count;

	ForEachUserSid( TimelineSidCallback, &Ctx );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Jump Lists scanning
 *
 * For each user profile, scans *.automaticDestinations-ms files under
 * AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\.
 * ----------------------------------------------------------------------- */

typedef struct _JUMPLISTS_CTX
{
	PCWSTR          ExecutableName;
	ULONG           NameLen;
	PARTIFACT_ENTRY Entries;
	ULONG           MaxEntries;
	PULONG          Count;
} JUMPLISTS_CTX, *PJUMPLISTS_CTX;

static VOID JumpListsSidCallback(
	IN PCWSTR SidString,
	IN ULONG  SidChars,
	IN PVOID  Context
)
{
	PJUMPLISTS_CTX    Ctx = (PJUMPLISTS_CTX)Context;
	WCHAR              ProfilePath[260];
	WCHAR              DirBuf[350];
	UNICODE_STRING     DirPath;
	OBJECT_ATTRIBUTES  DirAttr;
	HANDLE             DirHandle = NULL;
	IO_STATUS_BLOCK    IoStatus;
	NTSTATUS           Status;
	PVOID              Buffer;
	BOOLEAN            FirstQuery = TRUE;

	UNREFERENCED_PARAMETER( SidChars );

	if ( !ResolveProfilePath( SidString, ProfilePath, 260 ) )
		return;

	RtlStringCchPrintfW( DirBuf, 350,
		L"%ws\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations",
		ProfilePath );
	RtlInitUnicodeString( &DirPath, DirBuf );
	InitializeObjectAttributes( &DirAttr, &DirPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwCreateFile(
		&DirHandle,
		FILE_LIST_DIRECTORY | SYNCHRONIZE,
		&DirAttr, &IoStatus, NULL,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	if ( !NT_SUCCESS( Status ) )
		return;

	Buffer = ExAllocatePool2( POOL_FLAG_PAGED, 4096, 'NdBf' );
	if ( !Buffer )
	{
		ZwClose( DirHandle );
		return;
	}

	while ( *Ctx->Count < Ctx->MaxEntries )
	{
		PFILE_DIRECTORY_INFORMATION DirInfo;
		ULONG  FileChars;
		WCHAR  FileName[128];
		WCHAR  FilePath[450];

		Status = ZwQueryDirectoryFile(
			DirHandle, NULL, NULL, NULL,
			&IoStatus, Buffer, 4096,
			FileDirectoryInformation, TRUE, NULL, FirstQuery );
		FirstQuery = FALSE;

		if ( !NT_SUCCESS( Status ) )
			break;

		DirInfo = (PFILE_DIRECTORY_INFORMATION)Buffer;

		if ( DirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY )
			continue;

		FileChars = DirInfo->FileNameLength / sizeof( WCHAR );
		if ( FileChars >= 128 )
			continue;

		/* Only process .automaticDestinations-ms files */
		if ( FileChars < 28 )
			continue;

		RtlCopyMemory( FileName, DirInfo->FileName, FileChars * sizeof( WCHAR ) );
		FileName[FileChars] = L'\0';

		if ( !WideSubstringMatch( FileName, FileChars,
			L"automaticDestinations-ms", 24 ) )
			continue;

		RtlStringCchPrintfW( FilePath, 450,
			L"%ws\\%ws", DirBuf, FileName );

		if ( ScanFileForName( FilePath, Ctx->ExecutableName, Ctx->NameLen ) )
		{
			FLOG( "JUMPLISTS artifact: %ws", FileName );

			Ctx->Entries[*Ctx->Count].Type = ARTIFACT_TYPE_JUMPLISTS;
			RtlStringCchPrintfW(
				Ctx->Entries[*Ctx->Count].Path,
				MAX_ARTIFACT_PATH,
				L"AutomaticDestinations\\%ws",
				FileName
			);
			( *Ctx->Count )++;
		}
	}

	ExFreePoolWithTag( Buffer, 'NdBf' );
	ZwClose( DirHandle );
}

static NTSTATUS ScanJumpListArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	JUMPLISTS_CTX Ctx;

	Ctx.ExecutableName = ExecutableName;
	Ctx.NameLen        = (ULONG)wcslen( ExecutableName );
	Ctx.Entries        = Entries;
	Ctx.MaxEntries     = MaxEntries;
	Ctx.Count          = Count;

	ForEachUserSid( JumpListsSidCallback, &Ctx );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * RecentDocs scanning
 *
 * For each user profile, scans .lnk files under
 * AppData\Roaming\Microsoft\Windows\Recent\ (LNK files contain
 * target paths as Unicode).
 * ----------------------------------------------------------------------- */

typedef struct _RECENTDOCS_CTX
{
	PCWSTR          ExecutableName;
	ULONG           NameLen;
	PARTIFACT_ENTRY Entries;
	ULONG           MaxEntries;
	PULONG          Count;
} RECENTDOCS_CTX, *PRECENTDOCS_CTX;

static VOID RecentDocsSidCallback(
	IN PCWSTR SidString,
	IN ULONG  SidChars,
	IN PVOID  Context
)
{
	PRECENTDOCS_CTX   Ctx = (PRECENTDOCS_CTX)Context;
	WCHAR              ProfilePath[260];
	WCHAR              DirBuf[350];
	UNICODE_STRING     DirPath;
	OBJECT_ATTRIBUTES  DirAttr;
	HANDLE             DirHandle = NULL;
	IO_STATUS_BLOCK    IoStatus;
	NTSTATUS           Status;
	PVOID              Buffer;
	BOOLEAN            FirstQuery = TRUE;

	UNREFERENCED_PARAMETER( SidChars );

	if ( !ResolveProfilePath( SidString, ProfilePath, 260 ) )
		return;

	RtlStringCchPrintfW( DirBuf, 350,
		L"%ws\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
		ProfilePath );
	RtlInitUnicodeString( &DirPath, DirBuf );
	InitializeObjectAttributes( &DirAttr, &DirPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwCreateFile(
		&DirHandle,
		FILE_LIST_DIRECTORY | SYNCHRONIZE,
		&DirAttr, &IoStatus, NULL,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	if ( !NT_SUCCESS( Status ) )
		return;

	Buffer = ExAllocatePool2( POOL_FLAG_PAGED, 4096, 'NdBf' );
	if ( !Buffer )
	{
		ZwClose( DirHandle );
		return;
	}

	while ( *Ctx->Count < Ctx->MaxEntries )
	{
		PFILE_DIRECTORY_INFORMATION DirInfo;
		ULONG  FileChars;
		WCHAR  FileName[128];
		WCHAR  FilePath[450];

		Status = ZwQueryDirectoryFile(
			DirHandle, NULL, NULL, NULL,
			&IoStatus, Buffer, 4096,
			FileDirectoryInformation, TRUE, NULL, FirstQuery );
		FirstQuery = FALSE;

		if ( !NT_SUCCESS( Status ) )
			break;

		DirInfo = (PFILE_DIRECTORY_INFORMATION)Buffer;

		if ( DirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY )
			continue;

		FileChars = DirInfo->FileNameLength / sizeof( WCHAR );
		if ( FileChars < 5 || FileChars >= 128 )
			continue;

		RtlCopyMemory( FileName, DirInfo->FileName, FileChars * sizeof( WCHAR ) );
		FileName[FileChars] = L'\0';

		/* Only process .lnk files */
		if ( _wcsicmp( FileName + FileChars - 4, L".lnk" ) != 0 )
			continue;

		RtlStringCchPrintfW( FilePath, 450,
			L"%ws\\%ws", DirBuf, FileName );

		if ( ScanFileForName( FilePath, Ctx->ExecutableName, Ctx->NameLen ) )
		{
			FLOG( "RECENTDOCS artifact: %ws", FileName );

			Ctx->Entries[*Ctx->Count].Type = ARTIFACT_TYPE_RECENTDOCS;
			RtlStringCchPrintfW(
				Ctx->Entries[*Ctx->Count].Path,
				MAX_ARTIFACT_PATH,
				L"Recent\\%ws",
				FileName
			);
			( *Ctx->Count )++;
		}
	}

	ExFreePoolWithTag( Buffer, 'NdBf' );
	ZwClose( DirHandle );
}

static NTSTATUS ScanRecentDocsArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	RECENTDOCS_CTX Ctx;

	Ctx.ExecutableName = ExecutableName;
	Ctx.NameLen        = (ULONG)wcslen( ExecutableName );
	Ctx.Entries        = Entries;
	Ctx.MaxEntries     = MaxEntries;
	Ctx.Count          = Count;

	ForEachUserSid( RecentDocsSidCallback, &Ctx );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * WER (Windows Error Reporting) scanning
 *
 * Enumerates WER\ReportArchive and WER\ReportQueue directories.
 * Checks if subdirectory names contain the executable name, and scans
 * Report.wer files inside matching directories.
 * ----------------------------------------------------------------------- */
static NTSTATUS ScanWerDirectory(
	IN     PCWSTR          BasePath,
	IN     PCWSTR          ExecutableName,
	IN     ULONG           NameLen,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	UNICODE_STRING     DirPath;
	OBJECT_ATTRIBUTES  DirAttr;
	HANDLE             DirHandle = NULL;
	IO_STATUS_BLOCK    IoStatus;
	NTSTATUS           Status;
	PVOID              Buffer;
	BOOLEAN            FirstQuery = TRUE;

	RtlInitUnicodeString( &DirPath, BasePath );
	InitializeObjectAttributes( &DirAttr, &DirPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwCreateFile(
		&DirHandle,
		FILE_LIST_DIRECTORY | SYNCHRONIZE,
		&DirAttr, &IoStatus, NULL,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	if ( !NT_SUCCESS( Status ) )
		return Status;

	Buffer = ExAllocatePool2( POOL_FLAG_PAGED, 4096, 'NdBf' );
	if ( !Buffer )
	{
		ZwClose( DirHandle );
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	while ( *Count < MaxEntries )
	{
		PFILE_DIRECTORY_INFORMATION DirInfo;
		ULONG  SubChars;
		WCHAR  SubDir[128];
		WCHAR  WerFilePath[400];

		Status = ZwQueryDirectoryFile(
			DirHandle, NULL, NULL, NULL,
			&IoStatus, Buffer, 4096,
			FileDirectoryInformation, TRUE, NULL, FirstQuery );
		FirstQuery = FALSE;

		if ( !NT_SUCCESS( Status ) )
			break;

		DirInfo = (PFILE_DIRECTORY_INFORMATION)Buffer;

		if ( !( DirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY ) )
			continue;

		SubChars = DirInfo->FileNameLength / sizeof( WCHAR );
		if ( SubChars >= 128 )
			continue;
		if ( SubChars <= 2 && DirInfo->FileName[0] == L'.' )
			continue;

		RtlCopyMemory( SubDir, DirInfo->FileName, SubChars * sizeof( WCHAR ) );
		SubDir[SubChars] = L'\0';

		/* Check if directory name contains the executable name */
		if ( WideSubstringMatch( SubDir, SubChars, ExecutableName, NameLen ) )
		{
			FLOG( "WER artifact: %ws\\%ws", BasePath, SubDir );

			Entries[*Count].Type = ARTIFACT_TYPE_WER;
			RtlStringCchPrintfW(
				Entries[*Count].Path,
				MAX_ARTIFACT_PATH,
				L"WER\\%ws",
				SubDir
			);
			( *Count )++;

			if ( *Count >= MaxEntries )
				break;

			/* Also scan Report.wer inside this directory */
			RtlStringCchPrintfW( WerFilePath, 400,
				L"%ws\\%ws\\Report.wer", BasePath, SubDir );

			if ( ScanFileForName( WerFilePath, ExecutableName, NameLen ) )
			{
				Entries[*Count].Type = ARTIFACT_TYPE_WER;
				RtlStringCchPrintfW(
					Entries[*Count].Path,
					MAX_ARTIFACT_PATH,
					L"WER\\%ws\\Report.wer",
					SubDir
				);
				( *Count )++;
			}
		}
	}

	ExFreePoolWithTag( Buffer, 'NdBf' );
	ZwClose( DirHandle );

	return STATUS_SUCCESS;
}

static NTSTATUS ScanWerArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	ULONG NameLen = (ULONG)wcslen( ExecutableName );

	ScanWerDirectory(
		L"\\??\\C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive",
		ExecutableName, NameLen, Entries, MaxEntries, Count );

	ScanWerDirectory(
		L"\\??\\C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue",
		ExecutableName, NameLen, Entries, MaxEntries, Count );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */
NTSTATUS KmScanForensicArtifacts(
	IN  PCWSTR          ExecutableName,
	IN  ULONG           ArtifactTypes,
	OUT PARTIFACT_ENTRY Entries,
	IN  ULONG           MaxEntries,
	OUT PULONG          FoundCount
)
{
	ULONG Count = 0;

	if ( !ExecutableName || !Entries || !FoundCount )
		return STATUS_INVALID_PARAMETER;

	*FoundCount = 0;

	FLOG( "=== Forensic artifact scan for '%ws' (types: 0x%X) ===",
		ExecutableName, ArtifactTypes );

	if ( ArtifactTypes & ARTIFACT_TYPE_PREFETCH )
		ScanPrefetchArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_SHIMCACHE )
		ScanShimCacheArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_BAM )
		ScanBamArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_AMCACHE )
		ScanAmCacheArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_USERASSIST )
		ScanUserAssistArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_MUICACHE )
		ScanMuiCacheArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_RECENTAPPS )
		ScanRecentAppsArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_RUNMRU )
		ScanRunMruArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_SRUM )
		ScanSrumArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_TIMELINE )
		ScanTimelineArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_JUMPLISTS )
		ScanJumpListArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_RECENTDOCS )
		ScanRecentDocsArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_EVTLOG )
		ScanEventLogArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_WER )
		ScanWerArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	if ( ArtifactTypes & ARTIFACT_TYPE_SUPERFETCH )
		ScanSuperfetchArtifacts( ExecutableName, Entries, MaxEntries, &Count );

	FLOG( "=== Scan complete: %lu artifacts found ===", Count );

	*FoundCount = Count;
	return STATUS_SUCCESS;
}
