#include "forensics.h"
#include <ntddk.h>
#include <ntstrsafe.h>

#if DBG
#define FLOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
	"[osmium:forensics] " fmt "\n", __VA_ARGS__)
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

	Buffer = ExAllocatePoolWithTag( PagedPool, 4096, 'pfKm' );
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

	ExFreePoolWithTag( Buffer, 'pfKm' );
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

	ValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(
		PagedPool, ResultLength, 'scKm' );
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

	ExFreePoolWithTag( ValueInfo, 'scKm' );
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

	KeyInfoBuffer = ExAllocatePoolWithTag( PagedPool, 1024, 'bmKm' );
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

		ValBuffer = ExAllocatePoolWithTag( PagedPool, 2048, 'bvKm' );
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

		ExFreePoolWithTag( ValBuffer, 'bvKm' );
		ZwClose( SidHandle );
	}

	ExFreePoolWithTag( KeyInfoBuffer, 'bmKm' );
	ZwClose( BamHandle );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * AmCache scanning
 *
 * The AmCache is a registry hive at Amcache.hve. Full parsing from
 * kernel mode is non-trivial. We report the hive's presence and size
 * as an indicator that execution records likely exist.
 * ----------------------------------------------------------------------- */
static NTSTATUS ScanAmCacheArtifacts(
	IN     PCWSTR          ExecutableName,
	OUT    PARTIFACT_ENTRY Entries,
	IN     ULONG           MaxEntries,
	IN OUT PULONG          Count
)
{
	UNICODE_STRING             FilePath;
	OBJECT_ATTRIBUTES          ObjAttr;
	HANDLE                     FileHandle = NULL;
	IO_STATUS_BLOCK            IoStatus;
	NTSTATUS                   Status;
	FILE_STANDARD_INFORMATION  FileInfo;

	if ( *Count >= MaxEntries )
		return STATUS_SUCCESS;

	RtlInitUnicodeString( &FilePath,
		L"\\??\\C:\\Windows\\appcompat\\Programs\\Amcache.hve" );
	InitializeObjectAttributes( &ObjAttr, &FilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

	Status = ZwCreateFile(
		&FileHandle,
		FILE_READ_ATTRIBUTES | SYNCHRONIZE,
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
	{
		FLOG( "Amcache.hve not accessible: 0x%08X", Status );
		return Status;
	}

	Status = ZwQueryInformationFile( FileHandle, &IoStatus, &FileInfo,
		sizeof( FileInfo ), FileStandardInformation );

	if ( NT_SUCCESS( Status ) )
	{
		FLOG( "AMCACHE hive present: Amcache.hve (%I64d bytes)"
			" — likely contains execution records for '%ws'",
			FileInfo.EndOfFile.QuadPart, ExecutableName );

		Entries[*Count].Type = ARTIFACT_TYPE_AMCACHE;
		RtlStringCchPrintfW(
			Entries[*Count].Path,
			MAX_ARTIFACT_PATH,
			L"C:\\Windows\\appcompat\\Programs\\Amcache.hve (%I64d bytes)",
			FileInfo.EndOfFile.QuadPart
		);

		/* Clearing AmCache from kernel is complex:
		 * — The hive is loaded by the system and locked.
		 * — Would require: ZwUnloadKey, modify offline, ZwLoadKey.
		 * — Or: delete specific subkeys if hive is accessible via
		 *   \Registry\Machine\... (requires knowing the mount point).
		 */

		( *Count )++;
	}

	ZwClose( FileHandle );

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

	FLOG( "=== Scan complete: %lu artifacts found ===", Count );

	*FoundCount = Count;
	return STATUS_SUCCESS;
}
