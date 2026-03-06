#pragma once

/*
 * Shared IOCTL definitions for kernel driver <-> user-mode communication.
 * Include from both kernel (main.c) and user-mode (driver_interface.hpp).
 *
 * Detection of kernel vs user-mode:
 *   Kernel includes <ntddk.h> which defines _NTDDK_, so we use that guard.
 */

#ifdef _NTDDK_
#include <ntddk.h>
#else
#include <Windows.h>
#include <winioctl.h>
#endif

#pragma pack(push, 8)

/* -----------------------------------------------------------------------
 * Device name configuration
 * Change these to blend with the target environment.
 * ----------------------------------------------------------------------- */
#define OSMIUM_DEVICE_NAME    L"NdisWanIp6"
#define OSMIUM_DEVICE_PATH    L"\\Device\\NdisWanIp6"
#define OSMIUM_SYMLINK_PATH   L"\\DosDevices\\NdisWanIp6"
#define OSMIUM_WIN32_DEVICE   L"\\\\.\\NdisWanIp6"

/* -----------------------------------------------------------------------
 * IOCTL codes
 * Non-sequential function codes to avoid obvious enumeration patterns.
 * ----------------------------------------------------------------------- */
#define IOCTL_READ_MEMORY       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9C1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA37, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_BASE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xB52, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE_BASE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC8E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ELEVATE_TOKEN     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE29, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_THREADS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD47, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUM_CALLBACKS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE5B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_CALLBACK   CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF72, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STRIP_HANDLES     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD93, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCAN_ARTIFACTS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xEB4, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* -----------------------------------------------------------------------
 * Request / Response structures
 * All pointer-width fields use ULONG64 for WoW64 safety.
 * ----------------------------------------------------------------------- */

/* IOCTL_READ_MEMORY / IOCTL_WRITE_MEMORY */
typedef struct _MEMORY_REQUEST
{
	ULONG64 ProcessId;
	ULONG64 Address;
	ULONG64 Buffer;         /* user-mode pointer to source/destination */
	ULONG64 Size;
} MEMORY_REQUEST, *PMEMORY_REQUEST;

typedef struct _MEMORY_RESPONSE
{
	ULONG64 BytesTransferred;
	LONG    Status;          /* NTSTATUS or Win32 error */
} MEMORY_RESPONSE, *PMEMORY_RESPONSE;

/* IOCTL_GET_PROCESS_BASE */
typedef struct _PROCESS_BASE_REQUEST
{
	ULONG64 ProcessId;
} PROCESS_BASE_REQUEST, *PPROCESS_BASE_REQUEST;

typedef struct _PROCESS_BASE_RESPONSE
{
	ULONG64 BaseAddress;
	LONG    Status;
} PROCESS_BASE_RESPONSE, *PPROCESS_BASE_RESPONSE;

/* IOCTL_GET_MODULE_BASE */
#define MAX_MODULE_NAME_LENGTH 256

typedef struct _MODULE_BASE_REQUEST
{
	ULONG64 ProcessId;
	WCHAR   ModuleName[MAX_MODULE_NAME_LENGTH];
} MODULE_BASE_REQUEST, *PMODULE_BASE_REQUEST;

typedef struct _MODULE_BASE_RESPONSE
{
	ULONG64 BaseAddress;
	ULONG64 ModuleSize;
	LONG    Status;
} MODULE_BASE_RESPONSE, *PMODULE_BASE_RESPONSE;

/* IOCTL_HIDE_THREADS */
typedef struct _HIDE_THREADS_REQUEST
{
	ULONG64 ProcessId;
} HIDE_THREADS_REQUEST, *PHIDE_THREADS_REQUEST;

typedef struct _HIDE_THREADS_RESPONSE
{
	LONG    Status;
	ULONG   ThreadsHidden;
} HIDE_THREADS_RESPONSE, *PHIDE_THREADS_RESPONSE;

/* IOCTL_ENUM_CALLBACKS */
#define CALLBACK_TYPE_PROCESS  0
#define CALLBACK_TYPE_THREAD   1
#define CALLBACK_TYPE_IMAGE    2
#define MAX_CALLBACK_ENTRIES   64

typedef struct _CALLBACK_ENTRY
{
	ULONG   Index;
	ULONG64 Address;
} CALLBACK_ENTRY, *PCALLBACK_ENTRY;

typedef struct _ENUM_CALLBACKS_REQUEST
{
	ULONG CallbackType;
} ENUM_CALLBACKS_REQUEST, *PENUM_CALLBACKS_REQUEST;

typedef struct _ENUM_CALLBACKS_RESPONSE
{
	LONG           Status;
	ULONG          Count;
	CALLBACK_ENTRY Entries[MAX_CALLBACK_ENTRIES];
} ENUM_CALLBACKS_RESPONSE, *PENUM_CALLBACKS_RESPONSE;

/* IOCTL_REMOVE_CALLBACK */
typedef struct _REMOVE_CALLBACK_REQUEST
{
	ULONG CallbackType;
	ULONG Index;          /* index into the callback array (from enumeration) */
} REMOVE_CALLBACK_REQUEST, *PREMOVE_CALLBACK_REQUEST;

typedef struct _REMOVE_CALLBACK_RESPONSE
{
	LONG Status;
} REMOVE_CALLBACK_RESPONSE, *PREMOVE_CALLBACK_RESPONSE;

/* IOCTL_STRIP_HANDLES */
typedef struct _STRIP_HANDLES_REQUEST
{
	ULONG64 ProcessId;
} STRIP_HANDLES_REQUEST, *PSTRIP_HANDLES_REQUEST;

typedef struct _STRIP_HANDLES_RESPONSE
{
	LONG    Status;
	ULONG   HandlesStripped;
} STRIP_HANDLES_RESPONSE, *PSTRIP_HANDLES_RESPONSE;

/* IOCTL_SCAN_ARTIFACTS */
#define ARTIFACT_TYPE_PREFETCH    0x0001
#define ARTIFACT_TYPE_SHIMCACHE   0x0002
#define ARTIFACT_TYPE_BAM         0x0004
#define ARTIFACT_TYPE_AMCACHE     0x0008
#define ARTIFACT_TYPE_USERASSIST  0x0010
#define ARTIFACT_TYPE_MUICACHE    0x0020
#define ARTIFACT_TYPE_RECENTAPPS  0x0040
#define ARTIFACT_TYPE_RUNMRU      0x0080
#define ARTIFACT_TYPE_SRUM        0x0100
#define ARTIFACT_TYPE_TIMELINE    0x0200
#define ARTIFACT_TYPE_JUMPLISTS   0x0400
#define ARTIFACT_TYPE_RECENTDOCS  0x0800
#define ARTIFACT_TYPE_EVTLOG      0x1000
#define ARTIFACT_TYPE_WER         0x2000
#define ARTIFACT_TYPE_SUPERFETCH  0x4000
#define ARTIFACT_TYPE_ALL         0x7FFF

#define MAX_ARTIFACT_ENTRIES      128
#define MAX_ARTIFACT_PATH         260

typedef struct _ARTIFACT_ENTRY
{
	ULONG Type;
	WCHAR Path[MAX_ARTIFACT_PATH];
} ARTIFACT_ENTRY, *PARTIFACT_ENTRY;

typedef struct _SCAN_ARTIFACTS_REQUEST
{
	WCHAR ExecutableName[MAX_MODULE_NAME_LENGTH];
	ULONG ArtifactTypes;     /* bitmask of ARTIFACT_TYPE_* */
} SCAN_ARTIFACTS_REQUEST, *PSCAN_ARTIFACTS_REQUEST;

typedef struct _SCAN_ARTIFACTS_RESPONSE
{
	LONG           Status;
	ULONG          Count;
	ARTIFACT_ENTRY Entries[MAX_ARTIFACT_ENTRIES];
} SCAN_ARTIFACTS_RESPONSE, *PSCAN_ARTIFACTS_RESPONSE;

/* IOCTL_HIDE_PROCESS */
typedef struct _HIDE_PROCESS_REQUEST
{
	ULONG64 ProcessId;
} HIDE_PROCESS_REQUEST, *PHIDE_PROCESS_REQUEST;

typedef struct _HIDE_PROCESS_RESPONSE
{
	LONG    Status;
} HIDE_PROCESS_RESPONSE, *PHIDE_PROCESS_RESPONSE;

/* IOCTL_ELEVATE_TOKEN */
typedef struct _ELEVATE_TOKEN_REQUEST
{
	ULONG64 ProcessId;
} ELEVATE_TOKEN_REQUEST, *PELEVATE_TOKEN_REQUEST;

typedef struct _ELEVATE_TOKEN_RESPONSE
{
	LONG    Status;
} ELEVATE_TOKEN_RESPONSE, *PELEVATE_TOKEN_RESPONSE;

#pragma pack(pop)
