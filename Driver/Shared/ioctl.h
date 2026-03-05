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

#pragma pack(pop)
