#include <ntifs.h>
#include "../Shared/ioctl.h"
#include "memory.h"
#include "process.h"

/* -----------------------------------------------------------------------
 * Debug print macro — stripped in release builds
 * ----------------------------------------------------------------------- */
#if DBG
#define LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[osmium] " fmt "\n", __VA_ARGS__)
#else
#define LOG(fmt, ...) ((void)0)
#endif

/* -----------------------------------------------------------------------
 * Forward declarations
 * ----------------------------------------------------------------------- */
static NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
static NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
static NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
static VOID     DriverUnloadRoutine(IN PDRIVER_OBJECT DriverObject);

/* -----------------------------------------------------------------------
 * Dispatch: IRP_MJ_CREATE / IRP_MJ_CLOSE
 * ----------------------------------------------------------------------- */
static NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER( DeviceObject );

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	LOG( "Device opened" );

	return STATUS_SUCCESS;
}

static NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER( DeviceObject );

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	LOG( "Device closed" );

	return STATUS_SUCCESS;
}

/* -----------------------------------------------------------------------
 * Dispatch: IRP_MJ_DEVICE_CONTROL
 * ----------------------------------------------------------------------- */
static NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION Stack;
	ULONG              IoControlCode;
	PVOID              SystemBuffer;
	ULONG              InputLength;
	ULONG              OutputLength;
	NTSTATUS           Status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG              BytesReturned = 0;

	UNREFERENCED_PARAMETER( DeviceObject );

	Stack         = IoGetCurrentIrpStackLocation( Irp );
	IoControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;
	SystemBuffer  = Irp->AssociatedIrp.SystemBuffer;
	InputLength   = Stack->Parameters.DeviceIoControl.InputBufferLength;
	OutputLength  = Stack->Parameters.DeviceIoControl.OutputBufferLength;

	switch ( IoControlCode )
	{
		/* ---------------------------------------------------------------
		 * IOCTL_READ_MEMORY
		 * --------------------------------------------------------------- */
		case IOCTL_READ_MEMORY:
		{
			PMEMORY_REQUEST  Request;
			PMEMORY_RESPONSE Response;
			PEPROCESS        TargetProcess = NULL;
			SIZE_T           Copied = 0;
			PVOID            UserBuffer;

			if ( InputLength < sizeof( MEMORY_REQUEST ) ||
				 OutputLength < sizeof( MEMORY_RESPONSE ) )
			{
				Status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			Request  = (PMEMORY_REQUEST)SystemBuffer;
			Response = (PMEMORY_RESPONSE)SystemBuffer;

			if ( Request->Size == 0 || Request->Address == 0 )
			{
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			Status = PsLookupProcessByProcessId( (HANDLE)Request->ProcessId, &TargetProcess );
			if ( !NT_SUCCESS( Status ) )
				break;

			/* Allocate a kernel intermediate buffer (SystemBuffer belongs to I/O manager,
			   but we need the request fields before overwriting with response) */
			{
				ULONG64 ReqAddress  = Request->Address;
				ULONG64 ReqBuffer   = Request->Buffer;
				ULONG64 ReqSize     = Request->Size;

				/* Validate size to prevent excessive allocation */
				if ( ReqSize > 64 * 1024 * 1024 )
				{
					ObDereferenceObject( TargetProcess );
					Status = STATUS_INVALID_PARAMETER;
					break;
				}

				UserBuffer = (PVOID)(ULONG_PTR)ReqBuffer;

				Status = KmReadProcessMemory(
					TargetProcess,
					(PVOID)(ULONG_PTR)ReqAddress,
					UserBuffer,
					(SIZE_T)ReqSize,
					&Copied
				);

				ObDereferenceObject( TargetProcess );

				Response->BytesTransferred = (ULONG64)Copied;
				Response->Status = (LONG)Status;
				BytesReturned = sizeof( MEMORY_RESPONSE );

				/* Even if read partially failed, return the response */
				Status = STATUS_SUCCESS;
			}

			break;
		}

		/* ---------------------------------------------------------------
		 * IOCTL_WRITE_MEMORY
		 * --------------------------------------------------------------- */
		case IOCTL_WRITE_MEMORY:
		{
			PMEMORY_REQUEST  Request;
			PMEMORY_RESPONSE Response;
			PEPROCESS        TargetProcess = NULL;
			SIZE_T           Copied = 0;
			PVOID            UserBuffer;

			if ( InputLength < sizeof( MEMORY_REQUEST ) ||
				 OutputLength < sizeof( MEMORY_RESPONSE ) )
			{
				Status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			Request  = (PMEMORY_REQUEST)SystemBuffer;
			Response = (PMEMORY_RESPONSE)SystemBuffer;

			if ( Request->Size == 0 || Request->Address == 0 )
			{
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			Status = PsLookupProcessByProcessId( (HANDLE)Request->ProcessId, &TargetProcess );
			if ( !NT_SUCCESS( Status ) )
				break;

			{
				ULONG64 ReqAddress = Request->Address;
				ULONG64 ReqBuffer  = Request->Buffer;
				ULONG64 ReqSize    = Request->Size;

				if ( ReqSize > 64 * 1024 * 1024 )
				{
					ObDereferenceObject( TargetProcess );
					Status = STATUS_INVALID_PARAMETER;
					break;
				}

				UserBuffer = (PVOID)(ULONG_PTR)ReqBuffer;

				Status = KmWriteProcessMemory(
					TargetProcess,
					(PVOID)(ULONG_PTR)ReqAddress,
					UserBuffer,
					(SIZE_T)ReqSize,
					&Copied
				);

				ObDereferenceObject( TargetProcess );

				Response->BytesTransferred = (ULONG64)Copied;
				Response->Status = (LONG)Status;
				BytesReturned = sizeof( MEMORY_RESPONSE );

				Status = STATUS_SUCCESS;
			}

			break;
		}

		/* ---------------------------------------------------------------
		 * IOCTL_GET_PROCESS_BASE
		 * --------------------------------------------------------------- */
		case IOCTL_GET_PROCESS_BASE:
		{
			PPROCESS_BASE_REQUEST  Request;
			PPROCESS_BASE_RESPONSE Response;

			if ( InputLength < sizeof( PROCESS_BASE_REQUEST ) ||
				 OutputLength < sizeof( PROCESS_BASE_RESPONSE ) )
			{
				Status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			Request  = (PPROCESS_BASE_REQUEST)SystemBuffer;
			Response = (PPROCESS_BASE_RESPONSE)SystemBuffer;

			{
				ULONG64 Pid = Request->ProcessId;
				ULONG64 Base = 0;

				Status = KmGetProcessBaseAddress( (HANDLE)Pid, &Base );

				Response->BaseAddress = Base;
				Response->Status = (LONG)Status;
				BytesReturned = sizeof( PROCESS_BASE_RESPONSE );

				Status = STATUS_SUCCESS;
			}

			break;
		}

		/* ---------------------------------------------------------------
		 * IOCTL_GET_MODULE_BASE
		 * --------------------------------------------------------------- */
		case IOCTL_GET_MODULE_BASE:
		{
			PMODULE_BASE_REQUEST  Request;
			PMODULE_BASE_RESPONSE Response;

			if ( InputLength < sizeof( MODULE_BASE_REQUEST ) ||
				 OutputLength < sizeof( MODULE_BASE_RESPONSE ) )
			{
				Status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			Request  = (PMODULE_BASE_REQUEST)SystemBuffer;
			Response = (PMODULE_BASE_RESPONSE)SystemBuffer;

			/* Ensure null termination */
			Request->ModuleName[MAX_MODULE_NAME_LENGTH - 1] = L'\0';

			{
				ULONG64 Pid  = Request->ProcessId;
				WCHAR   Name[MAX_MODULE_NAME_LENGTH];
				ULONG64 Base = 0;
				ULONG64 Size = 0;

				RtlCopyMemory( Name, Request->ModuleName, sizeof( Name ) );

				Status = KmGetModuleBaseByName( (HANDLE)Pid, Name, &Base, &Size );

				Response->BaseAddress = Base;
				Response->ModuleSize  = Size;
				Response->Status = (LONG)Status;
				BytesReturned = sizeof( MODULE_BASE_RESPONSE );

				Status = STATUS_SUCCESS;
			}

			break;
		}

		default:
			Status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesReturned;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	return Status;
}

/* -----------------------------------------------------------------------
 * Driver Unload
 * ----------------------------------------------------------------------- */
static VOID DriverUnloadRoutine(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING SymlinkName;

	RtlInitUnicodeString( &SymlinkName, OSMIUM_SYMLINK_PATH );
	IoDeleteSymbolicLink( &SymlinkName );

	if ( DriverObject->DeviceObject )
		IoDeleteDevice( DriverObject->DeviceObject );

	LOG( "Driver unloaded" );
}

/* -----------------------------------------------------------------------
 * DriverEntry
 * ----------------------------------------------------------------------- */
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT  DriverObject,
	IN PUNICODE_STRING RegistryPath
)
{
	NTSTATUS        Status;
	PDEVICE_OBJECT  DeviceObject = NULL;
	UNICODE_STRING  DeviceName;
	UNICODE_STRING  SymlinkName;
	ULONG           i;

	UNREFERENCED_PARAMETER( RegistryPath );

	LOG( "Driver loading" );

	/* Create device object */
	RtlInitUnicodeString( &DeviceName, OSMIUM_DEVICE_PATH );
	RtlInitUnicodeString( &SymlinkName, OSMIUM_SYMLINK_PATH );

	Status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject
	);

	if ( !NT_SUCCESS( Status ) )
	{
		LOG( "IoCreateDevice failed: 0x%08X", Status );
		return Status;
	}

	/* Create symbolic link for user-mode access */
	Status = IoCreateSymbolicLink( &SymlinkName, &DeviceName );
	if ( !NT_SUCCESS( Status ) )
	{
		LOG( "IoCreateSymbolicLink failed: 0x%08X", Status );
		IoDeleteDevice( DeviceObject );
		return Status;
	}

	/* Set dispatch routines — handle all major functions to avoid
	   "unhandled IRP" signatures from driver verifier / scanners */
	for ( i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++ )
	{
		DriverObject->MajorFunction[i] = DispatchCreate; /* default: succeed silently */
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
	DriverObject->DriverUnload                          = DriverUnloadRoutine;

	/* Clear the initializing flag */
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	LOG( "Driver loaded successfully" );

	return STATUS_SUCCESS;
}
