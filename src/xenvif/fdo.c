/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */

#define INITGUID 1

#include <ntddk.h>
#include <wdmguid.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <util.h>

#include <evtchn_interface.h>
#include <debug_interface.h>
#include <store_interface.h>
#include <gnttab_interface.h>
#include <suspend_interface.h>
#include <emulated_interface.h>

#include "driver.h"
#include "registry.h"
#include "fdo.h"
#include "pdo.h"
#include "thread.h"
#include "mutex.h"
#include "frontend.h"
#include "names.h"
#include "log.h"
#include "assert.h"

#define FDO_POOL 'ODF'

#define MAXNAMELEN  128

typedef enum _FDO_RESOURCE_TYPE {
    MEMORY_RESOURCE = 0,
    INTERRUPT_RESOURCE,
    RESOURCE_COUNT
} FDO_RESOURCE_TYPE, *PFDO_RESOURCE_TYPE;

typedef struct _FDO_RESOURCE {
    CM_PARTIAL_RESOURCE_DESCRIPTOR Raw;
    CM_PARTIAL_RESOURCE_DESCRIPTOR Translated;
} FDO_RESOURCE, *PFDO_RESOURCE;

struct _XENVIF_FDO {
    PXENVIF_DX                  Dx;
    PDEVICE_OBJECT              LowerDeviceObject;
    PDEVICE_OBJECT              PhysicalDeviceObject;
    DEVICE_CAPABILITIES         LowerDeviceCapabilities;
    ULONG                       Usage[DeviceUsageTypeDumpFile + 1];
    BOOLEAN                     NotDisableable;

    PXENVIF_THREAD              SystemPowerThread;
    PIRP                        SystemPowerIrp;
    PXENVIF_THREAD              DevicePowerThread;
    PIRP                        DevicePowerIrp;

    PXENVIF_THREAD              ScanThread;
    KEVENT                      ScanEvent;
    PXENBUS_STORE_WATCH         ScanWatch;
    XENVIF_MUTEX                Mutex;
    ULONG                       References;

    FDO_RESOURCE                Resource[RESOURCE_COUNT];

    PXENBUS_EVTCHN_INTERFACE    EvtchnInterface;
    PXENBUS_DEBUG_INTERFACE     DebugInterface;
    PXENBUS_STORE_INTERFACE     StoreInterface;
    PXENBUS_GNTTAB_INTERFACE    GnttabInterface;
    PXENBUS_SUSPEND_INTERFACE   SuspendInterface;
    PXENFILT_EMULATED_INTERFACE EmulatedInterface;

    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
};

static FORCEINLINE PVOID
__FdoAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, FDO_POOL);
}

static FORCEINLINE VOID
__FdoFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, FDO_POOL);
}

static FORCEINLINE VOID
__FdoSetDevicePnpState(
    IN  PXENVIF_FDO         Fdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENVIF_DX              Dx = Fdo->Dx;

    // We can never transition out of the deleted state
    ASSERT(Dx->DevicePnpState != Deleted || State == Deleted);

    Dx->PreviousDevicePnpState = Dx->DevicePnpState;
    Dx->DevicePnpState = State;
}

static FORCEINLINE VOID
__FdoRestoreDevicePnpState(
    IN  PXENVIF_FDO         Fdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENVIF_DX              Dx = Fdo->Dx;

    if (Dx->DevicePnpState == State)
        Dx->DevicePnpState = Dx->PreviousDevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__FdoGetDevicePnpState(
    IN  PXENVIF_FDO     Fdo
    )
{
    PXENVIF_DX          Dx = Fdo->Dx;

    return Dx->DevicePnpState;
}

static FORCEINLINE VOID
__FdoSetDevicePowerState(
    IN  PXENVIF_FDO         Fdo,
    IN  DEVICE_POWER_STATE  State
    )
{
    PXENVIF_DX              Dx = Fdo->Dx;

    Dx->DevicePowerState = State;
}

static FORCEINLINE DEVICE_POWER_STATE
__FdoGetDevicePowerState(
    IN  PXENVIF_FDO     Fdo
    )
{
    PXENVIF_DX          Dx = Fdo->Dx;

    return Dx->DevicePowerState;
}

static FORCEINLINE VOID
__FdoSetSystemPowerState(
    IN  PXENVIF_FDO         Fdo,
    IN  SYSTEM_POWER_STATE  State
    )
{
    PXENVIF_DX              Dx = Fdo->Dx;

    Dx->SystemPowerState = State;
}

static FORCEINLINE SYSTEM_POWER_STATE
__FdoGetSystemPowerState(
    IN  PXENVIF_FDO     Fdo
    )
{
    PXENVIF_DX          Dx = Fdo->Dx;

    return Dx->SystemPowerState;
}

static FORCEINLINE PDEVICE_OBJECT
__FdoGetPhysicalDeviceObject(
    IN  PXENVIF_FDO Fdo
    )
{
    return Fdo->PhysicalDeviceObject;
}

PDEVICE_OBJECT
FdoGetPhysicalDeviceObject(
    IN  PXENVIF_FDO Fdo
    )
{
    return __FdoGetPhysicalDeviceObject(Fdo);
}

static FORCEINLINE NTSTATUS
__FdoSetName(
    IN  PXENVIF_FDO Fdo,
    IN  PWCHAR      Name
    )
{
    PXENVIF_DX      Dx = Fdo->Dx;
    UNICODE_STRING  Unicode;
    ANSI_STRING     Ansi;
    ULONG           Index;
    NTSTATUS        status;

    RtlInitUnicodeString(&Unicode, Name);

    Ansi.Buffer = Dx->Name;
    Ansi.MaximumLength = sizeof (Dx->Name);
    Ansi.Length = 0;

    status = RtlUnicodeStringToAnsiString(&Ansi, &Unicode, FALSE);
    if (!NT_SUCCESS(status))
        goto fail1;
    
    for (Index = 0; Dx->Name[Index] != '\0'; Index++) {
        if (!isalnum((UCHAR)Dx->Name[Index]))
            Dx->Name[Index] = '_';
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE PCHAR
__FdoGetName(
    IN  PXENVIF_FDO Fdo
    )
{
    PXENVIF_DX      Dx = Fdo->Dx;

    return Dx->Name;
}

PCHAR
FdoGetName(
    IN  PXENVIF_FDO Fdo
    )
{
    return __FdoGetName(Fdo);
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__FdoDelegateIrp(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PKEVENT             Event = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
FdoDelegateIrp(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PDEVICE_OBJECT      DeviceObject;
    PIO_STACK_LOCATION  StackLocation;
    PIRP                SubIrp;
    KEVENT              Event;
    PIO_STACK_LOCATION  SubStackLocation;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    // Find the top of the FDO stack and hold a reference
    DeviceObject = IoGetAttachedDeviceReference(Fdo->Dx->DeviceObject);

    // Get a new IRP for the FDO stack
    SubIrp = IoAllocateIrp(DeviceObject->StackSize, FALSE);

    status = STATUS_NO_MEMORY;
    if (SubIrp == NULL)
        goto done;

    // Copy in the information from the original IRP
    SubStackLocation = IoGetNextIrpStackLocation(SubIrp);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    RtlCopyMemory(SubStackLocation, StackLocation,
                  FIELD_OFFSET(IO_STACK_LOCATION, CompletionRoutine));
    SubStackLocation->Control = 0;

    IoSetCompletionRoutine(SubIrp,
                           __FdoDelegateIrp,
                           &Event,
                           TRUE,
                           TRUE,
                           TRUE);

    // Default completion status
    SubIrp->IoStatus.Status = Irp->IoStatus.Status;

    status = IoCallDriver(DeviceObject, SubIrp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = SubIrp->IoStatus.Status;
    } else {
        ASSERT3U(status, ==, SubIrp->IoStatus.Status);
    }

    IoFreeIrp(SubIrp);

done:
    ObDereferenceObject(DeviceObject);

    return status;
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
__FdoForwardIrpSynchronously(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PKEVENT             Event = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
FdoForwardIrpSynchronously(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    KEVENT              Event;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           __FdoForwardIrpSynchronously,
                           &Event,
                           TRUE,
                           TRUE,
                           TRUE);

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = Irp->IoStatus.Status;
    } else {
        ASSERT3U(status, ==, Irp->IoStatus.Status);
    }

    Trace("%08x\n", status);

    return status;
}

VOID
FdoAddPhysicalDeviceObject(
    IN  PXENVIF_FDO     Fdo,
    IN  PXENVIF_PDO     Pdo
    )
{
    PDEVICE_OBJECT      DeviceObject;
    PXENVIF_DX          Dx;

    DeviceObject = PdoGetDeviceObject(Pdo);
    Dx = (PXENVIF_DX)DeviceObject->DeviceExtension;
    ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

    InsertTailList(&Fdo->Dx->ListEntry, &Dx->ListEntry);
    ASSERT3U(Fdo->References, !=, 0);
    Fdo->References++;

    PdoResume(Pdo);
}

VOID
FdoRemovePhysicalDeviceObject(
    IN  PXENVIF_FDO     Fdo,
    IN  PXENVIF_PDO     Pdo
    )
{
    PDEVICE_OBJECT      DeviceObject;
    PXENVIF_DX          Dx;

    DeviceObject = PdoGetDeviceObject(Pdo);
    Dx = (PXENVIF_DX)DeviceObject->DeviceExtension;
    ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

    PdoSuspend(Pdo);

    RemoveEntryList(&Dx->ListEntry);
    ASSERT3U(Fdo->References, !=, 0);
    --Fdo->References;

    if (Fdo->ScanThread)
        ThreadWake(Fdo->ScanThread);
}

static FORCEINLINE VOID
__FdoAcquireMutex(
    IN  PXENVIF_FDO     Fdo
    )
{
    AcquireMutex(&Fdo->Mutex);
}

VOID
FdoAcquireMutex(
    IN  PXENVIF_FDO     Fdo
    )
{
    __FdoAcquireMutex(Fdo);
}

static FORCEINLINE VOID
__FdoReleaseMutex(
    IN  PXENVIF_FDO     Fdo
    )
{
    ReleaseMutex(&Fdo->Mutex);
}

VOID
FdoReleaseMutex(
    IN  PXENVIF_FDO     Fdo
    )
{
    __FdoReleaseMutex(Fdo);

    if (Fdo->References == 0)
        FdoDestroy(Fdo);
}

static FORCEINLINE BOOLEAN
__FdoEnumerate(
    IN  PXENVIF_FDO     Fdo,
    IN  PANSI_STRING    Devices
    )
{
    BOOLEAN             NeedInvalidate;
    PLIST_ENTRY         ListEntry;
    ULONG               Index;

    Trace("====>\n");

    NeedInvalidate = FALSE;

    if (DriverParameters.CreatePDOs == 0)
        goto done;

    __FdoAcquireMutex(Fdo);

    ListEntry = Fdo->Dx->ListEntry.Flink;
    while (ListEntry != &Fdo->Dx->ListEntry) {
        PLIST_ENTRY     Next = ListEntry->Flink;
        PXENVIF_DX      Dx = CONTAINING_RECORD(ListEntry, XENVIF_DX, ListEntry);
        PCHAR           Name = Dx->Name;
        PXENVIF_PDO     Pdo = Dx->Pdo;
        BOOLEAN         Missing;

        Missing = TRUE;

        // If the PDO exists in the device list
        // from xenstore then we don't want to remove it.

        for (Index = 0; Devices[Index].Buffer != NULL; Index++) {
            PANSI_STRING Device = &Devices[Index];

            if (strcmp(Name, Device->Buffer) == 0) {
                Missing = FALSE;
                Device->Length = 0;  // avoid duplication
                break;
            }
        }

        if (Missing &&
            !PdoIsMissing(Pdo) &&
            PdoGetDevicePnpState(Pdo) != Deleted) {
            PdoSetMissing(Pdo, "device disappeared");

            // If the PDO has not yet been enumerated then we can go ahead
            // and mark it as deleted, otherwise we need to notify PnP manager and
            // wait for the REMOVE_DEVICE IRP.
            if (PdoGetDevicePnpState(Pdo) == Present) {
                PdoSetDevicePnpState(Pdo, Deleted);
                PdoDestroy(Pdo);
            } else {
                NeedInvalidate = TRUE;
            }
        }

        ListEntry = Next;
    }

    // Check the device list from xenstore against the unsupported list
    for (Index = 0; Devices[Index].Buffer != NULL; Index++) {
        PANSI_STRING    Device = &Devices[Index];
        ULONG           Entry;
        BOOLEAN         Supported;

        Supported = TRUE;

        for (Entry = 0;
             DriverParameters.UnsupportedDevices != NULL && DriverParameters.UnsupportedDevices[Entry].Buffer != NULL;
             Entry++) {
            if (strncmp(Device->Buffer,
                        DriverParameters.UnsupportedDevices[Entry].Buffer,
                        Device->Length) == 0) {
                Supported = FALSE;
                break;
            }
        }

        if (!Supported)
            Device->Length = 0;  // avoid creation
    }

    // Walk the device list and create PDOs for any new devices

    for (Index = 0; Devices[Index].Buffer != NULL; Index++) {
        PANSI_STRING    Device = &Devices[Index];

        if (Device->Length != 0) {
            NTSTATUS        status;

            status = PdoCreate(Fdo, Device);
            if (NT_SUCCESS(status))
                NeedInvalidate = TRUE;
        }
    }

    __FdoReleaseMutex(Fdo);

done:
    Trace("<====\n");
    return NeedInvalidate;
}

static FORCEINLINE PANSI_STRING
__FdoMultiSzToUpcaseAnsi(
    IN  PCHAR       Buffer
    )
{
    PANSI_STRING    Ansi;
    LONG            Index;
    LONG            Count;
    NTSTATUS        status;

    Index = 0;
    Count = 0;
    for (;;) {
        if (Buffer[Index] == '\0') {
            Count++;
            Index++;

            // Check for double NUL
            if (Buffer[Index] == '\0')
                break;
        } else {
            Buffer[Index] = (CHAR)toupper(Buffer[Index]);
            Index++;
        }
    }

    Ansi = __FdoAllocate(sizeof (ANSI_STRING) * (Count + 1));

    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        ULONG   Length;

        Length = (ULONG)strlen(Buffer);
        Ansi[Index].MaximumLength = (USHORT)(Length + 1);
        Ansi[Index].Buffer = __FdoAllocate(Ansi[Index].MaximumLength);

        status = STATUS_NO_MEMORY;
        if (Ansi[Index].Buffer == NULL)
            goto fail2;

        RtlCopyMemory(Ansi[Index].Buffer, Buffer, Length);
        Ansi[Index].Length = (USHORT)Length;

        Buffer += Length + 1;
    }

    return Ansi;

fail2:
    Error("fail2\n");

    while (--Index >= 0)
        __FdoFree(Ansi[Index].Buffer);

    __FdoFree(Ansi);

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;
}

static FORCEINLINE VOID
__FdoFreeAnsi(
    IN  PANSI_STRING    Ansi
    )
{
    ULONG               Index;

    for (Index = 0; Ansi[Index].Buffer != NULL; Index++)
        __FdoFree(Ansi[Index].Buffer);
        
    __FdoFree(Ansi);
}

static NTSTATUS
FdoScan(
    PXENVIF_THREAD      Self,
    PVOID               Context
    )
{
    PXENVIF_FDO         Fdo = Context;
    BOOLEAN             NeedInvalidate;
    PKEVENT             Event;

    Trace("====>\n");

    NeedInvalidate = FALSE;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PCHAR           Buffer;
        PANSI_STRING    Devices;
        NTSTATUS        status;

        Trace("waiting...\n");

        (VOID) KeWaitForSingleObject(Event,
                                        Executive,
                                        KernelMode,
                                        FALSE,
                                        NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        STORE(Acquire, Fdo->StoreInterface);

        if (__FdoGetDevicePnpState(Fdo) != Started)
            goto loop;

        status = STORE(Directory,
                       Fdo->StoreInterface,
                       NULL,
                       "device",
                       "vif",
                       &Buffer);
        if (!NT_SUCCESS(status))
            goto loop;

        Devices = __FdoMultiSzToUpcaseAnsi(Buffer);

        STORE(Free,
              Fdo->StoreInterface,
              Buffer);

        if (Devices != NULL) {
            NeedInvalidate = __FdoEnumerate(Fdo, Devices);
            __FdoFreeAnsi(Devices);
        }

        if (NeedInvalidate) {
            NeedInvalidate = FALSE;
            IoInvalidateDeviceRelations(__FdoGetPhysicalDeviceObject(Fdo), 
                                        BusRelations);
        }

loop:
        STORE(Release, Fdo->StoreInterface);

        KeSetEvent(&Fdo->ScanEvent, IO_NO_INCREMENT, FALSE);
    }

    KeSetEvent(&Fdo->ScanEvent, IO_NO_INCREMENT, FALSE);

    Trace("<====\n");
    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
FdoParseResources(
    IN  PXENVIF_FDO             Fdo,
    IN  PCM_RESOURCE_LIST       RawResourceList,
    IN  PCM_RESOURCE_LIST       TranslatedResourceList
    )
{
    PCM_PARTIAL_RESOURCE_LIST   RawPartialList;
    PCM_PARTIAL_RESOURCE_LIST   TranslatedPartialList;
    ULONG                       Index;

    ASSERT3U(RawResourceList->Count, ==, 1);
    RawPartialList = &RawResourceList->List[0].PartialResourceList;

    ASSERT3U(RawPartialList->Version, ==, 1);
    ASSERT3U(RawPartialList->Revision, ==, 1);

    ASSERT3U(TranslatedResourceList->Count, ==, 1);
    TranslatedPartialList = &TranslatedResourceList->List[0].PartialResourceList;

    ASSERT3U(TranslatedPartialList->Version, ==, 1);
    ASSERT3U(TranslatedPartialList->Revision, ==, 1);

    for (Index = 0; Index < TranslatedPartialList->Count; Index++) {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR RawPartialDescriptor;
        PCM_PARTIAL_RESOURCE_DESCRIPTOR TranslatedPartialDescriptor;

        RawPartialDescriptor = &RawPartialList->PartialDescriptors[Index];
        TranslatedPartialDescriptor = &TranslatedPartialList->PartialDescriptors[Index];

        switch (TranslatedPartialDescriptor->Type) {
        case CmResourceTypeMemory:
            Fdo->Resource[MEMORY_RESOURCE].Raw = *RawPartialDescriptor;
            Fdo->Resource[MEMORY_RESOURCE].Translated = *TranslatedPartialDescriptor;
            break;

        case CmResourceTypeInterrupt:
            Fdo->Resource[INTERRUPT_RESOURCE].Raw = *RawPartialDescriptor;
            Fdo->Resource[INTERRUPT_RESOURCE].Translated = *TranslatedPartialDescriptor;
            break;

        default:
            break;
        }
    }
}

PXENBUS_EVTCHN_INTERFACE
FdoGetEvtchnInterface(
    IN  PXENVIF_FDO Fdo
    )
{
    return Fdo->EvtchnInterface;
}

PXENBUS_DEBUG_INTERFACE
FdoGetDebugInterface(
    IN  PXENVIF_FDO Fdo
    )
{
    return Fdo->DebugInterface;
}

PXENBUS_STORE_INTERFACE
FdoGetStoreInterface(
    IN  PXENVIF_FDO Fdo
    )
{
    return Fdo->StoreInterface;
}

PXENBUS_GNTTAB_INTERFACE
FdoGetGnttabInterface(
    IN  PXENVIF_FDO Fdo
    )
{
    return Fdo->GnttabInterface;
}

PXENBUS_SUSPEND_INTERFACE
FdoGetSuspendInterface(
    IN  PXENVIF_FDO Fdo
    )
{
    return Fdo->SuspendInterface;
}

static FORCEINLINE PXENFILT_EMULATED_INTERFACE
__FdoGetEmulatedInterface(
    IN  PXENVIF_FDO Fdo
    )
{
    return Fdo->EmulatedInterface;
}

PXENFILT_EMULATED_INTERFACE
FdoGetEmulatedInterface(
    IN  PXENVIF_FDO Fdo
    )
{
    return __FdoGetEmulatedInterface(Fdo);
}

static FORCEINLINE NTSTATUS
__FdoD3ToD0(
    IN  PXENVIF_FDO Fdo
    )
{
    POWER_STATE     PowerState;
    NTSTATUS        status;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3U(__FdoGetDevicePowerState(Fdo), ==, PowerDeviceD3);

    __FdoSetDevicePowerState(Fdo, PowerDeviceD0);

    STORE(Acquire, Fdo->StoreInterface);

    status = STORE(Watch,
                   Fdo->StoreInterface,
                   "device",
                   "vif",
                   ThreadGetEvent(Fdo->ScanThread),
                   &Fdo->ScanWatch);
    if (!NT_SUCCESS(status))
        goto fail1;

    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(Fdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    STORE(Release, Fdo->StoreInterface);

    __FdoSetDevicePowerState(Fdo, PowerDeviceD3);

    return status;
}

static FORCEINLINE VOID
__FdoD0ToD3(
    IN  PXENVIF_FDO Fdo
    )
{
    POWER_STATE     PowerState;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3U(__FdoGetDevicePowerState(Fdo), ==, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD3;
    PoSetPowerState(Fdo->Dx->DeviceObject,
                    DevicePowerState,
                    PowerState);

    __FdoSetDevicePowerState(Fdo, PowerDeviceD3);

    (VOID) STORE(Unwatch,
                 Fdo->StoreInterface,
                 Fdo->ScanWatch);
    Fdo->ScanWatch = NULL;

    STORE(Release, Fdo->StoreInterface);

    Trace("<====\n");
}

static DECLSPEC_NOINLINE VOID
FdoSuspendCallbackLate(
    IN  PVOID   Argument
    )
{
    PXENVIF_FDO Fdo = Argument;
    NTSTATUS    status;

    __FdoD0ToD3(Fdo);

    status = __FdoD3ToD0(Fdo);
    ASSERT(NT_SUCCESS(status));
}

static DECLSPEC_NOINLINE NTSTATUS
FdoD3ToD0(
    IN  PXENVIF_FDO Fdo
    )
{
    KIRQL           Irql;
    PLIST_ENTRY     ListEntry;
    NTSTATUS        status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    status = __FdoD3ToD0(Fdo);
    if (!NT_SUCCESS(status))
        goto fail1;

    SUSPEND(Acquire, Fdo->SuspendInterface);
    
    status = SUSPEND(Register,
                     Fdo->SuspendInterface,
                     SUSPEND_CALLBACK_LATE,
                     FdoSuspendCallbackLate,
                     Fdo,
                     &Fdo->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail2;

    KeLowerIrql(Irql);

    __FdoAcquireMutex(Fdo);

    for (ListEntry = Fdo->Dx->ListEntry.Flink;
         ListEntry != &Fdo->Dx->ListEntry;
         ListEntry = ListEntry->Flink) {
        PXENVIF_DX  Dx = CONTAINING_RECORD(ListEntry, XENVIF_DX, ListEntry);
        PXENVIF_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        PdoResume(Pdo);
    }

    __FdoReleaseMutex(Fdo);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    SUSPEND(Release, Fdo->SuspendInterface);

    __FdoD0ToD3(Fdo);

fail1:
    Error("fail1 (%08x)\n", status);

    KeLowerIrql(Irql);

    return status;
}

static DECLSPEC_NOINLINE VOID
FdoD0ToD3(
    IN  PXENVIF_FDO Fdo
    )
{
    PLIST_ENTRY     ListEntry;
    KIRQL           Irql;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    __FdoAcquireMutex(Fdo);

    for (ListEntry = Fdo->Dx->ListEntry.Flink;
         ListEntry != &Fdo->Dx->ListEntry;
         ListEntry = ListEntry->Flink) {
        PXENVIF_DX  Dx = CONTAINING_RECORD(ListEntry, XENVIF_DX, ListEntry);
        PXENVIF_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (PdoGetDevicePnpState(Pdo) == Deleted ||
            PdoIsMissing(Pdo))
            continue;

        PdoSuspend(Pdo);
    }

    __FdoReleaseMutex(Fdo);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    SUSPEND(Deregister,
            Fdo->SuspendInterface,
            Fdo->SuspendCallbackLate);
    Fdo->SuspendCallbackLate = NULL;

    SUSPEND(Release, Fdo->SuspendInterface);

    __FdoD0ToD3(Fdo);

    KeLowerIrql(Irql);
}

static DECLSPEC_NOINLINE VOID
FdoS4ToS3(
    IN  PXENVIF_FDO         Fdo
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__FdoGetSystemPowerState(Fdo), ==, PowerSystemHibernate);

    __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
}

static DECLSPEC_NOINLINE VOID
FdoS3ToS4(
    IN  PXENVIF_FDO Fdo
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__FdoGetSystemPowerState(Fdo), ==, PowerSystemSleeping3);

    __FdoSetSystemPowerState(Fdo, PowerSystemHibernate);
}

static DECLSPEC_NOINLINE NTSTATUS
FdoStartDevice(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    FdoParseResources(Fdo,
                      StackLocation->Parameters.StartDevice.AllocatedResources,
                      StackLocation->Parameters.StartDevice.AllocatedResourcesTranslated);

    KeInitializeEvent(&Fdo->ScanEvent, NotificationEvent, FALSE);

    status = ThreadCreate(FdoScan, Fdo, &Fdo->ScanThread);
    if (!NT_SUCCESS(status))
        goto fail2;

    __FdoSetSystemPowerState(Fdo, PowerSystemHibernate);
     FdoS4ToS3(Fdo);
    __FdoSetSystemPowerState(Fdo, PowerSystemWorking);

    status = FdoD3ToD0(Fdo);
    if (!NT_SUCCESS(status))
        goto fail3;

    __FdoSetDevicePnpState(Fdo, Started);
    ThreadWake(Fdo->ScanThread);

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

fail3:
    Error("fail3\n");

    __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
    FdoS3ToS4(Fdo);
    __FdoSetSystemPowerState(Fdo, PowerSystemShutdown);

    ThreadAlert(Fdo->ScanThread);
    ThreadJoin(Fdo->ScanThread);
    Fdo->ScanThread = NULL;

fail2:
    Error("fail2\n");

    RtlZeroMemory(&Fdo->ScanEvent, sizeof (KEVENT));

    RtlZeroMemory(&Fdo->Resource, sizeof (FDO_RESOURCE) * RESOURCE_COUNT);

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoQueryStopDevice(
    IN  PXENVIF_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __FdoSetDevicePnpState(Fdo, StopPending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoCancelStopDevice(
    IN  PXENVIF_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    Irp->IoStatus.Status = STATUS_SUCCESS;

    __FdoRestoreDevicePnpState(Fdo, StopPending);

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoStopDevice(
    IN  PXENVIF_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    FdoD0ToD3(Fdo);

    __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
    FdoS3ToS4(Fdo);
    __FdoSetSystemPowerState(Fdo, PowerSystemShutdown);

    ThreadAlert(Fdo->ScanThread);
    ThreadJoin(Fdo->ScanThread);
    Fdo->ScanThread = NULL;

    RtlZeroMemory(&Fdo->ScanEvent, sizeof (KEVENT));

    RtlZeroMemory(&Fdo->Resource, sizeof (FDO_RESOURCE) * RESOURCE_COUNT);

    __FdoSetDevicePnpState(Fdo, Stopped);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoQueryRemoveDevice(
    IN  PXENVIF_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __FdoSetDevicePnpState(Fdo, RemovePending);
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoCancelRemoveDevice(
    IN  PXENVIF_FDO Fdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __FdoRestoreDevicePnpState(Fdo, RemovePending);

    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoSurpriseRemoval(
    IN  PXENVIF_FDO Fdo,
    IN  PIRP        Irp
    )
{
    PLIST_ENTRY     ListEntry;
    NTSTATUS        status;

    __FdoSetDevicePnpState(Fdo, SurpriseRemovePending);

    __FdoAcquireMutex(Fdo);

    for (ListEntry = Fdo->Dx->ListEntry.Flink;
         ListEntry != &Fdo->Dx->ListEntry;
         ListEntry = ListEntry->Flink) {
        PXENVIF_DX  Dx = CONTAINING_RECORD(ListEntry, XENVIF_DX, ListEntry);
        PXENVIF_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (!PdoIsMissing(Pdo))
            PdoSetMissing(Pdo, "FDO surprise removed");
    }

    __FdoReleaseMutex(Fdo);

    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoRemoveDevice(
    IN  PXENVIF_FDO Fdo,
    IN  PIRP        Irp
    )
{
    PLIST_ENTRY     ListEntry;
    NTSTATUS        status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    if (__FdoGetDevicePowerState(Fdo) != PowerDeviceD0)
        goto done;

    KeClearEvent(&Fdo->ScanEvent);
    ThreadWake(Fdo->ScanThread);

    Trace("waiting for scan thread\n");

    (VOID) KeWaitForSingleObject(&Fdo->ScanEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    __FdoAcquireMutex(Fdo);

    ListEntry = Fdo->Dx->ListEntry.Flink;
    while (ListEntry != &Fdo->Dx->ListEntry) {
        PLIST_ENTRY Flink = ListEntry->Flink;
        PXENVIF_DX  Dx = CONTAINING_RECORD(ListEntry, XENVIF_DX, ListEntry);
        PXENVIF_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (!PdoIsMissing(Pdo))
            PdoSetMissing(Pdo, "FDO removed");

        if (PdoGetDevicePnpState(Pdo) != SurpriseRemovePending)
            PdoSetDevicePnpState(Pdo, Deleted);

        if (PdoGetDevicePnpState(Pdo) == Deleted)
            PdoDestroy(Pdo);

        ListEntry = Flink;
    }

    __FdoReleaseMutex(Fdo);

    FdoD0ToD3(Fdo);

    __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
    FdoS3ToS4(Fdo);
    __FdoSetSystemPowerState(Fdo, PowerSystemShutdown);

    ThreadAlert(Fdo->ScanThread);
    ThreadJoin(Fdo->ScanThread);
    Fdo->ScanThread = NULL;

    RtlZeroMemory(&Fdo->ScanEvent, sizeof (KEVENT));

    RtlZeroMemory(&Fdo->Resource, sizeof (FDO_RESOURCE) * RESOURCE_COUNT);

done:
    __FdoSetDevicePnpState(Fdo, Deleted);

    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    __FdoAcquireMutex(Fdo);
    ASSERT3U(Fdo->References, !=, 0);
    --Fdo->References;
    __FdoReleaseMutex(Fdo);

    if (Fdo->References == 0)
        FdoDestroy(Fdo);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoQueryDeviceRelations(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    ULONG               Size;
    PDEVICE_RELATIONS   Relations;
    ULONG               Count;
    PLIST_ENTRY         ListEntry;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    status = Irp->IoStatus.Status;

    if (StackLocation->Parameters.QueryDeviceRelations.Type != BusRelations) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    (VOID) KeWaitForSingleObject(&Fdo->ScanEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    __FdoAcquireMutex(Fdo);

    Count = 0;
    for (ListEntry = Fdo->Dx->ListEntry.Flink;
         ListEntry != &Fdo->Dx->ListEntry;
         ListEntry = ListEntry->Flink)
        Count++;

    Size = FIELD_OFFSET(DEVICE_RELATIONS, Objects) + (sizeof (DEVICE_OBJECT) * __min(Count, 1));

    Relations = ExAllocatePoolWithTag(PagedPool, Size, 'FIV');

    status = STATUS_NO_MEMORY;
    if (Relations == NULL)
        goto fail1;

    RtlZeroMemory(Relations, Size);

    for (ListEntry = Fdo->Dx->ListEntry.Flink;
         ListEntry != &Fdo->Dx->ListEntry;
         ListEntry = ListEntry->Flink) {
        PXENVIF_DX  Dx = CONTAINING_RECORD(ListEntry, XENVIF_DX, ListEntry);
        PXENVIF_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (PdoGetDevicePnpState(Pdo) == Deleted &&
            !PdoIsMissing(Pdo))
            PdoSetMissing(Pdo, "surprise remove");

        if (PdoIsMissing(Pdo))
            continue;

        if (PdoGetDevicePnpState(Pdo) == Present)
            PdoSetDevicePnpState(Pdo, Enumerated);

        ObReferenceObject(Dx->DeviceObject);
        Relations->Objects[Relations->Count++] = Dx->DeviceObject;
    }

    ASSERT3U(Relations->Count, <=, Count);

    Trace("%d PDO(s)\n", Relations->Count);

    __FdoReleaseMutex(Fdo);

    Irp->IoStatus.Information = (ULONG_PTR)Relations;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail2;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    __FdoAcquireMutex(Fdo);

    for (ListEntry = Fdo->Dx->ListEntry.Flink;
         ListEntry != &Fdo->Dx->ListEntry;
         ListEntry = ListEntry->Flink) {
        PXENVIF_DX  Dx = CONTAINING_RECORD(ListEntry, XENVIF_DX, ListEntry);
        PXENVIF_PDO Pdo = Dx->Pdo;

        ASSERT3U(Dx->Type, ==, PHYSICAL_DEVICE_OBJECT);

        if (PdoGetDevicePnpState(Pdo) == Deleted &&
            PdoIsMissing(Pdo))
            PdoDestroy(Pdo);
    }

    __FdoReleaseMutex(Fdo);

done:
    return status;

fail2:
    Error("fail2\n");

    __FdoAcquireMutex(Fdo);

fail1:
    Error("fail1 (%08x)\n", status);

    __FdoReleaseMutex(Fdo);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoQueryCapabilities(
    IN  PXENVIF_FDO         Fdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    PDEVICE_CAPABILITIES    Capabilities;
    SYSTEM_POWER_STATE      SystemPowerState;
    NTSTATUS                status;

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Capabilities = StackLocation->Parameters.DeviceCapabilities.Capabilities;

    Fdo->LowerDeviceCapabilities = *Capabilities;

    for (SystemPowerState = 0; SystemPowerState < PowerSystemMaximum; SystemPowerState++) {
        DEVICE_POWER_STATE  DevicePowerState;

        DevicePowerState = Fdo->LowerDeviceCapabilities.DeviceState[SystemPowerState];
        Trace("%s -> %s\n",
              PowerSystemStateName(SystemPowerState),
              PowerDeviceStateName(DevicePowerState));
    }

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoDeviceUsageNotification(
    IN  PXENVIF_FDO                 Fdo,
    IN  PIRP                        Irp
    )
{
    PIO_STACK_LOCATION              StackLocation;
    DEVICE_USAGE_NOTIFICATION_TYPE  Type;
    BOOLEAN                         InPath;
    BOOLEAN                         NotDisableable;
    NTSTATUS                        status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Type = StackLocation->Parameters.UsageNotification.Type;
    InPath = StackLocation->Parameters.UsageNotification.InPath;

    if (InPath) {
        Trace("%s: ADDING %s\n",
              __FdoGetName(Fdo),
              DeviceUsageTypeName(Type));
        Fdo->Usage[Type]++;
    } else {
        if (Fdo->Usage[Type] != 0) {
            Trace("%s: REMOVING %s\n",
                  __FdoGetName(Fdo),
                  DeviceUsageTypeName(Type));
            --Fdo->Usage[Type];
        }
    }

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto fail1;

    NotDisableable = FALSE;    
    for (Type = 0; Type <= DeviceUsageTypeDumpFile; Type++) {
        if (Fdo->Usage[Type] != 0) {
            NotDisableable = TRUE;
            break;
        }
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (Fdo->NotDisableable != NotDisableable) {
        Fdo->NotDisableable = NotDisableable;
    
        IoInvalidateDeviceState(__FdoGetPhysicalDeviceObject(Fdo));
    }

    return status;

fail1:
    Error("fail1 (%08x)\n", status);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoQueryPnpDeviceState(
    IN  PXENVIF_FDO                 Fdo,
    IN  PIRP                        Irp
    )
{
    ULONG_PTR                       State;
    NTSTATUS                        status;

    if (Irp->IoStatus.Status == STATUS_SUCCESS)
        State = Irp->IoStatus.Information;
    else if (Irp->IoStatus.Status == STATUS_NOT_SUPPORTED)
        State = 0;
    else
        goto done;

    if (Fdo->NotDisableable) {
        Info("%s: not disableable\n", __FdoGetName(Fdo));
        State |= PNP_DEVICE_NOT_DISABLEABLE;
    }

    Irp->IoStatus.Information = State;
    Irp->IoStatus.Status = STATUS_SUCCESS;

done:
    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoDispatchPnp(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    Trace("====> (%02x:%s)\n",
          MinorFunction, 
          PnpMinorFunctionName(MinorFunction)); 

    switch (StackLocation->MinorFunction) {
    case IRP_MN_START_DEVICE:
        status = FdoStartDevice(Fdo, Irp);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        status = FdoQueryStopDevice(Fdo, Irp);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        status = FdoCancelStopDevice(Fdo, Irp);
        break;

    case IRP_MN_STOP_DEVICE:
        status = FdoStopDevice(Fdo, Irp);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        status = FdoQueryRemoveDevice(Fdo, Irp);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        status = FdoSurpriseRemoval(Fdo, Irp);
        break;

    case IRP_MN_REMOVE_DEVICE:
        status = FdoRemoveDevice(Fdo, Irp);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        status = FdoCancelRemoveDevice(Fdo, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        status = FdoQueryDeviceRelations(Fdo, Irp);
        break;

    case IRP_MN_QUERY_CAPABILITIES:
        status = FdoQueryCapabilities(Fdo, Irp);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        status = FdoDeviceUsageNotification(Fdo, Irp);
        break;

    case IRP_MN_QUERY_PNP_DEVICE_STATE:
        status = FdoQueryPnpDeviceState(Fdo, Irp);
        break;

    default:
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
        break;
    }

    Trace("<==== (%02x:%s)(%08x)\n",
          MinorFunction, 
          PnpMinorFunctionName(MinorFunction),
          status); 

    return status;
}

static FORCEINLINE NTSTATUS
__FdoSetDevicePowerUp(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    Trace("====>\n");

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, <,  __FdoGetDevicePowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    Info("%s -> %s\n",
         PowerDeviceStateName(__FdoGetDevicePowerState(Fdo)),
         PowerDeviceStateName(DeviceState));

    ASSERT3U(DeviceState, ==, PowerDeviceD0);
    status = FdoD3ToD0(Fdo);
    ASSERT(NT_SUCCESS(status));

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Trace("<==== (%08x)\n", status);
    return status;
}

static FORCEINLINE NTSTATUS
__FdoSetDevicePowerDown(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __FdoGetDevicePowerState(Fdo));

    Info("%s -> %s\n",
         PowerDeviceStateName(__FdoGetDevicePowerState(Fdo)),
         PowerDeviceStateName(DeviceState));

    ASSERT3U(DeviceState, ==, PowerDeviceD3);

    if (__FdoGetDevicePowerState(Fdo) == PowerDeviceD0)
        FdoD0ToD3(Fdo);

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoSetDevicePower(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          PowerDeviceStateName(DeviceState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (DeviceState == __FdoGetDevicePowerState(Fdo)) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    status = (DeviceState < __FdoGetDevicePowerState(Fdo)) ?
             __FdoSetDevicePowerUp(Fdo, Irp) :
             __FdoSetDevicePowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerDeviceStateName(DeviceState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

__drv_functionClass(REQUEST_POWER_COMPLETE)
__drv_sameIRQL
VOID
__FdoRequestSetDevicePower(
    IN  PDEVICE_OBJECT      DeviceObject,
    IN  UCHAR               MinorFunction,
    IN  POWER_STATE         PowerState,
    IN  PVOID               Context,
    IN  PIO_STATUS_BLOCK    IoStatus
    )
{
    PKEVENT                 Event = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(MinorFunction);
    UNREFERENCED_PARAMETER(PowerState);

    ASSERT(NT_SUCCESS(IoStatus->Status));

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
}

static VOID
FdoRequestSetDevicePower(
    IN  PXENVIF_FDO         Fdo,
    IN  DEVICE_POWER_STATE  DeviceState
    )
{
    POWER_STATE             PowerState;
    KEVENT                  Event;
    NTSTATUS                status;

    Trace("%s\n", PowerDeviceStateName(DeviceState));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    PowerState.DeviceState = DeviceState;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = PoRequestPowerIrp(Fdo->LowerDeviceObject,
                               IRP_MN_SET_POWER,
                               PowerState,
                               __FdoRequestSetDevicePower,
                               &Event,
                               NULL);
    ASSERT(NT_SUCCESS(status));

    (VOID) KeWaitForSingleObject(&Event,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);
}

static FORCEINLINE NTSTATUS
__FdoSetSystemPowerUp(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{

    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, <,  __FdoGetSystemPowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    if (SystemState < PowerSystemHibernate &&
        __FdoGetSystemPowerState(Fdo) >= PowerSystemHibernate)
        __FdoSetSystemPowerState(Fdo, PowerSystemHibernate);
        FdoS4ToS3(Fdo);

    Info("%s -> %s\n",
         PowerSystemStateName(__FdoGetSystemPowerState(Fdo)),
         PowerSystemStateName(SystemState));

    __FdoSetSystemPowerState(Fdo, SystemState);

    DeviceState = Fdo->LowerDeviceCapabilities.DeviceState[SystemState];
    FdoRequestSetDevicePower(Fdo, DeviceState);

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoSetSystemPowerDown(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, >,  __FdoGetSystemPowerState(Fdo));

    DeviceState = Fdo->LowerDeviceCapabilities.DeviceState[SystemState];

    FdoRequestSetDevicePower(Fdo, DeviceState);

    Info("%s -> %s\n",
         PowerSystemStateName(__FdoGetSystemPowerState(Fdo)),
         PowerSystemStateName(SystemState));

    if (SystemState >= PowerSystemHibernate &&
        __FdoGetSystemPowerState(Fdo) < PowerSystemHibernate) {
        __FdoSetSystemPowerState(Fdo, PowerSystemSleeping3);
        FdoS3ToS4(Fdo);
    }

    __FdoSetSystemPowerState(Fdo, SystemState);

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoSetSystemPower(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          PowerSystemStateName(SystemState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (SystemState == __FdoGetSystemPowerState(Fdo)) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    status = (SystemState < __FdoGetSystemPowerState(Fdo)) ?
             __FdoSetSystemPowerUp(Fdo, Irp) :
             __FdoSetSystemPowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerSystemStateName(SystemState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

static FORCEINLINE NTSTATUS
__FdoQueryDevicePowerUp(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, <,  __FdoGetDevicePowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoQueryDevicePowerDown(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;

    ASSERT3U(DeviceState, >,  __FdoGetDevicePowerState(Fdo));

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoQueryDevicePower(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          PowerDeviceStateName(DeviceState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (DeviceState == __FdoGetDevicePowerState(Fdo)) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    status = (DeviceState < __FdoGetDevicePowerState(Fdo)) ?
             __FdoQueryDevicePowerUp(Fdo, Irp) :
             __FdoQueryDevicePowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerDeviceStateName(DeviceState), 
          PowerActionName(PowerAction),
          status);
    return status;
}

__drv_functionClass(REQUEST_POWER_COMPLETE)
__drv_sameIRQL
VOID
__FdoRequestQueryDevicePower(
    IN  PDEVICE_OBJECT      DeviceObject,
    IN  UCHAR               MinorFunction,
    IN  POWER_STATE         PowerState,
    IN  PVOID               Context,
    IN  PIO_STATUS_BLOCK    IoStatus
    )
{
    PKEVENT                 Event = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(MinorFunction);
    UNREFERENCED_PARAMETER(PowerState);

    ASSERT(NT_SUCCESS(IoStatus->Status));

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);
}

static VOID
FdoRequestQueryDevicePower(
    IN  PXENVIF_FDO         Fdo,
    IN  DEVICE_POWER_STATE  DeviceState
    )
{
    POWER_STATE             PowerState;
    KEVENT                  Event;
    NTSTATUS                status;

    Trace("%s\n", PowerDeviceStateName(DeviceState));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    PowerState.DeviceState = DeviceState;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = PoRequestPowerIrp(Fdo->LowerDeviceObject,
                               IRP_MN_QUERY_POWER,
                               PowerState,
                               __FdoRequestQueryDevicePower,
                               &Event,
                               NULL);
    ASSERT(NT_SUCCESS(status));

    (VOID) KeWaitForSingleObject(&Event,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);
}

static FORCEINLINE NTSTATUS
__FdoQuerySystemPowerUp(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{

    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, <,  __FdoGetSystemPowerState(Fdo));

    status = FdoForwardIrpSynchronously(Fdo, Irp);
    if (!NT_SUCCESS(status))
        goto done;

    DeviceState = Fdo->LowerDeviceCapabilities.DeviceState[SystemState];

    FdoRequestQueryDevicePower(Fdo, DeviceState);

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoQuerySystemPowerDown(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    DEVICE_POWER_STATE  DeviceState;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;

    ASSERT3U(SystemState, >,  __FdoGetSystemPowerState(Fdo));

    DeviceState = Fdo->LowerDeviceCapabilities.DeviceState[SystemState];

    FdoRequestQueryDevicePower(Fdo, DeviceState);

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

static FORCEINLINE NTSTATUS
__FdoQuerySystemPower(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          PowerSystemStateName(SystemState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (SystemState == __FdoGetSystemPowerState(Fdo)) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    status = (SystemState < __FdoGetSystemPowerState(Fdo)) ?
             __FdoQuerySystemPowerUp(Fdo, Irp) :
             __FdoQuerySystemPowerDown(Fdo, Irp);

done:
    Trace("<==== (%s:%s)(%08x)\n",
          PowerSystemStateName(SystemState), 
          PowerActionName(PowerAction),
          status);

    return status;
}

static NTSTATUS
FdoDevicePower(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_FDO         Fdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  StackLocation;
        UCHAR               MinorFunction;

        if (Fdo->DevicePowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Fdo->DevicePowerIrp;

        if (Irp == NULL)
            continue;

        Fdo->DevicePowerIrp = NULL;
        KeMemoryBarrier();

        StackLocation = IoGetCurrentIrpStackLocation(Irp);
        MinorFunction = StackLocation->MinorFunction;

        switch (StackLocation->MinorFunction) {
        case IRP_MN_SET_POWER:
            (VOID) __FdoSetDevicePower(Fdo, Irp);
            break;

        case IRP_MN_QUERY_POWER:
            (VOID) __FdoQueryDevicePower(Fdo, Irp);
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
FdoSystemPower(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_FDO         Fdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP                Irp;
        PIO_STACK_LOCATION  StackLocation;
        UCHAR               MinorFunction;

        if (Fdo->SystemPowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Fdo->SystemPowerIrp;

        if (Irp == NULL)
            continue;

        Fdo->SystemPowerIrp = NULL;
        KeMemoryBarrier();

        StackLocation = IoGetCurrentIrpStackLocation(Irp);
        MinorFunction = StackLocation->MinorFunction;

        switch (StackLocation->MinorFunction) {
        case IRP_MN_SET_POWER:
            (VOID) __FdoSetSystemPower(Fdo, Irp);
            break;

        case IRP_MN_QUERY_POWER:
            (VOID) __FdoQuerySystemPower(Fdo, Irp);
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoDispatchPower(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    POWER_STATE_TYPE    PowerType;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    if (MinorFunction != IRP_MN_QUERY_POWER &&
        MinorFunction != IRP_MN_SET_POWER) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    PowerType = StackLocation->Parameters.Power.Type;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    if (PowerAction >= PowerActionShutdown) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

        goto done;
    }

    switch (PowerType) {
    case DevicePowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Fdo->DevicePowerIrp, ==, NULL);
        Fdo->DevicePowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Fdo->DevicePowerThread);

        status = STATUS_PENDING;
        break;

    case SystemPowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Fdo->SystemPowerIrp, ==, NULL);
        Fdo->SystemPowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Fdo->SystemPowerThread);

        status = STATUS_PENDING;
        break;

    default:
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
        break;
    }

done:
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FdoDispatchDefault(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    IoSkipCurrentIrpStackLocation(Irp);
    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);

    return status;
}

NTSTATUS
FdoDispatch(
    IN  PXENVIF_FDO     Fdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->MajorFunction) {
    case IRP_MJ_PNP:
        status = FdoDispatchPnp(Fdo, Irp);
        break;

    case IRP_MJ_POWER:
        status = FdoDispatchPower(Fdo, Irp);
        break;

    default:
        status = FdoDispatchDefault(Fdo, Irp);
        break;
    }

    return status;
}

static NTSTATUS
FdoQueryEvtchnInterface(
    IN  PXENVIF_FDO             Fdo
    )
{
    KEVENT                      Event;
    IO_STATUS_BLOCK             StatusBlock;
    PIRP                        Irp;
    PIO_STACK_LOCATION          StackLocation;
    INTERFACE                   Interface;
    NTSTATUS                    status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));
    RtlZeroMemory(&Interface, sizeof(INTERFACE));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = &GUID_EVTCHN_INTERFACE;
    StackLocation->Parameters.QueryInterface.Size = sizeof (INTERFACE);
    StackLocation->Parameters.QueryInterface.Version = EVTCHN_INTERFACE_VERSION;
    StackLocation->Parameters.QueryInterface.Interface = &Interface;
    
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (Interface.Version != EVTCHN_INTERFACE_VERSION)
        goto fail3;

    Fdo->EvtchnInterface = Interface.Context;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
FdoQueryDebugInterface(
    IN  PXENVIF_FDO     Fdo
    )
{
    KEVENT              Event;
    IO_STATUS_BLOCK     StatusBlock;
    PIRP                Irp;
    PIO_STACK_LOCATION  StackLocation;
    INTERFACE           Interface;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));
    RtlZeroMemory(&Interface, sizeof(INTERFACE));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = &GUID_DEBUG_INTERFACE;
    StackLocation->Parameters.QueryInterface.Size = sizeof (INTERFACE);
    StackLocation->Parameters.QueryInterface.Version = DEBUG_INTERFACE_VERSION;
    StackLocation->Parameters.QueryInterface.Interface = &Interface;
    
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (Interface.Version != DEBUG_INTERFACE_VERSION)
        goto fail3;

    Fdo->DebugInterface = Interface.Context;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
FdoQueryStoreInterface(
    IN  PXENVIF_FDO     Fdo
    )
{
    KEVENT              Event;
    IO_STATUS_BLOCK     StatusBlock;
    PIRP                Irp;
    PIO_STACK_LOCATION  StackLocation;
    INTERFACE           Interface;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));
    RtlZeroMemory(&Interface, sizeof(INTERFACE));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = &GUID_STORE_INTERFACE;
    StackLocation->Parameters.QueryInterface.Size = sizeof (INTERFACE);
    StackLocation->Parameters.QueryInterface.Version = STORE_INTERFACE_VERSION;
    StackLocation->Parameters.QueryInterface.Interface = &Interface;
    
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (Interface.Version != STORE_INTERFACE_VERSION)
        goto fail3;

    Fdo->StoreInterface = Interface.Context;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
FdoQueryGnttabInterface(
    IN  PXENVIF_FDO     Fdo
    )
{
    KEVENT              Event;
    IO_STATUS_BLOCK     StatusBlock;
    PIRP                Irp;
    PIO_STACK_LOCATION  StackLocation;
    INTERFACE           Interface;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));
    RtlZeroMemory(&Interface, sizeof(INTERFACE));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = &GUID_GNTTAB_INTERFACE;
    StackLocation->Parameters.QueryInterface.Size = sizeof (INTERFACE);
    StackLocation->Parameters.QueryInterface.Version = GNTTAB_INTERFACE_VERSION;
    StackLocation->Parameters.QueryInterface.Interface = &Interface;
    
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (Interface.Version != GNTTAB_INTERFACE_VERSION)
        goto fail3;

    Fdo->GnttabInterface = Interface.Context;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");
    
fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
FdoQuerySuspendInterface(
    IN  PXENVIF_FDO     Fdo
    )
{
    KEVENT              Event;
    IO_STATUS_BLOCK     StatusBlock;
    PIRP                Irp;
    PIO_STACK_LOCATION  StackLocation;
    INTERFACE           Interface;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));
    RtlZeroMemory(&Interface, sizeof(INTERFACE));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = &GUID_SUSPEND_INTERFACE;
    StackLocation->Parameters.QueryInterface.Size = sizeof (INTERFACE);
    StackLocation->Parameters.QueryInterface.Version = SUSPEND_INTERFACE_VERSION;
    StackLocation->Parameters.QueryInterface.Interface = &Interface;
    
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (Interface.Version != SUSPEND_INTERFACE_VERSION)
        goto fail3;

    Fdo->SuspendInterface = Interface.Context;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static NTSTATUS
FdoQueryEmulatedInterface(
    IN  PXENVIF_FDO     Fdo
    )
{
    KEVENT              Event;
    IO_STATUS_BLOCK     StatusBlock;
    PIRP                Irp;
    PIO_STACK_LOCATION  StackLocation;
    INTERFACE           Interface;
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof(IO_STATUS_BLOCK));
    RtlZeroMemory(&Interface, sizeof(INTERFACE));

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                       Fdo->LowerDeviceObject,
                                       NULL,
                                       0,
                                       NULL,
                                       &Event,
                                       &StatusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_INTERFACE;

    StackLocation->Parameters.QueryInterface.InterfaceType = &GUID_EMULATED_INTERFACE;
    StackLocation->Parameters.QueryInterface.Size = sizeof (INTERFACE);
    StackLocation->Parameters.QueryInterface.Version = EMULATED_INTERFACE_VERSION;
    StackLocation->Parameters.QueryInterface.Interface = &Interface;
    
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(Fdo->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    status = STATUS_INVALID_PARAMETER;
    if (Interface.Version != EMULATED_INTERFACE_VERSION)
        goto fail3;

    Fdo->EmulatedInterface = Interface.Context;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
FdoCreate(
    IN  PDEVICE_OBJECT  PhysicalDeviceObject
    )
{
    PDEVICE_OBJECT      FunctionDeviceObject;
    PXENVIF_DX          Dx;
    PXENVIF_FDO         Fdo;
    WCHAR               Name[MAXNAMELEN * sizeof (WCHAR)];
    ULONG               Size;
    NTSTATUS            status;

#pragma prefast(suppress:28197) // Possibly leaking memory 'FunctionDeviceObject'
    status = IoCreateDevice(DriverObject,
                            sizeof (XENVIF_DX),
                            NULL,
                            FILE_DEVICE_BUS_EXTENDER,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &FunctionDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    Dx = (PXENVIF_DX)FunctionDeviceObject->DeviceExtension;
    RtlZeroMemory(Dx, sizeof (XENVIF_DX));

    Dx->Type = FUNCTION_DEVICE_OBJECT;
    Dx->DeviceObject = FunctionDeviceObject;
    Dx->DevicePnpState = Added;
    Dx->SystemPowerState = PowerSystemShutdown;
    Dx->DevicePowerState = PowerDeviceD3;

    Fdo = __FdoAllocate(sizeof (XENVIF_FDO));

    status = STATUS_NO_MEMORY;
    if (Fdo == NULL)
        goto fail2;

    Fdo->Dx = Dx;
    Fdo->PhysicalDeviceObject = PhysicalDeviceObject;
    Fdo->LowerDeviceObject = IoAttachDeviceToDeviceStack(FunctionDeviceObject,
                                                         PhysicalDeviceObject);

    status = ThreadCreate(FdoSystemPower, Fdo, &Fdo->SystemPowerThread);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = ThreadCreate(FdoDevicePower, Fdo, &Fdo->DevicePowerThread);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = IoGetDeviceProperty(PhysicalDeviceObject,
                                 DevicePropertyLocationInformation,
                                 sizeof (Name),
                                 Name,
                                 &Size);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = __FdoSetName(Fdo, Name);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = FdoQueryEvtchnInterface(Fdo);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = FdoQueryDebugInterface(Fdo);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = FdoQueryStoreInterface(Fdo);
    if (!NT_SUCCESS(status))
        goto fail9;

    status = FdoQueryGnttabInterface(Fdo);
    if (!NT_SUCCESS(status))
        goto fail10;

    status = FdoQuerySuspendInterface(Fdo);
    if (!NT_SUCCESS(status))
        goto fail11;

    status = FdoQueryEmulatedInterface(Fdo);
    ASSERT(IMPLY(!NT_SUCCESS(status),
                 __FdoGetEmulatedInterface(Fdo) == NULL));

    InitializeMutex(&Fdo->Mutex);
    InitializeListHead(&Dx->ListEntry);
    Fdo->References = 1;

    Info("%p (%s)\n",
         FunctionDeviceObject,
         __FdoGetName(Fdo));

    Dx->Fdo = Fdo;
    FunctionDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;

fail11:
    Error("fail11\n");

    Fdo->GnttabInterface = NULL;

fail10:
    Error("fail10\n");

    Fdo->StoreInterface = NULL;

fail9:
    Error("fail9\n");

    Fdo->DebugInterface = NULL;

fail8:
    Error("fail8\n");

    Fdo->EvtchnInterface = NULL;

fail7:
    Error("fail7\n");

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

    ThreadAlert(Fdo->DevicePowerThread);
    ThreadJoin(Fdo->DevicePowerThread);
    Fdo->DevicePowerThread = NULL;
    
fail4:
    Error("fail4\n");

    ThreadAlert(Fdo->SystemPowerThread);
    ThreadJoin(Fdo->SystemPowerThread);
    Fdo->SystemPowerThread = NULL;
    
fail3:
    Error("fail3\n");

#pragma prefast(suppress:28183) // Fdo->LowerDeviceObject could be NULL
    IoDetachDevice(Fdo->LowerDeviceObject);

    Fdo->PhysicalDeviceObject = NULL;
    Fdo->LowerDeviceObject = NULL;
    Fdo->Dx = NULL;

    ASSERT(IsZeroMemory(Fdo, sizeof (XENVIF_FDO)));
    __FdoFree(Fdo);

fail2:
    Error("fail2\n");

    IoDeleteDevice(FunctionDeviceObject);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
FdoDestroy(
    IN  PXENVIF_FDO     Fdo
    )
{
    PXENVIF_DX          Dx = Fdo->Dx;
    PDEVICE_OBJECT      FunctionDeviceObject = Dx->DeviceObject;

    ASSERT(IsListEmpty(&Dx->ListEntry));
    ASSERT3U(Fdo->References, ==, 0);
    ASSERT3U(__FdoGetDevicePnpState(Fdo), ==, Deleted);

    Fdo->NotDisableable = FALSE;

    Info("%p (%s)\n",
         FunctionDeviceObject,
         __FdoGetName(Fdo));

    Dx->Fdo = NULL;

    RtlZeroMemory(&Fdo->Mutex, sizeof (XENVIF_MUTEX));

    Fdo->EmulatedInterface = NULL;
    Fdo->SuspendInterface = NULL;
    Fdo->GnttabInterface = NULL;
    Fdo->StoreInterface = NULL;
    Fdo->DebugInterface = NULL;
    Fdo->EvtchnInterface = NULL;

    ThreadAlert(Fdo->DevicePowerThread);
    ThreadJoin(Fdo->DevicePowerThread);
    Fdo->DevicePowerThread = NULL;

    ThreadAlert(Fdo->SystemPowerThread);
    ThreadJoin(Fdo->SystemPowerThread);
    Fdo->SystemPowerThread = NULL;

    IoDetachDevice(Fdo->LowerDeviceObject);

    RtlZeroMemory(&Fdo->LowerDeviceCapabilities, sizeof (DEVICE_CAPABILITIES));
    Fdo->LowerDeviceObject = NULL;
    Fdo->PhysicalDeviceObject = NULL;
    Fdo->Dx = NULL;

    ASSERT(IsZeroMemory(Fdo, sizeof (XENVIF_FDO)));
    __FdoFree(Fdo);

    IoDeleteDevice(FunctionDeviceObject);
}


