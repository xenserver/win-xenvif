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
#include <devguid.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <netioapi.h>
#include <util.h>
#include <xen.h>
#include <store_interface.h>
#include <emulated_interface.h>

#include "names.h"
#include "fdo.h"
#include "pdo.h"
#include "bus.h"
#include "frontend.h"
#include "vif.h"
#include "driver.h"
#include "registry.h"
#include "thread.h"
#include "dbg_print.h"
#include "assert.h"

#define PDO_POOL 'ODP'

struct _XENVIF_PDO {
    PXENVIF_DX                  Dx;

    PXENVIF_THREAD              SystemPowerThread;
    PIRP                        SystemPowerIrp;
    PXENVIF_THREAD              DevicePowerThread;
    PIRP                        DevicePowerIrp;

    PXENVIF_FDO                 Fdo;
    BOOLEAN                     Missing;
    const CHAR                  *Reason;

    ETHERNET_ADDRESS            PermanentMacAddress;
    NET_LUID                    NetLuid;
    ETHERNET_ADDRESS            CurrentMacAddress;

    BUS_INTERFACE_STANDARD      BusInterface;

    PXENVIF_FRONTEND            Frontend;
    XENVIF_VIF_INTERFACE        VifInterface;

    PXENBUS_SUSPEND_INTERFACE   SuspendInterface;

    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
};

static FORCEINLINE PVOID
__PdoAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, PDO_POOL);
}

static FORCEINLINE VOID
__PdoFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, PDO_POOL);
}

static FORCEINLINE VOID
__PdoSetDevicePnpState(
    IN  PXENVIF_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENVIF_DX              Dx = Pdo->Dx;

    // We can never transition out of the deleted state
    ASSERT(Dx->DevicePnpState != Deleted || State == Deleted);

    Dx->PreviousDevicePnpState = Dx->DevicePnpState;
    Dx->DevicePnpState = State;
}

VOID
PdoSetDevicePnpState(
    IN  PXENVIF_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    __PdoSetDevicePnpState(Pdo, State);
}

static FORCEINLINE VOID
__PdoRestoreDevicePnpState(
    IN  PXENVIF_PDO         Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXENVIF_DX              Dx = Pdo->Dx;

    if (Dx->DevicePnpState == State)
        Dx->DevicePnpState = Dx->PreviousDevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__PdoGetDevicePnpState(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;

    return Dx->DevicePnpState;
}

DEVICE_PNP_STATE
PdoGetDevicePnpState(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetDevicePnpState(Pdo);
}

static FORCEINLINE VOID
__PdoSetSystemPowerState(
    IN  PXENVIF_PDO         Pdo,
    IN  SYSTEM_POWER_STATE  State
    )
{
    PXENVIF_DX              Dx = Pdo->Dx;

    Dx->SystemPowerState = State;
}

static FORCEINLINE SYSTEM_POWER_STATE
__PdoGetSystemPowerState(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;

    return Dx->SystemPowerState;
}

static FORCEINLINE VOID
__PdoSetDevicePowerState(
    IN  PXENVIF_PDO         Pdo,
    IN  DEVICE_POWER_STATE  State
    )
{
    PXENVIF_DX              Dx = Pdo->Dx;

    Dx->DevicePowerState = State;
}

static FORCEINLINE DEVICE_POWER_STATE
__PdoGetDevicePowerState(
    IN  PXENVIF_PDO         Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;

    return Dx->DevicePowerState;
}

static FORCEINLINE VOID
__PdoSetMissing(
    IN  PXENVIF_PDO Pdo,
    IN  const CHAR  *Reason
    )
{
    Pdo->Reason = Reason;
    Pdo->Missing = TRUE;
}

VOID
PdoSetMissing(
    IN  PXENVIF_PDO Pdo,
    IN  const CHAR  *Reason
    )
{
    __PdoSetMissing(Pdo, Reason);
}

static FORCEINLINE BOOLEAN
__PdoIsMissing(
    IN  PXENVIF_PDO Pdo
    )
{
    return Pdo->Missing;
}

BOOLEAN
PdoIsMissing(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoIsMissing(Pdo);
}

static FORCEINLINE VOID
__PdoSetName(
    IN  PXENVIF_PDO     Pdo,
    IN  PANSI_STRING    Ansi
    )
{
    PXENVIF_DX          Dx = Pdo->Dx;
    NTSTATUS            status;

    status = RtlStringCbPrintfA(Dx->Name, 
                                MAX_DEVICE_ID_LEN, 
                                "%Z", 
                                Ansi);
    ASSERT(NT_SUCCESS(status));
}

static FORCEINLINE PCHAR
__PdoGetName(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;

    return Dx->Name;
}

PCHAR
PdoGetName(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetName(Pdo);
}

static FORCEINLINE ULONG
__PdoGetRevision(
    IN  PXENVIF_PDO Pdo
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    return 0;
}

static FORCEINLINE PDEVICE_OBJECT
__PdoGetDeviceObject(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;

    return (Dx->DeviceObject);
}
    
PDEVICE_OBJECT
PdoGetDeviceObject(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetDeviceObject(Pdo);
}

static FORCEINLINE VOID
__PdoLink(
    IN  PXENVIF_PDO Pdo,
    IN  PXENVIF_FDO Fdo
    )
{
    Pdo->Fdo = Fdo;

    FdoAddPhysicalDeviceObject(Fdo, Pdo);
}

static FORCEINLINE VOID
__PdoUnlink(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_FDO     Fdo = Pdo->Fdo;

    ASSERT(Fdo != NULL);

    FdoRemovePhysicalDeviceObject(Fdo, Pdo);

    Pdo->Fdo = NULL;
}

static FORCEINLINE PXENVIF_FDO
__PdoGetFdo(
    IN  PXENVIF_PDO Pdo
    )
{
    return Pdo->Fdo;
}

static FORCEINLINE PCHAR
__PdoGetVendorName(
    IN  PXENVIF_PDO Pdo
    )
{
    return FdoGetVendorName(__PdoGetFdo(Pdo));
}

static FORCEINLINE PXENVIF_FRONTEND
__PdoGetFrontend(
    IN  PXENVIF_PDO Pdo
    )
{
    return Pdo->Frontend;
}

PXENVIF_FRONTEND
PdoGetFrontend(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetFrontend(Pdo);
}

static FORCEINLINE PXENBUS_EVTCHN_INTERFACE
__PdoGetEvtchnInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return FdoGetEvtchnInterface(__PdoGetFdo(Pdo));
}

PXENBUS_EVTCHN_INTERFACE
PdoGetEvtchnInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetEvtchnInterface(Pdo);
}

static FORCEINLINE PXENBUS_DEBUG_INTERFACE
__PdoGetDebugInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return FdoGetDebugInterface(__PdoGetFdo(Pdo));
}

PXENBUS_DEBUG_INTERFACE
PdoGetDebugInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetDebugInterface(Pdo);
}

static FORCEINLINE PXENBUS_GNTTAB_INTERFACE
__PdoGetGnttabInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return FdoGetGnttabInterface(__PdoGetFdo(Pdo));
}

PXENBUS_GNTTAB_INTERFACE
PdoGetGnttabInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetGnttabInterface(Pdo);
}

static FORCEINLINE PXENBUS_SUSPEND_INTERFACE
__PdoGetSuspendInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return FdoGetSuspendInterface(__PdoGetFdo(Pdo));
}

PXENBUS_SUSPEND_INTERFACE
PdoGetSuspendInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetSuspendInterface(Pdo);
}

static FORCEINLINE PXENBUS_STORE_INTERFACE
__PdoGetStoreInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return FdoGetStoreInterface(__PdoGetFdo(Pdo));
}

PXENBUS_STORE_INTERFACE
PdoGetStoreInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetStoreInterface(Pdo);
}

static FORCEINLINE PXENFILT_EMULATED_INTERFACE
__PdoGetEmulatedInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return FdoGetEmulatedInterface(__PdoGetFdo(Pdo));
}

PXENFILT_EMULATED_INTERFACE
PdoGetEmulatedInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetEmulatedInterface(Pdo);
}

static FORCEINLINE PXENVIF_VIF_INTERFACE
__PdoGetVifInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return &Pdo->VifInterface;
}

PXENVIF_VIF_INTERFACE
PdoGetVifInterface(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetVifInterface(Pdo);
}

static FORCEINLINE NTSTATUS
__PdoSetNetLuid(
    IN  PXENVIF_PDO Pdo
    )
{
    HANDLE          Key;
    ULONG           IfType;
    ULONG           NetLuidIndex;
    NTSTATUS        status;

    status = RegistryOpenSoftwareKey(__PdoGetDeviceObject(Pdo),
                                     KEY_READ,
                                     &Key);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryQueryDwordValue(Key, "*IfType", &IfType);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryQueryDwordValue(Key, "NetLuidIndex", &NetLuidIndex);
    if (!NT_SUCCESS(status))
        goto fail3;

    Pdo->NetLuid.Info.IfType = IfType;
    Pdo->NetLuid.Info.NetLuidIndex = NetLuidIndex;

    RegistryCloseKey(Key);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    RegistryCloseKey(Key);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE PNET_LUID
__PdoGetNetLuid(
    IN  PXENVIF_PDO Pdo
    )
{
    return &Pdo->NetLuid;
}

PNET_LUID
PdoGetNetLuid(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetNetLuid(Pdo);
}

static FORCEINLINE NTSTATUS
__PdoParseMacAddress(
    IN  PCHAR               Buffer,
    OUT PETHERNET_ADDRESS   Address
    )
{
    ULONG                   Length;
    NTSTATUS                status;

    Length = 0;
    for (;;) {
        CHAR    Character;
        UCHAR   Byte;

        Character = *Buffer++;
        if (Character == '\0')
            break;

        if (Character >= '0' && Character <= '9')
            Byte = Character - '0';
        else if (Character >= 'A' && Character <= 'F')
            Byte = 0x0A + Character - 'A';
        else if (Character >= 'a' && Character <= 'f')
            Byte = 0x0A + Character - 'a';
        else
            break;

        Byte <<= 4;

        Character = *Buffer++;
        if (Character == '\0')
            break;

        if (Character >= '0' && Character <= '9')
            Byte += Character - '0';
        else if (Character >= 'A' && Character <= 'F')
            Byte += 0x0A + Character - 'A';
        else if (Character >= 'a' && Character <= 'f')
            Byte += 0x0A + Character - 'a';
        else
            break;

        Address->Byte[Length++] = Byte;

        // Skip over any separator
        if (*Buffer == ':' || *Buffer == '-')
            Buffer++;
    }

    status = STATUS_INVALID_PARAMETER;
    if (Length != ETHERNET_ADDRESS_LENGTH)
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetPermanentMacAddress(
    IN  PXENVIF_PDO             Pdo,
    IN  PXENBUS_STORE_INTERFACE StoreInterface
    )
{
    PCHAR                       Buffer;
    HANDLE                      AddressesKey;
    ANSI_STRING                 Ansi;
    ULONG                       Index;
    NTSTATUS                    status;

    STORE(Acquire, StoreInterface);

    status = STORE(Read,
                   StoreInterface,
                   NULL,
                   FrontendGetPath(__PdoGetFrontend(Pdo)),
                   "mac",
                   &Buffer);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = __PdoParseMacAddress(Buffer, &Pdo->PermanentMacAddress);
    if (!NT_SUCCESS(status))
        goto fail2;

    AddressesKey = DriverGetAddressesKey();
    ASSERT(AddressesKey != NULL);

    RtlInitAnsiString(&Ansi, Buffer);
    for (Index = 0; Index < Ansi.Length; Index++)
        if (Ansi.Buffer[Index] == ':')
            Ansi.Buffer[Index] = '-';
    
    status = RegistryUpdateSzValue(AddressesKey,
                                   __PdoGetName(Pdo),
                                   REG_SZ,
                                   &Ansi);
    if (!NT_SUCCESS(status))
        goto fail3;

    STORE(Free,
          StoreInterface,
          Buffer);

    STORE(Release, StoreInterface);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    RtlZeroMemory(&Pdo->PermanentMacAddress, sizeof (ETHERNET_ADDRESS));

fail2:
    Error("fail2\n");

    STORE(Free,
          StoreInterface,
          Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    STORE(Release, StoreInterface);

    return status;
}

static FORCEINLINE PETHERNET_ADDRESS
__PdoGetPermanentMacAddress(
    IN  PXENVIF_PDO Pdo
    )
{
    return &Pdo->PermanentMacAddress;
}

PETHERNET_ADDRESS
PdoGetPermanentMacAddress(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetPermanentMacAddress(Pdo);
}

static FORCEINLINE NTSTATUS
__PdoSetCurrentMacAddress(
    IN  PXENVIF_PDO Pdo
    )
{
    HANDLE          SoftwareKey;
    PANSI_STRING    Ansi;
    NTSTATUS        status;

    status = RegistryOpenSoftwareKey(__PdoGetDeviceObject(Pdo),
                                     KEY_READ,
                                     &SoftwareKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryQuerySzValue(SoftwareKey, "NetworkAddress", &Ansi);
    if (!NT_SUCCESS(status)) {
        RtlCopyMemory(&Pdo->CurrentMacAddress,
                      &Pdo->PermanentMacAddress,
                      sizeof (ETHERNET_ADDRESS));
        goto done;
    }

    status = __PdoParseMacAddress(Ansi->Buffer, &Pdo->CurrentMacAddress);
    if (!NT_SUCCESS(status))
        goto fail2;

    RegistryFreeSzValue(Ansi);

done:
    RegistryCloseKey(SoftwareKey);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RegistryFreeSzValue(Ansi);

    RegistryCloseKey(SoftwareKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE PETHERNET_ADDRESS
__PdoGetCurrentMacAddress(
    IN  PXENVIF_PDO Pdo
    )
{
    return &Pdo->CurrentMacAddress;
}

PETHERNET_ADDRESS
PdoGetCurrentMacAddress(
    IN  PXENVIF_PDO Pdo
    )
{
    return __PdoGetCurrentMacAddress(Pdo);
}

PDMA_ADAPTER
PdoGetDmaAdapter(
    IN  PXENVIF_PDO         Pdo,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    )
{
    Trace("<===>\n");

    return FdoGetDmaAdapter(__PdoGetFdo(Pdo),
                            DeviceDescriptor,
                            NumberOfMapRegisters);
}

BOOLEAN
PdoTranslateBusAddress(
    IN      PXENVIF_PDO         Pdo,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    )
{
    Trace("<===>\n");

    return FdoTranslateBusAddress(__PdoGetFdo(Pdo),
                                  BusAddress,
                                  Length,
                                  AddressSpace,
                                  TranslatedAddress);
}

ULONG
PdoSetBusData(
    IN  PXENVIF_PDO     Pdo,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    )
{
    Trace("<===>\n");

    return FdoSetBusData(__PdoGetFdo(Pdo),
                         DataType,
                         Buffer,
                         Offset,
                         Length);
}

ULONG
PdoGetBusData(
    IN  PXENVIF_PDO     Pdo,
    IN  ULONG           DataType,
    IN  PVOID           Buffer,
    IN  ULONG           Offset,
    IN  ULONG           Length
    )
{
    Trace("<===>\n");

    return FdoGetBusData(__PdoGetFdo(Pdo),
                         DataType,
                         Buffer,
                         Offset,
                         Length);
}

VOID
PdoRequestEject(
    IN  PXENVIF_PDO Pdo
    )
{
    IoRequestDeviceEject(__PdoGetDeviceObject(Pdo));
}

static FORCEINLINE NTSTATUS
__PdoD3ToD0(
    IN  PXENVIF_PDO             Pdo
    )
{
    POWER_STATE                 PowerState;
    NTSTATUS                    status;

    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3U(__PdoGetDevicePowerState(Pdo), ==, PowerDeviceD3);

    status = FrontendSetState(__PdoGetFrontend(Pdo), FRONTEND_CONNECTED);
    if (!NT_SUCCESS(status))
        goto fail1;

    __PdoSetDevicePowerState(Pdo, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    Trace("(%s) <====\n", __PdoGetName(Pdo));

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE VOID
__PdoD0ToD3(
    IN  PXENVIF_PDO     Pdo
    )
{
    POWER_STATE         PowerState;

    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3U(__PdoGetDevicePowerState(Pdo), ==, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD3;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    __PdoSetDevicePowerState(Pdo, PowerDeviceD3);

    (VOID) FrontendSetState(__PdoGetFrontend(Pdo), FRONTEND_CLOSED);

    Trace("(%s) <====\n", __PdoGetName(Pdo));
}

static DECLSPEC_NOINLINE VOID
PdoSuspendCallbackLate(
    IN  PVOID               Argument
    )
{
    PXENVIF_PDO             Pdo = Argument;
    NTSTATUS                status;

    __PdoD0ToD3(Pdo);

    status = __PdoD3ToD0(Pdo);
    ASSERT(NT_SUCCESS(status));
}

static DECLSPEC_NOINLINE NTSTATUS
PdoD3ToD0(
    IN  PXENVIF_PDO Pdo
    )
{
    KIRQL           Irql;
    NTSTATUS        status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    status = __PdoD3ToD0(Pdo);
    KeLowerIrql(Irql);

    if (!NT_SUCCESS(status))
        goto fail1;

    Pdo->SuspendInterface = __PdoGetSuspendInterface(Pdo);

    SUSPEND(Acquire, Pdo->SuspendInterface);

    status = SUSPEND(Register,
                     Pdo->SuspendInterface,
                     SUSPEND_CALLBACK_LATE,
                     PdoSuspendCallbackLate,
                     Pdo,
                     &Pdo->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    SUSPEND(Release, Pdo->SuspendInterface);
    Pdo->SuspendInterface = NULL;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __PdoD0ToD3(Pdo);
    KeLowerIrql(Irql);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static DECLSPEC_NOINLINE VOID
PdoD0ToD3(
    IN  PXENVIF_PDO Pdo
    )
{
    KIRQL           Irql;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    SUSPEND(Deregister,
            Pdo->SuspendInterface,
            Pdo->SuspendCallbackLate);
    Pdo->SuspendCallbackLate = NULL;

    SUSPEND(Release, Pdo->SuspendInterface);
    Pdo->SuspendInterface = NULL;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __PdoD0ToD3(Pdo);
    KeLowerIrql(Irql);
}

static DECLSPEC_NOINLINE VOID
PdoS4ToS3(
    IN  PXENVIF_PDO Pdo
    )
{
    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__PdoGetSystemPowerState(Pdo), ==, PowerSystemHibernate);

    __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);

    Trace("(%s) <====\n", __PdoGetName(Pdo));
}

static DECLSPEC_NOINLINE VOID
PdoS3ToS4(
    IN  PXENVIF_PDO Pdo
    )
{
    Trace("(%s) ====>\n", __PdoGetName(Pdo));

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__PdoGetSystemPowerState(Pdo), ==, PowerSystemSleeping3);

    __PdoSetSystemPowerState(Pdo, PowerSystemHibernate);

    Trace("(%s) <====\n", __PdoGetName(Pdo));
}

static FORCEINLINE VOID
__PdoNotifyInstaller(
    IN  PXENVIF_PDO Pdo
    )
{
    HANDLE          ServiceKey;

    UNREFERENCED_PARAMETER(Pdo);

    ServiceKey = DriverGetServiceKey();

    (VOID) RegistryUpdateDwordValue(ServiceKey, "NeedReboot", 1);
}

#define HKEY_LOCAL_MACHINE  "\\Registry\\Machine"
#define CLASS_KEY           HKEY_LOCAL_MACHINE "\\SYSTEM\\CurrentControlSet\\Control\\Class"
#define NETWORK_KEY         HKEY_LOCAL_MACHINE "\\SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

static FORCEINLINE NTSTATUS
__PdoGetDeviceInstanceIDFromAliasSoftwareKey(
    IN      HANDLE          AliasSoftwareKey,
    IN OUT  PANSI_STRING    *DeviceInstanceID
    )
{
    HANDLE                      ConnectionKey;
    HANDLE                      GuidKey;
    HANDLE                      NetworkKey;
    PANSI_STRING                Guid;
    NTSTATUS                    status;
    
    status = RegistryQuerySzValue(AliasSoftwareKey,
                                  "DeviceInstanceID",
                                  DeviceInstanceID);
    if (NT_SUCCESS(status))
        return status;

    // Win2k8 and earlier don't provide DeviceInstanceID

    status = RegistryQuerySzValue(AliasSoftwareKey, 
                                  "NetCfgInstanceId",
                                  &Guid);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryOpenSubKey(NULL,
                                NETWORK_KEY,
                                KEY_READ,
                                &NetworkKey);
    if (!NT_SUCCESS(status))
        goto fail2;
    
    status = RegistryOpenSubKey(NetworkKey,
                                Guid->Buffer,
                                KEY_READ,
                                &GuidKey);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RegistryOpenSubKey(GuidKey,
                                "Connection",
                                KEY_READ,
                                &ConnectionKey);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = RegistryQuerySzValue(ConnectionKey,
                                  "PnpInstanceID",
                                  DeviceInstanceID);
    if (!NT_SUCCESS(status))
        goto fail5;
    
    RegistryCloseKey(ConnectionKey);
    RegistryCloseKey(GuidKey);
    RegistryCloseKey(NetworkKey);
    RegistryFreeSzValue(Guid);
    
    return status;


fail5:
    Error("fail5\n");
    RegistryCloseKey(ConnectionKey);

fail4:
    Error("fail4\n");
    RegistryCloseKey(GuidKey);

fail3:
    Error("fail3\n");
    RegistryCloseKey(NetworkKey);

fail2:
    Error("fail2\n");
    RegistryFreeSzValue(Guid);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoCheckForAlias(
    IN  PXENVIF_PDO             Pdo
    )
{
    HANDLE                      AliasesKey;
    PANSI_STRING                Alias;
    HANDLE                      ClassKey;
    HANDLE                      AliasSoftwareKey;
    PANSI_STRING                DeviceInstanceID;
    PCHAR                       DeviceID;
    PCHAR                       InstanceID;
    PXENFILT_EMULATED_INTERFACE EmulatedInterface;
    NTSTATUS                    status;

    EmulatedInterface = __PdoGetEmulatedInterface(Pdo);

    status = STATUS_NOT_SUPPORTED;
    if (EmulatedInterface == NULL) {
        __PdoNotifyInstaller(Pdo);
        goto fail1;
    }

    AliasesKey = DriverGetAliasesKey();
    ASSERT(AliasesKey != NULL);

    status = RegistryQuerySzValue(AliasesKey,
                                  __PdoGetName(Pdo),
                                  &Alias);
    if (!NT_SUCCESS(status))
        goto fail2;

    if (Alias->Length == 0)   // No alias
        goto done;

    Trace("%Z\n", Alias);

    status = RegistryOpenSubKey(NULL,
                                CLASS_KEY,
                                KEY_READ,
                                &ClassKey);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RegistryOpenSubKey(ClassKey,
                                Alias->Buffer,
                                KEY_READ,
                                &AliasSoftwareKey);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = __PdoGetDeviceInstanceIDFromAliasSoftwareKey(AliasSoftwareKey,
                                                          &DeviceInstanceID);

    if (!NT_SUCCESS(status))
        goto fail5;

    Trace("DeviceInstanceID = %Z\n", DeviceInstanceID);

    DeviceID = DeviceInstanceID->Buffer;

    InstanceID = strrchr(DeviceID, '\\');
    if (InstanceID == NULL)
        goto fail6;

    *(InstanceID++) = '\0';

    EMULATED(Acquire, EmulatedInterface);

    status = STATUS_OBJECTID_EXISTS;
    if (EMULATED(IsDevicePresent,
                 EmulatedInterface,
                 DeviceID,
                 InstanceID)) {
        __PdoNotifyInstaller(Pdo);
        goto fail7;
    }

    EMULATED(Release, EmulatedInterface);
    
    RegistryFreeSzValue(DeviceInstanceID);

    RegistryCloseKey(AliasSoftwareKey);

    RegistryCloseKey(ClassKey);

done:
    RegistryFreeSzValue(Alias);

    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

    EMULATED(Release, EmulatedInterface);

fail6:
    Error("fail6\n");

    RegistryFreeSzValue(DeviceInstanceID);

fail5:
    Error("fail5\n");

    RegistryCloseKey(AliasSoftwareKey);

fail4:
    Error("fail4\n");

    RegistryCloseKey(ClassKey);

fail3:
    Error("fail3\n");

    RegistryFreeSzValue(Alias);

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoStartDevice(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    status = __PdoCheckForAlias(Pdo);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = __PdoSetCurrentMacAddress(Pdo);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = __PdoSetNetLuid(Pdo);
    if (!NT_SUCCESS(status))
        goto fail3;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    __PdoSetSystemPowerState(Pdo, PowerSystemHibernate);
    PdoS4ToS3(Pdo);
    __PdoSetSystemPowerState(Pdo, PowerSystemWorking);

    status = PdoD3ToD0(Pdo);
    if (!NT_SUCCESS(status))
        goto fail4;

    __PdoSetDevicePnpState(Pdo, Started);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);
    PdoS3ToS4(Pdo);
    __PdoSetSystemPowerState(Pdo, PowerSystemShutdown);

    RtlZeroMemory(&Pdo->NetLuid, sizeof (NET_LUID));

fail3:
    Error("fail3\n");

    RtlZeroMemory(&Pdo->CurrentMacAddress, sizeof (ETHERNET_ADDRESS));

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryStopDevice(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoSetDevicePnpState(Pdo, StopPending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoCancelStopDevice(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoRestoreDevicePnpState(Pdo, StopPending);

    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoStopDevice(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    PdoD0ToD3(Pdo);

    __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);
    PdoS3ToS4(Pdo);
    __PdoSetSystemPowerState(Pdo, PowerSystemShutdown);

    RtlZeroMemory(&Pdo->NetLuid, sizeof (NET_LUID));

    RtlZeroMemory(&Pdo->CurrentMacAddress, sizeof (ETHERNET_ADDRESS));

    __PdoSetDevicePnpState(Pdo, Stopped);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryRemoveDevice(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoSetDevicePnpState(Pdo, RemovePending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoCancelRemoveDevice(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    FrontendRemoveFailed(__PdoGetFrontend(Pdo));

    __PdoRestoreDevicePnpState(Pdo, RemovePending);

    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoSurpriseRemoval(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    Warning("%s\n", __PdoGetName(Pdo));

    __PdoSetDevicePnpState(Pdo, SurpriseRemovePending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoRemoveDevice(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PXENVIF_FDO         Fdo = __PdoGetFdo(Pdo);
    BOOLEAN             NeedInvalidate;
    NTSTATUS            status;

    if (__PdoGetDevicePowerState(Pdo) != PowerDeviceD0)
        goto done;

    PdoD0ToD3(Pdo);

    __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);
    PdoS3ToS4(Pdo);
    __PdoSetSystemPowerState(Pdo, PowerSystemShutdown);

done:
    RtlZeroMemory(&Pdo->NetLuid, sizeof (NET_LUID));

    RtlZeroMemory(&Pdo->CurrentMacAddress, sizeof (ETHERNET_ADDRESS));

    NeedInvalidate = FALSE;

    FdoAcquireMutex(Fdo);

    if (__PdoIsMissing(Pdo) ||
        __PdoGetDevicePnpState(Pdo) == SurpriseRemovePending)
        __PdoSetDevicePnpState(Pdo, Deleted);
    else
        __PdoSetDevicePnpState(Pdo, Enumerated);

    if (__PdoIsMissing(Pdo)) {
        if (__PdoGetDevicePnpState(Pdo) == Deleted)
            PdoDestroy(Pdo);
        else
            NeedInvalidate = TRUE;
    }

    FdoReleaseMutex(Fdo);

    if (NeedInvalidate)
        IoInvalidateDeviceRelations(FdoGetPhysicalDeviceObject(Fdo), 
                                    BusRelations);

    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryDeviceRelations(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    PDEVICE_RELATIONS   Relations;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    status = Irp->IoStatus.Status;

    if (StackLocation->Parameters.QueryDeviceRelations.Type != TargetDeviceRelation)
        goto done;

    Relations = ExAllocatePoolWithTag(PagedPool, sizeof (DEVICE_RELATIONS), 'FIV');

    status = STATUS_NO_MEMORY;
    if (Relations == NULL)
        goto done;

    RtlZeroMemory(Relations, sizeof (DEVICE_RELATIONS));

    Relations->Count = 1;
    ObReferenceObject(__PdoGetDeviceObject(Pdo));
    Relations->Objects[0] = __PdoGetDeviceObject(Pdo);

    Irp->IoStatus.Information = (ULONG_PTR)Relations;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoDelegateIrp(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    return FdoDelegateIrp(Pdo->Fdo, Irp);
}

static NTSTATUS
PdoQueryVifInterface(
    IN  PXENVIF_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    USHORT                  Size;
    USHORT                  Version;
    PINTERFACE              Interface;
    NTSTATUS                status;

    status = Irp->IoStatus.Status;        

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Size = StackLocation->Parameters.QueryInterface.Size;
    Version = StackLocation->Parameters.QueryInterface.Version;
    Interface = StackLocation->Parameters.QueryInterface.Interface;

    if (StackLocation->Parameters.QueryInterface.Version != VIF_INTERFACE_VERSION)
        goto done;

    status = STATUS_BUFFER_TOO_SMALL;        
    if (StackLocation->Parameters.QueryInterface.Size < sizeof (INTERFACE))
        goto done;

    Interface->Size = sizeof (INTERFACE);
    Interface->Version = VIF_INTERFACE_VERSION;
    Interface->Context = __PdoGetVifInterface(Pdo);
    Interface->InterfaceReference = NULL;
    Interface->InterfaceDereference = NULL;

    Irp->IoStatus.Information = 0;
    status = STATUS_SUCCESS;

done:
    return status;
}

struct _INTERFACE_ENTRY {
    const GUID  *Guid;
    const CHAR  *Name;
    NTSTATUS    (*Handler)(PXENVIF_PDO, PIRP);
};

#define DEFINE_HANDLER(_Guid, _Function)    \
        { &GUID_ ## _Guid, #_Guid, (_Function) }

struct _INTERFACE_ENTRY PdoInterfaceTable[] = {
    DEFINE_HANDLER(VIF_INTERFACE, PdoQueryVifInterface),
    { NULL, NULL, NULL }
};

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryInterface(
    IN  PXENVIF_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    const GUID              *InterfaceType;
    struct _INTERFACE_ENTRY *Entry;
    NTSTATUS                status;

    status = Irp->IoStatus.Status;        

    if (status != STATUS_NOT_SUPPORTED)
        goto done;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    InterfaceType = StackLocation->Parameters.QueryInterface.InterfaceType;

    for (Entry = PdoInterfaceTable; Entry->Guid != NULL; Entry++) {
        if (IsEqualGUID(InterfaceType, Entry->Guid)) {
            Trace("%s: %s\n",
                  __PdoGetName(Pdo),
                  Entry->Name);
            status = Entry->Handler(Pdo, Irp);
            goto done;
        }
    }

    Trace("%s: (%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x)\n",
          __PdoGetName(Pdo),
          InterfaceType->Data1,
          InterfaceType->Data2,
          InterfaceType->Data3,
          InterfaceType->Data4[0],
          InterfaceType->Data4[1],
          InterfaceType->Data4[2],
          InterfaceType->Data4[3],
          InterfaceType->Data4[4],
          InterfaceType->Data4[5],
          InterfaceType->Data4[6],
          InterfaceType->Data4[7]);

    status = __PdoDelegateIrp(Pdo, Irp);

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryCapabilities(
    IN  PXENVIF_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    PDEVICE_CAPABILITIES    Capabilities;
    SYSTEM_POWER_STATE      SystemPowerState;
    NTSTATUS                status;

    UNREFERENCED_PARAMETER(Pdo);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Capabilities = StackLocation->Parameters.DeviceCapabilities.Capabilities;

    status = STATUS_INVALID_PARAMETER;
    if (Capabilities->Version != 1)
        goto done;

    Capabilities->DeviceD1 = 0;
    Capabilities->DeviceD2 = 0;
    Capabilities->LockSupported = 0;
    Capabilities->EjectSupported = 1;
    Capabilities->Removable = 1;
    Capabilities->DockDevice = 0;
    Capabilities->UniqueID = 1;
    Capabilities->SilentInstall = 1;
    Capabilities->RawDeviceOK = 0;
    Capabilities->SurpriseRemovalOK = 1;
    Capabilities->HardwareDisabled = 0;
    Capabilities->NoDisplayInUI = 0;

    Capabilities->Address = 0xffffffff;
    Capabilities->UINumber = 0xffffffff;

    for (SystemPowerState = 0; SystemPowerState < PowerSystemMaximum; SystemPowerState++) {
        switch (SystemPowerState) {
        case PowerSystemUnspecified:
        case PowerSystemSleeping1:
        case PowerSystemSleeping2:
            break;

        case PowerSystemWorking:
            Capabilities->DeviceState[SystemPowerState] = PowerDeviceD0;
            break;

        default:
            Capabilities->DeviceState[SystemPowerState] = PowerDeviceD3;
            break;
        }
    }

    Capabilities->SystemWake = PowerSystemUnspecified;
    Capabilities->DeviceWake = PowerDeviceUnspecified;
    Capabilities->D1Latency = 0;
    Capabilities->D2Latency = 0;
    Capabilities->D3Latency = 0;

    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

#define MAXTEXTLEN  128

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryDeviceText(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    PWCHAR              Buffer;
    UNICODE_STRING      Text;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextDescription:
        Trace("DeviceTextDescription\n");
        break;

    case DeviceTextLocationInformation:
        Trace("DeviceTextLocationInformation\n");
        break;

    default:
        Irp->IoStatus.Information = 0;
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }

    Buffer = ExAllocatePoolWithTag(PagedPool, MAXTEXTLEN, 'FIV');

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto done;

    RtlZeroMemory(Buffer, MAXTEXTLEN);

    Text.Buffer = Buffer;
    Text.MaximumLength = MAXTEXTLEN;
    Text.Length = 0;

    switch (StackLocation->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextDescription: {
        status = RtlStringCbPrintfW(Buffer,
                                    MAXTEXTLEN,
                                    L"%hs %hs",
                                    FdoGetName(Pdo->Fdo),
                                    __PdoGetName(Pdo));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;
    }
    case DeviceTextLocationInformation:
        status = RtlStringCbPrintfW(Buffer,
                                    MAXTEXTLEN,
                                    L"%hs",
                                    __PdoGetName(Pdo));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Text.Length = (USHORT)((ULONG_PTR)Buffer - (ULONG_PTR)Text.Buffer);

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Trace("%s: %wZ\n", __PdoGetName(Pdo), &Text);

    Irp->IoStatus.Information = (ULONG_PTR)Text.Buffer;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoReadConfig(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoWriteConfig(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryId(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    PWCHAR              Buffer;
    UNICODE_STRING      Id;
    ULONG               Type;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->Parameters.QueryId.IdType) {
    case BusQueryInstanceID:
        Trace("BusQueryInstanceID\n");
        break;

    case BusQueryDeviceID:
        Trace("BusQueryDeviceID\n");
        break;

    case BusQueryHardwareIDs:
        Trace("BusQueryHardwareIDs\n");
        break;

    case BusQueryCompatibleIDs:
        Trace("BusQueryCompatibleIDs\n");
        break;

    case BusQueryContainerID:
        Trace("BusQueryContainerID\n");
        break;

    default:
        Irp->IoStatus.Information = 0;
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }

    Buffer = ExAllocatePoolWithTag(PagedPool, MAX_DEVICE_ID_LEN, 'FIV');

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto done;

    RtlZeroMemory(Buffer, MAX_DEVICE_ID_LEN);

    Id.Buffer = Buffer;
    Id.MaximumLength = MAX_DEVICE_ID_LEN - 1;
    Id.Length = 0;

    switch (StackLocation->Parameters.QueryId.IdType) {
    case BusQueryInstanceID:
    case BusQueryContainerID:
        Type = REG_SZ;

        status = RtlStringCbPrintfW(Buffer,
                                    MAX_DEVICE_ID_LEN - 1,
                                    L"%hs",
                                    __PdoGetName(Pdo));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;

    case BusQueryDeviceID:
        Type = REG_SZ;

        status = RtlStringCbPrintfW(Buffer,
                                    MAX_DEVICE_ID_LEN,
                                    L"XENVIF\\VEN_%hs&DEV_NET&REV_%08X",
                                    __PdoGetVendorName(Pdo),
                                    __PdoGetRevision(Pdo));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;

    case BusQueryHardwareIDs:
    case BusQueryCompatibleIDs: {
        ULONG   Length;

        Type = REG_MULTI_SZ;

        Length = MAX_DEVICE_ID_LEN;
        status = RtlStringCbPrintfW(Buffer,
                                    MAX_DEVICE_ID_LEN,
                                    L"XENVIF\\VEN_%hs&DEV_NET&REV_%08X",
                                    __PdoGetVendorName(Pdo),
                                    __PdoGetRevision(Pdo));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);
        Buffer++;

        Length = MAX_DEVICE_ID_LEN - (ULONG)((ULONG_PTR)Buffer - (ULONG_PTR)Id.Buffer); 
        status = RtlStringCbPrintfW(Buffer,
                                    Length,
                                    L"XENDEVICE");
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);
        Buffer++;

        break;
    }
    default:
        Type = REG_NONE;

        ASSERT(FALSE);
        break;
    }

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    Id.Length = (USHORT)((ULONG_PTR)Buffer - (ULONG_PTR)Id.Buffer);
    Buffer = Id.Buffer;

    switch (Type) {
    case REG_SZ:
        Trace("- %ws\n", Buffer);
        break;

    case REG_MULTI_SZ:
        do {
            Trace("- %ws\n", Buffer);
            Buffer += wcslen(Buffer);
            Buffer++;
        } while (*Buffer != L'\0');
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Irp->IoStatus.Information = (ULONG_PTR)Id.Buffer;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryBusInformation(
    IN  PXENVIF_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PPNP_BUS_INFORMATION    Info;
    NTSTATUS                status;

    UNREFERENCED_PARAMETER(Pdo);

    Info = ExAllocatePoolWithTag(PagedPool, sizeof (PNP_BUS_INFORMATION), 'FIV');

    status = STATUS_NO_MEMORY;
    if (Info == NULL)
        goto done;

    RtlZeroMemory(Info, sizeof (PNP_BUS_INFORMATION));

    Info->BusTypeGuid = GUID_BUS_TYPE_INTERNAL;
    Info->LegacyBusType = PNPBus;
    Info->BusNumber = 0;

    Irp->IoStatus.Information = (ULONG_PTR)Info;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDeviceUsageNotification(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    status = __PdoDelegateIrp(Pdo, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoEject(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    PXENVIF_FDO     Fdo = __PdoGetFdo(Pdo);
    NTSTATUS        status;

    Trace("%s\n", __PdoGetName(Pdo));

    FdoAcquireMutex(Fdo);

    __PdoSetDevicePnpState(Pdo, Deleted);
    __PdoSetMissing(Pdo, "device ejected");

    PdoDestroy(Pdo);

    FdoReleaseMutex(Fdo);

    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchPnp(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    Trace("====> (%s) (%02x:%s)\n",
          __PdoGetName(Pdo),
          MinorFunction, 
          PnpMinorFunctionName(MinorFunction));

    switch (StackLocation->MinorFunction) {
    case IRP_MN_START_DEVICE:
        status = PdoStartDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        status = PdoQueryStopDevice(Pdo, Irp);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        status = PdoCancelStopDevice(Pdo, Irp);
        break;

    case IRP_MN_STOP_DEVICE:
        status = PdoStopDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        status = PdoQueryRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        status = PdoCancelRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        status = PdoSurpriseRemoval(Pdo, Irp);
        break;

    case IRP_MN_REMOVE_DEVICE:
        status = PdoRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        status = PdoQueryDeviceRelations(Pdo, Irp);
        break;

    case IRP_MN_QUERY_INTERFACE:
        status = PdoQueryInterface(Pdo, Irp);
        break;

    case IRP_MN_QUERY_CAPABILITIES:
        status = PdoQueryCapabilities(Pdo, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_TEXT:
        status = PdoQueryDeviceText(Pdo, Irp);
        break;

    case IRP_MN_READ_CONFIG:
        status = PdoReadConfig(Pdo, Irp);
        break;

    case IRP_MN_WRITE_CONFIG:
        status = PdoWriteConfig(Pdo, Irp);
        break;

    case IRP_MN_QUERY_ID:
        status = PdoQueryId(Pdo, Irp);
        break;

    case IRP_MN_QUERY_BUS_INFORMATION:
        status = PdoQueryBusInformation(Pdo, Irp);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        status = PdoDeviceUsageNotification(Pdo, Irp);
        break;

    case IRP_MN_EJECT:
        status = PdoEject(Pdo, Irp);
        break;

    default:
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    }

    Trace("<==== (%02x:%s)(%08x)\n",
          MinorFunction, 
          PnpMinorFunctionName(MinorFunction),
          status);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetDevicePower(
    IN  PXENVIF_PDO     Pdo,
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

    Trace("====> (%s) (%s:%s)\n",
          __PdoGetName(Pdo),
          PowerDeviceStateName(DeviceState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (__PdoGetDevicePowerState(Pdo) > DeviceState) {
        Trace("%s: POWERING UP: %s -> %s\n",
              __PdoGetName(Pdo),
              PowerDeviceStateName(__PdoGetDevicePowerState(Pdo)),
              PowerDeviceStateName(DeviceState));

        ASSERT3U(DeviceState, ==, PowerDeviceD0);
        status = PdoD3ToD0(Pdo);
        ASSERT(NT_SUCCESS(status));
    } else if (__PdoGetDevicePowerState(Pdo) < DeviceState) {
        Trace("%s: POWERING DOWN: %s -> %s\n",
              __PdoGetName(Pdo),
              PowerDeviceStateName(__PdoGetDevicePowerState(Pdo)),
              PowerDeviceStateName(DeviceState));

        ASSERT3U(DeviceState, ==, PowerDeviceD3);
        PdoD0ToD3(Pdo);
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Trace("<==== (%s:%s)\n",
          PowerDeviceStateName(DeviceState), 
          PowerActionName(PowerAction));

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoDevicePower(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_PDO         Pdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP    Irp;

        if (Pdo->DevicePowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Pdo->DevicePowerIrp;

        if (Irp == NULL)
            continue;

        Pdo->DevicePowerIrp = NULL;
        KeMemoryBarrier();

        (VOID) __PdoSetDevicePower(Pdo, Irp);
    }

    return STATUS_SUCCESS;
}

static FORCEINLINE NTSTATUS
__PdoSetSystemPower(
    IN  PXENVIF_PDO         Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    SYSTEM_POWER_STATE      SystemState;
    POWER_ACTION            PowerAction;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s) (%s:%s)\n",
          __PdoGetName(Pdo),
          PowerSystemStateName(SystemState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (__PdoGetSystemPowerState(Pdo) > SystemState) {
        if (SystemState < PowerSystemHibernate &&
            __PdoGetSystemPowerState(Pdo) >= PowerSystemHibernate) {
            __PdoSetSystemPowerState(Pdo, PowerSystemHibernate);
            PdoS4ToS3(Pdo);
        }

        Trace("%s: POWERING UP: %s -> %s\n",
              __PdoGetName(Pdo),
              PowerSystemStateName(__PdoGetSystemPowerState(Pdo)),
              PowerSystemStateName(SystemState));
    } else if (__PdoGetSystemPowerState(Pdo) < SystemState) {
        Trace("%s: POWERING DOWN: %s -> %s\n",
              __PdoGetName(Pdo),
              PowerSystemStateName(__PdoGetSystemPowerState(Pdo)),
              PowerSystemStateName(SystemState));

        if (SystemState >= PowerSystemHibernate &&
            __PdoGetSystemPowerState(Pdo) < PowerSystemHibernate) {
            __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);
            PdoS3ToS4(Pdo);
        }
    }

    __PdoSetSystemPowerState(Pdo, SystemState);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Trace("<==== (%s:%s)\n",
          PowerSystemStateName(SystemState), 
          PowerActionName(PowerAction));

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoSystemPower(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_PDO         Pdo = Context;
    PKEVENT             Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP    Irp;

        if (Pdo->SystemPowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Pdo->SystemPowerIrp;

        if (Irp == NULL)
            continue;

        Pdo->SystemPowerIrp = NULL;
        KeMemoryBarrier();

        (VOID) __PdoSetSystemPower(Pdo, Irp);
    }

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoSetPower(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    POWER_STATE_TYPE    PowerType;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;
    
    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    PowerType = StackLocation->Parameters.Power.Type;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    if (PowerAction >= PowerActionShutdown) {
        Irp->IoStatus.Status = STATUS_SUCCESS;

        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    switch (PowerType) {
    case DevicePowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Pdo->DevicePowerIrp, ==, NULL);
        Pdo->DevicePowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Pdo->DevicePowerThread);

        status = STATUS_PENDING;
        break;

    case SystemPowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Pdo->SystemPowerIrp, ==, NULL);
        Pdo->SystemPowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Pdo->SystemPowerThread);

        status = STATUS_PENDING;
        break;

    default:
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    }

done:    
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryPower(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;
    
    UNREFERENCED_PARAMETER(Pdo);

    Irp->IoStatus.Status = STATUS_SUCCESS;

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchPower(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    switch (StackLocation->MinorFunction) {
    case IRP_MN_SET_POWER:
        status = PdoSetPower(Pdo, Irp);
        break;

    case IRP_MN_QUERY_POWER:
        status = PdoQueryPower(Pdo, Irp);
        break;

    default:
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    }

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchDefault(
    IN  PXENVIF_PDO Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    UNREFERENCED_PARAMETER(Pdo);

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS
PdoDispatch(
    IN  PXENVIF_PDO     Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->MajorFunction) {
    case IRP_MJ_PNP:
        status = PdoDispatchPnp(Pdo, Irp);
        break;

    case IRP_MJ_POWER:
        status = PdoDispatchPower(Pdo, Irp);
        break;

    default:
        status = PdoDispatchDefault(Pdo, Irp);
        break;
    }

    return status;
}

VOID
PdoResume(
    IN  PXENVIF_PDO     Pdo
    )
{
    FrontendResume(__PdoGetFrontend(Pdo));
}

VOID
PdoSuspend(
    IN  PXENVIF_PDO     Pdo
    )
{
    FrontendSuspend(__PdoGetFrontend(Pdo));
}

NTSTATUS
PdoCreate(
    IN  PXENVIF_FDO     Fdo,
    IN  PANSI_STRING    Name
    )
{
    PDEVICE_OBJECT      PhysicalDeviceObject;
    PXENVIF_DX          Dx;
    PXENVIF_PDO         Pdo;
    NTSTATUS            status;

#pragma prefast(suppress:28197) // Possibly leaking memory 'PhysicalDeviceObject'
    status = IoCreateDevice(DriverGetDriverObject(),
                            sizeof(XENVIF_DX),
                            NULL,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN | FILE_AUTOGENERATED_DEVICE_NAME,
                            FALSE,
                            &PhysicalDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    Dx = (PXENVIF_DX)PhysicalDeviceObject->DeviceExtension;
    RtlZeroMemory(Dx, sizeof (XENVIF_DX));

    Dx->Type = PHYSICAL_DEVICE_OBJECT;
    Dx->DeviceObject = PhysicalDeviceObject;
    Dx->DevicePnpState = Present;
    Dx->SystemPowerState = PowerSystemShutdown;
    Dx->DevicePowerState = PowerDeviceD3;

    Pdo = __PdoAllocate(sizeof (XENVIF_PDO));

    status = STATUS_NO_MEMORY;
    if (Pdo == NULL)
        goto fail2;

    Pdo->Dx = Dx;

    status = ThreadCreate(PdoSystemPower, Pdo, &Pdo->SystemPowerThread);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = ThreadCreate(PdoDevicePower, Pdo, &Pdo->DevicePowerThread);
    if (!NT_SUCCESS(status))
        goto fail4;

    __PdoSetName(Pdo, Name);

    status = BusInitialize(Pdo, &Pdo->BusInterface);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = FrontendInitialize(Pdo, &Pdo->Frontend);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = __PdoSetPermanentMacAddress(Pdo, FdoGetStoreInterface(Fdo));
    if (!NT_SUCCESS(status))
        goto fail7;

    status = VifInitialize(Pdo, &Pdo->VifInterface);
    if (!NT_SUCCESS(status))
        goto fail8;

    Info("%p (%s)\n",
         PhysicalDeviceObject,
         __PdoGetName(Pdo));

    Dx->Pdo = Pdo;
    PhysicalDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    __PdoLink(Pdo, Fdo);

    return STATUS_SUCCESS;

fail8:
    Error("fail8\n");

    RtlZeroMemory(&Pdo->PermanentMacAddress, sizeof (ETHERNET_ADDRESS));

fail7:
    Error("fail7\n");

    FrontendTeardown(Pdo->Frontend);
    Pdo->Frontend = NULL;    


fail6:
    Error("fail6\n");

    BusTeardown(&Pdo->BusInterface);

fail5:
    Error("fail5\n");

    ThreadAlert(Pdo->DevicePowerThread);
    ThreadJoin(Pdo->DevicePowerThread);
    Pdo->DevicePowerThread = NULL;

fail4:
    Error("fail4\n");

    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

fail3:
    Error("fail3\n");

    Pdo->Dx = NULL;

    ASSERT(IsZeroMemory(Pdo, sizeof (XENVIF_PDO)));
    __PdoFree(Pdo);

fail2:
    Error("fail2\n");

    IoDeleteDevice(PhysicalDeviceObject);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
PdoDestroy(
    IN  PXENVIF_PDO Pdo
    )
{
    PXENVIF_DX      Dx = Pdo->Dx;
    PDEVICE_OBJECT  PhysicalDeviceObject = Dx->DeviceObject;

    ASSERT3U(__PdoGetDevicePnpState(Pdo), ==, Deleted);

    ASSERT(__PdoIsMissing(Pdo));
    Pdo->Missing = FALSE;

    Info("%p (%s) (%s)\n",
         PhysicalDeviceObject,
         __PdoGetName(Pdo),
         Pdo->Reason);

    Pdo->Reason = NULL;

    __PdoUnlink(Pdo);

    Dx->Pdo = NULL;

    VifTeardown(__PdoGetVifInterface(Pdo));

    RtlZeroMemory(&Pdo->PermanentMacAddress, sizeof (ETHERNET_ADDRESS));

    FrontendTeardown(__PdoGetFrontend(Pdo));
    Pdo->Frontend = NULL;    

    BusTeardown(&Pdo->BusInterface);

    ThreadAlert(Pdo->DevicePowerThread);
    ThreadJoin(Pdo->DevicePowerThread);
    Pdo->DevicePowerThread = NULL;

    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

    Pdo->Dx = NULL;

    ASSERT(IsZeroMemory(Pdo, sizeof (XENVIF_PDO)));
    __PdoFree(Pdo);

    IoDeleteDevice(PhysicalDeviceObject);
}


