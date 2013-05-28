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

#include <ntddk.h>
#include <util.h>
#include <version.h>

#include "registry.h"
#include "fdo.h"
#include "pdo.h"
#include "receiver.h"
#include "driver.h"
#include "log.h"
#include "assert.h"

extern PULONG       InitSafeBootMode;

PDRIVER_OBJECT      DriverObject;

XENVIF_PARAMETERS   DriverParameters;

DRIVER_UNLOAD       DriverUnload;

VOID
DriverUnload(
    IN  PDRIVER_OBJECT  _DriverObject
    )
{
    ASSERT3P(_DriverObject, ==, DriverObject);

    Trace("====>\n");

    if (*InitSafeBootMode > 0)
        goto done;

    RegistryFreeSzValue(DriverParameters.UnsupportedDevices);

    RegistryTeardown();

done:
    DriverObject = NULL;

    Trace("<====\n");
}

DRIVER_ADD_DEVICE   AddDevice;

NTSTATUS
AddDevice(
    IN  PDRIVER_OBJECT  _DriverObject,
    IN  PDEVICE_OBJECT  DeviceObject
    )
{
    NTSTATUS            status;

    ASSERT3P(_DriverObject, ==, DriverObject);

    status = FdoCreate(DeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    // prefast stupidity
    ASSERT(!(DeviceObject->Flags & DO_DEVICE_INITIALIZING));
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

DRIVER_DISPATCH Dispatch;

NTSTATUS 
Dispatch(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PXENVIF_DX          Dx;
    NTSTATUS            status;

    Dx = (PXENVIF_DX)DeviceObject->DeviceExtension;
    ASSERT3P(Dx->DeviceObject, ==, DeviceObject);

    if (Dx->DevicePnpState == Deleted) {
        status = STATUS_NO_SUCH_DEVICE;

        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        goto done;
    }

    status = STATUS_NOT_SUPPORTED;
    switch (Dx->Type) {
    case PHYSICAL_DEVICE_OBJECT: {
        PXENVIF_PDO Pdo = Dx->Pdo;

        status = PdoDispatch(Pdo, Irp);
        break;
    }
    case FUNCTION_DEVICE_OBJECT: {
        PXENVIF_FDO Fdo = Dx->Fdo;

        status = FdoDispatch(Fdo, Irp);
        break;
    }
    default:
        ASSERT(FALSE);
        break;
    }

done:
    return status;
}

DRIVER_INITIALIZE   DriverEntry;

NTSTATUS
DriverEntry(
    IN  PDRIVER_OBJECT  _DriverObject,
    IN  PUNICODE_STRING RegistryPath
    )
{
    HANDLE              Key;
    ULONG               Index;
    NTSTATUS            status;

    ASSERT3P(DriverObject, ==, NULL);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    Trace("====>\n");

    Info("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    DriverObject = _DriverObject;
    DriverObject->DriverUnload = DriverUnload;

    if (*InitSafeBootMode > 0)
        goto done;

    status = RegistryInitialize(RegistryPath);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryOpenSubKey("Parameters", KEY_READ, &Key);
    if (NT_SUCCESS(status)) {
        status = RegistryQuerySzValue(Key,
                                      "UnsupportedDevices",
                                      &DriverParameters.UnsupportedDevices);
        if (!NT_SUCCESS(status))
            DriverParameters.UnsupportedDevices = NULL;

        status = RegistryQueryDwordValue(Key,
                                         "ReceiverMaximumProtocol",
                                         &DriverParameters.ReceiverMaximumProtocol);
        if (!NT_SUCCESS(status))
            DriverParameters.ReceiverMaximumProtocol = 0;

        status = RegistryQueryDwordValue(Key,
                                         "ReceiverCalculateChecksums",
                                         &DriverParameters.ReceiverCalculateChecksums);
        if (!NT_SUCCESS(status))
            DriverParameters.ReceiverCalculateChecksums = 0;

        status = RegistryQueryDwordValue(Key,
                                         "ReceiverAllowGsoPackets",
                                         &DriverParameters.ReceiverAllowGsoPackets);
        if (!NT_SUCCESS(status))
            DriverParameters.ReceiverAllowGsoPackets = 1;

        status = RegistryQueryDwordValue(Key,
                                         "ReceiverIpAlignOffset",
                                         &DriverParameters.ReceiverIpAlignOffset);
        if (!NT_SUCCESS(status))
            DriverParameters.ReceiverIpAlignOffset = 0;

        status = RegistryQueryDwordValue(Key,
                                         "CreatePDOs",
                                         &DriverParameters.CreatePDOs);
        if (!NT_SUCCESS(status))
            DriverParameters.CreatePDOs = 1;

        RegistryCloseKey(Key);
    }

    DriverObject->DriverExtension->AddDevice = AddDevice;

    for (Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; Index++) {
#pragma prefast(suppress:28169) // No __drv_dispatchType annotation
#pragma prefast(suppress:28168) // No matching __drv_dispatchType annotation for IRP_MJ_CREATE
        DriverObject->MajorFunction[Index] = Dispatch;
    }

done:
    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}
