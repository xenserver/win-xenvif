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

#ifndef _XENVIF_FDO_H
#define _XENVIF_FDO_H

#include <ntddk.h>
#include <evtchn_interface.h>
#include <debug_interface.h>
#include <store_interface.h>
#include <gnttab_interface.h>
#include <suspend_interface.h>
#include <emulated_interface.h>

#include "driver.h"
#include "types.h"

extern PCHAR
FdoGetName(
    IN  PXENVIF_FDO Fdo
    );

extern NTSTATUS
FdoCreate(
    IN  PDEVICE_OBJECT  PhysicalDeviceObject
    );

extern VOID
FdoDestroy(
    IN  PXENVIF_FDO    Fdo
    );

extern VOID
FdoAddPhysicalDeviceObject(
    IN  PXENVIF_FDO     Fdo,
    IN  PXENVIF_PDO     Pdo
    );

extern VOID
FdoRemovePhysicalDeviceObject(
    IN  PXENVIF_FDO     Fdo,
    IN  PXENVIF_PDO     Pdo
    );

extern VOID
FdoAcquireMutex(
    IN  PXENVIF_FDO     Fdo
    );

extern VOID
FdoReleaseMutex(
    IN  PXENVIF_FDO     Fdo
    );

extern PDEVICE_OBJECT
FdoGetPhysicalDeviceObject(
    IN  PXENVIF_FDO Fdo
    );

extern VOID
FdoReap(
    IN  PXENVIF_FDO Fdo
    );

extern NTSTATUS
FdoDelegateIrp(
    IN  PXENVIF_FDO    Fdo,
    IN  PIRP            Irp
    );

extern PXENBUS_EVTCHN_INTERFACE
FdoGetEvtchnInterface(
    IN  PXENVIF_FDO     Fdo
    );

extern PXENBUS_DEBUG_INTERFACE
FdoGetDebugInterface(
    IN  PXENVIF_FDO     Fdo
    );

extern PXENBUS_STORE_INTERFACE
FdoGetStoreInterface(
    IN  PXENVIF_FDO     Fdo
    );

extern PXENBUS_GNTTAB_INTERFACE
FdoGetGnttabInterface(
    IN  PXENVIF_FDO     Fdo
    );

extern PXENBUS_SUSPEND_INTERFACE
FdoGetSuspendInterface(
    IN  PXENVIF_FDO     Fdo
    );

extern PXENFILT_EMULATED_INTERFACE
FdoGetEmulatedInterface(
    IN  PXENVIF_FDO Fdo
    );

extern NTSTATUS
FdoDispatch(
    IN  PXENVIF_FDO    Fdo,
    IN  PIRP            Irp
    );

#endif  // _XENVIF_FDO_H
