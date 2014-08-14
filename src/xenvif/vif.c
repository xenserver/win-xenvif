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
#include <ntstrsafe.h>
#include <stdarg.h>
#include <xen.h>
#include <util.h>

#include "pdo.h"
#include "vif.h"
#include "mrsw.h"
#include "thread.h"
#include "dbg_print.h"
#include "assert.h"

struct _XENVIF_VIF_CONTEXT {
    PXENVIF_PDO                 Pdo;
    XENVIF_MRSW_LOCK            Lock;
    LONG                        References;
    PXENVIF_FRONTEND            Frontend;
    BOOLEAN                     Enabled;    
    XENVIF_VIF_CALLBACK         Callback;
    PVOID                       Argument;
    PXENVIF_THREAD              MacThread;
    KEVENT                      MacEvent;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
};

#define XENVIF_VIF_TAG  'FIV'

static FORCEINLINE PVOID
__VifAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, XENVIF_VIF_TAG);
}

static FORCEINLINE VOID
__VifFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_VIF_TAG);
}

static NTSTATUS
VifMac(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           _Context
    )
{
    PXENVIF_VIF_CONTEXT Context = _Context;
    PKEVENT             Event;

    Trace("====>\n");

    Event = ThreadGetEvent(Self);

    for (;;) {
        Trace("waiting...\n");

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        Trace("awake\n");

        if (ThreadIsAlerted(Self))
            break;
        
        if (Context->Enabled)
            Context->Callback(Context->Argument,
                              XENVIF_MAC_STATE_CHANGE);

        KeSetEvent(&Context->MacEvent, IO_NO_INCREMENT, FALSE);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static NTSTATUS
VifEnable(
    IN  PINTERFACE          Interface,
    IN  XENVIF_VIF_CALLBACK Callback,
    IN  PVOID               Argument
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    KIRQL                   Irql;
    NTSTATUS                status;

    Trace("====>\n");

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (Context->Enabled)
        goto done;

    Context->Callback = Callback;
    Context->Argument = Argument;

    Context->Enabled = TRUE;

    KeMemoryBarrier();

    status = FrontendSetState(Context->Frontend, FRONTEND_ENABLED);
    if (!NT_SUCCESS(status))
        goto fail1;

done:
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    Context->Argument = NULL;
    Context->Callback = NULL;

    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    return status;
}

static VOID
VifDisable(
    IN  PINTERFACE      Interface
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;
    KIRQL               Irql;

    Trace("====>\n");

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (!Context->Enabled) {
        ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);
        goto done;
    }

    Context->Enabled = FALSE;

    KeMemoryBarrier();

    (VOID) FrontendSetState(Context->Frontend, FRONTEND_CONNECTED);

    ReleaseMrswLockExclusive(&Context->Lock, Irql, TRUE);

    ReceiverWaitForPackets(FrontendGetReceiver(Context->Frontend));
    TransmitterAbortPackets(FrontendGetTransmitter(Context->Frontend));

    Trace("waiting for mac thread..\n");

    KeClearEvent(&Context->MacEvent);
    ThreadWake(Context->MacThread);

    (VOID) KeWaitForSingleObject(&Context->MacEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    Trace("done\n");

    Context->Argument = NULL;
    Context->Callback = NULL;

    ReleaseMrswLockShared(&Context->Lock);

done:
    Trace("<====\n");
}

static NTSTATUS
VifQueryStatistic(
    IN  PINTERFACE              Interface,
    IN  XENVIF_VIF_STATISTIC    Index,
    OUT PULONGLONG              Value
    )
{
    PXENVIF_VIF_CONTEXT         Context = Interface->Context;
    NTSTATUS                    status;

    status = STATUS_INVALID_PARAMETER;
    if (Index >= XENVIF_VIF_STATISTIC_COUNT)
        goto done;
        
    AcquireMrswLockShared(&Context->Lock);

    FrontendQueryStatistic(Context->Frontend, Index, Value);

    ReleaseMrswLockShared(&Context->Lock);
    status = STATUS_SUCCESS;

done:
    return status;
}

static NTSTATUS
VifTransmitterSetPacketOffset(
    IN  PINTERFACE                          Interface,
    IN  XENVIF_TRANSMITTER_PACKET_OFFSET    Type,
    IN  LONG_PTR                            Value
    )
{
    PXENVIF_VIF_CONTEXT                     Context = Interface->Context;
    NTSTATUS                                status;

    AcquireMrswLockShared(&Context->Lock);

    status = TransmitterSetPacketOffset(FrontendGetTransmitter(Context->Frontend),
                                        Type,
                                        Value);
    
    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifReceiverReturnPackets( 
    IN  PINTERFACE      Interface,
    IN  PLIST_ENTRY     List
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverReturnPackets(FrontendGetReceiver(Context->Frontend),
                          List);

    ReleaseMrswLockShared(&Context->Lock);
}


static NTSTATUS
VifTransmitterQueuePackets(
    IN  PINTERFACE                  Interface,
    IN  PXENVIF_TRANSMITTER_PACKET  Head
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    NTSTATUS                        status;

    AcquireMrswLockShared(&Context->Lock);

    status = STATUS_UNSUCCESSFUL;
    if (Context->Enabled == FALSE)
        goto fail1;

    TransmitterQueuePackets(FrontendGetTransmitter(Context->Frontend),
                            Head);            

    ReleaseMrswLockShared(&Context->Lock);

    return STATUS_SUCCESS;

fail1:
    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifTransmitterQueryOffloadOptions(
    IN  PINTERFACE                  Interface,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS Options
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    TransmitterQueryOffloadOptions(FrontendGetTransmitter(Context->Frontend),
                                   Options);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifTransmitterQueryLargePacketSize(
    IN  PINTERFACE      Interface,
    IN  UCHAR           Version,
    OUT PULONG          Size
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    TransmitterQueryLargePacketSize(FrontendGetTransmitter(Context->Frontend),
                                    Version,
                                    Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifReceiverSetOffloadOptions(
    IN  PINTERFACE                  Interface,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  Options
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverSetOffloadOptions(FrontendGetReceiver(Context->Frontend),
                              Options);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifMacQueryState(
    IN  PINTERFACE                  Interface,
    OUT PNET_IF_MEDIA_CONNECT_STATE MediaConnectState OPTIONAL,
    OUT PULONG64                    LinkSpeed OPTIONAL,
    OUT PNET_IF_MEDIA_DUPLEX_STATE  MediaDuplexState OPTIONAL
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryState(FrontendGetMac(Context->Frontend),
                  MediaConnectState,
                  LinkSpeed,
                  MediaDuplexState);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifMacQueryMaximumFrameSize(
    IN  PINTERFACE      Interface,
    OUT PULONG          Size
    )
{
    PXENVIF_VIF_CONTEXT Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryMaximumFrameSize(FrontendGetMac(Context->Frontend), Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifMacQueryPermanentAddress(
    IN  PINTERFACE          Interface,
    OUT PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryPermanentAddress(FrontendGetMac(Context->Frontend), Address);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifMacQueryCurrentAddress(
    IN  PINTERFACE          Interface,
    OUT PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    MacQueryCurrentAddress(FrontendGetMac(Context->Frontend), Address);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifMacQueryMulticastAddresses(
    IN      PINTERFACE          Interface,
    OUT     PETHERNET_ADDRESS   Address OPTIONAL,
    IN OUT  PULONG              Count
    )
{
    PXENVIF_VIF_CONTEXT         Context = Interface->Context;
    NTSTATUS                    status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacQueryMulticastAddresses(FrontendGetMac(Context->Frontend),
                                        Address,
                                        Count);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifMacSetMulticastAddresses(
    IN  PINTERFACE          Interface,
    IN  PETHERNET_ADDRESS   Address,
    IN  ULONG               Count
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    NTSTATUS                status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacSetMulticastAddresses(FrontendGetMac(Context->Frontend),
                                      Address,
                                      Count);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifMacQueryFilterLevel(
    IN  PINTERFACE                  Interface,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    OUT PXENVIF_MAC_FILTER_LEVEL    Level
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    NTSTATUS                status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacQueryFilterLevel(FrontendGetMac(Context->Frontend),
                                 Type,
                                 Level);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifMacSetFilterLevel(
    IN  PINTERFACE                  Interface,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    IN  XENVIF_MAC_FILTER_LEVEL     Level
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    NTSTATUS                        status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacSetFilterLevel(FrontendGetMac(Context->Frontend), Type, Level);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifReceiverQueryRingSize(
    IN  PINTERFACE          Interface,
    OUT PULONG              Size
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    ReceiverQueryRingSize(FrontendGetReceiver(Context->Frontend), Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifTransmitterQueryRingSize(
    IN  PINTERFACE          Interface,
    OUT PULONG              Size
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;

    AcquireMrswLockShared(&Context->Lock);

    TransmitterQueryRingSize(FrontendGetTransmitter(Context->Frontend), Size);

    ReleaseMrswLockShared(&Context->Lock);
}

static DECLSPEC_NOINLINE VOID
VifSuspendCallbackLate(
    IN  PVOID           Argument
    )
{
    PXENVIF_VIF_CONTEXT Context = Argument;
    NTSTATUS            status;

    if (!Context->Enabled)
        return;

    status = FrontendSetState(Context->Frontend, FRONTEND_ENABLED);
    ASSERT(NT_SUCCESS(status));

    TransmitterAdvertiseAddresses(FrontendGetTransmitter(Context->Frontend));
}

static NTSTATUS
VifAcquire(
    PINTERFACE              Interface
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    KIRQL                   Irql;
    NTSTATUS                status;

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (Context->References++ != 0)
        goto done;

    Trace("====>\n");

    status = XENBUS_SUSPEND(Acquire, &Context->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail1;   

    status = XENBUS_SUSPEND(Register,
                            &Context->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            VifSuspendCallbackLate,
                            Context,
                            &Context->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail2;

    Context->Frontend = PdoGetFrontend(Context->Pdo);

    Trace("<====\n");

done:
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    XENBUS_SUSPEND(Release, &Context->SuspendInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    --Context->References;
    ASSERT3U(Context->References, ==, 0);
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    return status;
}

VOID
VifRelease(
    IN  PINTERFACE          Interface
    )
{
    PXENVIF_VIF_CONTEXT     Context = Interface->Context;
    KIRQL                   Irql;

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (--Context->References > 0)
        goto done;

    Trace("====>\n");

    ASSERT(!Context->Enabled);

    Context->Frontend = NULL;

    XENBUS_SUSPEND(Deregister,
                   &Context->SuspendInterface,
                   Context->SuspendCallbackLate);
    Context->SuspendCallbackLate = NULL;

    XENBUS_SUSPEND(Release, &Context->SuspendInterface);

    Trace("<====\n");

done:
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);
}

static struct _XENVIF_VIF_INTERFACE_V1 VifInterfaceVersion1 = {
    { sizeof (struct _XENVIF_VIF_INTERFACE_V1), 1, NULL, NULL, NULL },
    VifAcquire,
    VifRelease,
    VifEnable,
    VifDisable,
    VifQueryStatistic,
    VifReceiverReturnPackets,
    VifReceiverSetOffloadOptions,
    VifReceiverQueryRingSize,
    VifTransmitterSetPacketOffset,
    VifTransmitterQueuePackets,
    VifTransmitterQueryOffloadOptions,
    VifTransmitterQueryLargePacketSize,
    VifTransmitterQueryRingSize,
    VifMacQueryState,
    VifMacQueryMaximumFrameSize,
    VifMacQueryPermanentAddress,
    VifMacQueryCurrentAddress,
    VifMacQueryMulticastAddresses,
    VifMacSetMulticastAddresses,
    VifMacSetFilterLevel,
    VifMacQueryFilterLevel
};

NTSTATUS
VifInitialize(
    IN  PXENVIF_PDO         Pdo,
    OUT PXENVIF_VIF_CONTEXT *Context
    )
{
    NTSTATUS                status;

    Trace("====>\n");

    *Context = __VifAllocate(sizeof (XENVIF_VIF_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (*Context == NULL)
        goto fail1;

    InitializeMrswLock(&(*Context)->Lock);

    FdoGetSuspendInterface(PdoGetFdo(Pdo),&(*Context)->SuspendInterface);

    KeInitializeEvent(&(*Context)->MacEvent, NotificationEvent, FALSE);

    status = ThreadCreate(VifMac,
                          *Context,
                          &(*Context)->MacThread);
    if (!NT_SUCCESS(status))
        goto fail2;

    (*Context)->Pdo = Pdo;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail3\n");

    RtlZeroMemory(&(*Context)->MacEvent, sizeof (KEVENT));

    RtlZeroMemory(&(*Context)->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&(*Context)->Lock, sizeof (XENVIF_MRSW_LOCK));

    ASSERT(IsZeroMemory(*Context, sizeof (XENVIF_VIF_CONTEXT)));
    __VifFree(*Context);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
VifGetInterface(
    IN      PXENVIF_VIF_CONTEXT Context,
    IN      ULONG               Version,
    IN OUT  PINTERFACE          Interface,
    IN      ULONG               Size
    )
{
    NTSTATUS                    status;

    switch (Version) {
    case 1: {
        struct _XENVIF_VIF_INTERFACE_V1 *VifInterface;

        VifInterface = (struct _XENVIF_VIF_INTERFACE_V1 *)Interface;

        status = STATUS_BUFFER_OVERFLOW;
        if (Size < sizeof (struct _XENVIF_VIF_INTERFACE_V1))
            break;

        *VifInterface = VifInterfaceVersion1;

        ASSERT3U(Interface->Version, ==, Version);
        Interface->Context = Context;

        status = STATUS_SUCCESS;
        break;
    }
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    return status;
}   

VOID
VifTeardown(
    IN  PXENVIF_VIF_CONTEXT Context
    )
{
    Trace("====>\n");

    Context->Pdo = NULL;

    ThreadAlert(Context->MacThread);
    ThreadJoin(Context->MacThread);
    Context->MacThread = NULL;

    RtlZeroMemory(&Context->MacEvent, sizeof (KEVENT));

    RtlZeroMemory(&Context->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&Context->Lock, sizeof (XENVIF_MRSW_LOCK));

    ASSERT(IsZeroMemory(Context, sizeof (XENVIF_VIF_CONTEXT)));
    __VifFree(Context);

    Trace("<====\n");
}

VOID
VifReceiverQueuePackets(
    IN  PXENVIF_VIF_CONTEXT Context,
    IN  PLIST_ENTRY         List
    )
{
    Context->Callback(Context->Argument,
                      XENVIF_RECEIVER_QUEUE_PACKETS,
                      List);
}

VOID
VifTransmitterReturnPackets(
    IN  PXENVIF_VIF_CONTEXT         Context,
    IN  PXENVIF_TRANSMITTER_PACKET  Head
    )
{
    Context->Callback(Context->Argument,
                      XENVIF_TRANSMITTER_RETURN_PACKETS,
                      Head);
}

extern PXENVIF_THREAD
VifGetMacThread(
    IN  PXENVIF_VIF_CONTEXT Context
    )
{
    return Context->MacThread;
}
