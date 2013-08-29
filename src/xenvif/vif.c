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

#define VIF_POOL   ' FIV'

typedef struct _VIF_CALLBACK {
    VOID    (*Function)(PVOID, XENVIF_CALLBACK_TYPE, ...);
    PVOID   Argument;
} VIF_CALLBACK, *PVIF_CALLBACK;

struct _XENVIF_VIF_CONTEXT {
    LONG                        References;
    XENVIF_MRSW_LOCK            Lock;
    PXENVIF_PDO                 Pdo;
    BOOLEAN                     Enabled;
    PXENVIF_THREAD              MonitorThread;
    KEVENT                      MonitorEvent;
    VIF_CALLBACK                Callback;

    PXENBUS_SUSPEND_INTERFACE   SuspendInterface;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
};

static FORCEINLINE PVOID
__VifAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, VIF_POOL);
}

static FORCEINLINE VOID
__VifFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, VIF_POOL);
}

VOID
VifCompletePackets(
    IN  PXENVIF_VIF_INTERFACE       Interface,
    IN  PXENVIF_TRANSMITTER_PACKET  HeadPacket
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;
    PVIF_CALLBACK                   Callback = &Context->Callback;

    ASSERT(Callback != NULL);

    Callback->Function(Callback->Argument,
                       XENVIF_CALLBACK_COMPLETE_PACKETS,
                       HeadPacket);
}

VOID
VifReceivePackets(
    IN  PXENVIF_VIF_INTERFACE   Interface,
    IN  PLIST_ENTRY             List
    )
{
    PXENVIF_VIF_CONTEXT         Context = Interface->Context;
    PVIF_CALLBACK               Callback = &Context->Callback;

    ASSERT(Callback != NULL);

    Callback->Function(Callback->Argument,
                       XENVIF_CALLBACK_RECEIVE_PACKETS,
                       List);
}

enum {
    THREAD_EVENT = 0,
    MAC_EVENT,
    EVENT_COUNT
};

C_ASSERT(EVENT_COUNT <= THREAD_WAIT_OBJECTS);

#define STATUS_MASK ((1 << 6) - 1)

static NTSTATUS
VifMonitor(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           _Context
    )
{
    PXENVIF_VIF_CONTEXT Context = _Context;
    PXENVIF_FRONTEND    Frontend = PdoGetFrontend(Context->Pdo);
    PKEVENT             Event[EVENT_COUNT];

    Trace("====>\n");

    Event[THREAD_EVENT] = ThreadGetEvent(Self);
    Event[MAC_EVENT] = MacGetEvent(FrontendGetMac(Frontend));

    for (;;) {
        NTSTATUS    status;

        Trace("waiting...\n");

        status = KeWaitForMultipleObjects(EVENT_COUNT,
                                          Event,
                                          WaitAny,
                                          Executive,
                                          KernelMode,
                                          FALSE,
                                          NULL,
                                          NULL);

        Trace("awake\n");

        if (status >= STATUS_WAIT_0 &&
            status < STATUS_WAIT_0 + EVENT_COUNT) {
            switch (status & STATUS_MASK) {
            case MAC_EVENT: {
                KeClearEvent(Event[MAC_EVENT]);

                Trace("MAC_EVENT\n");

                if (Context->Enabled) {
                    PVIF_CALLBACK   Callback = &Context->Callback;

                    Callback->Function(Callback->Argument,
                                       XENVIF_CALLBACK_MEDIA_STATE_CHANGE);
                }

                break;
            }
            case THREAD_EVENT:
                KeClearEvent(Event[THREAD_EVENT]);

                Trace("THREAD_EVENT\n");

                if (ThreadIsAlerted(Self))
                    goto done;

                KeSetEvent(&Context->MonitorEvent, IO_NO_INCREMENT, FALSE);
                break;

            default:
                ASSERT(FALSE);
                break;
            }
        }
    }

done:
    KeSetEvent(&Context->MonitorEvent, IO_NO_INCREMENT, FALSE);

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
VifSuspendCallbackLate(
    IN  PVOID           Argument
    )
{
    PXENVIF_VIF_CONTEXT Context = Argument;
    PXENVIF_FRONTEND    Frontend = PdoGetFrontend(Context->Pdo);
    NTSTATUS            status;

    status = FrontendSetState(Frontend, FRONTEND_ENABLED);
    ASSERT(NT_SUCCESS(status));

    TransmitterAdvertizeAddresses(FrontendGetTransmitter(Frontend));
}

static NTSTATUS
VifEnable(
    IN  PXENVIF_VIF_CONTEXT Context,
    IN  VOID                (*Function)(PVOID, XENVIF_CALLBACK_TYPE, ...),
    IN  PVOID               Argument
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);
    KIRQL                   Irql;
    PVIF_CALLBACK           Callback;
    PKEVENT                 Event;
    NTSTATUS                status;

    Trace("====>\n");

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (Context->Enabled)
        goto done;

    Callback = &Context->Callback;
    Callback->Function = Function;
    Callback->Argument = Argument;

    status = FrontendSetState(Frontend, FRONTEND_ENABLED);
    if (!NT_SUCCESS(status))
        goto fail1;

    Context->SuspendInterface = FrontendGetSuspendInterface(Frontend);

    SUSPEND(Acquire, Context->SuspendInterface);

    status = SUSPEND(Register,
                     Context->SuspendInterface,
                     SUSPEND_CALLBACK_LATE,
                     VifSuspendCallbackLate,
                     Context,
                     &Context->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail2;

    Context->Enabled = TRUE;

    Event = MacGetEvent(FrontendGetMac(Frontend));
    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

done:
    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    SUSPEND(Release, Context->SuspendInterface);
    Context->SuspendInterface = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    RtlZeroMemory(&Context->Callback, sizeof (VIF_CALLBACK));

    ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);

    return status;
}

static VOID
VifDisable(
    IN  PXENVIF_VIF_CONTEXT Context
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);
    KIRQL                   Irql;
    PKEVENT                 Event;

    Trace("====>\n");

    AcquireMrswLockExclusive(&Context->Lock, &Irql);

    if (!Context->Enabled) {
        ReleaseMrswLockExclusive(&Context->Lock, Irql, FALSE);
        goto done;
    }

    Context->Enabled = FALSE;

    Event = MacGetEvent(FrontendGetMac(Frontend));
    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    SUSPEND(Deregister,
            Context->SuspendInterface,
            Context->SuspendCallbackLate);
    Context->SuspendCallbackLate = NULL;

    SUSPEND(Release, Context->SuspendInterface);
    Context->SuspendInterface = NULL;

    (VOID) FrontendSetState(Frontend, FRONTEND_CONNECTED);

    ReleaseMrswLockExclusive(&Context->Lock, Irql, TRUE);

    ReceiverWaitForPackets(FrontendGetReceiver(Frontend));
    TransmitterAbortPackets(FrontendGetTransmitter(Frontend));

    KeClearEvent(&Context->MonitorEvent);
    ThreadWake(Context->MonitorThread);

    Trace("waiting for monitor thread\n");

    (VOID) KeWaitForSingleObject(&Context->MonitorEvent,
                                 Executive,
                                 KernelMode,
                                 FALSE,
                                 NULL);

    RtlZeroMemory(&Context->Callback, sizeof (VIF_CALLBACK));

    ReleaseMrswLockShared(&Context->Lock);

done:
    Trace("<====\n");
}

static VOID
VifQueryPacketStatistics(
    IN  PXENVIF_VIF_CONTEXT         Context,
    OUT PXENVIF_PACKET_STATISTICS   Statistics
    )
{
    PXENVIF_FRONTEND                Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    ReceiverGetPacketStatistics(FrontendGetReceiver(Frontend),
                                &Statistics->Receiver);
    TransmitterGetPacketStatistics(FrontendGetTransmitter(Frontend),
                                   &Statistics->Transmitter);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifUpdatePacketMetadata(
    IN  PXENVIF_VIF_CONTEXT                 Context,
    IN  PXENVIF_TRANSMITTER_PACKET_METADATA Metadata
    )
{
    PXENVIF_FRONTEND                        Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    TransmitterSetPacketMetadata(FrontendGetTransmitter(Frontend),
                                 *Metadata);
    
    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifReturnPacket(
    IN  PXENVIF_VIF_CONTEXT     Context,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PXENVIF_FRONTEND            Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    ReceiverReturnPacket(FrontendGetReceiver(Frontend),
                         Packet);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifQueuePackets(
    IN  PXENVIF_VIF_CONTEXT         Context,
    IN  PXENVIF_TRANSMITTER_PACKET  HeadPacket
    )
{
    PXENVIF_FRONTEND                Frontend = PdoGetFrontend(Context->Pdo);
    NTSTATUS                        status;

    AcquireMrswLockShared(&Context->Lock);

    status = STATUS_UNSUCCESSFUL;
    if (Context->Enabled == FALSE) {
        Trace("NOT ENABLED\n");

        goto fail1;
    }

    TransmitterQueuePackets(FrontendGetTransmitter(Frontend),
                            HeadPacket);            

    ReleaseMrswLockShared(&Context->Lock);

    return STATUS_SUCCESS;

fail1:
    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifQueryOffloadOptions(
    IN  PXENVIF_VIF_CONTEXT     Context,
    OUT PXENVIF_OFFLOAD_OPTIONS Options
    )
{
    PXENVIF_FRONTEND            Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    TransmitterGetOffloadOptions(FrontendGetTransmitter(Frontend),
                                 Options);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifUpdateOffloadOptions(
    IN  PXENVIF_VIF_CONTEXT     Context,
    IN  XENVIF_OFFLOAD_OPTIONS  Options
    )
{
    PXENVIF_FRONTEND            Frontend = PdoGetFrontend(Context->Pdo);
    NTSTATUS                    status;

    AcquireMrswLockShared(&Context->Lock);

    status = ReceiverSetOffloadOptions(FrontendGetReceiver(Frontend),
                                       Options);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifQueryLargePacketSize(
    IN  PXENVIF_VIF_CONTEXT Context,
    IN  UCHAR               Version,
    OUT PULONG              Size
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    *Size = TransmitterGetLargePacketSize(FrontendGetTransmitter(Frontend), Version);

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifQueryMediaState(
    IN  PXENVIF_VIF_CONTEXT         Context,
    OUT PNET_IF_MEDIA_CONNECT_STATE MediaConnectState OPTIONAL,
    OUT PULONG64                    LinkSpeed OPTIONAL,
    OUT PNET_IF_MEDIA_DUPLEX_STATE  MediaDuplexState OPTIONAL
    )
{
    PXENVIF_FRONTEND                Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    if (Context->Enabled && MacGetLinkState(FrontendGetMac(Frontend))) {
        if (MediaConnectState != NULL)
            *MediaConnectState = MediaConnectStateConnected;

        if (LinkSpeed != NULL)
            *LinkSpeed = (ULONGLONG)MacGetLinkSpeed(FrontendGetMac(Frontend)) * 1000000000ull;

        if (MediaDuplexState != NULL)
            *MediaDuplexState = MediaDuplexStateFull;
    } else {
        if (MediaConnectState != NULL)
            *MediaConnectState = MediaConnectStateDisconnected;

        if (LinkSpeed != NULL)
            *LinkSpeed = 0;

        if (MediaDuplexState != NULL)
            *MediaDuplexState = MediaDuplexStateUnknown;
    }

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifQueryMaximumFrameSize(
    IN  PXENVIF_VIF_CONTEXT Context,
    OUT PULONG              Size
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    *Size = MacGetMaximumFrameSize(FrontendGetMac(Frontend));

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifQueryPermanentAddress(
    IN  PXENVIF_VIF_CONTEXT Context,
    OUT PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    *Address = *MacGetPermanentAddress(FrontendGetMac(Frontend));

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifQueryCurrentAddress(
    IN  PXENVIF_VIF_CONTEXT Context,
    OUT PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    *Address = *MacGetCurrentAddress(FrontendGetMac(Frontend));

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifUpdateCurrentAddress(
    IN  PXENVIF_VIF_CONTEXT Context,
    OUT PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);
    NTSTATUS                status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacSetCurrentAddress(FrontendGetMac(Frontend), Address);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifQueryMulticastAddresses(
    IN  PXENVIF_VIF_CONTEXT Context,
    OUT ETHERNET_ADDRESS    Address[] OPTIONAL,
    OUT PULONG              Count
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);
    ULONG                   Size;
    NTSTATUS                status;

    AcquireMrswLockShared(&Context->Lock);

    Size = sizeof (ETHERNET_ADDRESS) * *Count;

    (VOID) MacGetMulticastAddresses(FrontendGetMac(Frontend),
                                    Count);

    status = STATUS_BUFFER_TOO_SMALL;
    if (Size < sizeof (ETHERNET_ADDRESS) * *Count)
        goto fail1;

    RtlCopyMemory(Address,
                  MacGetMulticastAddresses(FrontendGetMac(Frontend), Count),
                  Size);

    ReleaseMrswLockShared(&Context->Lock);

    return STATUS_SUCCESS;

fail1:
    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static NTSTATUS
VifUpdateMulticastAddresses(
    IN  PXENVIF_VIF_CONTEXT Context,
    IN  ETHERNET_ADDRESS    Address[],
    IN  ULONG               Count
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);
    NTSTATUS                status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacSetMulticastAddresses(FrontendGetMac(Frontend),
                                      Address,
                                      Count);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifQueryFilterLevel(
    IN  PXENVIF_VIF_CONTEXT         Context,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    OUT PXENVIF_MAC_FILTER_LEVEL    Level
    )
{
    PXENVIF_FRONTEND                Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    *Level = MacGetFilterLevel(FrontendGetMac(Frontend),
                               Type);

    ReleaseMrswLockShared(&Context->Lock);
}

static NTSTATUS
VifUpdateFilterLevel(
    IN  PXENVIF_VIF_CONTEXT     Context,
    IN  ETHERNET_ADDRESS_TYPE   Type,
    IN  XENVIF_MAC_FILTER_LEVEL Level
    )
{
    PXENVIF_FRONTEND            Frontend = PdoGetFrontend(Context->Pdo);
    NTSTATUS                    status;

    AcquireMrswLockShared(&Context->Lock);

    status = MacSetFilterLevel(FrontendGetMac(Frontend),
                               Type,
                               Level);

    ReleaseMrswLockShared(&Context->Lock);

    return status;
}

static VOID
VifQueryReceiverRingSize(
    IN  PXENVIF_VIF_CONTEXT Context,
    OUT PULONG              Size
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    *Size = ReceiverGetRingSize(FrontendGetReceiver(Frontend));

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifQueryTransmitterRingSize(
    IN  PXENVIF_VIF_CONTEXT Context,
    OUT PULONG              Size
    )
{
    PXENVIF_FRONTEND        Frontend = PdoGetFrontend(Context->Pdo);

    AcquireMrswLockShared(&Context->Lock);

    *Size = TransmitterGetRingSize(FrontendGetTransmitter(Frontend));

    ReleaseMrswLockShared(&Context->Lock);
}

static VOID
VifAcquire(
    IN  PXENVIF_VIF_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->References);
}

static VOID
VifRelease(
    IN  PXENVIF_VIF_CONTEXT Context
    )
{
    ASSERT(Context->References != 0);
    InterlockedDecrement(&Context->References);
}

#define VIF_OPERATION(_Type, _Name, _Arguments) \
        Vif ## _Name,

static XENVIF_VIF_OPERATIONS  Operations = {
    DEFINE_VIF_OPERATIONS
};

#undef VIF_OPERATION

NTSTATUS
VifInitialize(
    IN  PXENVIF_PDO             Pdo,
    OUT PXENVIF_VIF_INTERFACE   Interface
    )
{
    PXENVIF_VIF_CONTEXT         Context;
    NTSTATUS                    status;

    Context = __VifAllocate(sizeof (XENVIF_VIF_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (Context == NULL)
        goto fail1;

    InitializeMrswLock(&Context->Lock);

    Context->Pdo = Pdo;

    KeInitializeEvent(&Context->MonitorEvent, NotificationEvent, FALSE);

    status = ThreadCreate(VifMonitor, Context, &Context->MonitorThread);
    if (!NT_SUCCESS(status))
        goto fail2;

    Interface->Context = Context;
    Interface->Operations = &Operations;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RtlZeroMemory(&Context->MonitorEvent, sizeof (KEVENT));

    Context->Pdo = NULL;
    RtlZeroMemory(&Context->Lock, sizeof (XENVIF_MRSW_LOCK));

    ASSERT(IsZeroMemory(Context, sizeof (XENVIF_VIF_CONTEXT)));
    __VifFree(Context);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
VifTeardown(
    IN OUT  PXENVIF_VIF_INTERFACE   Interface
    )
{
    PXENVIF_VIF_CONTEXT             Context = Interface->Context;

    ThreadAlert(Context->MonitorThread);
    ThreadJoin(Context->MonitorThread);
    Context->MonitorThread = NULL;

    RtlZeroMemory(&Context->MonitorEvent, sizeof (KEVENT));

    Context->Pdo = NULL;
    RtlZeroMemory(&Context->Lock, sizeof (XENVIF_MRSW_LOCK));

    ASSERT(IsZeroMemory(Context, sizeof (XENVIF_VIF_CONTEXT)));
    __VifFree(Context);

    RtlZeroMemory(Interface, sizeof (XENVIF_VIF_INTERFACE));
}

