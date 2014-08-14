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
#include <stdlib.h>
#include <util.h>

#include "pdo.h"
#include "frontend.h"
#include "notifier.h"
#include "receiver.h"
#include "transmitter.h"
#include "dbg_print.h"
#include "assert.h"

typedef enum _XENVIF_NOTIFIER_EVTCHN {
    XENVIF_NOTIFIER_EVTCHN_COMBINED = 0,
    XENVIF_NOTIFIER_EVTCHN_RX,
    XENVIF_NOTIFIER_EVTCHN_TX,
    XENVIF_NOTIFIER_EVTCHN_COUNT
} XENVIF_NOTIFIER_EVTCHN, *PXENVIF_NOTIFIER_EVTCHN;

struct _XENVIF_NOTIFIER {
    PXENVIF_FRONTEND            Frontend;
    XENBUS_EVTCHN_INTERFACE     EvtchnInterface;
    PXENBUS_EVTCHN_CHANNEL      Channel[XENVIF_NOTIFIER_EVTCHN_COUNT];
    KDPC                        Dpc[XENVIF_NOTIFIER_EVTCHN_COUNT];
    ULONG                       Dpcs[XENVIF_NOTIFIER_EVTCHN_COUNT];
    ULONG                       Events[XENVIF_NOTIFIER_EVTCHN_COUNT];
    BOOLEAN                     Connected;
    KSPIN_LOCK                  Lock;
    BOOLEAN                     Split;
    BOOLEAN                     Enabled;
    XENBUS_STORE_INTERFACE      StoreInterface;
    XENBUS_DEBUG_INTERFACE      DebugInterface;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
};

#define XENVIF_NOTIFIER_TAG 'ITON'

static FORCEINLINE PVOID
__NotifierAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, XENVIF_NOTIFIER_TAG);
}

static FORCEINLINE VOID
__NotifierFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_NOTIFIER_TAG);
}

static FORCEINLINE BOOLEAN
__NotifierUnmask(
    IN  PXENVIF_NOTIFIER        Notifier,
    IN  XENVIF_NOTIFIER_EVTCHN  Index
    )
{
    PXENVIF_FRONTEND            Frontend;
    BOOLEAN                     Pending;

    Frontend = Notifier->Frontend;

    KeAcquireSpinLockAtDpcLevel(&Notifier->Lock);

    Pending = (Notifier->Connected) ?
              XENBUS_EVTCHN(Unmask,
                            &Notifier->EvtchnInterface,
                            Notifier->Channel[Index],
                            FALSE) :
              FALSE;

    KeReleaseSpinLockFromDpcLevel(&Notifier->Lock);

    return Pending;
}

__drv_functionClass(KDEFERRED_ROUTINE)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_minIRQL(DISPATCH_LEVEL)
__drv_requiresIRQL(DISPATCH_LEVEL)
__drv_sameIRQL
static VOID
NotifierDpc(
    IN  PKDPC               Dpc,
    IN  PVOID               Context,
    IN  PVOID               Argument1,
    IN  PVOID               Argument2
    )
{
    PXENVIF_NOTIFIER        Notifier = Context;
    XENVIF_NOTIFIER_EVTCHN  Index = (ULONG_PTR)Argument1;
    PXENVIF_FRONTEND        Frontend;
    BOOLEAN                 Pending;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Notifier != NULL);

    Frontend = Notifier->Frontend;

    do {
        if (Notifier->Enabled) {
            switch (Index) {
            case XENVIF_NOTIFIER_EVTCHN_TX:
                TransmitterNotify(FrontendGetTransmitter(Frontend));
                break;

            case XENVIF_NOTIFIER_EVTCHN_RX:
                ReceiverNotify(FrontendGetReceiver(Frontend));
                break;

            case XENVIF_NOTIFIER_EVTCHN_COMBINED:
                TransmitterNotify(FrontendGetTransmitter(Frontend));
                ReceiverNotify(FrontendGetReceiver(Frontend));
                break;

            default:
                ASSERT(FALSE);
                break;
            }
        }

        Pending = __NotifierUnmask(Notifier, Index);
    } while (Pending);
}

static FORCEINLINE BOOLEAN
__NotifierEvtchnCallback(
    IN  PXENVIF_NOTIFIER    Notifier,
    IN  XENVIF_NOTIFIER_EVTCHN     Index
    )
{
    Notifier->Events[Index]++;

    if (KeInsertQueueDpc(&Notifier->Dpc[Index],
                         (PVOID)(ULONG_PTR)Index,
                         NULL))
        Notifier->Dpcs[Index]++;

    return TRUE;
}

#define DEFINE_XENVIF_NOTIFIER_EVTCHN_CALLBACK(_Type)                   \
                                                                        \
KSERVICE_ROUTINE    Notifier ## _Type ## EvtchnCallback;                \
                                                                        \
BOOLEAN                                                                 \
Notifier ## _Type ## EvtchnCallback(                                    \
    IN  PKINTERRUPT         InterruptObject,                            \
    IN  PVOID               Argument                                    \
    )                                                                   \
{                                                                       \
    PXENVIF_NOTIFIER        Notifier = Argument;                        \
                                                                        \
    UNREFERENCED_PARAMETER(InterruptObject);                            \
                                                                        \
    ASSERT(Notifier != NULL);                                           \
    return __NotifierEvtchnCallback(Notifier,                           \
                                    XENVIF_NOTIFIER_EVTCHN_ ## _Type);  \
}

DEFINE_XENVIF_NOTIFIER_EVTCHN_CALLBACK(COMBINED)
DEFINE_XENVIF_NOTIFIER_EVTCHN_CALLBACK(RX)
DEFINE_XENVIF_NOTIFIER_EVTCHN_CALLBACK(TX)

#undef DEFINE_XENVIF_NOTIFIER_EVTCHN_CALLBACK

#define DEFINE_XENVIF_NOTIFIER_EVTCHN_CALLBACK(_Type)   \
    Notifier ## _Type ## EvtchnCallback,

PKSERVICE_ROUTINE   NotifierEvtchnCallback[] = {
    DEFINE_XENVIF_NOTIFIER_EVTCHN_CALLBACK(COMBINED)
    DEFINE_XENVIF_NOTIFIER_EVTCHN_CALLBACK(RX)
    DEFINE_XENVIF_NOTIFIER_EVTCHN_CALLBACK(TX)
};

#undef DEFINE_XENVIF_NOTIFIER_EVTCHN_CALLBACK

C_ASSERT(ARRAYSIZE(NotifierEvtchnCallback) == XENVIF_NOTIFIER_EVTCHN_COUNT);

static VOID
NotifierDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_NOTIFIER    Notifier = Argument;
    PXENVIF_FRONTEND    Frontend;
    ULONG               Index;

    UNREFERENCED_PARAMETER(Crashing);

    Frontend = Notifier->Frontend;

    for (Index = 0; Index < XENVIF_NOTIFIER_EVTCHN_COUNT; Index++)
        XENBUS_DEBUG(Printf,
                     &Notifier->DebugInterface,
                     "[%s]: Events = %lu Dpcs = %lu\n",
                     ((Index == XENVIF_NOTIFIER_EVTCHN_COMBINED) ? "COMBINED" :
                      ((Index == XENVIF_NOTIFIER_EVTCHN_RX) ? "RX" :
                       ((Index == XENVIF_NOTIFIER_EVTCHN_TX) ? "TX" :
                        "UNKNOWN"))),
                     Notifier->Events[Index],
                     Notifier->Dpcs[Index]);
}

NTSTATUS
NotifierInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_NOTIFIER    *Notifier
    )
{
    ULONG                   Index;
    NTSTATUS                status;

    *Notifier = __NotifierAllocate(sizeof (XENVIF_NOTIFIER));

    status = STATUS_NO_MEMORY;
    if (*Notifier == NULL)
        goto fail1;

    FdoGetEvtchnInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                          &(*Notifier)->EvtchnInterface);

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Notifier)->DebugInterface);

    FdoGetStoreInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Notifier)->StoreInterface);

    (*Notifier)->Frontend = Frontend;

    KeInitializeSpinLock(&(*Notifier)->Lock);
    for (Index = 0; Index < XENVIF_NOTIFIER_EVTCHN_COUNT; Index++)
        KeInitializeDpc(&(*Notifier)->Dpc[Index],
                        NotifierDpc,
                        *Notifier);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
NotifierConnect(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Index;
    PCHAR                   Buffer;
    NTSTATUS                status;

    Frontend = Notifier->Frontend;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Notifier->Lock);

    ASSERT(!Notifier->Connected);

    status = XENBUS_EVTCHN(Acquire, &Notifier->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Acquire, &Notifier->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_STORE(Acquire, &Notifier->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    for (Index = 0; Index < XENVIF_NOTIFIER_EVTCHN_COUNT; Index++) {
        PKSERVICE_ROUTINE   Callback = NotifierEvtchnCallback[Index];
        BOOLEAN             Pending;

        Notifier->Channel[Index] = XENBUS_EVTCHN(Open,
                                                &Notifier->EvtchnInterface,
                                                XENBUS_EVTCHN_TYPE_UNBOUND,
                                                Callback,
                                                Notifier,
                                                FrontendGetBackendDomain(Frontend),
                                                TRUE);

        status = STATUS_UNSUCCESSFUL;
        if (Notifier->Channel[Index] == NULL)
            goto fail4;

        Pending = XENBUS_EVTCHN(Unmask,
                                &Notifier->EvtchnInterface,
                                Notifier->Channel[Index],
                                FALSE);
        if (Pending)
            XENBUS_EVTCHN(Trigger,
                          &Notifier->EvtchnInterface,
                          Notifier->Channel[Index]);
    }

    status = XENBUS_DEBUG(Register,
                          &Notifier->DebugInterface,
                          __MODULE__ "|NOTIFIER",
                          NotifierDebugCallback,
                          Notifier,
                          &Notifier->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENBUS_STORE(Read,
                          &Notifier->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-split-event-channels",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Notifier->Split = FALSE;
    } else {
        Notifier->Split = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Notifier->StoreInterface,
                     Buffer);
    }

    Notifier->Connected = TRUE;
    KeReleaseSpinLockFromDpcLevel(&Notifier->Lock);

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    Index = XENVIF_NOTIFIER_EVTCHN_COUNT;

fail4:
    Error("fail4\n");

    while (--Index >= 0) {
        XENBUS_EVTCHN(Close,
                      &Notifier->EvtchnInterface,
                      Notifier->Channel[Index]);
        Notifier->Channel[Index] = NULL;

        Notifier->Events[Index] = 0;
    }

    XENBUS_STORE(Release, &Notifier->StoreInterface);

fail3:
    Error("fail3\n");

    XENBUS_DEBUG(Release, &Notifier->DebugInterface);

fail2:
    Error("fail2\n");

    XENBUS_EVTCHN(Release, &Notifier->EvtchnInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLockFromDpcLevel(&Notifier->Lock);

    return status;
}

NTSTATUS
NotifierStoreWrite(
    IN  PXENVIF_NOTIFIER            Notifier,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_FRONTEND                Frontend = Notifier->Frontend;
    ULONG                           Index;
    NTSTATUS                        status;

    for (Index = 0; Index < XENVIF_NOTIFIER_EVTCHN_COUNT; Index++) {
        PCHAR   Node;
        ULONG   Port;

        switch (Index) {
        case XENVIF_NOTIFIER_EVTCHN_COMBINED:
            if (Notifier->Split)
                continue;

            Node = "event-channel";
            break;

        case XENVIF_NOTIFIER_EVTCHN_RX:
            if (!Notifier->Split)
                continue;

            Node = "event-channel-rx";
            break;

        case XENVIF_NOTIFIER_EVTCHN_TX:
            if (!Notifier->Split)
                continue;

            Node = "event-channel-tx";
            break;

        default:
            ASSERT(FALSE);

            Node = "";
            break;
        }

        Port = XENBUS_EVTCHN(GetPort,
                             &Notifier->EvtchnInterface,
                             Notifier->Channel[Index]);

        status = XENBUS_STORE(Printf,
                              &Notifier->StoreInterface,
                              Transaction,
                              FrontendGetPath(Frontend),
                              Node,
                              "%u",
                              Port);

        if (!NT_SUCCESS(status))
            goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
NotifierEnable(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{   
    ULONG                   Index;

    ASSERT(!Notifier->Enabled);
    Notifier->Enabled = TRUE;

    for (Index = 0; Index < XENVIF_NOTIFIER_EVTCHN_COUNT; Index++) {
        switch (Index) {
        case XENVIF_NOTIFIER_EVTCHN_COMBINED:
            if (Notifier->Split)
                continue;

            break;

        case XENVIF_NOTIFIER_EVTCHN_RX:
            if (!Notifier->Split)
                continue;

            break;

        case XENVIF_NOTIFIER_EVTCHN_TX:
            if (!Notifier->Split)
                continue;

            break;

        default:
            ASSERT(FALSE);

            break;
        }

        if (KeInsertQueueDpc(&Notifier->Dpc[Index],
                             (PVOID)(ULONG_PTR)Index,
                             NULL))
            Notifier->Dpcs[Index]++;
    }

    return STATUS_SUCCESS;
}

VOID
NotifierDisable(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    ASSERT(Notifier->Enabled);
    Notifier->Enabled = FALSE;
}

VOID
NotifierDisconnect(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    PXENVIF_FRONTEND        Frontend;
    LONG                    Index;

    Frontend = Notifier->Frontend;

    KeAcquireSpinLockAtDpcLevel(&Notifier->Lock);

    ASSERT(Notifier->Connected);
    Notifier->Connected = FALSE;

    Notifier->Split = FALSE;

    XENBUS_DEBUG(Deregister,
                 &Notifier->DebugInterface,
                 Notifier->DebugCallback);
    Notifier->DebugCallback = NULL;

    Index = XENVIF_NOTIFIER_EVTCHN_COUNT;
    while (--Index >= 0) {
        XENBUS_EVTCHN(Close,
                      &Notifier->EvtchnInterface,
                      Notifier->Channel[Index]);
        Notifier->Channel[Index] = NULL;

        Notifier->Events[Index] = 0;
    }

    XENBUS_STORE(Release, &Notifier->StoreInterface);

    XENBUS_DEBUG(Release, &Notifier->DebugInterface);

    XENBUS_EVTCHN(Release, &Notifier->EvtchnInterface);

    KeReleaseSpinLockFromDpcLevel(&Notifier->Lock);
}

VOID
NotifierTeardown(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    LONG                    Index;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    KeFlushQueuedDpcs();

    Index = XENVIF_NOTIFIER_EVTCHN_COUNT;
    while (--Index >= 0) {
        Notifier->Dpcs[Index] = 0;
        RtlZeroMemory(&Notifier->Dpc[Index], sizeof (KDPC));
    }

    Notifier->Frontend = NULL;

    RtlZeroMemory(&Notifier->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Notifier->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Notifier->EvtchnInterface,
                  sizeof (XENBUS_EVTCHN_INTERFACE));

    RtlZeroMemory(&Notifier->Lock, sizeof (KSPIN_LOCK));

    ASSERT(IsZeroMemory(Notifier, sizeof (XENVIF_NOTIFIER)));

    __NotifierFree(Notifier);
}

static FORCEINLINE VOID
__NotifierSend(
    IN  PXENVIF_NOTIFIER    Notifier,
    IN  ULONG               Index
    )
{
    PXENVIF_FRONTEND        Frontend;
    KIRQL                   Irql;

    Frontend = Notifier->Frontend;

    KeAcquireSpinLock(&Notifier->Lock, &Irql);

    if (Notifier->Connected)
        (VOID) XENBUS_EVTCHN(Send,
                             &Notifier->EvtchnInterface,
                             Notifier->Channel[Index]);

    KeReleaseSpinLock(&Notifier->Lock, Irql);
}

VOID
NotifierSendTx(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    if (Notifier->Split)
        __NotifierSend(Notifier, XENVIF_NOTIFIER_EVTCHN_TX);
    else
        __NotifierSend(Notifier, XENVIF_NOTIFIER_EVTCHN_COMBINED);
}

VOID
NotifierSendRx(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    if (Notifier->Split)
        __NotifierSend(Notifier, XENVIF_NOTIFIER_EVTCHN_RX);
    else
        __NotifierSend(Notifier, XENVIF_NOTIFIER_EVTCHN_COMBINED);
}

static FORCEINLINE VOID
__NotifierTrigger(
    IN  PXENVIF_NOTIFIER    Notifier,
    IN  ULONG               Index
    )
{
    PXENVIF_FRONTEND        Frontend;
    KIRQL                   Irql;

    Frontend = Notifier->Frontend;

    KeAcquireSpinLock(&Notifier->Lock, &Irql);

    if (Notifier->Connected)
        (VOID) XENBUS_EVTCHN(Trigger,
                             &Notifier->EvtchnInterface,
                             Notifier->Channel[Index]);

    KeReleaseSpinLock(&Notifier->Lock, Irql);
}

VOID
NotifierTriggerTx(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    if (Notifier->Split)
        __NotifierTrigger(Notifier, XENVIF_NOTIFIER_EVTCHN_TX);
    else
        __NotifierTrigger(Notifier, XENVIF_NOTIFIER_EVTCHN_COMBINED);
}

VOID
NotifierTriggerRx(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    if (Notifier->Split)
        __NotifierTrigger(Notifier, XENVIF_NOTIFIER_EVTCHN_RX);
    else
        __NotifierTrigger(Notifier, XENVIF_NOTIFIER_EVTCHN_COMBINED);
}
