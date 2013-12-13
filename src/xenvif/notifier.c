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
#include <evtchn_interface.h>
#include <store_interface.h>

#include "pdo.h"
#include "frontend.h"
#include "notifier.h"
#include "receiver.h"
#include "transmitter.h"
#include "dbg_print.h"
#include "assert.h"

typedef enum _NOTIFIER_EVTCHN {
    NOTIFIER_EVTCHN_COMBINED = 0,
    NOTIFIER_EVTCHN_RX,
    NOTIFIER_EVTCHN_TX,
    NOTIFIER_EVTCHN_COUNT
} NOTIFIER_EVTCHN, *PNOTIFIER_EVTCHN;

struct _XENVIF_NOTIFIER {
    PXENVIF_FRONTEND            Frontend;
    PXENBUS_EVTCHN_DESCRIPTOR   Evtchn[NOTIFIER_EVTCHN_COUNT];
    KDPC                        Dpc[NOTIFIER_EVTCHN_COUNT];
    ULONG                       Dpcs[NOTIFIER_EVTCHN_COUNT];
    ULONG                       Events[NOTIFIER_EVTCHN_COUNT];
    BOOLEAN                     Connected;
    KSPIN_LOCK                  Lock;
    BOOLEAN                     Split;
    BOOLEAN                     Enabled;

    PXENBUS_EVTCHN_INTERFACE    EvtchnInterface;
    PXENBUS_DEBUG_INTERFACE     DebugInterface;
    PXENBUS_STORE_INTERFACE     StoreInterface;

    PXENBUS_DEBUG_CALLBACK      DebugCallback;
};

#define NOTIFIER_POOL    'ITON'

static FORCEINLINE PVOID
__NotifierAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, NOTIFIER_POOL);
}

static FORCEINLINE VOID
__NotifierFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, NOTIFIER_POOL);
}

static FORCEINLINE BOOLEAN
__NotifierUnmask(
    IN  PXENVIF_NOTIFIER    Notifier,
    IN  NOTIFIER_EVTCHN     Index
    )
{
    BOOLEAN                 Pending;

    KeAcquireSpinLockAtDpcLevel(&Notifier->Lock);

    Pending = (Notifier->Connected) ?
              EVTCHN(Unmask,
                     Notifier->EvtchnInterface,
                     Notifier->Evtchn[Index],
                     FALSE) :
              FALSE;

    KeReleaseSpinLockFromDpcLevel(&Notifier->Lock);

    return Pending;
}

#pragma warning(push)
#pragma warning(disable:6011)   // Dereferencing NULL pointer

KDEFERRED_ROUTINE   NotifierDpc;

VOID
NotifierDpc(
    IN  PKDPC           Dpc,
    IN  PVOID           Context,
    IN  PVOID           Argument1,
    IN  PVOID           Argument2
    )
{
    PXENVIF_NOTIFIER    Notifier = Context;
    NOTIFIER_EVTCHN     Index = (ULONG_PTR)Argument1;
    PXENVIF_FRONTEND    Frontend;
    BOOLEAN             Pending;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Notifier != NULL);

    Frontend = Notifier->Frontend;

    do {
        if (Notifier->Enabled) {
            switch (Index) {
            case NOTIFIER_EVTCHN_TX:
                TransmitterNotify(FrontendGetTransmitter(Frontend));
                break;

            case NOTIFIER_EVTCHN_RX:
                ReceiverNotify(FrontendGetReceiver(Frontend));
                break;

            case NOTIFIER_EVTCHN_COMBINED:
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
    IN  NOTIFIER_EVTCHN     Index
    )
{
    Notifier->Events[Index]++;

    if (KeInsertQueueDpc(&Notifier->Dpc[Index],
                         (PVOID)(ULONG_PTR)Index,
                         NULL))
        Notifier->Dpcs[Index]++;

    return TRUE;
}

#define DEFINE_NOTIFIER_EVTCHN_CALLBACK(_Type)                  \
                                                                \
KSERVICE_ROUTINE    Notifier_ ## _Type ## _EvtchnCallback;      \
                                                                \
BOOLEAN                                                         \
Notifier_ ## _Type ## _EvtchnCallback(                          \
    IN  PKINTERRUPT         InterruptObject,                    \
    IN  PVOID               Argument                            \
    )                                                           \
{                                                               \
    PXENVIF_NOTIFIER        Notifier = Argument;                \
                                                                \
    UNREFERENCED_PARAMETER(InterruptObject);                    \
                                                                \
    ASSERT(Notifier != NULL);                                   \
    return __NotifierEvtchnCallback(Notifier,                   \
                                    NOTIFIER_EVTCHN_ ## _Type); \
}

DEFINE_NOTIFIER_EVTCHN_CALLBACK(COMBINED)
DEFINE_NOTIFIER_EVTCHN_CALLBACK(RX)
DEFINE_NOTIFIER_EVTCHN_CALLBACK(TX)

#undef DEFINE_NOTIFIER_EVTCHN_CALLBACK

#define DEFINE_NOTIFIER_EVTCHN_CALLBACK(_Type)                  \
    Notifier_ ## _Type ## _EvtchnCallback,

PKSERVICE_ROUTINE   NotifierEvtchnCallback[] = {
    DEFINE_NOTIFIER_EVTCHN_CALLBACK(COMBINED)
    DEFINE_NOTIFIER_EVTCHN_CALLBACK(RX)
    DEFINE_NOTIFIER_EVTCHN_CALLBACK(TX)
};

#undef DEFINE_NOTIFIER_EVTCHN_CALLBACK

C_ASSERT((sizeof (NotifierEvtchnCallback) / sizeof (NotifierEvtchnCallback[0])) == NOTIFIER_EVTCHN_COUNT);

static VOID
NotifierDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_NOTIFIER    Notifier = Argument;
    ULONG               Index;

    UNREFERENCED_PARAMETER(Crashing);

    for (Index = 0; Index < NOTIFIER_EVTCHN_COUNT; Index++)
        DEBUG(Printf,
              Notifier->DebugInterface,
              Notifier->DebugCallback,
              "[%s]: Events = %lu Dpcs = %lu\n",
              ((Index == NOTIFIER_EVTCHN_COMBINED) ? "COMBINED" :
               ((Index == NOTIFIER_EVTCHN_RX) ? "RX" :
                ((Index == NOTIFIER_EVTCHN_TX) ? "TX" :
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

    (*Notifier)->Frontend = Frontend;

    KeInitializeSpinLock(&(*Notifier)->Lock);
    for (Index = 0; Index < NOTIFIER_EVTCHN_COUNT; Index++)
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
    PXENVIF_FRONTEND        Frontend = Notifier->Frontend;
    LONG                    Index;
    PCHAR                   Buffer;
    NTSTATUS                status;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Notifier->Lock);

    ASSERT(!Notifier->Connected);

    Notifier->EvtchnInterface = FrontendGetEvtchnInterface(Frontend);

    EVTCHN(Acquire, Notifier->EvtchnInterface);

    for (Index = 0; Index < NOTIFIER_EVTCHN_COUNT; Index++) {
        PKSERVICE_ROUTINE   Callback = NotifierEvtchnCallback[Index];
        BOOLEAN             Pending;

        Notifier->Evtchn[Index] = EVTCHN(Open,
                                         Notifier->EvtchnInterface,
                                         EVTCHN_UNBOUND,
                                         Callback,
                                         Notifier,
                                         FrontendGetBackendDomain(Frontend),
                                         TRUE);

        status = STATUS_UNSUCCESSFUL;
        if (Notifier->Evtchn[Index] == NULL)
            goto fail1;

        Pending = EVTCHN(Unmask,
                         Notifier->EvtchnInterface,
                         Notifier->Evtchn[Index],
                         FALSE);
        if (Pending)
            EVTCHN(Trigger,
                   Notifier->EvtchnInterface,
                   Notifier->Evtchn[Index]);
    }

    Notifier->DebugInterface = FrontendGetDebugInterface(Frontend);

    DEBUG(Acquire, Notifier->DebugInterface);

    status = DEBUG(Register,
                   Notifier->DebugInterface,
                   __MODULE__ "|NOTIFIER",
                   NotifierDebugCallback,
                   Notifier,
                   &Notifier->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail2;

    Notifier->StoreInterface = FrontendGetStoreInterface(Frontend);

    STORE(Acquire, Notifier->StoreInterface);

    status = STORE(Read,
                   Notifier->StoreInterface,
                   NULL,
                   FrontendGetBackendPath(Frontend),
                   "feature-split-event-channels",
                   &Buffer);
    if (!NT_SUCCESS(status)) {
        Notifier->Split = FALSE;
    } else {
        Notifier->Split = (BOOLEAN)strtol(Buffer, NULL, 2);

        STORE(Free,
              Notifier->StoreInterface,
              Buffer);
    }

    Notifier->Connected = TRUE;
    KeReleaseSpinLockFromDpcLevel(&Notifier->Lock);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    DEBUG(Release, Notifier->DebugInterface);

    Index = NOTIFIER_EVTCHN_COUNT;

fail1:
    Error("fail1 (%08x)\n", status);

    while (--Index >= 0) {
        EVTCHN(Close,
               Notifier->EvtchnInterface,
               Notifier->Evtchn[Index]);
        Notifier->Evtchn[Index] = NULL;

        Notifier->Events[Index] = 0;
    }

    EVTCHN(Release, Notifier->EvtchnInterface);

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

    for (Index = 0; Index < NOTIFIER_EVTCHN_COUNT; Index++) {
        PCHAR   Node;
        ULONG   Port;

        switch (Index) {
        case NOTIFIER_EVTCHN_COMBINED:
            if (Notifier->Split)
                continue;

            Node = "event-channel";
            break;

        case NOTIFIER_EVTCHN_RX:
            if (!Notifier->Split)
                continue;

            Node = "event-channel-rx";
            break;

        case NOTIFIER_EVTCHN_TX:
            if (!Notifier->Split)
                continue;

            Node = "event-channel-tx";
            break;

        default:
            ASSERT(FALSE);

            Node = "";
            break;
        }

        Port = EVTCHN(Port,
                      Notifier->EvtchnInterface,
                      Notifier->Evtchn[Index]);

        status = STORE(Printf,
                       Notifier->StoreInterface,
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

    for (Index = 0; Index < NOTIFIER_EVTCHN_COUNT; Index++) {
        switch (Index) {
        case NOTIFIER_EVTCHN_COMBINED:
            if (Notifier->Split)
                continue;

            break;

        case NOTIFIER_EVTCHN_RX:
            if (!Notifier->Split)
                continue;

            break;

        case NOTIFIER_EVTCHN_TX:
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
    LONG                    Index;

    KeAcquireSpinLockAtDpcLevel(&Notifier->Lock);

    ASSERT(Notifier->Connected);
    Notifier->Connected = FALSE;

    Notifier->Split = FALSE;

    STORE(Release, Notifier->StoreInterface);
    Notifier->StoreInterface = NULL;

    DEBUG(Deregister,
          Notifier->DebugInterface,
          Notifier->DebugCallback);
    Notifier->DebugCallback = NULL;

    DEBUG(Release, Notifier->DebugInterface);
    Notifier->DebugInterface = NULL;

    Index = NOTIFIER_EVTCHN_COUNT;
    while (--Index >= 0) {
        EVTCHN(Close,
               Notifier->EvtchnInterface,
               Notifier->Evtchn[Index]);
        Notifier->Evtchn[Index] = NULL;

        Notifier->Events[Index] = 0;
    }

    EVTCHN(Release, Notifier->EvtchnInterface);
    Notifier->EvtchnInterface = NULL;

    KeReleaseSpinLockFromDpcLevel(&Notifier->Lock);
}

VOID
NotifierTeardown(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    LONG                    Index;

    KeFlushQueuedDpcs();

    Index = NOTIFIER_EVTCHN_COUNT;
    while (--Index >= 0) {
        Notifier->Dpcs[Index] = 0;
        RtlZeroMemory(&Notifier->Dpc[Index], sizeof (KDPC));
    }

    Notifier->Frontend = NULL;

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
    KIRQL                   Irql;

    KeAcquireSpinLock(&Notifier->Lock, &Irql);

    if (Notifier->Connected)
        (VOID) EVTCHN(Send,
                      Notifier->EvtchnInterface,
                      Notifier->Evtchn[Index]);

    KeReleaseSpinLock(&Notifier->Lock, Irql);
}

VOID
NotifierSendTx(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    if (Notifier->Split)
        __NotifierSend(Notifier, NOTIFIER_EVTCHN_TX);
    else
        __NotifierSend(Notifier, NOTIFIER_EVTCHN_COMBINED);
}

VOID
NotifierSendRx(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    if (Notifier->Split)
        __NotifierSend(Notifier, NOTIFIER_EVTCHN_RX);
    else
        __NotifierSend(Notifier, NOTIFIER_EVTCHN_COMBINED);
}

static FORCEINLINE VOID
__NotifierTrigger(
    IN  PXENVIF_NOTIFIER    Notifier,
    IN  ULONG               Index
    )
{
    KIRQL                   Irql;

    KeAcquireSpinLock(&Notifier->Lock, &Irql);

    if (Notifier->Connected)
        (VOID) EVTCHN(Trigger,
                      Notifier->EvtchnInterface,
                      Notifier->Evtchn[Index]);

    KeReleaseSpinLock(&Notifier->Lock, Irql);
}

VOID
NotifierTriggerTx(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    if (Notifier->Split)
        __NotifierTrigger(Notifier, NOTIFIER_EVTCHN_TX);
    else
        __NotifierTrigger(Notifier, NOTIFIER_EVTCHN_COMBINED);
}

VOID
NotifierTriggerRx(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    if (Notifier->Split)
        __NotifierTrigger(Notifier, NOTIFIER_EVTCHN_RX);
    else
        __NotifierTrigger(Notifier, NOTIFIER_EVTCHN_COMBINED);
}
