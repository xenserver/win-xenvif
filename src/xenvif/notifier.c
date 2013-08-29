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

struct _XENVIF_NOTIFIER {
    PXENVIF_FRONTEND            Frontend;
    PXENBUS_EVTCHN_DESCRIPTOR   Evtchn;
    KDPC                        Dpc;
    ULONG                       Events;
    ULONG                       Dpcs;
    BOOLEAN                     Connected;
    KSPIN_LOCK                  Lock;
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

#pragma warning(push)
#pragma warning(disable:6011)   // Dereferencing NULL pointer

static FORCEINLINE VOID
__NotifierNotify(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    PXENVIF_FRONTEND        Frontend;

    Frontend = Notifier->Frontend;

    TransmitterNotify(FrontendGetTransmitter(Frontend));
    ReceiverNotify(FrontendGetReceiver(Frontend));
}

static FORCEINLINE BOOLEAN
__NotifierUnmask(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    BOOLEAN                 Pending;

    KeAcquireSpinLockAtDpcLevel(&Notifier->Lock);

    Pending = (Notifier->Connected) ?
              EVTCHN(Unmask,
                     Notifier->EvtchnInterface,
                     Notifier->Evtchn,
                     FALSE) :
              FALSE;

    KeReleaseSpinLockFromDpcLevel(&Notifier->Lock);

    return Pending;
}


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
    BOOLEAN             Pending;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Notifier != NULL);

    do {
        if (Notifier->Enabled)
            __NotifierNotify(Notifier);

        Pending = __NotifierUnmask(Notifier);
    } while (Pending);
}

#pragma warning(pop)

KSERVICE_ROUTINE    NotifierEvtchnCallback;

BOOLEAN
NotifierEvtchnCallback(
    IN  PKINTERRUPT         InterruptObject,
    IN  PVOID               Argument
    )
{
    PXENVIF_NOTIFIER        Notifier = Argument;

    UNREFERENCED_PARAMETER(InterruptObject);

    ASSERT(Notifier != NULL);

    Notifier->Events++;

    if (KeInsertQueueDpc(&Notifier->Dpc, NULL, NULL))
        Notifier->Dpcs++;

    return TRUE;
}

static VOID
NotifierDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_NOTIFIER    Notifier = Argument;

    UNREFERENCED_PARAMETER(Crashing);

    DEBUG(Printf,
          Notifier->DebugInterface,
          Notifier->DebugCallback,
          "Events = %lu Dpcs = %lu\n",
          Notifier->Events,
          Notifier->Dpcs);
}

NTSTATUS
NotifierInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_NOTIFIER    *Notifier
    )
{
    NTSTATUS                status;

    *Notifier = __NotifierAllocate(sizeof (XENVIF_NOTIFIER));

    status = STATUS_NO_MEMORY;
    if (*Notifier == NULL)
        goto fail1;

    (*Notifier)->Frontend = Frontend;

    KeInitializeSpinLock(&(*Notifier)->Lock);
    KeInitializeDpc(&(*Notifier)->Dpc,
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
    BOOLEAN                 Pending;
    NTSTATUS                status;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Notifier->Lock);

    ASSERT(!Notifier->Connected);

    Notifier->EvtchnInterface = FrontendGetEvtchnInterface(Frontend);

    EVTCHN(Acquire, Notifier->EvtchnInterface);

    Notifier->Evtchn = EVTCHN(Open,
                              Notifier->EvtchnInterface,
                              EVTCHN_UNBOUND,
                              NotifierEvtchnCallback,
                              Notifier,
                              FrontendGetBackendDomain(Frontend),
                              TRUE);

    status = STATUS_UNSUCCESSFUL;
    if (Notifier->Evtchn == NULL)
        goto fail1;

    Pending = EVTCHN(Unmask,
                     Notifier->EvtchnInterface,
                     Notifier->Evtchn,
                     FALSE);
    if (Pending)
        EVTCHN(Trigger,
               Notifier->EvtchnInterface,
               Notifier->Evtchn);

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

    Notifier->Connected = TRUE;
    KeReleaseSpinLockFromDpcLevel(&Notifier->Lock);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    DEBUG(Release, Notifier->DebugInterface);

    EVTCHN(Close,
           Notifier->EvtchnInterface,
           Notifier->Evtchn);
    Notifier->Evtchn = NULL;

    Notifier->Events = 0;

fail1:
    Error("fail1 (%08x)\n", status);

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
    ULONG                           Port;
    NTSTATUS                        status;

    Port = EVTCHN(Port,
                  Notifier->EvtchnInterface,
                  Notifier->Evtchn);

    status = STORE(Printf,
                   Notifier->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "event-channel",
                   "%u",
                   Port);

    if (!NT_SUCCESS(status))
        goto fail1;

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
    ASSERT(!Notifier->Enabled);
    Notifier->Enabled = TRUE;

    if (KeInsertQueueDpc(&Notifier->Dpc, NULL, NULL))
        Notifier->Dpcs++;

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
    KeAcquireSpinLockAtDpcLevel(&Notifier->Lock);

    ASSERT(Notifier->Connected);
    Notifier->Connected = FALSE;

    STORE(Release, Notifier->StoreInterface);
    Notifier->StoreInterface = NULL;

    DEBUG(Deregister,
          Notifier->DebugInterface,
          Notifier->DebugCallback);
    Notifier->DebugCallback = NULL;

    DEBUG(Release, Notifier->DebugInterface);
    Notifier->DebugInterface = NULL;

    EVTCHN(Close,
           Notifier->EvtchnInterface,
           Notifier->Evtchn);
    Notifier->Evtchn = NULL;

    Notifier->Events = 0;

    EVTCHN(Release, Notifier->EvtchnInterface);
    Notifier->EvtchnInterface = NULL;

    KeReleaseSpinLockFromDpcLevel(&Notifier->Lock);
}

VOID
NotifierTeardown(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    KeFlushQueuedDpcs();

    Notifier->Dpcs = 0;
    Notifier->Frontend = NULL;

    RtlZeroMemory(&Notifier->Dpc, sizeof (KDPC));
    RtlZeroMemory(&Notifier->Lock, sizeof (KSPIN_LOCK));

    ASSERT(IsZeroMemory(Notifier, sizeof (XENVIF_NOTIFIER)));

    __NotifierFree(Notifier);
}

VOID
NotifierSend(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    KIRQL                   Irql;

    KeAcquireSpinLock(&Notifier->Lock, &Irql);

    if (Notifier->Connected)
        (VOID) EVTCHN(Send,
                      Notifier->EvtchnInterface,
                      Notifier->Evtchn);

    KeReleaseSpinLock(&Notifier->Lock, Irql);
}

VOID
NotifierTrigger(
    IN  PXENVIF_NOTIFIER    Notifier
    )
{
    KIRQL                   Irql;

    KeAcquireSpinLock(&Notifier->Lock, &Irql);

    if (Notifier->Connected)
        (VOID) EVTCHN(Trigger,
                      Notifier->EvtchnInterface,
                      Notifier->Evtchn);

    KeReleaseSpinLock(&Notifier->Lock, Irql);
}
