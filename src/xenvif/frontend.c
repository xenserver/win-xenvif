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
#include <netioapi.h>
#include <util.h>
#include <xen.h>
#include <store_interface.h>
#include <gnttab_interface.h>
#include <vif_interface.h>

#include "driver.h"
#include "registry.h"
#include "fdo.h"
#include "pdo.h"
#include "thread.h"
#include "frontend.h"
#include "names.h"
#include "notifier.h"
#include "mac.h"
#include "tcpip.h"
#include "receiver.h"
#include "transmitter.h"
#include "dbg_print.h"
#include "assert.h"

struct _XENVIF_FRONTEND {
    PXENVIF_PDO                 Pdo;
    PCHAR                       Path;
    PCHAR                       Prefix;
    XENVIF_FRONTEND_STATE       State;
    KSPIN_LOCK                  Lock;
    PXENVIF_THREAD              MibThread;
    PXENVIF_THREAD              EjectThread;
    BOOLEAN                     EjectRequested;
    PXENBUS_STORE_WATCH         Watch;
    PCHAR                       BackendPath;
    USHORT                      BackendDomain;
    PXENVIF_NOTIFIER            Notifier;
    PXENVIF_MAC                 Mac;
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_TRANSMITTER         Transmitter;

    PXENBUS_SUSPEND_INTERFACE   SuspendInterface;
    PXENBUS_STORE_INTERFACE     StoreInterface;
    PXENBUS_DEBUG_INTERFACE     DebugInterface;

    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    HANDLE                      Handle;
};

static const PCHAR
FrontendStateName(
    IN  XENVIF_FRONTEND_STATE   State
    )
{
#define _STATE_NAME(_State)     \
    case  FRONTEND_ ## _State:  \
        return #_State;

    switch (State) {
    _STATE_NAME(CLOSED);
    _STATE_NAME(PREPARED);
    _STATE_NAME(CONNECTED);
    _STATE_NAME(ENABLED);
    default:
        break;
    }

    return "INVALID";

#undef  _STATE_NAME
}

#define FRONTEND_POOL    'NORF'

static FORCEINLINE PVOID
__FrontendAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, FRONTEND_POOL);
}

static FORCEINLINE VOID
__FrontendFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, FRONTEND_POOL);
}

static FORCEINLINE PXENVIF_PDO
__FrontendGetPdo(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Pdo;
}

static FORCEINLINE PXENBUS_EVTCHN_INTERFACE
__FrontendGetEvtchnInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return PdoGetEvtchnInterface(__FrontendGetPdo(Frontend));
}

PXENBUS_EVTCHN_INTERFACE
FrontendGetEvtchnInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetEvtchnInterface(Frontend);
}

static FORCEINLINE PXENBUS_DEBUG_INTERFACE
__FrontendGetDebugInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return PdoGetDebugInterface(__FrontendGetPdo(Frontend));
}

PXENBUS_DEBUG_INTERFACE
FrontendGetDebugInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetDebugInterface(Frontend);
}

static FORCEINLINE PXENBUS_SUSPEND_INTERFACE
__FrontendGetSuspendInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return PdoGetSuspendInterface(__FrontendGetPdo(Frontend));
}

PXENBUS_SUSPEND_INTERFACE
FrontendGetSuspendInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetSuspendInterface(Frontend);
}

static FORCEINLINE PXENBUS_STORE_INTERFACE
__FrontendGetStoreInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return PdoGetStoreInterface(__FrontendGetPdo(Frontend));
}

PXENBUS_STORE_INTERFACE
FrontendGetStoreInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetStoreInterface(Frontend);
}

static FORCEINLINE PXENBUS_GNTTAB_INTERFACE
__FrontendGetGnttabInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return PdoGetGnttabInterface(__FrontendGetPdo(Frontend));
}

PXENBUS_GNTTAB_INTERFACE
FrontendGetGnttabInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetGnttabInterface(Frontend);
}

static FORCEINLINE PXENVIF_VIF_INTERFACE
__FrontendGetVifInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return PdoGetVifInterface(__FrontendGetPdo(Frontend));
}

PXENVIF_VIF_INTERFACE
FrontendGetVifInterface(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetVifInterface(Frontend);
}

static FORCEINLINE PCHAR
__FrontendGetPath(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Path;
}

PCHAR
FrontendGetPath(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetPath(Frontend);
}

static FORCEINLINE PCHAR
__FrontendGetPrefix(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Prefix;
}

PCHAR
FrontendGetPrefix(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetPrefix(Frontend);
}

static FORCEINLINE PCHAR
__FrontendGetBackendPath(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->BackendPath;
}

PCHAR
FrontendGetBackendPath(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetBackendPath(Frontend);
}

static FORCEINLINE USHORT
__FrontendGetBackendDomain(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->BackendDomain;
}

USHORT
FrontendGetBackendDomain(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetBackendDomain(Frontend);
}

static FORCEINLINE PXENVIF_NOTIFIER
__FrontendGetNotifier(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Notifier;
}

PXENVIF_NOTIFIER
FrontendGetNotifier(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetNotifier(Frontend);
}

static FORCEINLINE PXENVIF_MAC
__FrontendGetMac(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Mac;
}

PXENVIF_MAC
FrontendGetMac(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetMac(Frontend);
}

static FORCEINLINE PXENVIF_RECEIVER
__FrontendGetReceiver(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Receiver;
}

PXENVIF_RECEIVER
FrontendGetReceiver(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetReceiver(Frontend);
}

static FORCEINLINE PXENVIF_TRANSMITTER
__FrontendGetTransmitter(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return Frontend->Transmitter;
}

PXENVIF_TRANSMITTER
FrontendGetTransmitter(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetTransmitter(Frontend);
}

static FORCEINLINE PNET_LUID
__FrontendGetNetLuid(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return PdoGetNetLuid(__FrontendGetPdo(Frontend));
}

static FORCEINLINE PETHERNET_ADDRESS
__FrontendGetPermanentMacAddress(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return PdoGetPermanentMacAddress(__FrontendGetPdo(Frontend));
}

PETHERNET_ADDRESS
FrontendGetPermanentMacAddress(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetPermanentMacAddress(Frontend);
}

static FORCEINLINE PETHERNET_ADDRESS
__FrontendGetCurrentMacAddress(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return PdoGetCurrentMacAddress(__FrontendGetPdo(Frontend));
}

PETHERNET_ADDRESS
FrontendGetCurrentMacAddress(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetCurrentMacAddress(Frontend);
}

static DECLSPEC_NOINLINE NTSTATUS
FrontendEject(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_FRONTEND    Frontend = Context;
    PKEVENT             Event;

    Trace("%s: ====>\n", __FrontendGetPath(Frontend));

    Event = ThreadGetEvent(Self);

    for (;;) {
        KIRQL               Irql;
        BOOLEAN             Online;
        XenbusState         State;
        ULONG               Attempt;
        NTSTATUS            status;

        KeWaitForSingleObject(Event,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        KeAcquireSpinLock(&Frontend->Lock, &Irql);

        if (Frontend->State == FRONTEND_CLOSED) {
            KeReleaseSpinLock(&Frontend->Lock, Irql);
            continue;
        }

        STORE(Acquire, Frontend->StoreInterface);

        Online = TRUE;
        State = XenbusStateUnknown;

        Attempt = 0;
        for (;;) {
            PXENBUS_STORE_TRANSACTION   Transaction;
            PCHAR                       Buffer;

            status = STATUS_UNSUCCESSFUL;
            if (__FrontendGetBackendPath(Frontend) == NULL)
                break;

            status = STORE(TransactionStart,
                           Frontend->StoreInterface,
                           &Transaction);
            if (!NT_SUCCESS(status))
                break;

            status = STORE(Read,
                           Frontend->StoreInterface,
                           Transaction,
                           __FrontendGetBackendPath(Frontend),
                           "online",
                           &Buffer);
            if (!NT_SUCCESS(status))
                goto abort;

            Online = (BOOLEAN)strtol(Buffer, NULL, 2);

            STORE(Free,
                  Frontend->StoreInterface,
                  Buffer);

            status = STORE(Read,
                           Frontend->StoreInterface,
                           Transaction,
                           __FrontendGetBackendPath(Frontend),
                           "state",
                           &Buffer);
            if (!NT_SUCCESS(status))
                goto abort;

            State = (XenbusState)strtol(Buffer, NULL, 10);

            STORE(Free,
                  Frontend->StoreInterface,
                  Buffer);

            status = STORE(TransactionEnd,
                           Frontend->StoreInterface,
                           Transaction,
                           TRUE);
            if (status != STATUS_RETRY || ++Attempt > 10)
                break;

            continue;

abort:
            (VOID) STORE(TransactionEnd,
                         Frontend->StoreInterface,
                         Transaction,
                         FALSE);
            break;
        }

        if (!NT_SUCCESS(status)) {
            Online = TRUE;
            State = XenbusStateUnknown;
        }

        if (!Online && State == XenbusStateClosing) {
            Info("%s: requesting device eject\n", __FrontendGetPath(Frontend));

            PdoRequestEject(Frontend->Pdo);
            Frontend->EjectRequested = TRUE;
        }

        STORE(Release, Frontend->StoreInterface);

        KeReleaseSpinLock(&Frontend->Lock, Irql);
    }

    Trace("%s: <====\n", __FrontendGetPath(Frontend));

    return STATUS_SUCCESS;
}

static FORCEINLINE NTSTATUS
__FrontendGetAddressTable(
    IN  PXENVIF_FRONTEND            Frontend,
    OUT PSOCKADDR_INET              *AddressTable,
    OUT PULONG                      AddressCount
    )
{
    PNET_LUID                       NetLuid;
    ULONG                           Index;
    PMIB_UNICASTIPADDRESS_TABLE     Table;
    ULONG                           Count;
    NTSTATUS                        status;

    NetLuid = __FrontendGetNetLuid(Frontend);

    status = GetUnicastIpAddressTable(AF_UNSPEC, &Table);
    if (!NT_SUCCESS(status))
        goto fail1;

    *AddressCount = 0;
    for (Index = 0; Index < Table->NumEntries; Index++) {
        PMIB_UNICASTIPADDRESS_ROW   Row = &Table->Table[Index];

        if (Row->InterfaceLuid.Info.IfType != NetLuid->Info.IfType)
            continue;

        if (Row->InterfaceLuid.Info.NetLuidIndex != NetLuid->Info.NetLuidIndex)
            continue;

        if (Row->Address.si_family != AF_INET &&
            Row->Address.si_family != AF_INET6)
            continue;

        (*AddressCount)++;
    }

    *AddressTable = NULL;

    if (*AddressCount == 0)
        goto done;

    *AddressTable = __FrontendAllocate(sizeof (SOCKADDR_INET) * *AddressCount);

    status = STATUS_NO_MEMORY;
    if (*AddressTable == NULL)
        goto fail2;

    Count = 0;

    for (Index = 0; Index < Table->NumEntries; Index++) {
        PMIB_UNICASTIPADDRESS_ROW   Row = &Table->Table[Index];

        if (Row->InterfaceLuid.Info.IfType != NetLuid->Info.IfType)
            continue;

        if (Row->InterfaceLuid.Info.NetLuidIndex != NetLuid->Info.NetLuidIndex)
            continue;

        switch (Row->Address.si_family) {
        case AF_INET:
        case AF_INET6:
            (*AddressTable)[Count++] = Row->Address;
            break;
        default:
            break;
        }
    }
    ASSERT3U(Count, ==, *AddressCount);

done:
    FreeMibTable(Table);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    FreeMibTable(Table);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
FrontendMib(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_FRONTEND    Frontend = Context;
    PKEVENT             Event;

    Trace("====>\n");

    Event = ThreadGetEvent(Self);

    for (;;) { 
        PSOCKADDR_INET  Table;
        ULONG           Count;
        NTSTATUS        status;

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        status = __FrontendGetAddressTable(Frontend,
                                           &Table,
                                           &Count);
        if (!NT_SUCCESS(status))
            continue;

        TransmitterUpdateAddressTable(__FrontendGetTransmitter(Frontend),
                                      Table,
                                      Count);

        if (Count != 0)
            __FrontendFree(Table);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static VOID
FrontendIpAddressChange(
    IN  PVOID                       Context,
    IN  PMIB_UNICASTIPADDRESS_ROW   _Row OPTIONAL,
    IN  MIB_NOTIFICATION_TYPE       NotificationType
    )
{
    PXENVIF_FRONTEND                Frontend = Context;

    UNREFERENCED_PARAMETER(_Row);
    UNREFERENCED_PARAMETER(NotificationType);

    ThreadWake(Frontend->MibThread);
}

#define TIME_US(_us)            ((_us) * 10)
#define TIME_MS(_ms)            (TIME_US((_ms) * 1000))
#define TIME_S(_s)              (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)       (-(_t))

static FORCEINLINE NTSTATUS
__FrontendWaitForStateChange(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  PCHAR               Path,
    IN  XenbusState         *State
    )
{
    KEVENT                  Event;
    PXENBUS_STORE_WATCH     Watch;
    LARGE_INTEGER           Start;
    ULONGLONG               TimeDelta;
    LARGE_INTEGER           Timeout;
    XenbusState             Old = *State;
    NTSTATUS                status;

    Trace("%s: ====> (%s)\n", Path, XenbusStateName(*State));

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = STORE(Watch,
                   Frontend->StoreInterface,
                   Path,
                   "state",
                   &Event,
                   &Watch);
    if (!NT_SUCCESS(status))
        goto fail1;

    KeQuerySystemTime(&Start);
    TimeDelta = 0;

    Timeout.QuadPart = 0;

    while (*State == Old && TimeDelta < 120000) {
        ULONG           Attempt;
        PCHAR           Buffer;
        LARGE_INTEGER   Now;

        Attempt = 0;
        while (++Attempt < 1000) {
            status = KeWaitForSingleObject(&Event,
                                           Executive,
                                           KernelMode,
                                           FALSE,
                                           &Timeout);
            if (status != STATUS_TIMEOUT)
                break;

            // We are waiting for a watch event at DISPATCH_LEVEL so
            // it is our responsibility to poll the store ring.
            STORE(Poll,
                  Frontend->StoreInterface);

            KeStallExecutionProcessor(1000);   // 1ms
        }

        KeClearEvent(&Event);

        status = STORE(Read,
                       Frontend->StoreInterface,
                       NULL,
                       Path,
                       "state",
                       &Buffer);
        if (!NT_SUCCESS(status))
            goto fail2;

        *State = (XenbusState)strtol(Buffer, NULL, 10);

        STORE(Free,
              Frontend->StoreInterface,
              Buffer);

        KeQuerySystemTime(&Now);

        TimeDelta = (Now.QuadPart - Start.QuadPart) / 10000ull;
    }

    status = STATUS_UNSUCCESSFUL;
    if (*State == Old)
        goto fail3;

    (VOID) STORE(Unwatch,
                 Frontend->StoreInterface,
                 Watch);

    Trace("%s: <==== (%s)\n", Path, XenbusStateName(*State));

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    (VOID) STORE(Unwatch,
                 Frontend->StoreInterface,
                 Watch);

fail1:
    Error("fail1 (%08x)\n", status);
                   
    return status;
}

static FORCEINLINE NTSTATUS
__FrontendClose(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    PCHAR                   Path;
    XenbusState             State;
    NTSTATUS                status;

    Trace("====>\n");

    ASSERT(Frontend->Watch != NULL);
    (VOID) STORE(Unwatch,
                 Frontend->StoreInterface,
                 Frontend->Watch);
    Frontend->Watch = NULL;

    // Release cached information about the backend
    ASSERT(Frontend->BackendPath != NULL);
    STORE(Free,
          Frontend->StoreInterface,
          Frontend->BackendPath);
    Frontend->BackendPath = NULL;

    Frontend->BackendDomain = DOMID_INVALID;

    status = STORE(Read,
                   Frontend->StoreInterface,
                   NULL,
                   __FrontendGetPath(Frontend),
                   "backend",
                   &Path);
    if (!NT_SUCCESS(status))
        goto fail1;

    State = XenbusStateInitialising;
    status = __FrontendWaitForStateChange(Frontend, Path, &State);
    if (!NT_SUCCESS(status))
        goto fail2;

    while (State != XenbusStateClosing &&
           State != XenbusStateClosed &&
           State != XenbusStateUnknown) {
        (VOID) STORE(Printf,
                     Frontend->StoreInterface,
                     NULL,
                     __FrontendGetPath(Frontend),
                     "state",
                     "%u",
                     XenbusStateClosing);
        status = __FrontendWaitForStateChange(Frontend, Path, &State);
        if (!NT_SUCCESS(status))
            goto fail2;
    }

    while (State != XenbusStateClosed &&
           State != XenbusStateUnknown) {
        (VOID) STORE(Printf,
                     Frontend->StoreInterface,
                     NULL,
                     __FrontendGetPath(Frontend),
                     "state",
                     "%u",
                     XenbusStateClosed);
        status = __FrontendWaitForStateChange(Frontend, Path, &State);
        if (!NT_SUCCESS(status))
            goto fail3;
    }

    STORE(Free,
          Frontend->StoreInterface,
          Path);

    STORE(Release, Frontend->StoreInterface);
    Frontend->StoreInterface = NULL;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    STORE(Free,
          Frontend->StoreInterface,
          Path);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__FrontendPrepare(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    PCHAR                   Path;
    XenbusState             State;
    PCHAR                   Buffer;
    NTSTATUS                status;

    Trace("====>\n");

    Frontend->StoreInterface = __FrontendGetStoreInterface(Frontend);

    STORE(Acquire, Frontend->StoreInterface);

    status = STORE(Read,
                   Frontend->StoreInterface,
                   NULL,
                   __FrontendGetPath(Frontend),
                   "backend",
                   &Path);
    if (!NT_SUCCESS(status))
        goto fail1;

    State = XenbusStateUnknown;
    status = __FrontendWaitForStateChange(Frontend, Path, &State);
    if (!NT_SUCCESS(status))
        goto fail2;

    while (State != XenbusStateClosed &&
           State != XenbusStateInitialising &&
           State != XenbusStateInitWait) {
        status = __FrontendWaitForStateChange(Frontend, Path, &State);
        if (!NT_SUCCESS(status))
            goto fail3;
    }

    status = STORE(Printf,
                   Frontend->StoreInterface,
                   NULL,
                   __FrontendGetPath(Frontend),
                   "state",
                   "%u",
                   XenbusStateInitialising);
    if (!NT_SUCCESS(status))
        goto fail4;

    while (State == XenbusStateClosed ||
           State == XenbusStateInitialising) {
        status = __FrontendWaitForStateChange(Frontend, Path, &State);
        if (!NT_SUCCESS(status))
            goto fail5;
    }

    status = STATUS_UNSUCCESSFUL;
    if (State != XenbusStateInitWait)
        goto fail6;

    Frontend->BackendPath = Path;

    status = STORE(Read,
                   Frontend->StoreInterface,
                   NULL,
                   __FrontendGetPath(Frontend),
                   "backend-id",
                   &Buffer);
    if (!NT_SUCCESS(status)) {
        Frontend->BackendDomain = 0;
    } else {
        Frontend->BackendDomain = (USHORT)strtol(Buffer, NULL, 10);

        STORE(Free,
              Frontend->StoreInterface,
              Buffer);
    }

    status = STORE(Watch,
                   Frontend->StoreInterface,
                   __FrontendGetBackendPath(Frontend),
                   "online",
                   ThreadGetEvent(Frontend->EjectThread),
                   &Frontend->Watch);
    if (!NT_SUCCESS(status))
        goto fail7;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");

    Frontend->BackendDomain = DOMID_INVALID;
    Frontend->BackendPath = NULL;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    STORE(Free,
          Frontend->StoreInterface,
          Path);

fail1:
    Error("fail1 (%08x)\n", status);

    STORE(Release, Frontend->StoreInterface);
    Frontend->StoreInterface = NULL;

    Trace("<====\n");
    return status;
}

static VOID
FrontendDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_FRONTEND    Frontend = Argument;

    UNREFERENCED_PARAMETER(Crashing);

    DEBUG(Printf,
          Frontend->DebugInterface,
          Frontend->DebugCallback,
          "PATH: %s\n",
          __FrontendGetPath(Frontend));
}

static FORCEINLINE NTSTATUS
__FrontendConnect(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    PCHAR                   Path = __FrontendGetBackendPath(Frontend);
    XenbusState             State;
    ULONG                   Attempt;
    NTSTATUS                status;

    Trace("====>\n");

    Frontend->DebugInterface = __FrontendGetDebugInterface(Frontend);

    DEBUG(Acquire, Frontend->DebugInterface);

    status = DEBUG(Register,
                   Frontend->DebugInterface,
                   __MODULE__ "|FRONTEND",
                   FrontendDebugCallback,
                   Frontend,
                   &Frontend->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = MacConnect(__FrontendGetMac(Frontend));
    if (!NT_SUCCESS(status))
        goto fail2;

    status = ReceiverConnect(__FrontendGetReceiver(Frontend));
    if (!NT_SUCCESS(status))
        goto fail3;

    status = TransmitterConnect(__FrontendGetTransmitter(Frontend));
    if (!NT_SUCCESS(status))
        goto fail4;

    status = NotifierConnect(__FrontendGetNotifier(Frontend));
    if (!NT_SUCCESS(status))
        goto fail5;

    Attempt = 0;
    do {
        PXENBUS_STORE_TRANSACTION   Transaction;

        status = STORE(TransactionStart,
                       Frontend->StoreInterface,
                       &Transaction);
        if (!NT_SUCCESS(status))
            break;

        status = NotifierStoreWrite(__FrontendGetNotifier(Frontend),
                                    Transaction);
        if (!NT_SUCCESS(status))
            goto abort;

        status = ReceiverStoreWrite(__FrontendGetReceiver(Frontend),
                                    Transaction);
        if (!NT_SUCCESS(status))
            goto abort;

        status = TransmitterStoreWrite(__FrontendGetTransmitter(Frontend),
                                       Transaction);
        if (!NT_SUCCESS(status))
            goto abort;

        status = STORE(TransactionEnd,
                       Frontend->StoreInterface,
                       Transaction,
                       TRUE);
        if (status != STATUS_RETRY || ++Attempt > 10)
            break;

        continue;

abort:
        (VOID) STORE(TransactionEnd,
                     Frontend->StoreInterface,
                     Transaction,
                     FALSE);
        break;
    } while (status == STATUS_RETRY);

    if (!NT_SUCCESS(status))
        goto fail6;

    status = STORE(Printf,
                   Frontend->StoreInterface,
                   NULL,
                   __FrontendGetPath(Frontend),
                   "state",
                   "%u",
                   XenbusStateConnected);
    if (!NT_SUCCESS(status))
        goto fail7;

    State = XenbusStateInitWait;
    status = __FrontendWaitForStateChange(Frontend, Path, &State);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = STATUS_UNSUCCESSFUL;
    if (State != XenbusStateConnected)
        goto fail9;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail9:
    Error("fail9\n");

fail8:
    Error("fail8\n");

fail7:
    Error("fail7\n");

fail6:
    Error("fail7\n");

    NotifierDisconnect(__FrontendGetNotifier(Frontend));

fail5:
    Error("fail5\n");

    TransmitterDisconnect(__FrontendGetTransmitter(Frontend));

fail4:
    Error("fail4\n");

    ReceiverDisconnect(__FrontendGetReceiver(Frontend));

fail3:
    Error("fail3\n");

    MacDisconnect(__FrontendGetMac(Frontend));

fail2:
    Error("fail2\n");

    DEBUG(Deregister,
          Frontend->DebugInterface,
          Frontend->DebugCallback);
    Frontend->DebugCallback = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    DEBUG(Release, Frontend->DebugInterface);
    Frontend->DebugInterface = NULL;

    Trace("<====\n");
    return status;
}

static FORCEINLINE VOID
__FrontendDisconnect(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    Trace("====>\n");

    NotifierDisconnect(__FrontendGetNotifier(Frontend));
    TransmitterDisconnect(__FrontendGetTransmitter(Frontend));
    ReceiverDisconnect(__FrontendGetReceiver(Frontend));
    MacDisconnect(__FrontendGetMac(Frontend));

    DEBUG(Deregister,
          Frontend->DebugInterface,
          Frontend->DebugCallback);
    Frontend->DebugCallback = NULL;

    DEBUG(Release, Frontend->DebugInterface);
    Frontend->DebugInterface = NULL;

    Trace("<====\n");
}

static FORCEINLINE NTSTATUS
__FrontendEnable(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    NTSTATUS                status;

    Trace("====>\n");

    status = MacEnable(__FrontendGetMac(Frontend));
    if (!NT_SUCCESS(status))
        goto fail1;

    status = ReceiverEnable(__FrontendGetReceiver(Frontend));
    if (!NT_SUCCESS(status))
        goto fail2;

    status = TransmitterEnable(__FrontendGetTransmitter(Frontend));
    if (!NT_SUCCESS(status))
        goto fail3;

    status = NotifierEnable(__FrontendGetNotifier(Frontend));
    if (!NT_SUCCESS(status))
        goto fail4;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    TransmitterDisable(__FrontendGetTransmitter(Frontend));

fail3:
    Error("fail3\n");

    ReceiverDisable(__FrontendGetReceiver(Frontend));

fail2:
    Error("fail2\n");

    MacDisable(__FrontendGetMac(Frontend));

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE VOID
__FrontendDisable(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    Trace("====>\n");

    NotifierDisable(__FrontendGetNotifier(Frontend));
    TransmitterDisable(__FrontendGetTransmitter(Frontend));
    ReceiverDisable(__FrontendGetReceiver(Frontend));
    MacDisable(__FrontendGetMac(Frontend));

    Trace("<====\n");
}

NTSTATUS
FrontendSetState(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_FRONTEND_STATE   State
    )
{
    BOOLEAN                     Failed;
    KIRQL                       Irql;

    KeAcquireSpinLock(&Frontend->Lock, &Irql);

    Trace("%s: ====> '%s' -> '%s'\n",
          __FrontendGetPath(Frontend),
          FrontendStateName(Frontend->State),
          FrontendStateName(State));

    Failed = FALSE;
    while (Frontend->State != State && !Failed) {
        NTSTATUS    status;

        switch (Frontend->State) {
        case FRONTEND_CLOSED:
            switch (State) {
            case FRONTEND_PREPARED:
            case FRONTEND_CONNECTED:
            case FRONTEND_ENABLED:
                status = __FrontendPrepare(Frontend);
                if (NT_SUCCESS(status)) {
                    Frontend->State = FRONTEND_PREPARED;
                } else {
                    Failed = TRUE;
                }
                break;

            default:
                ASSERT(FALSE);
                break;
            }
            break;

        case FRONTEND_PREPARED:
            switch (State) {
            case FRONTEND_CONNECTED:
            case FRONTEND_ENABLED:
                status = __FrontendConnect(Frontend);
                if (NT_SUCCESS(status)) {
                    Frontend->State = FRONTEND_CONNECTED;
                } else {
                    status = __FrontendClose(Frontend);
                    if (NT_SUCCESS(status))
                        Frontend->State = FRONTEND_CLOSED;
                    else
                        Frontend->State = FRONTEND_STATE_INVALID;

                    Failed = TRUE;
                }
                break;

            case FRONTEND_CLOSED:
                status = __FrontendClose(Frontend);
                if (NT_SUCCESS(status)) {
                    Frontend->State = FRONTEND_CLOSED;
                } else {
                    Frontend->State = FRONTEND_STATE_INVALID;
                    Failed = TRUE;
                }

                break;

            default:
                ASSERT(FALSE);
                break;
            }
            break;

        case FRONTEND_CONNECTED:
            switch (State) {
            case FRONTEND_ENABLED:
                status = __FrontendEnable(Frontend);
                if (NT_SUCCESS(status)) {
                    Frontend->State = FRONTEND_ENABLED;
                } else {
                    status = __FrontendClose(Frontend);
                    if (NT_SUCCESS(status))
                        Frontend->State = FRONTEND_CLOSED;
                    else
                        Frontend->State = FRONTEND_STATE_INVALID;

                    Failed = TRUE;
                }
                break;

            case FRONTEND_PREPARED:
            case FRONTEND_CLOSED:
                status = __FrontendClose(Frontend);
                if (NT_SUCCESS(status)) {
                    Frontend->State = FRONTEND_CLOSED;
                } else {
                    Frontend->State = FRONTEND_STATE_INVALID;
                    Failed = TRUE;
                }

                __FrontendDisconnect(Frontend);

                break;

            default:
                ASSERT(FALSE);
                break;
            }
            break;

        case FRONTEND_ENABLED:
            switch (State) {
            case FRONTEND_CONNECTED:
            case FRONTEND_PREPARED:
            case FRONTEND_CLOSED:
                __FrontendDisable(Frontend);
                Frontend->State = FRONTEND_CONNECTED;
                break;

            default:
                ASSERT(FALSE);
                break;
            }
            break;

        case FRONTEND_STATE_INVALID:
            Failed = TRUE;
            break;

        default:
            ASSERT(FALSE);
            break;
        }

        Trace("%s in state '%s'\n",
              __FrontendGetPath(Frontend),
              FrontendStateName(Frontend->State));
    }

    KeReleaseSpinLock(&Frontend->Lock, Irql);

    Trace("%s: <=====\n", __FrontendGetPath(Frontend));

    return (!Failed) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static FORCEINLINE NTSTATUS
__FrontendResume(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    NTSTATUS                status;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    status = FrontendSetState(Frontend, FRONTEND_PREPARED);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = FrontendSetState(Frontend, FRONTEND_CLOSED);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    STORE(Release, Frontend->StoreInterface);
    Frontend->StoreInterface = NULL;

    Frontend->State = FRONTEND_CLOSED;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE VOID
__FrontendSuspend(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    UNREFERENCED_PARAMETER(Frontend);

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
}

static DECLSPEC_NOINLINE VOID
FrontendSuspendCallbackLate(
    IN  PVOID           Argument
    )
{
    PXENVIF_FRONTEND    Frontend = Argument;
    NTSTATUS            status;

    __FrontendSuspend(Frontend);

    status = __FrontendResume(Frontend);
    ASSERT(NT_SUCCESS(status));
}

NTSTATUS
FrontendResume(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    KIRQL                   Irql;
    NTSTATUS                status;

    Trace("====>\n");

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    status = __FrontendResume(Frontend);
    KeLowerIrql(Irql);

    if (!NT_SUCCESS(status))
        goto fail1;

    Frontend->SuspendInterface = __FrontendGetSuspendInterface(Frontend);

    SUSPEND(Acquire, Frontend->SuspendInterface);

    status = SUSPEND(Register,
                     Frontend->SuspendInterface,
                     SUSPEND_CALLBACK_LATE,
                     FrontendSuspendCallbackLate,
                     Frontend,
                     &Frontend->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail2;

    Trace("<====\n");

    return STATUS_SUCCESS;
    
fail2:
    Error("fail2\n");

    SUSPEND(Release, Frontend->SuspendInterface);
    Frontend->SuspendInterface = NULL;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __FrontendSuspend(Frontend);
    KeLowerIrql(Irql);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
FrontendSuspend(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    KIRQL                   Irql;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    // FrontendResume() may have failed
    if (Frontend->SuspendInterface == NULL)
        goto done;

    SUSPEND(Deregister,
            Frontend->SuspendInterface,
            Frontend->SuspendCallbackLate);
    Frontend->SuspendCallbackLate = NULL;

    SUSPEND(Release, Frontend->SuspendInterface);
    Frontend->SuspendInterface = NULL;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __FrontendSuspend(Frontend);
    KeLowerIrql(Irql);

done:
    Trace("<====\n");
}

NTSTATUS
FrontendInitialize(
    IN  PXENVIF_PDO         Pdo,
    OUT PXENVIF_FRONTEND    *Frontend
    )
{
    PCHAR                   Name;
    ULONG                   Length;
    PCHAR                   Path;
    PCHAR                   Prefix;
    NTSTATUS                status;

    Trace("====>\n");

    Name = PdoGetName(Pdo);

    Length = sizeof ("devices/vif/") + (ULONG)strlen(Name);
    Path = __FrontendAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Path == NULL)
        goto fail1;

    status = RtlStringCbPrintfA(Path, 
                                Length,
                                "device/vif/%s", 
                                Name);
    if (!NT_SUCCESS(status))
        goto fail2;

    Length = sizeof ("attr/eth") + (ULONG)strlen(Name);
    Prefix = __FrontendAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Prefix == NULL)
        goto fail3;

    status = RtlStringCbPrintfA(Prefix, 
                                Length,
                                "attr/eth%s", 
                                Name);
    if (!NT_SUCCESS(status))
        goto fail4;

    *Frontend = __FrontendAllocate(sizeof (XENVIF_FRONTEND));

    status = STATUS_NO_MEMORY;
    if (*Frontend == NULL)
        goto fail5;

    (*Frontend)->Pdo = Pdo;
    (*Frontend)->Path = Path;
    (*Frontend)->Prefix = Prefix;
    (*Frontend)->BackendDomain = DOMID_INVALID;

    KeInitializeSpinLock(&(*Frontend)->Lock);

    (*Frontend)->State = FRONTEND_CLOSED;

    status = ThreadCreate(FrontendEject, *Frontend, &(*Frontend)->EjectThread);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = MacInitialize(*Frontend, &(*Frontend)->Mac);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = NotifierInitialize(*Frontend, &(*Frontend)->Notifier);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = ReceiverInitialize(*Frontend, 1, &(*Frontend)->Receiver);
    if (!NT_SUCCESS(status))
        goto fail9;

    status = TransmitterInitialize(*Frontend, 1, &(*Frontend)->Transmitter);
    if (!NT_SUCCESS(status))
        goto fail10;

    status = ThreadCreate(FrontendMib, *Frontend, &(*Frontend)->MibThread);
    if (!NT_SUCCESS(status))
        goto fail11;

    status = NotifyUnicastIpAddressChange(AF_UNSPEC,
                                          FrontendIpAddressChange,
                                          *Frontend,
                                          TRUE,
                                          &(*Frontend)->Handle);
    if (!NT_SUCCESS(status)) {
        if (status != STATUS_NOT_SUPPORTED) 
            goto fail12;
        
        // If IP Helper isn't available (as in Windows PE) then
        // NotifyUnicastIpAddressChange will not be supported
        Warning("Cannot record or update network info to XAPI %x\n", status);
        (*Frontend)->Handle = NULL;
    }

    Trace("<====\n");

    return STATUS_SUCCESS;

fail12:
    Error("fail12\n");

    ThreadAlert((*Frontend)->MibThread);
    ThreadJoin((*Frontend)->MibThread);
    (*Frontend)->MibThread = NULL;

fail11:
    Error("fail11\n");

    TransmitterTeardown(__FrontendGetTransmitter(*Frontend));
    (*Frontend)->Transmitter = NULL;

fail10:
    Error("fail10\n");

    ReceiverTeardown(__FrontendGetReceiver(*Frontend));
    (*Frontend)->Receiver = NULL;

fail9:
    Error("fail9\n");

    NotifierTeardown(__FrontendGetNotifier(*Frontend));
    (*Frontend)->Notifier = NULL;

fail8:
    Error("fail8\n");

    MacTeardown(__FrontendGetMac(*Frontend));
    (*Frontend)->Mac = NULL;

fail7:
    Error("fail7\n");

    ThreadAlert((*Frontend)->EjectThread);
    ThreadJoin((*Frontend)->EjectThread);
    (*Frontend)->EjectThread = NULL;

fail6:
    Error("fail6\n");

    (*Frontend)->State = FRONTEND_STATE_INVALID;
    RtlZeroMemory(&(*Frontend)->Lock, sizeof (KSPIN_LOCK));

    (*Frontend)->BackendDomain = 0;
    (*Frontend)->Prefix = NULL;
    (*Frontend)->Path = NULL;
    (*Frontend)->Pdo = NULL;

    ASSERT(IsZeroMemory(*Frontend, sizeof (XENVIF_FRONTEND)));

    __FrontendFree(*Frontend);
    *Frontend = NULL;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

    __FrontendFree(Prefix);

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    __FrontendFree(Path);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
FrontendTeardown(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    Trace("====>\n");

    ASSERT(Frontend->State != FRONTEND_ENABLED);
    ASSERT(Frontend->State != FRONTEND_CONNECTED);

    if (Frontend->Handle != NULL) {
        CancelMibChangeNotify2(Frontend->Handle);
        Frontend->Handle = NULL;
    }

    if (Frontend->State == FRONTEND_PREPARED) {

        ASSERT(Frontend->Watch != NULL);
        (VOID) STORE(Unwatch,
                     Frontend->StoreInterface,
                     Frontend->Watch);
        Frontend->Watch = NULL;

        // Release cached information about the backend
        ASSERT(Frontend->BackendPath != NULL);
        STORE(Free,
              Frontend->StoreInterface,
              Frontend->BackendPath);
        Frontend->BackendPath = NULL;

        Frontend->BackendDomain = DOMID_INVALID;

        Frontend->State = FRONTEND_CLOSED;
    }

    ASSERT3U(Frontend->State, ==, FRONTEND_CLOSED);

    ThreadAlert(Frontend->MibThread);
    ThreadJoin(Frontend->MibThread);
    Frontend->MibThread = NULL;

    TransmitterTeardown(__FrontendGetTransmitter(Frontend));
    Frontend->Transmitter = NULL;

    ReceiverTeardown(__FrontendGetReceiver(Frontend));
    Frontend->Receiver = NULL;

    NotifierTeardown(__FrontendGetNotifier(Frontend));
    Frontend->Notifier = NULL;

    MacTeardown(__FrontendGetMac(Frontend));
    Frontend->Mac = NULL;

    ThreadAlert(Frontend->EjectThread);
    ThreadJoin(Frontend->EjectThread);
    Frontend->EjectThread = NULL;

    Frontend->State = FRONTEND_STATE_INVALID;
    RtlZeroMemory(&Frontend->Lock, sizeof (KSPIN_LOCK));

    Frontend->BackendDomain = 0;

    __FrontendFree(Frontend->Prefix);
    Frontend->Prefix = NULL;

    __FrontendFree(Frontend->Path);
    Frontend->Path = NULL;

    Frontend->Pdo = NULL;

    ASSERT(IsZeroMemory(Frontend, sizeof (XENVIF_FRONTEND)));

    __FrontendFree(Frontend);

    Trace("<====\n");
}

VOID
FrontendRemoveFailed(
    IN PXENVIF_FRONTEND Frontend
    )
{
    KIRQL               Irql;
    ULONG               Length;
    PCHAR               Path;
    NTSTATUS            status;

    KeAcquireSpinLock(&Frontend->Lock, &Irql);
    if (!Frontend->EjectRequested)
        goto done;

    Frontend->EjectRequested = FALSE;

    Info("%s: device eject failed\n", __FrontendGetPath(Frontend));

    Length = sizeof ("error/") + (ULONG)strlen(__FrontendGetPath(Frontend));
    Path = __FrontendAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Path == NULL)
        goto fail1;

    status = RtlStringCbPrintfA(Path, 
                                Length,
                                "error/%s", 
                                __FrontendGetPath(Frontend));
    if (!NT_SUCCESS(status))
        goto fail2;

    (VOID) STORE(Printf,
                 Frontend->StoreInterface,
                 NULL,
                 Path,
                 "error",
                 "UNPLUG FAILED: device is still in use");

    __FrontendFree(Path);

done:        
    KeReleaseSpinLock(&Frontend->Lock, Irql);
    return;

fail2:
    Error("fail2\n");

    __FrontendFree(Path);

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Frontend->Lock, Irql);
}
