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

#include "driver.h"
#include "registry.h"
#include "fdo.h"
#include "pdo.h"
#include "thread.h"
#include "frontend.h"
#include "names.h"
#include "granter.h"
#include "notifier.h"
#include "mac.h"
#include "tcpip.h"
#include "receiver.h"
#include "transmitter.h"
#include "link.h"
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

    PCHAR                       BackendPath;
    USHORT                      BackendDomain;

    PXENVIF_GRANTER             Granter;
    PXENVIF_NOTIFIER            Notifier;
    PXENVIF_MAC                 Mac;
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_TRANSMITTER         Transmitter;

    XENBUS_DEBUG_INTERFACE      DebugInterface;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    XENBUS_STORE_INTERFACE      StoreInterface;

    PXENBUS_SUSPEND_CALLBACK    SuspendCallbackLate;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    PXENBUS_STORE_WATCH         Watch;

    ULONGLONG                   Statistic[XENVIF_VIF_STATISTIC_COUNT][MAXIMUM_PROCESSORS];
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

PXENVIF_PDO
FrontendGetPdo(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    return __FrontendGetPdo(Frontend);
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

#define DEFINE_FRONTEND_GET_FUNCTION(_Function, _Type)  \
static FORCEINLINE _Type                                \
__FrontendGet ## _Function(                             \
    IN  PXENVIF_FRONTEND    Frontend                    \
    )                                                   \
{                                                       \
    return Frontend-> ## _Function;                     \
}                                                       \
                                                        \
_Type                                                   \
FrontendGet ## _Function(                               \
    IN  PXENVIF_FRONTEND    Frontend                    \
    )                                                   \
{                                                       \
    return __FrontendGet ## _Function ## (Frontend);    \
}

DEFINE_FRONTEND_GET_FUNCTION(Granter, PXENVIF_GRANTER)
DEFINE_FRONTEND_GET_FUNCTION(Notifier, PXENVIF_NOTIFIER)
DEFINE_FRONTEND_GET_FUNCTION(Mac, PXENVIF_MAC)
DEFINE_FRONTEND_GET_FUNCTION(Transmitter, PXENVIF_TRANSMITTER)
DEFINE_FRONTEND_GET_FUNCTION(Receiver, PXENVIF_RECEIVER)

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
        BOOLEAN             Online;
        XenbusState         State;
        ULONG               Attempt;
        KIRQL               Irql;
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

        // It is not safe to use interfaces before this point
        if (Frontend->State == FRONTEND_CLOSED) {
            KeReleaseSpinLock(&Frontend->Lock, Irql);
            continue;
        }

        Online = TRUE;
        State = XenbusStateUnknown;

        Attempt = 0;
        for (;;) {
            PXENBUS_STORE_TRANSACTION   Transaction;
            PCHAR                       Buffer;

            status = STATUS_UNSUCCESSFUL;
            if (__FrontendGetBackendPath(Frontend) == NULL)
                break;

            status = XENBUS_STORE(TransactionStart,
                                  &Frontend->StoreInterface,
                                  &Transaction);
            if (!NT_SUCCESS(status))
                break;

            status = XENBUS_STORE(Read,
                                  &Frontend->StoreInterface,
                                  Transaction,
                                  __FrontendGetBackendPath(Frontend),
                                  "online",
                                  &Buffer);
            if (!NT_SUCCESS(status))
                goto abort;

            Online = (BOOLEAN)strtol(Buffer, NULL, 2);

            XENBUS_STORE(Free,
                         &Frontend->StoreInterface,
                         Buffer);

            status = XENBUS_STORE(Read,
                                  &Frontend->StoreInterface,
                                  Transaction,
                                  __FrontendGetBackendPath(Frontend),
                                  "state",
                                  &Buffer);
            if (!NT_SUCCESS(status))
                goto abort;

            State = (XenbusState)strtol(Buffer, NULL, 10);

            XENBUS_STORE(Free,
                         &Frontend->StoreInterface,
                         Buffer);

            status = XENBUS_STORE(TransactionEnd,
                                  &Frontend->StoreInterface,
                                  Transaction,
                                  TRUE);
            if (status != STATUS_RETRY || ++Attempt > 10)
                break;

            continue;

abort:
            (VOID) XENBUS_STORE(TransactionEnd,
                                &Frontend->StoreInterface,
                                Transaction,
                                FALSE);
            break;
        }

        if (!NT_SUCCESS(status)) {
            Online = TRUE;
            State = XenbusStateUnknown;
        }

        if (!Online && State == XenbusStateClosing) {
            Info("%s: requesting device eject\n",
                 __FrontendGetPath(Frontend));

            PdoRequestEject(Frontend->Pdo);
        }

        KeReleaseSpinLock(&Frontend->Lock, Irql);
    }

    Trace("%s: <====\n", __FrontendGetPath(Frontend));

    return STATUS_SUCCESS;
}

VOID
FrontendEjectFailed(
    IN PXENVIF_FRONTEND Frontend
    )
{
    KIRQL               Irql;
    ULONG               Length;
    PCHAR               Path;
    NTSTATUS            status;

    KeAcquireSpinLock(&Frontend->Lock, &Irql);

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

    (VOID) XENBUS_STORE(Printf,
                        &Frontend->StoreInterface,
                        NULL,
                        Path,
                        "error",
                        "UNPLUG FAILED: device is still in use");

    __FrontendFree(Path);

    KeReleaseSpinLock(&Frontend->Lock, Irql);
    return;

fail2:
    Error("fail2\n");

    __FrontendFree(Path);

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Frontend->Lock, Irql);
}

static FORCEINLINE NTSTATUS
__FrontendInsertAddress(
    IN OUT  PSOCKADDR_INET      *AddressTable,
    IN      const SOCKADDR_INET *Address,
    IN OUT  PULONG              AddressCount
    )
{
    ULONG                       Index;
    PSOCKADDR_INET              Table;
    NTSTATUS                    status;

    for (Index = 0; Index < *AddressCount; Index++) {
        if ((*AddressTable)[Index].si_family != Address->si_family)
            continue;

        if (Address->si_family == AF_INET) {
            if (RtlCompareMemory(&Address->Ipv4.sin_addr.s_addr,
                                 &(*AddressTable)[Index].Ipv4.sin_addr.s_addr,
                                 IPV4_ADDRESS_LENGTH) == IPV4_ADDRESS_LENGTH)
                goto done;
        } else {
            ASSERT3U(Address->si_family, ==, AF_INET6);

            if (RtlCompareMemory(&Address->Ipv6.sin6_addr.s6_addr,
                                 &(*AddressTable)[Index].Ipv6.sin6_addr.s6_addr,
                                 IPV6_ADDRESS_LENGTH) == IPV6_ADDRESS_LENGTH)
                goto done;
        }
    }

    // We have an address we've not seen before so grow the table
    Table = __FrontendAllocate(sizeof (SOCKADDR_INET) * (*AddressCount + 1));

    status = STATUS_NO_MEMORY;
    if (Table == NULL)
        goto fail1;

    RtlCopyMemory(Table, *AddressTable, sizeof (SOCKADDR_INET) * *AddressCount);
    Table[(*AddressCount)++] = *Address;

    if (*AddressTable != NULL)
        __FrontendFree(*AddressTable);

    *AddressTable = Table;

done:
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__FrontendProcessAddressTable(
    IN  PXENVIF_FRONTEND            Frontend,
    IN  PMIB_UNICASTIPADDRESS_TABLE MibTable,
    OUT PSOCKADDR_INET              *AddressTable,
    OUT PULONG                      AddressCount
    )
{
    PNET_LUID                       Luid;
    ULONG                           Index;
    NTSTATUS                        status;

    *AddressTable = NULL;
    *AddressCount = 0;

    Luid = PdoGetLuid(Frontend->Pdo);

    for (Index = 0; Index < MibTable->NumEntries; Index++) {
        PMIB_UNICASTIPADDRESS_ROW   Row = &MibTable->Table[Index];

        if (Row->InterfaceLuid.Info.IfType != Luid->Info.IfType)
            continue;

        if (Row->InterfaceLuid.Info.NetLuidIndex != Luid->Info.NetLuidIndex)
            continue;

        if (Row->Address.si_family != AF_INET &&
            Row->Address.si_family != AF_INET6)
            continue;

        status = __FrontendInsertAddress(AddressTable,
                                         &Row->Address,
                                         AddressCount);
        if (!NT_SUCCESS(status))
            goto fail1;
    }

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    if (*AddressTable != NULL)
        __FrontendFree(*AddressTable);

    return status;
}

static FORCEINLINE NTSTATUS
__FrontendDumpAddressTable(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  PSOCKADDR_INET          AddressTable,
    IN  ULONG                   AddressCount
    )
{
    PXENBUS_STORE_TRANSACTION   Transaction;
    ULONG                       Index;
    ULONG                       IpVersion4Count;
    ULONG                       IpVersion6Count;
    NTSTATUS                    status;

    status = XENBUS_STORE(TransactionStart,
                          &Frontend->StoreInterface,
                          &Transaction);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Remove,
                          &Frontend->StoreInterface,
                          Transaction,
                          __FrontendGetPrefix(Frontend),
                          "ipv4");
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND)
        goto fail2;

    status = XENBUS_STORE(Remove,
                          &Frontend->StoreInterface,
                          Transaction,
                          __FrontendGetPrefix(Frontend),
                          "ipv6");
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND)
        goto fail3;

    IpVersion4Count = 0;
    IpVersion6Count = 0;

    for (Index = 0; Index < AddressCount; Index++) {
        switch (AddressTable[Index].si_family) {
        case AF_INET: {
            IPV4_ADDRESS    Address;
            CHAR            Node[sizeof ("ipv4/XXXXXXXX/addr")];

            RtlCopyMemory(Address.Byte,
                          &AddressTable[Index].Ipv4.sin_addr.s_addr,
                          IPV4_ADDRESS_LENGTH);

            status = RtlStringCbPrintfA(Node,
                                        sizeof (Node),
                                        "ipv4/%u/addr",
                                        IpVersion4Count);
            ASSERT(NT_SUCCESS(status));

            status = XENBUS_STORE(Printf,
                                  &Frontend->StoreInterface,
                                  Transaction,
                                  __FrontendGetPrefix(Frontend),
                                  Node,
                                  "%u.%u.%u.%u",
                                  Address.Byte[0],
                                  Address.Byte[1],
                                  Address.Byte[2],
                                  Address.Byte[3]);
            if (!NT_SUCCESS(status))
                goto fail4;

            IpVersion4Count++;
            break;
        }
        case AF_INET6: {
            IPV6_ADDRESS    Address;
            CHAR            Node[sizeof ("ipv6/XXXXXXXX/addr")];

            RtlCopyMemory(Address.Byte,
                          &AddressTable[Index].Ipv6.sin6_addr.s6_addr,
                          IPV6_ADDRESS_LENGTH);

            status = RtlStringCbPrintfA(Node,
                                        sizeof (Node),
                                        "ipv6/%u/addr",
                                        IpVersion6Count);
            ASSERT(NT_SUCCESS(status));

            status = XENBUS_STORE(Printf,
                                  &Frontend->StoreInterface,
                                  Transaction,
                                  __FrontendGetPrefix(Frontend),
                                  Node,
                                  "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                                  NTOHS(Address.Word[0]),
                                  NTOHS(Address.Word[1]),
                                  NTOHS(Address.Word[2]),
                                  NTOHS(Address.Word[3]),
                                  NTOHS(Address.Word[4]),
                                  NTOHS(Address.Word[5]),
                                  NTOHS(Address.Word[6]),
                                  NTOHS(Address.Word[7]));
            if (!NT_SUCCESS(status))
                goto fail4;

            IpVersion6Count++;
            break;
        }
        default:
            break;
        }
    }

    status = XENBUS_STORE(TransactionEnd,
                          &Frontend->StoreInterface,
                          Transaction,
                          TRUE);

    return status;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    (VOID) XENBUS_STORE(TransactionEnd,
                        &Frontend->StoreInterface,
                        Transaction,
                        FALSE);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static VOID
FrontendIpAddressChange(
    IN  PVOID                       Context,
    IN  PMIB_UNICASTIPADDRESS_ROW   Row OPTIONAL,
    IN  MIB_NOTIFICATION_TYPE       NotificationType
    )
{
    PXENVIF_FRONTEND                Frontend = Context;

    UNREFERENCED_PARAMETER(Row);
    UNREFERENCED_PARAMETER(NotificationType);

    ThreadWake(Frontend->MibThread);
}

static DECLSPEC_NOINLINE NTSTATUS
FrontendMib(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVIF_FRONTEND    Frontend = Context;
    PKEVENT             Event;
    NTSTATUS            (*__NotifyUnicastIpAddressChange)(ADDRESS_FAMILY,
                                                          PUNICAST_IPADDRESS_CHANGE_CALLBACK,
                                                          PVOID,    
                                                          BOOLEAN,
                                                          HANDLE *);
    NTSTATUS            (*__GetUnicastIpAddressTable)(ADDRESS_FAMILY,
                                                      PMIB_UNICASTIPADDRESS_TABLE *);

    VOID                (*__FreeMibTable)(PVOID);
    NTSTATUS            (*__CancelMibChangeNotify2)(HANDLE);
    HANDLE              Handle;
    NTSTATUS            status;

    Trace("====>\n");

    status = LinkGetRoutineAddress("netio.sys",
                                   "NotifyUnicastIpAddressChange",
                                   (PVOID *)&__NotifyUnicastIpAddressChange);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = LinkGetRoutineAddress("netio.sys",
                                   "GetUnicastIpAddressTable",
                                   (PVOID *)&__GetUnicastIpAddressTable);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = LinkGetRoutineAddress("netio.sys",
                                   "FreeMibTable",
                                   (PVOID *)&__FreeMibTable);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = LinkGetRoutineAddress("netio.sys",
                                   "CancelMibChangeNotify2",
                                   (PVOID *)&__CancelMibChangeNotify2);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = __NotifyUnicastIpAddressChange(AF_UNSPEC,
                                            FrontendIpAddressChange,
                                            Frontend,
                                            TRUE,
                                            &Handle);
    if (!NT_SUCCESS(status))
        goto fail5;

    Event = ThreadGetEvent(Self);

    for (;;) { 
        PMIB_UNICASTIPADDRESS_TABLE MibTable;
        KIRQL                       Irql;
        PSOCKADDR_INET              AddressTable;
        ULONG                       AddressCount;

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        status = __GetUnicastIpAddressTable(AF_UNSPEC, &MibTable);
        if (!NT_SUCCESS(status))
            continue;

        KeAcquireSpinLock(&Frontend->Lock, &Irql);

        // It is not safe to use interfaces before this point
        if (Frontend->State != FRONTEND_CONNECTED &&
            Frontend->State != FRONTEND_ENABLED)
            goto loop;

        status = __FrontendProcessAddressTable(Frontend,
                                               MibTable,
                                               &AddressTable,
                                               &AddressCount);
        if (!NT_SUCCESS(status))
            goto loop;

        TransmitterUpdateAddressTable(__FrontendGetTransmitter(Frontend),
                                      AddressTable,
                                      AddressCount);

        (VOID) __FrontendDumpAddressTable(Frontend,
                                          AddressTable,
                                          AddressCount);

        if (AddressCount != 0)
            __FrontendFree(AddressTable);

loop:
        KeReleaseSpinLock(&Frontend->Lock, Irql);

        __FreeMibTable(MibTable);
    }

    status = __CancelMibChangeNotify2(Handle);
    ASSERT(NT_SUCCESS(status));

    Trace("<====\n");

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

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

    status = XENBUS_STORE(WatchAdd,
                          &Frontend->StoreInterface,
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
            XENBUS_STORE(Poll,
                         &Frontend->StoreInterface);

            KeStallExecutionProcessor(1000);   // 1ms
        }

        KeClearEvent(&Event);

        status = XENBUS_STORE(Read,
                              &Frontend->StoreInterface,
                              NULL,
                              Path,
                              "state",
                              &Buffer);
        if (!NT_SUCCESS(status)) {
            if (status != STATUS_OBJECT_NAME_NOT_FOUND)
                goto fail2;

            *State = XenbusStateUnknown;
        } else {
            *State = (XenbusState)strtol(Buffer, NULL, 10);

            XENBUS_STORE(Free,
                         &Frontend->StoreInterface,
                         Buffer);
        }

        KeQuerySystemTime(&Now);

        TimeDelta = (Now.QuadPart - Start.QuadPart) / 10000ull;
    }

    status = STATUS_UNSUCCESSFUL;
    if (*State == Old)
        goto fail3;

    (VOID) XENBUS_STORE(WatchRemove,
                        &Frontend->StoreInterface,
                        Watch);

    Trace("%s: <==== (%s)\n", Path, XenbusStateName(*State));

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    (VOID) XENBUS_STORE(WatchRemove,
                        &Frontend->StoreInterface,
                        Watch);

fail1:
    Error("fail1 (%08x)\n", status);
                   
    return status;
}

static FORCEINLINE NTSTATUS
__FrontendClose(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  BOOLEAN             Force            
    )
{
    PCHAR                   Path;
    XenbusState             State;
    NTSTATUS                status;

    Trace("====>\n");

    ASSERT(Frontend->Watch != NULL);
    (VOID) XENBUS_STORE(WatchRemove,
                        &Frontend->StoreInterface,
                        Frontend->Watch);
    Frontend->Watch = NULL;

    // Release cached information about the backend
    ASSERT(Frontend->BackendPath != NULL);
    XENBUS_STORE(Free,
                 &Frontend->StoreInterface,
                 Frontend->BackendPath);
    Frontend->BackendPath = NULL;

    Frontend->BackendDomain = DOMID_INVALID;

    if (Force)
        goto done;

    status = XENBUS_STORE(Read,
                          &Frontend->StoreInterface,
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
        (VOID) XENBUS_STORE(Printf,
                            &Frontend->StoreInterface,
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
        (VOID) XENBUS_STORE(Printf,
                            &Frontend->StoreInterface,
                            NULL,
                            __FrontendGetPath(Frontend),
                            "state",
                            "%u",
                            XenbusStateClosed);
        status = __FrontendWaitForStateChange(Frontend, Path, &State);
        if (!NT_SUCCESS(status))
            goto fail3;
    }

    XENBUS_STORE(Free,
                 &Frontend->StoreInterface,
                 Path);

done:
    XENBUS_STORE(Release, &Frontend->StoreInterface);

    Trace("<====\n");
    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    XENBUS_STORE(Free,
                 &Frontend->StoreInterface,
                 Path);

fail1:
    Error("fail1 (%08x)\n", status);

    XENBUS_STORE(Release, &Frontend->StoreInterface);

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

    status = XENBUS_STORE(Acquire, &Frontend->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Read,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetPath(Frontend),
                          "backend",
                          &Path);
    if (!NT_SUCCESS(status))
        goto fail2;

    State = XenbusStateUnknown;
    status = __FrontendWaitForStateChange(Frontend, Path, &State);
    if (!NT_SUCCESS(status))
        goto fail3;

    while (State != XenbusStateClosed &&
           State != XenbusStateInitialising &&
           State != XenbusStateInitWait) {
        status = __FrontendWaitForStateChange(Frontend, Path, &State);
        if (!NT_SUCCESS(status))
            goto fail4;
    }

    status = XENBUS_STORE(Printf,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetPath(Frontend),
                          "state",
                          "%u",
                          XenbusStateInitialising);
    if (!NT_SUCCESS(status))
        goto fail5;

    while (State == XenbusStateClosed ||
           State == XenbusStateInitialising) {
        status = __FrontendWaitForStateChange(Frontend, Path, &State);
        if (!NT_SUCCESS(status))
            goto fail6;
    }

    status = STATUS_UNSUCCESSFUL;
    if (State != XenbusStateInitWait)
        goto fail7;

    Frontend->BackendPath = Path;

    status = XENBUS_STORE(Read,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetPath(Frontend),
                          "backend-id",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Frontend->BackendDomain = 0;
    } else {
        Frontend->BackendDomain = (USHORT)strtol(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Frontend->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(WatchAdd,
                          &Frontend->StoreInterface,
                          __FrontendGetBackendPath(Frontend),
                          "online",
                          ThreadGetEvent(Frontend->EjectThread),
                          &Frontend->Watch);
    if (!NT_SUCCESS(status))
        goto fail8;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail8:
    Error("fail8\n");

    Frontend->BackendDomain = DOMID_INVALID;
    Frontend->BackendPath = NULL;

fail7:
    Error("fail7\n");

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    XENBUS_STORE(Free,
                 &Frontend->StoreInterface,
                 Path);
fail2:
    Error("fail2\n");

    XENBUS_STORE(Release, &Frontend->StoreInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    Trace("<====\n");
    return status;
}

static FORCEINLINE VOID
__FrontendQueryStatistic(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_VIF_STATISTIC    Index,
    OUT PULONGLONG              Value
    )
{
    ULONG                       Cpu;

    ASSERT(Index < XENVIF_VIF_STATISTIC_COUNT);

    *Value = 0;
    for (Cpu = 0; Cpu < MAXIMUM_PROCESSORS; Cpu++)
        *Value += Frontend->Statistic[Index][Cpu];
}

VOID
FrontendQueryStatistic(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_VIF_STATISTIC    Index,
    OUT PULONGLONG              Value
    )
{
    __FrontendQueryStatistic(Frontend, Index, Value);
}

VOID
FrontendIncrementStatistic(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_VIF_STATISTIC    Index,
    IN  ULONGLONG               Delta
    )
{
    ULONG                       Cpu;

    ASSERT(Index < XENVIF_VIF_STATISTIC_COUNT);

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Cpu = KeGetCurrentProcessorNumber();
    Frontend->Statistic[Index][Cpu] += Delta;
}

static FORCEINLINE const CHAR *
__FrontendStatisticName(
    IN  XENVIF_VIF_STATISTIC    Index
    )
{
#define _FRONTEND_STATISTIC_NAME(_Index)    \
    case XENVIF_ ## _Index:                 \
        return #_Index;

    switch (Index) {
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_PACKETS_DROPPED);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_BACKEND_ERRORS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_FRONTEND_ERRORS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_UNICAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_UNICAST_OCTETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_MULTICAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_MULTICAST_OCTETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_BROADCAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(TRANSMITTER_BROADCAST_OCTETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_PACKETS_DROPPED);
    _FRONTEND_STATISTIC_NAME(RECEIVER_BACKEND_ERRORS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_FRONTEND_ERRORS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_UNICAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_UNICAST_OCTETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_MULTICAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_MULTICAST_OCTETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_BROADCAST_PACKETS);
    _FRONTEND_STATISTIC_NAME(RECEIVER_BROADCAST_OCTETS);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _FRONTEND_STATISTIC_NAME
}

static VOID
FrontendDebugCallback(
    IN  PVOID               Argument,
    IN  BOOLEAN             Crashing
    )
{
    PXENVIF_FRONTEND        Frontend = Argument;
    XENVIF_VIF_STATISTIC    Index;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Frontend->DebugInterface,
                 "PATH: %s\n",
                 __FrontendGetPath(Frontend));

    XENBUS_DEBUG(Printf,
                 &Frontend->DebugInterface,
                 "STATISTICS:\n");

    for (Index = 0; Index < XENVIF_VIF_STATISTIC_COUNT; Index++) {
        ULONGLONG   Value;

        __FrontendQueryStatistic(Frontend, Index, &Value);

        XENBUS_DEBUG(Printf,
                     &Frontend->DebugInterface,
                     " - %40s %lu\n",
                     __FrontendStatisticName(Index),
                     Value);
    }
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

    status = XENBUS_DEBUG(Acquire, &Frontend->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Register,
                          &Frontend->DebugInterface,
                          __MODULE__ "|FRONTEND",
                          FrontendDebugCallback,
                          Frontend,
                          &Frontend->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = GranterConnect(__FrontendGetGranter(Frontend));
    if (!NT_SUCCESS(status))
        goto fail3;

    status = MacConnect(__FrontendGetMac(Frontend));
    if (!NT_SUCCESS(status))
        goto fail4;

    status = ReceiverConnect(__FrontendGetReceiver(Frontend));
    if (!NT_SUCCESS(status))
        goto fail5;

    status = TransmitterConnect(__FrontendGetTransmitter(Frontend));
    if (!NT_SUCCESS(status))
        goto fail6;

    status = NotifierConnect(__FrontendGetNotifier(Frontend));
    if (!NT_SUCCESS(status))
        goto fail7;

    Attempt = 0;
    do {
        PXENBUS_STORE_TRANSACTION   Transaction;

        status = XENBUS_STORE(TransactionStart,
                              &Frontend->StoreInterface,
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

        status = XENBUS_STORE(TransactionEnd,
                              &Frontend->StoreInterface,
                              Transaction,
                              TRUE);
        if (status != STATUS_RETRY || ++Attempt > 10)
            break;

        continue;

abort:
        (VOID) XENBUS_STORE(TransactionEnd,
                            &Frontend->StoreInterface,
                            Transaction,
                            FALSE);
        break;
    } while (status == STATUS_RETRY);

    if (!NT_SUCCESS(status))
        goto fail8;

    status = XENBUS_STORE(Printf,
                          &Frontend->StoreInterface,
                          NULL,
                          __FrontendGetPath(Frontend),
                          "state",
                          "%u",
                          XenbusStateConnected);
    if (!NT_SUCCESS(status))
        goto fail9;

    State = XenbusStateInitWait;
    status = __FrontendWaitForStateChange(Frontend, Path, &State);
    if (!NT_SUCCESS(status))
        goto fail10;

    status = STATUS_UNSUCCESSFUL;
    if (State != XenbusStateConnected)
        goto fail11;

    ThreadWake(Frontend->MibThread);

    Trace("<====\n");
    return STATUS_SUCCESS;

fail11:
    Error("fail11\n");

fail10:
    Error("fail10\n");

fail9:
    Error("fail9\n");

fail8:
    Error("fail8\n");

    NotifierDisconnect(__FrontendGetNotifier(Frontend));

fail7:
    Error("fail7\n");

    TransmitterDisconnect(__FrontendGetTransmitter(Frontend));

fail6:
    Error("fail6\n");

    ReceiverDisconnect(__FrontendGetReceiver(Frontend));

fail5:
    Error("fail5\n");

    MacDisconnect(__FrontendGetMac(Frontend));

fail4:
    Error("fail4\n");

    GranterDisconnect(__FrontendGetGranter(Frontend));

fail3:
    Error("fail3\n");

    XENBUS_DEBUG(Deregister,
                 &Frontend->DebugInterface,
                 Frontend->DebugCallback);
    Frontend->DebugCallback = NULL;

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Frontend->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

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
    GranterDisconnect(__FrontendGetGranter(Frontend));

    XENBUS_DEBUG(Deregister,
                 &Frontend->DebugInterface,
                 Frontend->DebugCallback);
    Frontend->DebugCallback = NULL;

    XENBUS_DEBUG(Release, &Frontend->DebugInterface);

    RtlZeroMemory(&Frontend->Statistic, sizeof (Frontend->Statistic));

    Trace("<====\n");
}

static FORCEINLINE NTSTATUS
__FrontendEnable(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    NTSTATUS                status;

    Trace("====>\n");

    status = GranterEnable(__FrontendGetGranter(Frontend));
    if (!NT_SUCCESS(status))
        goto fail1;

    status = MacEnable(__FrontendGetMac(Frontend));
    if (!NT_SUCCESS(status))
        goto fail2;

    status = ReceiverEnable(__FrontendGetReceiver(Frontend));
    if (!NT_SUCCESS(status))
        goto fail3;

    status = TransmitterEnable(__FrontendGetTransmitter(Frontend));
    if (!NT_SUCCESS(status))
        goto fail4;

    status = NotifierEnable(__FrontendGetNotifier(Frontend));
    if (!NT_SUCCESS(status))
        goto fail5;

    Trace("<====\n");
    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    TransmitterDisable(__FrontendGetTransmitter(Frontend));

fail4:
    Error("fail4\n");

    ReceiverDisable(__FrontendGetReceiver(Frontend));

fail3:
    Error("fail3\n");

    MacDisable(__FrontendGetMac(Frontend));

fail2:
    Error("fail2\n");

    GranterDisable(__FrontendGetGranter(Frontend));

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
    GranterDisable(__FrontendGetGranter(Frontend));

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
                    status = __FrontendClose(Frontend, FALSE);
                    if (NT_SUCCESS(status))
                        Frontend->State = FRONTEND_CLOSED;
                    else
                        Frontend->State = FRONTEND_STATE_INVALID;

                    Failed = TRUE;
                }
                break;

            case FRONTEND_CLOSED:
                status = __FrontendClose(Frontend, FALSE);
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
                    status = __FrontendClose(Frontend, FALSE);
                    if (NT_SUCCESS(status))
                        Frontend->State = FRONTEND_CLOSED;
                    else
                        Frontend->State = FRONTEND_STATE_INVALID;

                    __FrontendDisconnect(Frontend);
                    Failed = TRUE;
                }
                break;

            case FRONTEND_PREPARED:
            case FRONTEND_CLOSED:
                status = __FrontendClose(Frontend, FALSE);
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

    status = XENBUS_SUSPEND(Acquire, &Frontend->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = __FrontendResume(Frontend);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_SUSPEND(Register,
                            &Frontend->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            FrontendSuspendCallbackLate,
                            Frontend,
                            &Frontend->SuspendCallbackLate);
    if (!NT_SUCCESS(status))
        goto fail3;

    KeLowerIrql(Irql);

    Trace("<====\n");

    return STATUS_SUCCESS;
    
fail3:
    Error("fail3\n");

    __FrontendSuspend(Frontend);

fail2:
    Error("fail2\n");

    XENBUS_SUSPEND(Release, &Frontend->SuspendInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    KeLowerIrql(Irql);

    return status;
}

VOID
FrontendSuspend(
    IN  PXENVIF_FRONTEND    Frontend
    )
{
    KIRQL                   Irql;

    Trace("====>\n");

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    XENBUS_SUSPEND(Deregister,
                   &Frontend->SuspendInterface,
                   Frontend->SuspendCallbackLate);
    Frontend->SuspendCallbackLate = NULL;

    __FrontendSuspend(Frontend);

    XENBUS_SUSPEND(Release, &Frontend->SuspendInterface);

    KeLowerIrql(Irql);

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

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

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

    Length = sizeof ("data/vif/") + (ULONG)strlen(Name);
    Prefix = __FrontendAllocate(Length);

    status = STATUS_NO_MEMORY;
    if (Prefix == NULL)
        goto fail3;

    status = RtlStringCbPrintfA(Prefix, 
                                Length,
                                "data/vif/%s", 
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

    FdoGetDebugInterface(PdoGetFdo(Pdo), &(*Frontend)->DebugInterface);
    FdoGetSuspendInterface(PdoGetFdo(Pdo), &(*Frontend)->SuspendInterface);
    FdoGetStoreInterface(PdoGetFdo(Pdo), &(*Frontend)->StoreInterface);

    status = GranterInitialize(*Frontend, &(*Frontend)->Granter);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = NotifierInitialize(*Frontend, &(*Frontend)->Notifier);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = MacInitialize(*Frontend, &(*Frontend)->Mac);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = ReceiverInitialize(*Frontend, 1, &(*Frontend)->Receiver);
    if (!NT_SUCCESS(status))
        goto fail9;

    status = TransmitterInitialize(*Frontend, 1, &(*Frontend)->Transmitter);
    if (!NT_SUCCESS(status))
        goto fail10;

    status = ThreadCreate(FrontendEject, *Frontend, &(*Frontend)->EjectThread);
    if (!NT_SUCCESS(status))
        goto fail11;

    status = ThreadCreate(FrontendMib, *Frontend, &(*Frontend)->MibThread);
    if (!NT_SUCCESS(status))
        goto fail12;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail12:
    Error("fail12\n");

    ThreadAlert((*Frontend)->EjectThread);
    ThreadJoin((*Frontend)->EjectThread);
    (*Frontend)->EjectThread = NULL;

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

    MacTeardown(__FrontendGetMac(*Frontend));
    (*Frontend)->Mac = NULL;

fail8:
    Error("fail8\n");

    NotifierTeardown(__FrontendGetNotifier(*Frontend));
    (*Frontend)->Notifier = NULL;

fail7:
    Error("fail7\n");

    GranterTeardown(__FrontendGetGranter(*Frontend));
    (*Frontend)->Granter = NULL;

    RtlZeroMemory(&(*Frontend)->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&(*Frontend)->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&(*Frontend)->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

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

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    ASSERT(Frontend->State != FRONTEND_ENABLED);
    ASSERT(Frontend->State != FRONTEND_CONNECTED);

    if (Frontend->State == FRONTEND_PREPARED) {
        (VOID) __FrontendClose(Frontend, TRUE);
        Frontend->State = FRONTEND_CLOSED;
    }

    ASSERT(Frontend->State == FRONTEND_CLOSED ||
           Frontend->State == FRONTEND_STATE_INVALID);

    ThreadAlert(Frontend->MibThread);
    ThreadJoin(Frontend->MibThread);
    Frontend->MibThread = NULL;

    ThreadAlert(Frontend->EjectThread);
    ThreadJoin(Frontend->EjectThread);
    Frontend->EjectThread = NULL;

    TransmitterTeardown(__FrontendGetTransmitter(Frontend));
    Frontend->Transmitter = NULL;

    ReceiverTeardown(__FrontendGetReceiver(Frontend));
    Frontend->Receiver = NULL;

    MacTeardown(__FrontendGetMac(Frontend));
    Frontend->Mac = NULL;

    NotifierTeardown(__FrontendGetNotifier(Frontend));
    Frontend->Notifier = NULL;

    GranterTeardown(__FrontendGetGranter(Frontend));
    Frontend->Granter = NULL;

    RtlZeroMemory(&Frontend->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Frontend->SuspendInterface,
                  sizeof (XENBUS_SUSPEND_INTERFACE));

    RtlZeroMemory(&Frontend->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

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
