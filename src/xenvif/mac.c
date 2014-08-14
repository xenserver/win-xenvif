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
#include <ethernet.h>

#include "pdo.h"
#include "frontend.h"
#include "mac.h"
#include "thread.h"
#include "dbg_print.h"
#include "assert.h"

struct _XENVIF_MAC {
    PXENVIF_FRONTEND        Frontend;
    KSPIN_LOCK              Lock;
    BOOLEAN                 Connected;
    BOOLEAN                 Enabled;
    ULONG                   MaximumFrameSize;
    ETHERNET_ADDRESS        PermanentAddress;
    ETHERNET_ADDRESS        CurrentAddress;
    ETHERNET_ADDRESS        BroadcastAddress;
    PETHERNET_ADDRESS       MulticastAddress;
    ULONG                   MulticastAddressCount;
    XENVIF_MAC_FILTER_LEVEL FilterLevel[ETHERNET_ADDRESS_TYPE_COUNT];
    XENBUS_DEBUG_INTERFACE  DebugInterface;
    PXENBUS_DEBUG_CALLBACK  DebugCallback;
    XENBUS_STORE_INTERFACE  StoreInterface;
    PXENBUS_STORE_WATCH     Watch;
};

#define XENVIF_MAC_TAG  'CAM'

static FORCEINLINE PVOID
__MacAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, XENVIF_MAC_TAG);
}

static FORCEINLINE VOID
__MacFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_MAC_TAG);
}

static FORCEINLINE NTSTATUS
__MacSetPermanentAddress(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Mac->Frontend;

    status = STATUS_INVALID_PARAMETER;
    if (Address->Byte[0] & 0x01)
        goto fail1;

    Mac->PermanentAddress = *Address;

    (VOID) XENBUS_STORE(Printf,
                        &Mac->StoreInterface,
                        NULL,
                        FrontendGetPrefix(Frontend),
                        "mac/unicast/permanent",
                        "%02x:%02x:%02x:%02x:%02x:%02x",
                        Mac->PermanentAddress.Byte[0],
                        Mac->PermanentAddress.Byte[1],
                        Mac->PermanentAddress.Byte[2],
                        Mac->PermanentAddress.Byte[3],
                        Mac->PermanentAddress.Byte[4],
                        Mac->PermanentAddress.Byte[5]);

    return STATUS_SUCCESS;

fail1:
    return status;
}

VOID
MacQueryPermanentAddress(
    IN  PXENVIF_MAC         Mac,
    OUT PETHERNET_ADDRESS   Address
    )
{
    *Address = Mac->PermanentAddress;
}

static FORCEINLINE NTSTATUS
__MacSetCurrentAddress(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Mac->Frontend;

    status = STATUS_INVALID_PARAMETER;
    if (Address->Byte[0] & 0x01)
        goto fail1;

    Mac->CurrentAddress = *Address;

    (VOID) XENBUS_STORE(Printf,
                        &Mac->StoreInterface,
                        NULL,
                        FrontendGetPrefix(Frontend),
                        "mac/unicast/current",
                        "%02x:%02x:%02x:%02x:%02x:%02x",
                        Mac->CurrentAddress.Byte[0],
                        Mac->CurrentAddress.Byte[1],
                        Mac->CurrentAddress.Byte[2],
                        Mac->CurrentAddress.Byte[3],
                        Mac->CurrentAddress.Byte[4],
                        Mac->CurrentAddress.Byte[5]);

    return STATUS_SUCCESS;

fail1:
    return status;
}

VOID
MacQueryCurrentAddress(
    IN  PXENVIF_MAC         Mac,
    OUT PETHERNET_ADDRESS   Address
    )
{
    *Address = Mac->CurrentAddress;
}

static VOID
MacDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_MAC         Mac = Argument;
    PXENVIF_FRONTEND    Frontend;

    UNREFERENCED_PARAMETER(Crashing);

    Frontend = Mac->Frontend;

    XENBUS_DEBUG(Printf,
                 &Mac->DebugInterface,
                 "FilterLevel[ETHERNET_ADDRESS_UNICAST] = %s\n",
                 (Mac->FilterLevel[ETHERNET_ADDRESS_UNICAST] == XENVIF_MAC_FILTER_ALL) ? "All" :
                 (Mac->FilterLevel[ETHERNET_ADDRESS_UNICAST] == XENVIF_MAC_FILTER_MATCHING) ? "Matching" :
                 "None");

    XENBUS_DEBUG(Printf,
                 &Mac->DebugInterface,
                 "FilterLevel[ETHERNET_ADDRESS_MULTICAST] = %s\n",
                 (Mac->FilterLevel[ETHERNET_ADDRESS_MULTICAST] == XENVIF_MAC_FILTER_ALL) ? "All" :
                 (Mac->FilterLevel[ETHERNET_ADDRESS_MULTICAST] == XENVIF_MAC_FILTER_MATCHING) ? "Matching" :
                 "None");

    XENBUS_DEBUG(Printf,
                 &Mac->DebugInterface,
                 "FilterLevel[ETHERNET_ADDRESS_BROADCAST] = %s\n",
                 (Mac->FilterLevel[ETHERNET_ADDRESS_BROADCAST] == XENVIF_MAC_FILTER_ALL) ? "All" :
                 (Mac->FilterLevel[ETHERNET_ADDRESS_BROADCAST] == XENVIF_MAC_FILTER_MATCHING) ? "Matching" :
                 "None");
}

NTSTATUS
MacInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_MAC         *Mac
    )
{
    NTSTATUS                status;

    *Mac = __MacAllocate(sizeof (XENVIF_MAC));

    status = STATUS_NO_MEMORY;
    if (*Mac == NULL)
        goto fail1;

    KeInitializeSpinLock(&(*Mac)->Lock);

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Mac)->DebugInterface);

    FdoGetStoreInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Mac)->StoreInterface);

    (*Mac)->Frontend = Frontend;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n");

    return status;
}

NTSTATUS
MacConnect(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;
    PETHERNET_ADDRESS   Address;
    PCHAR               Buffer;
    ULONG64             Mtu;
    NTSTATUS            status;

    Frontend = Mac->Frontend;

    status = XENBUS_DEBUG(Acquire, &Mac->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Acquire, &Mac->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    Address = PdoGetPermanentAddress(FrontendGetPdo(Frontend));

    status = __MacSetPermanentAddress(Mac, Address);
    if (!NT_SUCCESS(status))
        goto fail3;

    Address = PdoGetCurrentAddress(FrontendGetPdo(Frontend));

    status = __MacSetCurrentAddress(Mac, Address);
    if (!NT_SUCCESS(status))
        __MacSetCurrentAddress(Mac, &Mac->PermanentAddress);

    RtlFillMemory(Mac->BroadcastAddress.Byte, ETHERNET_ADDRESS_LENGTH, 0xFF);

    status = XENBUS_STORE(Read,
                          &Mac->StoreInterface,
                          NULL,
                          FrontendGetPath(Frontend),
                          "mtu",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Mtu = ETHERNET_MTU;
    } else {
        Mtu = strtol(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Mac->StoreInterface,
                     Buffer);
    }

    status = STATUS_INVALID_PARAMETER;
    if (Mtu < ETHERNET_MIN)
        goto fail4;

    Mac->MaximumFrameSize = (ULONG)Mtu + sizeof (ETHERNET_TAGGED_HEADER);

    status = XENBUS_DEBUG(Register,
                          &Mac->DebugInterface,
                          __MODULE__ "|MAC",
                          MacDebugCallback,
                          Mac,
                          &Mac->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail5;

    ASSERT(!Mac->Connected);
    Mac->Connected = TRUE;

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    Mac->MaximumFrameSize = 0;

fail4:
    Error("fail4\n");

    RtlZeroMemory(&Mac->BroadcastAddress, sizeof (ETHERNET_ADDRESS));
    RtlZeroMemory(&Mac->CurrentAddress, sizeof (ETHERNET_ADDRESS));
    RtlZeroMemory(&Mac->PermanentAddress, sizeof (ETHERNET_ADDRESS));

    (VOID) XENBUS_STORE(Remove,
                        &Mac->StoreInterface,
                        NULL,
                        FrontendGetPrefix(Frontend),
                        "mac");

fail3:
    Error("fail3\n");

    XENBUS_STORE(Release, &Mac->StoreInterface);

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Mac->DebugInterface);

fail1:
    Error("fail1 (%08x)\n");

    return status;
}

NTSTATUS
MacEnable(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;
    PXENVIF_THREAD      Thread;
    NTSTATUS            status;

    Frontend = Mac->Frontend;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Mac->Lock);

    Thread = VifGetMacThread(PdoGetVifContext(FrontendGetPdo(Frontend)));

    status = XENBUS_STORE(WatchAdd,
                          &Mac->StoreInterface,
                          FrontendGetPath(Frontend),
                          "disconnect",
                          ThreadGetEvent(Thread),
                          &Mac->Watch);
    if (!NT_SUCCESS(status))
        goto fail1;

    ASSERT(!Mac->Enabled);
    Mac->Enabled = TRUE;

    KeReleaseSpinLockFromDpcLevel(&Mac->Lock);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n");

    KeReleaseSpinLockFromDpcLevel(&Mac->Lock);

    return status;
}

VOID
MacDisable(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;

    Frontend = Mac->Frontend;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Mac->Lock);

    ASSERT(Mac->Enabled);
    Mac->Enabled = FALSE;

    (VOID) XENBUS_STORE(WatchRemove,
                        &Mac->StoreInterface,
                        Mac->Watch);
    Mac->Watch = NULL;

    KeReleaseSpinLockFromDpcLevel(&Mac->Lock);
}

VOID
MacDisconnect(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;

    Frontend = Mac->Frontend;

    ASSERT(Mac->Connected);
    Mac->Connected = FALSE;

    XENBUS_DEBUG(Deregister,
                 &Mac->DebugInterface,
                 Mac->DebugCallback);
    Mac->DebugCallback = NULL;

    Mac->MaximumFrameSize = 0;

    RtlZeroMemory(&Mac->BroadcastAddress, sizeof (ETHERNET_ADDRESS));
    RtlZeroMemory(&Mac->CurrentAddress, sizeof (ETHERNET_ADDRESS));
    RtlZeroMemory(&Mac->PermanentAddress, sizeof (ETHERNET_ADDRESS));

    (VOID) XENBUS_STORE(Remove,
                        &Mac->StoreInterface,
                        NULL,
                        FrontendGetPrefix(Frontend),
                        "mac");

    XENBUS_STORE(Release, &Mac->StoreInterface);

    XENBUS_DEBUG(Release, &Mac->DebugInterface);
}

VOID
MacTeardown(
    IN  PXENVIF_MAC Mac
    )
{
    if (Mac->MulticastAddressCount != 0) {
        __MacFree(Mac->MulticastAddress);
        Mac->MulticastAddress = NULL;
        Mac->MulticastAddressCount = 0;
    }

    RtlZeroMemory(&Mac->FilterLevel,
                  ETHERNET_ADDRESS_TYPE_COUNT * sizeof (XENVIF_MAC_FILTER_LEVEL));

    Mac->Frontend = NULL;

    RtlZeroMemory(&Mac->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Mac->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Mac->Lock, sizeof (KSPIN_LOCK));

    ASSERT(IsZeroMemory(Mac, sizeof (XENVIF_MAC)));
    __MacFree(Mac);
}

static FORCEINLINE ULONG
__MacGetSpeed(
    IN  PXENVIF_MAC Mac
    )
{
    PXENVIF_FRONTEND    Frontend;
    PCHAR               Buffer;
    ULONG               Speed;
    NTSTATUS            status;

    Frontend = Mac->Frontend;

    status = XENBUS_STORE(Read,
                          &Mac->StoreInterface,
                          NULL,
                          FrontendGetPath(Mac->Frontend),
                          "speed",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Speed = 1;
    } else {
        Speed = (ULONG)strtol(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Mac->StoreInterface,
                     Buffer);
    }

    return Speed;
}

static FORCEINLINE BOOLEAN
__MacGetDisconnect(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;
    PCHAR               Buffer;
    BOOLEAN             Disconnect;
    NTSTATUS            status;

    Frontend = Mac->Frontend;

    status = XENBUS_STORE(Read,
                          &Mac->StoreInterface,
                          NULL,
                          FrontendGetPath(Mac->Frontend),
                          "disconnect",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Disconnect = FALSE;
    } else {
        Disconnect = (BOOLEAN)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Mac->StoreInterface,
                     Buffer);
    }

    return Disconnect;
}

VOID
MacQueryState(
    IN  PXENVIF_MAC                 Mac,
    OUT PNET_IF_MEDIA_CONNECT_STATE MediaConnectState OPTIONAL,
    OUT PULONG64                    LinkSpeed OPTIONAL,
    OUT PNET_IF_MEDIA_DUPLEX_STATE  MediaDuplexState OPTIONAL
    )
{
    if (MediaConnectState != NULL || MediaDuplexState != NULL) {
        BOOLEAN Disconnect = __MacGetDisconnect(Mac);

        if (MediaConnectState != NULL)
            *MediaConnectState = (Disconnect) ?
                                 MediaConnectStateDisconnected :
                                 MediaConnectStateConnected;

        if (MediaDuplexState != NULL)
            *MediaDuplexState = (Disconnect) ?
                                MediaDuplexStateUnknown :
                                MediaDuplexStateFull;
    }

    if (LinkSpeed != NULL)
        *LinkSpeed = (ULONG64)__MacGetSpeed(Mac) * 1000000000ull;
}

VOID
MacQueryMaximumFrameSize(
    IN  PXENVIF_MAC Mac,
    OUT PULONG      Size                     
    )
{
    *Size = Mac->MaximumFrameSize;
}

NTSTATUS
MacSetMulticastAddresses(
    IN  PXENVIF_MAC         Mac,
    IN  ETHERNET_ADDRESS    Address[],
    IN  ULONG               Count
    )
{
    KIRQL                   Irql;
    PETHERNET_ADDRESS       MulticastAddress;
    ULONG                   Index;
    NTSTATUS                status;

    KeAcquireSpinLock(&Mac->Lock, &Irql);

    status = STATUS_INVALID_PARAMETER;
    for (Index = 0; Index < Count; Index++) {
        if (!(Address[Index].Byte[0] & 0x01))
            goto fail1;
    }

    if (Count != 0) {
        MulticastAddress = __MacAllocate(sizeof (ETHERNET_ADDRESS) * Count);

        status = STATUS_NO_MEMORY;
        if (MulticastAddress == NULL)
            goto fail2;

        for (Index = 0; Index < Count; Index++)
            MulticastAddress[Index] = Address[Index];
    } else {
        MulticastAddress = NULL;
    }

    if (Mac->MulticastAddressCount != 0)
        __MacFree(Mac->MulticastAddress);

    Mac->MulticastAddress = MulticastAddress;
    Mac->MulticastAddressCount = Count;

    KeReleaseSpinLock(&Mac->Lock, Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Mac->Lock, Irql);

    return status;
}

NTSTATUS
MacQueryMulticastAddresses(
    IN      PXENVIF_MAC         Mac,
    IN      PETHERNET_ADDRESS   Address,
    IN OUT  PULONG              Count
    )
{
    KIRQL                       Irql;
    ULONG                       Index;
    NTSTATUS                    status;

    KeAcquireSpinLock(&Mac->Lock, &Irql);

    status = STATUS_BUFFER_OVERFLOW;
    if (*Count < Mac->MulticastAddressCount)
        goto fail1;

    for (Index = 0; Index < Mac->MulticastAddressCount; Index++)
        Address[Index] = Mac->MulticastAddress[Index];

    *Count = Mac->MulticastAddressCount;

    KeReleaseSpinLock(&Mac->Lock, Irql);

    return STATUS_SUCCESS;

fail1:
    *Count = Mac->MulticastAddressCount;

    KeReleaseSpinLock(&Mac->Lock, Irql);

    return status;
}

VOID
MacQueryBroadcastAddress(
    IN  PXENVIF_MAC         Mac,
    OUT PETHERNET_ADDRESS   Address
    )
{
    *Address = Mac->BroadcastAddress;
}

NTSTATUS
MacSetFilterLevel(
    IN  PXENVIF_MAC             Mac,
    IN  ETHERNET_ADDRESS_TYPE   Type,
    IN  XENVIF_MAC_FILTER_LEVEL Level
    )
{
    KIRQL                       Irql;
    NTSTATUS                    status;

    status = STATUS_INVALID_PARAMETER;
    if (Type >= ETHERNET_ADDRESS_TYPE_COUNT)
        goto fail1;

    KeAcquireSpinLock(&Mac->Lock, &Irql);

    status = STATUS_INVALID_PARAMETER;
    if (Level > XENVIF_MAC_FILTER_ALL || Level < XENVIF_MAC_FILTER_NONE)
        goto fail2;

    Mac->FilterLevel[Type] = Level;
    KeReleaseSpinLock(&Mac->Lock, Irql);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    KeReleaseSpinLock(&Mac->Lock, Irql);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
MacQueryFilterLevel(
    IN  PXENVIF_MAC                 Mac,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    OUT PXENVIF_MAC_FILTER_LEVEL    Level
    )
{
    NTSTATUS                        status;

    status = STATUS_INVALID_PARAMETER;
    if (Type >= ETHERNET_ADDRESS_TYPE_COUNT)
        goto fail1;

    *Level = Mac->FilterLevel[Type];

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

BOOLEAN
MacApplyFilters(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   DestinationAddress
    )
{
    ETHERNET_ADDRESS_TYPE   Type;
    BOOLEAN                 Allow;

    Type = GET_ETHERNET_ADDRESS_TYPE(DestinationAddress);
    Allow = FALSE;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Mac->Lock);

    switch (Type) {
    case ETHERNET_ADDRESS_UNICAST:
        switch (Mac->FilterLevel[ETHERNET_ADDRESS_UNICAST]) {
        case XENVIF_MAC_FILTER_NONE:
            break;

        case XENVIF_MAC_FILTER_MATCHING:
            if (RtlEqualMemory(&Mac->CurrentAddress,
                               DestinationAddress,
                               ETHERNET_ADDRESS_LENGTH))
                Allow = TRUE;

            break;

        case XENVIF_MAC_FILTER_ALL:
            Allow = TRUE;
            break;

        default:
            ASSERT(FALSE);
            break;
        }
        break;

    case ETHERNET_ADDRESS_MULTICAST:
        switch (Mac->FilterLevel[ETHERNET_ADDRESS_MULTICAST]) {
        case XENVIF_MAC_FILTER_NONE:
            break;

        case XENVIF_MAC_FILTER_MATCHING: {
            ULONG Index;

            for (Index = 0; Index < Mac->MulticastAddressCount; Index++) {
                if (RtlEqualMemory(&Mac->MulticastAddress[Index],
                                   DestinationAddress,
                                   ETHERNET_ADDRESS_LENGTH))
                    Allow = TRUE;
            }
            break;
        }

        case XENVIF_MAC_FILTER_ALL:
            Allow = TRUE;
            break;

        default:
            ASSERT(FALSE);
            break;
        }
        break;

    case ETHERNET_ADDRESS_BROADCAST:
        switch (Mac->FilterLevel[ETHERNET_ADDRESS_BROADCAST]) {
        case XENVIF_MAC_FILTER_NONE:
            break;

        case XENVIF_MAC_FILTER_MATCHING:
        case XENVIF_MAC_FILTER_ALL:
            Allow = TRUE;
            break;

        default:
            ASSERT(FALSE);
            break;
        }
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    KeReleaseSpinLockFromDpcLevel(&Mac->Lock);

    return Allow;
}
