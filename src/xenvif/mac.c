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
#include <store_interface.h>

#include "pdo.h"
#include "frontend.h"
#include "mac.h"
#include "thread.h"
#include "log.h"
#include "assert.h"

struct _XENVIF_MAC {
    PXENVIF_FRONTEND            Frontend;
    KSPIN_LOCK                  Lock;
    BOOLEAN                     Connected;
    BOOLEAN                     Enabled;
    KEVENT                      Event;
    ULONG                       MaximumFrameSize;
    ETHERNET_ADDRESS            PermanentAddress;
    ETHERNET_ADDRESS            CurrentAddress;
    ETHERNET_ADDRESS            BroadcastAddress;
    ETHERNET_ADDRESS            MulticastAddress[MAXIMUM_MULTICAST_ADDRESS_COUNT];
    ULONG                       MulticastAddressCount;
    XENVIF_MAC_FILTER_LEVEL     FilterLevel[ETHERNET_ADDRESS_TYPE_COUNT];

    PXENBUS_STORE_INTERFACE     StoreInterface;
    PXENBUS_DEBUG_INTERFACE     DebugInterface;

    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    PXENBUS_STORE_WATCH         Watch;
};

#define MAC_POOL    'CAM'

static FORCEINLINE PVOID
__MacAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, MAC_POOL);
}

static FORCEINLINE VOID
__MacFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, MAC_POOL);
}

static FORCEINLINE NTSTATUS
__MacParseNetworkAddress(
    IN  PCHAR               Buffer,
    OUT PETHERNET_ADDRESS   Address
    )
{
    ULONG                   Length;
    NTSTATUS                status;

    Length = 0;
    for (;;) {
        CHAR    Character;
        UCHAR   Byte;

        Character = *Buffer++;
        if (Character == '\0')
            break;

        if (Character >= '0' && Character <= '9')
            Byte = Character - '0';
        else if (Character >= 'A' && Character <= 'F')
            Byte = 0x0A + Character - 'A';
        else if (Character >= 'a' && Character <= 'f')
            Byte = 0x0A + Character - 'a';
        else
            break;

        Byte <<= 4;

        Character = *Buffer++;
        if (Character == '\0')
            break;

        if (Character >= '0' && Character <= '9')
            Byte += Character - '0';
        else if (Character >= 'A' && Character <= 'F')
            Byte += 0x0A + Character - 'A';
        else if (Character >= 'a' && Character <= 'f')
            Byte += 0x0A + Character - 'a';
        else
            break;

        Address->Byte[Length++] = Byte;

        // Skip over any separator
        if (*Buffer == ':' || *Buffer == '-')
            Buffer++;
    }

    status = STATUS_INVALID_PARAMETER;
    if (Length != ETHERNET_ADDRESS_LENGTH)
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE VOID
__MacSetPermanentAddress(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND        Frontend;

    ASSERT(!(Address->Byte[0] & 0x01));

    Frontend = Mac->Frontend;

    Mac->PermanentAddress = *Address;

    STORE(Printf,
          Mac->StoreInterface,
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
}

static FORCEINLINE PETHERNET_ADDRESS
__MacGetPermanentAddress(
    IN  PXENVIF_MAC         Mac
    )
{
    return &Mac->PermanentAddress;
}

PETHERNET_ADDRESS
MacGetPermanentAddress(
    IN  PXENVIF_MAC         Mac
    )
{
    return __MacGetPermanentAddress(Mac);
}

static FORCEINLINE VOID
__MacSetCurrentAddress(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND        Frontend;

    ASSERT(!(Address->Byte[0] & 0x01));

    Frontend = Mac->Frontend;

    Mac->CurrentAddress = *Address;

    STORE(Printf,
          Mac->StoreInterface,
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
}

static FORCEINLINE PETHERNET_ADDRESS
__MacGetCurrentAddress(
    IN  PXENVIF_MAC         Mac
    )
{
    return &Mac->CurrentAddress;
}

PETHERNET_ADDRESS
MacGetCurrentAddress(
    IN  PXENVIF_MAC         Mac
    )
{
    return __MacGetCurrentAddress(Mac);
}

static VOID
MacDebugCallback(
    IN  PVOID   Argument,
    IN  BOOLEAN Crashing
    )
{
    PXENVIF_MAC Mac = Argument;
    ULONG       Index;

    UNREFERENCED_PARAMETER(Crashing);

    DEBUG(Printf,
          Mac->DebugInterface,
          Mac->DebugCallback,
          "MaximumFrameSize = %u\n",
          Mac->MaximumFrameSize);

    DEBUG(Printf,
          Mac->DebugInterface,
          Mac->DebugCallback,
          "PermanentAddress = %02x:%02x:%02x:%02x:%02x:%02x\n",
          Mac->PermanentAddress.Byte[0],
          Mac->PermanentAddress.Byte[1],
          Mac->PermanentAddress.Byte[2],
          Mac->PermanentAddress.Byte[3],
          Mac->PermanentAddress.Byte[4],
          Mac->PermanentAddress.Byte[5]);

    DEBUG(Printf,
          Mac->DebugInterface,
          Mac->DebugCallback,
          "CurrentAddress = %02x:%02x:%02x:%02x:%02x:%02x\n",
          Mac->CurrentAddress.Byte[0],
          Mac->CurrentAddress.Byte[1],
          Mac->CurrentAddress.Byte[2],
          Mac->CurrentAddress.Byte[3],
          Mac->CurrentAddress.Byte[4],
          Mac->CurrentAddress.Byte[5]);

    for (Index = 0; Index < Mac->MulticastAddressCount; Index++)
        DEBUG(Printf,
              Mac->DebugInterface,
              Mac->DebugCallback,
              "MulticastAddress[%u] = %02x:%02x:%02x:%02x:%02x:%02x\n",
              Index,
              Mac->MulticastAddress[Index].Byte[0],
              Mac->MulticastAddress[Index].Byte[1],
              Mac->MulticastAddress[Index].Byte[2],
              Mac->MulticastAddress[Index].Byte[3],
              Mac->MulticastAddress[Index].Byte[4],
              Mac->MulticastAddress[Index].Byte[5]);

    DEBUG(Printf,
          Mac->DebugInterface,
          Mac->DebugCallback,
          "FilterLevel[ETHERNET_ADDRESS_UNICAST] = %s\n",
          (Mac->FilterLevel[ETHERNET_ADDRESS_UNICAST] == MAC_FILTER_ALL) ? "All" :
          (Mac->FilterLevel[ETHERNET_ADDRESS_UNICAST] == MAC_FILTER_MATCHING) ? "Matching" :
          "None");

    DEBUG(Printf,
          Mac->DebugInterface,
          Mac->DebugCallback,
          "FilterLevel[ETHERNET_ADDRESS_MULTICAST] = %s\n",
          (Mac->FilterLevel[ETHERNET_ADDRESS_MULTICAST] == MAC_FILTER_ALL) ? "All" :
          (Mac->FilterLevel[ETHERNET_ADDRESS_MULTICAST] == MAC_FILTER_MATCHING) ? "Matching" :
          "None");

    DEBUG(Printf,
          Mac->DebugInterface,
          Mac->DebugCallback,
          "FilterLevel[ETHERNET_ADDRESS_BROADCAST] = %s\n",
          (Mac->FilterLevel[ETHERNET_ADDRESS_BROADCAST] == MAC_FILTER_ALL) ? "All" :
          (Mac->FilterLevel[ETHERNET_ADDRESS_BROADCAST] == MAC_FILTER_MATCHING) ? "Matching" :
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

    (*Mac)->Frontend = Frontend;

    KeInitializeSpinLock(&(*Mac)->Lock);
    KeInitializeEvent(&(*Mac)->Event, NotificationEvent, FALSE);

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
    PCHAR               Buffer;
    ULONG64             Mtu;
    ETHERNET_ADDRESS    Address;
    NTSTATUS            status;

    Frontend = Mac->Frontend;

    Mac->StoreInterface = FrontendGetStoreInterface(Frontend);

    STORE(Acquire, Mac->StoreInterface);

    status = STORE(Read,
                   Mac->StoreInterface,
                   NULL,
                   FrontendGetPath(Frontend),
                   "mtu",
                   &Buffer);
    if (!NT_SUCCESS(status)) {
        Mtu = ETHERNET_MTU;
    } else {
        Mtu = strtol(Buffer, NULL, 10);

        STORE(Free,
              Mac->StoreInterface,
              Buffer);

        Buffer = NULL;
    }

    status = STATUS_INVALID_PARAMETER;
    if (Mtu < ETHERNET_MIN)
        goto fail1;

    Mac->MaximumFrameSize = (ULONG)Mtu + sizeof (ETHERNET_UNTAGGED_HEADER);

    status = STORE(Read,
                   Mac->StoreInterface,
                   NULL,
                   FrontendGetPath(Frontend),
                   "mac",
                   &Buffer);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = __MacParseNetworkAddress(Buffer, &Address);
    if (!NT_SUCCESS(status))
        goto fail3;

    STORE(Free,
          Mac->StoreInterface,
          Buffer);

    Buffer = NULL;

    __MacSetPermanentAddress(Mac, &Address);

    Buffer = FrontendGetAddress(Frontend);
    if (Buffer != NULL) {
        status = __MacParseNetworkAddress(Buffer, &Address);
        if (!NT_SUCCESS(status))
            goto fail4;

        if (Address.Byte[0] & 0x01)
            Address = *__MacGetPermanentAddress(Mac);
    } else {
        Address = *__MacGetPermanentAddress(Mac);
    }

    __MacSetCurrentAddress(Mac, &Address);

    RtlFillMemory(Mac->BroadcastAddress.Byte, ETHERNET_ADDRESS_LENGTH, 0xFF);

    Mac->DebugInterface = FrontendGetDebugInterface(Frontend);

    DEBUG(Acquire, Mac->DebugInterface);

    status = DEBUG(Register,
                   Mac->DebugInterface,
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

    DEBUG(Release, Mac->DebugInterface);
    Mac->DebugInterface = NULL;

    RtlZeroMemory(Mac->BroadcastAddress.Byte, ETHERNET_ADDRESS_LENGTH);
    RtlZeroMemory(Mac->CurrentAddress.Byte, ETHERNET_ADDRESS_LENGTH);

fail4:
    Error("fail4\n");

    Buffer = NULL;

    RtlZeroMemory(Mac->PermanentAddress.Byte, ETHERNET_ADDRESS_LENGTH);

fail3:
    Error("fail3\n");

    if (Buffer != NULL) {
        STORE(Free,
              Mac->StoreInterface,
              Buffer);

        Buffer = NULL;
    }

fail2:
    Error("fail2\n");

    Mac->MaximumFrameSize = 0;

fail1:
    Error("fail1 (%08x)\n");

    STORE(Release, Mac->StoreInterface);
    Mac->StoreInterface = 0;

    return status;
}

NTSTATUS
MacEnable(
    IN  PXENVIF_MAC     Mac
    )
{
    PXENVIF_FRONTEND    Frontend;
    NTSTATUS            status;

    Frontend = Mac->Frontend;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Mac->Lock);

    status = STORE(Watch,
                   Mac->StoreInterface,
                   FrontendGetPath(Frontend),
                   "disconnect",
                   &Mac->Event,
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
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Mac->Lock);

    ASSERT(Mac->Enabled);
    Mac->Enabled = FALSE;

    (VOID) STORE(Unwatch,
                 Mac->StoreInterface,
                 Mac->Watch);
    Mac->Watch = NULL;

    KeReleaseSpinLockFromDpcLevel(&Mac->Lock);
}

VOID
MacDisconnect(
    IN  PXENVIF_MAC     Mac
    )
{
    ASSERT(Mac->Connected);
    Mac->Connected = FALSE;

    DEBUG(Deregister,
          Mac->DebugInterface,
          Mac->DebugCallback);
    Mac->DebugCallback = NULL;

    DEBUG(Release, Mac->DebugInterface);
    Mac->DebugInterface = NULL;

    RtlZeroMemory(Mac->BroadcastAddress.Byte, ETHERNET_ADDRESS_LENGTH);
    RtlZeroMemory(Mac->CurrentAddress.Byte, ETHERNET_ADDRESS_LENGTH);
    RtlZeroMemory(Mac->PermanentAddress.Byte, ETHERNET_ADDRESS_LENGTH);

    Mac->MaximumFrameSize = 0;

    STORE(Release, Mac->StoreInterface);
    Mac->StoreInterface = 0;
}

VOID
MacTeardown(
    IN  PXENVIF_MAC     Mac
    )
{
    RtlZeroMemory(Mac->MulticastAddress,
                  MAXIMUM_MULTICAST_ADDRESS_COUNT * sizeof (ETHERNET_ADDRESS));
    Mac->MulticastAddressCount = 0;

    RtlZeroMemory(&Mac->FilterLevel,
                  ETHERNET_ADDRESS_TYPE_COUNT * sizeof (XENVIF_MAC_FILTER_LEVEL));

    RtlZeroMemory(&Mac->Event, sizeof (KEVENT));
    RtlZeroMemory(&Mac->Lock, sizeof (KSPIN_LOCK));

    Mac->Frontend = NULL;

    ASSERT(IsZeroMemory(Mac, sizeof (XENVIF_MAC)));
    __MacFree(Mac);
}

ULONG
MacGetLinkSpeed(
    IN  PXENVIF_MAC     Mac
    )
{
    PCHAR               Buffer;
    ULONG               Speed;
    NTSTATUS            status;

    status = STORE(Read,
                   Mac->StoreInterface,
                   NULL,
                   FrontendGetPath(Mac->Frontend),
                   "speed",
                   &Buffer);
    if (!NT_SUCCESS(status)) {
        Speed = 1;
    } else {
        Speed = (ULONG)strtol(Buffer, NULL, 10);

        STORE(Free,
              Mac->StoreInterface,
              Buffer);
    }

    return Speed;
}

PKEVENT
MacGetEvent(
    IN  PXENVIF_MAC     Mac
    )
{
    return &Mac->Event;
}

BOOLEAN
MacGetLinkState(
    IN  PXENVIF_MAC     Mac
    )
{
    PCHAR               Buffer;
    BOOLEAN             Disconnect;
    NTSTATUS            status;

    status = STORE(Read,
                   Mac->StoreInterface,
                   NULL,
                   FrontendGetPath(Mac->Frontend),
                   "disconnect",
                   &Buffer);
    if (!NT_SUCCESS(status)) {
        Disconnect = FALSE;
    } else {
        Disconnect = (BOOLEAN)strtol(Buffer, NULL, 2);

        STORE(Free,
              Mac->StoreInterface,
              Buffer);
    }

    return !Disconnect;
}

ULONG
MacGetMaximumFrameSize(
    IN  PXENVIF_MAC Mac
    )
{
    return Mac->MaximumFrameSize;
}

NTSTATUS
MacSetCurrentAddress(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   Address
    )
{
    PXENVIF_FRONTEND        Frontend;
    KIRQL                   Irql;
    NTSTATUS                status;

    Frontend = Mac->Frontend;

    KeAcquireSpinLock(&Mac->Lock, &Irql);

    status = STATUS_INVALID_PARAMETER;
    if (Address->Byte[0] & 0x01)
        goto fail1;

    __MacSetCurrentAddress(Mac, Address);

    KeReleaseSpinLock(&Mac->Lock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Mac->Lock, Irql);

    return status;
}

NTSTATUS
MacSetMulticastAddresses(
    IN  PXENVIF_MAC         Mac,
    IN  ETHERNET_ADDRESS    Address[],
    IN  ULONG               Count
    )
{
    KIRQL                   Irql;
    ULONG                   Index;
    NTSTATUS                status;

    KeAcquireSpinLock(&Mac->Lock, &Irql);

    status = STATUS_BUFFER_OVERFLOW;
    if (Count > MAXIMUM_MULTICAST_ADDRESS_COUNT)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        if (!(Address[Index].Byte[0] & 0x01))
            goto fail2;
    }

    for (Index = 0; Index < Count; Index++)
        Mac->MulticastAddress[Index] = Address[Index];

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

PETHERNET_ADDRESS
MacGetMulticastAddresses(
    IN      PXENVIF_MAC         Mac,
    IN OUT  PULONG              Count
    )
{
    *Count = Mac->MulticastAddressCount;

    return Mac->MulticastAddress;
}

PETHERNET_ADDRESS
MacGetBroadcastAddress(
    IN  PXENVIF_MAC         Mac
    )
{
    return &Mac->BroadcastAddress;
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

    ASSERT3U(Type, <, ETHERNET_ADDRESS_TYPE_COUNT);

    KeAcquireSpinLock(&Mac->Lock, &Irql);

    status = STATUS_INVALID_PARAMETER;
    if (Level > MAC_FILTER_ALL || Level < MAC_FILTER_NONE)
        goto fail1;

    Mac->FilterLevel[Type] = Level;
    KeReleaseSpinLock(&Mac->Lock, Irql);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    KeReleaseSpinLock(&Mac->Lock, Irql);

    return status;
}

XENVIF_MAC_FILTER_LEVEL
MacGetFilterLevel(
    IN  PXENVIF_MAC             Mac,
    IN  ETHERNET_ADDRESS_TYPE   Type
    )
{
    ASSERT3U(Type, <, ETHERNET_ADDRESS_TYPE_COUNT);

    return Mac->FilterLevel[Type];
}

BOOLEAN
MacApplyFilters(
    IN  PXENVIF_MAC             Mac,
    IN  PETHERNET_ADDRESS       DestinationAddress
    )
{
    ETHERNET_ADDRESS_TYPE       Type;
    BOOLEAN                     Allow;

    Type = GET_ETHERNET_ADDRESS_TYPE(DestinationAddress);
    Allow = FALSE;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&Mac->Lock);

    switch (Type) {
    case ETHERNET_ADDRESS_UNICAST:
        switch (Mac->FilterLevel[ETHERNET_ADDRESS_UNICAST]) {
        case MAC_FILTER_NONE:
            break;

        case MAC_FILTER_MATCHING:
            if (RtlEqualMemory(&Mac->CurrentAddress,
                               DestinationAddress,
                               ETHERNET_ADDRESS_LENGTH))
                Allow = TRUE;

            break;

        case MAC_FILTER_ALL:
            Allow = TRUE;
            break;

        default:
            ASSERT(FALSE);
            break;
        }
        break;

    case ETHERNET_ADDRESS_MULTICAST:
        switch (Mac->FilterLevel[ETHERNET_ADDRESS_MULTICAST]) {
        case MAC_FILTER_NONE:
            break;

        case MAC_FILTER_MATCHING: {
            ULONG Index;

            for (Index = 0; Index < Mac->MulticastAddressCount; Index++) {
                if (RtlEqualMemory(&Mac->MulticastAddress[Index],
                                   DestinationAddress,
                                   ETHERNET_ADDRESS_LENGTH))
                    Allow = TRUE;
            }
            break;
        }

        case MAC_FILTER_ALL:
            Allow = TRUE;
            break;

        default:
            ASSERT(FALSE);
            break;
        }
        break;

    case ETHERNET_ADDRESS_BROADCAST:
        switch (Mac->FilterLevel[ETHERNET_ADDRESS_BROADCAST]) {
        case MAC_FILTER_NONE:
            break;

        case MAC_FILTER_MATCHING:
        case MAC_FILTER_ALL:
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
