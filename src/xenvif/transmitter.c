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
#include <debug_interface.h>
#include <store_interface.h>
#include <cache_interface.h>
#include <gnttab_interface.h>
#include <range_set_interface.h>

#include "ethernet.h"
#include "tcpip.h"
#include "pdo.h"
#include "frontend.h"
#include "checksum.h"
#include "parse.h"
#include "transmitter.h"
#include "granter.h"
#include "mac.h"
#include "vif.h"
#include "thread.h"
#include "registry.h"
#include "dbg_print.h"
#include "assert.h"

#ifndef XEN_NETIF_GSO_TYPE_TCPV6
#define XEN_NETIF_GSO_TYPE_TCPV6    2
#endif

#define MAXNAMELEN  128

typedef struct _XENVIF_TRANSMITTER_BUFFER {
    PMDL        Mdl;
    PVOID       Context;
    ULONG       Reference;
} XENVIF_TRANSMITTER_BUFFER, *PXENVIF_TRANSMITTER_BUFFER;

typedef enum _XENVIF_TRANSMITTER_FRAGMENT_TYPE {
    XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID = 0,
    XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET,
    XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER
} XENVIF_TRANSMITTER_FRAGMENT_TYPE, *PXENVIF_TRANSMITTER_FRAGMENT_TYPE;

typedef struct _XENVIF_TRANSMITTER_FRAGMENT {
    LIST_ENTRY                          ListEntry;
    USHORT                              Id;
    XENVIF_TRANSMITTER_FRAGMENT_TYPE    Type;
    PVOID                               Context;
    XENVIF_GRANTER_HANDLE               Handle;
    ULONG                               Offset;
    ULONG                               Length;
    BOOLEAN                             Extra;
} XENVIF_TRANSMITTER_FRAGMENT, *PXENVIF_TRANSMITTER_FRAGMENT;

#define XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID  0x03FF

typedef struct _XENVIF_TRANSMITTER_STATE {
    PXENVIF_TRANSMITTER_PACKET          Packet;
    XENVIF_TRANSMITTER_PACKET_SEND_INFO Send;
    PUCHAR                              StartVa;
    XENVIF_PACKET_INFO                  Info;
    XENVIF_PACKET_PAYLOAD               Payload;
    LIST_ENTRY                          List;
    ULONG                               Count;
} XENVIF_TRANSMITTER_STATE, *PXENVIF_TRANSMITTER_STATE;

#define XENVIF_TRANSMITTER_RING_SIZE   (__CONST_RING_SIZE(netif_tx, PAGE_SIZE))

typedef struct _XENVIF_TRANSMITTER_PACKET_LIST {
    PXENVIF_TRANSMITTER_PACKET  HeadPacket;
    PXENVIF_TRANSMITTER_PACKET  *TailPacket;
} XENVIF_TRANSMITTER_PACKET_LIST, *PXENVIF_TRANSMITTER_PACKET_LIST;

typedef struct _XENVIF_TRANSMITTER_RING {
    PXENVIF_TRANSMITTER             Transmitter;
    LIST_ENTRY                      ListEntry;
    ULONG                           Index;
    PXENBUS_CACHE                   BufferCache;
    PXENBUS_CACHE                   FragmentCache;
    PXENBUS_RANGE_SET               RangeSet;
    PMDL                            Mdl;
    netif_tx_front_ring_t           Front;
    netif_tx_sring_t                *Shared;
    XENVIF_GRANTER_HANDLE           Handle;
    BOOLEAN                         Connected;
    BOOLEAN                         Enabled;
    BOOLEAN                         Stopped;
    PXENVIF_TRANSMITTER_PACKET      Lock;
    PKTHREAD                        LockThread;
    XENVIF_TRANSMITTER_PACKET_LIST  Queued;
    XENVIF_TRANSMITTER_STATE        State;
    ULONG                           PacketsQueued;
    ULONG                           PacketsGranted;
    ULONG                           PacketsCopied;
    ULONG                           PacketsFaked;
    ULONG                           PacketsUnprepared;
    ULONG                           PacketsPrepared;
    PXENVIF_TRANSMITTER_FRAGMENT    Pending[XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID + 1];
    ULONG                           RequestsPosted;
    ULONG                           RequestsPushed;
    ULONG                           ResponsesProcessed;
    ULONG                           PacketsSent;
    XENVIF_TRANSMITTER_PACKET_LIST  Completed;
    ULONG                           PacketsCompleted;
    PSOCKADDR_INET                  AddressTable;
    ULONG                           AddressCount;
    ULONG                           AddressIndex;
    PXENBUS_DEBUG_CALLBACK          DebugCallback;
    PXENVIF_THREAD                  WatchdogThread;
} XENVIF_TRANSMITTER_RING, *PXENVIF_TRANSMITTER_RING;

struct _XENVIF_TRANSMITTER {
    PXENVIF_FRONTEND            Frontend;
    XENBUS_CACHE_INTERFACE      CacheInterface;
    XENBUS_RANGE_SET_INTERFACE  RangeSetInterface;
    LIST_ENTRY                  List;
    LONG_PTR                    Offset[XENVIF_TRANSMITTER_PACKET_OFFSET_COUNT];
    ULONG                       DisableIpVersion4Gso;
    ULONG                       DisableIpVersion6Gso;
    ULONG                       AlwaysCopy;
    XENBUS_STORE_INTERFACE      StoreInterface;
    XENBUS_DEBUG_INTERFACE      DebugInterface;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
};

#define XENVIF_TRANSMITTER_TAG  'NART'

static FORCEINLINE PVOID
__TransmitterAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, XENVIF_TRANSMITTER_TAG);
}

static FORCEINLINE VOID
__TransmitterFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, XENVIF_TRANSMITTER_TAG);
}

static NTSTATUS
TransmitterBufferCtor(
    IN  PVOID                   Argument,
    IN  PVOID                   Object
    )
{
    PXENVIF_TRANSMITTER_BUFFER  Buffer = Object;
    PMDL		                Mdl;
    PUCHAR		                MdlMappedSystemVa;
    NTSTATUS	                status;

    UNREFERENCED_PARAMETER(Argument);

    ASSERT(IsZeroMemory(Buffer, sizeof (XENVIF_TRANSMITTER_BUFFER)));

    Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Mdl == NULL)
	goto fail1;

    MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(MdlMappedSystemVa != NULL);
    RtlFillMemory(MdlMappedSystemVa, PAGE_SIZE, 0xAA);

    Mdl->ByteCount = 0;
    Buffer->Mdl = Mdl;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(Buffer, sizeof (XENVIF_TRANSMITTER_BUFFER)));

    return status;
}

static VOID
TransmitterBufferDtor(
    IN  PVOID                   Argument,
    IN  PVOID                   Object
    )
{
    PXENVIF_TRANSMITTER_BUFFER  Buffer = Object;
    PMDL                        Mdl;

    UNREFERENCED_PARAMETER(Argument);

    Mdl = Buffer->Mdl;
    Buffer->Mdl = NULL;

    Mdl->ByteCount = PAGE_SIZE;

    __FreePage(Mdl);
    ExFreePool(Mdl);

    ASSERT(IsZeroMemory(Buffer, sizeof (XENVIF_TRANSMITTER_BUFFER)));
}

static FORCEINLINE PXENVIF_TRANSMITTER_BUFFER
__TransmitterGetBuffer(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Buffer = XENBUS_CACHE(Get,
                          &Transmitter->CacheInterface,
                          Ring->BufferCache,
                          TRUE);

    ASSERT(IMPLY(Buffer != NULL, Buffer->Mdl->ByteCount == 0));

    return Buffer;
}

static FORCEINLINE VOID
__TransmitterPutBuffer(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_BUFFER  Buffer
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT3U(Buffer->Reference, ==, 0);
    ASSERT3P(Buffer->Context, ==, NULL);

    Buffer->Mdl->ByteCount = 0;

    XENBUS_CACHE(Put,
                 &Transmitter->CacheInterface,
                 Ring->BufferCache,
                 Buffer,
                 TRUE);
}

static NTSTATUS
TransmitterFragmentCtor(
    IN  PVOID                       Argument,
    IN  PVOID                       Object
    )
{
    PXENVIF_TRANSMITTER_RING        Ring = Argument;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment = Object;
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    LONGLONG                        Id;
    NTSTATUS	                    status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_TRANSMITTER_FRAGMENT)));

    status = XENBUS_RANGE_SET(Pop,
                              &Transmitter->RangeSetInterface,
                              Ring->RangeSet,
                              1,
                              &Id);
    if (!NT_SUCCESS(status))
        goto fail1;

    Fragment->Id = (USHORT)Id;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_TRANSMITTER_FRAGMENT)));

    return status;
}

static VOID
TransmitterFragmentDtor(
    IN  PVOID                       Argument,
    IN  PVOID                       Object
    )
{
    PXENVIF_TRANSMITTER_RING        Ring = Argument;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment = Object;
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    LONGLONG                        Id;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Id = Fragment->Id;
    Fragment->Id = 0;

    XENBUS_RANGE_SET(Put,
                     &Transmitter->RangeSetInterface,
                     Ring->RangeSet,
                     Id,
                     1);

    ASSERT(IsZeroMemory(Fragment, sizeof (XENVIF_TRANSMITTER_FRAGMENT)));
}

static FORCEINLINE PXENVIF_TRANSMITTER_FRAGMENT
__TransmitterGetFragment(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    return XENBUS_CACHE(Get,
                        &Transmitter->CacheInterface,
                        Ring->FragmentCache,
                        TRUE);
}

static FORCEINLINE
__TransmitterPutFragment(
    IN  PXENVIF_TRANSMITTER_RING        Ring,
    IN  PXENVIF_TRANSMITTER_FRAGMENT    Fragment
    )
{
    PXENVIF_TRANSMITTER                 Transmitter;
    PXENVIF_FRONTEND                    Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT3U(Fragment->Length, ==, 0);
    ASSERT3U(Fragment->Offset, ==, 0);
    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID);
    ASSERT3P(Fragment->Context, ==, NULL);
    ASSERT(!Fragment->Extra);

    XENBUS_CACHE(Put,
                 &Transmitter->CacheInterface,
                 Ring->FragmentCache,
                 Fragment,
                 TRUE);
}

static VOID
TransmitterRingDebugCallback(
    IN  PVOID                   Argument,
    IN  BOOLEAN                 Crashing
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Argument;
    PXENVIF_TRANSMITTER         Transmitter;

    UNREFERENCED_PARAMETER(Crashing);

    Transmitter = Ring->Transmitter;

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "0x%p [%s]\n",
                 Ring,
                 (Ring->Enabled) ? "ENABLED" : "DISABLED");

    // Dump front ring
    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "FRONT: req_prod_pvt = %u rsp_cons = %u nr_ents = %u sring = %p\n",
                 Ring->Front.req_prod_pvt,
                 Ring->Front.rsp_cons,
                 Ring->Front.nr_ents,
                 Ring->Front.sring);

    // Dump shared ring
    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
                 Ring->Shared->req_prod,
                 Ring->Shared->req_event,
                 Ring->Shared->rsp_prod,
                 Ring->Shared->rsp_event);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "RequestsPosted = %u RequestsPushed = %u ResponsesProcessed = %u\n",
                 Ring->RequestsPosted,
                 Ring->RequestsPushed,
                 Ring->ResponsesProcessed);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "State:\n");

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "- Packet = %p\n",
                 Ring->State.Packet);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "- Count = %u\n",
                 Ring->State.Count);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "PacketsGranted = %u PacketsCopied = %u PacketsFaked = %u\n",
                 Ring->PacketsGranted,
                 Ring->PacketsCopied,
                 Ring->PacketsFaked);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "PacketsQueued = %u PacketsPrepared = %u PacketsUnprepared = %u PacketsSent = %u PacketsCompleted = %u\n",
                 Ring->PacketsQueued,
                 Ring->PacketsPrepared,
                 Ring->PacketsUnprepared,
                 Ring->PacketsSent,
                 Ring->PacketsCompleted);
}

static BOOLEAN
TransmitterRingPullup(
    IN      PVOID                   Argument,
    IN      PUCHAR                  DestinationVa,
    IN OUT  PXENVIF_PACKET_PAYLOAD  Payload,
    IN      ULONG                   Length
    )
{
    PMDL                            Mdl;
    ULONG                           Offset;

    UNREFERENCED_PARAMETER(Argument);

    Mdl = Payload->Mdl;
    Offset = Payload->Offset;

    if (Payload->Length < Length)
        goto fail1;

    Payload->Length -= Length;

    while (Length != 0) {
        PUCHAR  MdlMappedSystemVa;
        ULONG   MdlByteCount;
        ULONG   CopyLength;

        ASSERT(Mdl != NULL);

        MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        ASSERT(MdlMappedSystemVa != NULL);

        MdlMappedSystemVa += Offset;

        MdlByteCount = Mdl->ByteCount - Offset;

        CopyLength = __min(MdlByteCount, Length);

        RtlCopyMemory(DestinationVa, MdlMappedSystemVa, CopyLength);
        DestinationVa += CopyLength;

        Offset += CopyLength;
        Length -= CopyLength;

        MdlByteCount -= CopyLength;
        if (MdlByteCount == 0) {
            Mdl = Mdl->Next;
            Offset = 0;
        }
    }

    Payload->Mdl = Mdl;
    Payload->Offset = Offset;

    return TRUE;

fail1:
    Error("fail1\n");

    return FALSE;
}

#define INCREMENT_PACKET_REFERENCE(_Packet)                         \
        do {                                                        \
            PULONG_PTR Reference = (PULONG_PTR)&(_Packet)->Next;    \
                                                                    \
            ASSERT(Packet != NULL);                                 \
            (*Reference)++;                                         \
        } while (FALSE)

#define DECREMENT_PACKET_REFERENCE(_Packet)                         \
        do {                                                        \
            PULONG_PTR Reference = (PULONG_PTR)&(_Packet)->Next;    \
                                                                    \
            ASSERT(Packet != NULL);                                 \
            ASSERT(*Reference != 0);                                \
            --(*Reference);                                         \
        } while (FALSE)

#define PACKET_REFERENCE(_Packet)                                   \
        (*(PULONG_PTR)&(_Packet)->Next)

static FORCEINLINE NTSTATUS
__TransmitterRingCopyPayload(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    XENVIF_PACKET_PAYLOAD           Payload;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Packet = State->Packet;

    Payload = State->Payload;

    ASSERT3U(PACKET_REFERENCE(Packet), ==, 1);

    while (Payload.Length != 0) {
        PMDL        Mdl;
        ULONG       Length;
        PUCHAR      MdlMappedSystemVa;
        PFN_NUMBER  Pfn;

        Buffer = __TransmitterGetBuffer(Ring);

        status = STATUS_NO_MEMORY;
        if (Buffer == NULL)
            goto fail1;

        Buffer->Context = Packet;
        INCREMENT_PACKET_REFERENCE(Packet);

        Mdl = Buffer->Mdl;

        Length = __min(Payload.Length, PAGE_SIZE);

        MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        TransmitterRingPullup(Ring, MdlMappedSystemVa, &Payload, Length);

        Mdl->ByteCount = Length;

        Fragment = __TransmitterGetFragment(Ring);

        status = STATUS_NO_MEMORY;
        if (Fragment == NULL)
            goto fail2;

        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
        Fragment->Context = Buffer;
        Buffer->Reference++;

        Pfn = MmGetMdlPfnArray(Mdl)[0];

        status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                     Pfn,
                                     TRUE,
                                     &Fragment->Handle);
        if (!NT_SUCCESS(status))
            goto fail3;

        Fragment->Offset = 0;
        Fragment->Length = Mdl->ByteCount;

        ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
        InsertTailList(&State->List, &Fragment->ListEntry);
        State->Count++;

        ASSERT3U(State->Count, <=, XEN_NETIF_NR_SLOTS_MIN);
    }

    Ring->PacketsCopied++;
    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
    ASSERT3P(Buffer, ==, Fragment->Context);
    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail2:
    Error("fail2\n");

    ASSERT3P(Buffer->Context, ==, Packet);
    Buffer->Context = NULL;        

    DECREMENT_PACKET_REFERENCE(Packet);

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    while (PACKET_REFERENCE(Packet) != 1) {
        PLIST_ENTRY         ListEntry;

        ASSERT(State->Count != 0);
        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        Fragment->Length = 0;
        Fragment->Offset = 0;

        GranterRevokeAccess(FrontendGetGranter(Frontend),
                            Fragment->Handle);
        Fragment->Handle = NULL;

        ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
        Buffer = Fragment->Context;
        Fragment->Context = NULL;
        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

        ASSERT(Buffer->Reference != 0);
        --Buffer->Reference;

        __TransmitterPutFragment(Ring, Fragment);

        ASSERT3P(Buffer->Context, ==, Packet);
        Buffer->Context = NULL;        

        DECREMENT_PACKET_REFERENCE(Packet);

        __TransmitterPutBuffer(Ring, Buffer);
    }

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingGrantPayload(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PMDL                            Mdl;
    ULONG                           Offset;
    ULONG                           Length;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Packet = State->Packet;
    Payload = &State->Payload;

    ASSERT3U(PACKET_REFERENCE(Packet), ==, 1);

    Mdl = Payload->Mdl;
    Offset = Payload->Offset;
    Length = Payload->Length;

    while (Length != 0) {
        ULONG   MdlOffset;
        ULONG   MdlByteCount;
        ULONG   MdlLength;

        MdlOffset = Mdl->ByteOffset + Offset;
        MdlByteCount = Mdl->ByteCount - Offset;

        MdlLength = __min(MdlByteCount, Length);

        while (MdlLength != 0) {
            PFN_NUMBER          Pfn;
            ULONG               PageOffset;
            ULONG               PageLength;

            Fragment = __TransmitterGetFragment(Ring);

            status = STATUS_NO_MEMORY;
            if (Fragment == NULL)
                goto fail1;

            Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET;
            Fragment->Context = Packet;
            INCREMENT_PACKET_REFERENCE(Packet);

            Pfn = MmGetMdlPfnArray(Mdl)[MdlOffset / PAGE_SIZE];
            PageOffset = MdlOffset & (PAGE_SIZE - 1);
            PageLength = __min(MdlLength, PAGE_SIZE - PageOffset);

            status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                         Pfn,
                                         TRUE,
                                         &Fragment->Handle);
            if (!NT_SUCCESS(status))
                goto fail2;

            Fragment->Offset = PageOffset;
            Fragment->Length = PageLength;

            ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
            InsertTailList(&State->List, &Fragment->ListEntry);
            State->Count++;

            Fragment = NULL;

            // Bounce the packet if it is too highly fragmented
            status = STATUS_BUFFER_OVERFLOW;
            if (State->Count > XEN_NETIF_NR_SLOTS_MIN)
                goto fail3;

            MdlOffset += PageLength;

            ASSERT3U(MdlLength, >=, PageLength);
            MdlLength -= PageLength;

            ASSERT3U(Length, >=, PageLength);
            Length -= PageLength;
        }

        Mdl = Mdl->Next;
        Offset = 0;
    }

    Ring->PacketsGranted++;
    return STATUS_SUCCESS;

fail3:
fail2:
    Error("fail2\n");

    if (Fragment != NULL) {
        ASSERT3P(Fragment->Context, ==, Packet);
        Fragment->Context = NULL;
        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

        DECREMENT_PACKET_REFERENCE(Packet);

        __TransmitterPutFragment(Ring, Fragment);
    }

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT3P(Fragment, ==, NULL);

    while (PACKET_REFERENCE(Packet) != 1) {
        PLIST_ENTRY         ListEntry;

        ASSERT(State->Count != 0);
        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        Fragment->Length = 0;
        Fragment->Offset = 0;

        GranterRevokeAccess(FrontendGetGranter(Frontend),
                            Fragment->Handle);
        Fragment->Handle = NULL;

        ASSERT3P(Fragment->Context, ==, Packet);
        Fragment->Context = NULL;
        Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

        DECREMENT_PACKET_REFERENCE(Packet);

        __TransmitterPutFragment(Ring, Fragment);
    }

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPrepareHeader(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_MAC                     Mac;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PXENVIF_PACKET_INFO             Info;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    PMDL                            Mdl;
    PUCHAR                          StartVa;
    PFN_NUMBER                      Pfn;
    PETHERNET_HEADER                EthernetHeader;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;
    Mac = FrontendGetMac(Frontend);

    State = &Ring->State;
    Packet = State->Packet;
    Payload = &State->Payload;
    Info = &State->Info;

    ASSERT3U(PACKET_REFERENCE(Packet), ==, 0);

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Buffer->Context = Packet;
    INCREMENT_PACKET_REFERENCE(Packet);

    Mdl = Buffer->Mdl;

    StartVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(StartVa != NULL);

    status = ParsePacket(StartVa, TransmitterRingPullup, Ring, Payload, Info);
    if (!NT_SUCCESS(status))
        goto fail2;

    State->StartVa = StartVa;

    Mdl->ByteCount = Info->Length;

    Fragment = __TransmitterGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail3;

    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
    Fragment->Context = Buffer;
 
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 TRUE,
                                 &Fragment->Handle);
    if (!NT_SUCCESS(status))
        goto fail4;

    Fragment->Offset = 0;
    Fragment->Length = Mdl->ByteCount + Payload->Length;

    ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Fragment->ListEntry);
    State->Count++;

    ASSERT(Info->EthernetHeader.Length != 0);
    EthernetHeader = (PETHERNET_HEADER)(StartVa + Info->EthernetHeader.Offset);        

    if (State->Send.OffloadOptions.OffloadTagManipulation) {
        ULONG   Offset;

        Offset = FIELD_OFFSET(ETHERNET_TAGGED_HEADER, Tag);

        RtlMoveMemory((PUCHAR)EthernetHeader + Offset + sizeof (ETHERNET_TAG),
                      (PUCHAR)EthernetHeader + Offset,
                      Mdl->ByteCount - Offset);

        // Insert the tag
        EthernetHeader->Tagged.Tag.ProtocolID = HTONS(ETHERTYPE_TPID);
        EthernetHeader->Tagged.Tag.ControlInformation = HTONS(State->Send.TagControlInformation);
        ASSERT(ETHERNET_HEADER_IS_TAGGED(EthernetHeader));

        Mdl->ByteCount += sizeof (ETHERNET_TAG);
        Fragment->Length += sizeof (ETHERNET_TAG);

        // Fix up the packet information
        Info->EthernetHeader.Length += sizeof (ETHERNET_TAG);
        Info->Length += sizeof (ETHERNET_TAG);

        if (Info->IpHeader.Length != 0)
            Info->IpHeader.Offset += sizeof (ETHERNET_TAG);

        if (Info->IpOptions.Length != 0)
            Info->IpOptions.Offset += sizeof (ETHERNET_TAG);

        if (Info->UdpHeader.Length != 0)
            Info->UdpHeader.Offset += sizeof (ETHERNET_TAG);

        if (Info->TcpHeader.Length != 0)
            Info->TcpHeader.Offset += sizeof (ETHERNET_TAG);

        if (Info->TcpOptions.Length != 0)
            Info->TcpOptions.Offset += sizeof (ETHERNET_TAG);
    }

    if (State->Send.OffloadOptions.OffloadIpVersion4LargePacket) {
        PIP_HEADER  IpHeader;
        PTCP_HEADER TcpHeader;
        ULONG       Length;

        ASSERT(!Info->IsAFragment);

        ASSERT(Info->IpHeader.Length != 0);
        IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

        ASSERT(Info->TcpHeader.Length != 0);
        TcpHeader = (PTCP_HEADER)(StartVa + Info->TcpHeader.Offset);

        // Fix up the IP packet length
        Length = Info->IpHeader.Length +
                 Info->IpOptions.Length + 
                 Info->TcpHeader.Length + 
                 Info->TcpOptions.Length + 
                 Payload->Length;

        ASSERT3U((USHORT)Length, ==, Length);

        ASSERT3U(IpHeader->Version, ==, 4);

        IpHeader->Version4.PacketLength = HTONS((USHORT)Length);

        // IP checksum calulcation must be offloaded for large packets
        State->Send.OffloadOptions.OffloadIpVersion4HeaderChecksum = 1;

        // TCP checksum calulcation must be offloaded for large packets
        TcpHeader->Checksum = ChecksumPseudoHeader(StartVa, Info);
        State->Send.OffloadOptions.OffloadIpVersion4TcpChecksum = 1;

        // If the MSS is such that the payload would constitute only a single fragment then
        // we no longer need trate the packet as a large packet.
        ASSERT3U(State->Send.MaximumSegmentSize, <=, Payload->Length);
        if (State->Send.MaximumSegmentSize == Payload->Length)
            State->Send.OffloadOptions.OffloadIpVersion4LargePacket = 0;
    }
    
    if (State->Send.OffloadOptions.OffloadIpVersion6LargePacket) {
        PIP_HEADER  IpHeader;
        PTCP_HEADER TcpHeader;
        ULONG       Length;

        ASSERT(!Info->IsAFragment);

        ASSERT(Info->IpHeader.Length != 0);
        IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

        ASSERT(Info->TcpHeader.Length != 0);
        TcpHeader = (PTCP_HEADER)(StartVa + Info->TcpHeader.Offset);

        // Fix up the IP payload length
        Length = Info->IpOptions.Length + 
                 Info->TcpHeader.Length + 
                 Info->TcpOptions.Length + 
                 Payload->Length;

        ASSERT3U((USHORT)Length, ==, Length);

        ASSERT3U(IpHeader->Version, ==, 6);

        IpHeader->Version6.PayloadLength = HTONS((USHORT)Length);

        // TCP checksum calulcation must be offloaded for large packets
        TcpHeader->Checksum = ChecksumPseudoHeader(StartVa, Info);
        State->Send.OffloadOptions.OffloadIpVersion6TcpChecksum = 1;

        // If the MSS is such that the payload would constitute only a single fragment then
        // we no longer need treat the packet as a large packet.
        ASSERT3U(State->Send.MaximumSegmentSize, <=, Payload->Length);
        if (State->Send.MaximumSegmentSize == Payload->Length)
            State->Send.OffloadOptions.OffloadIpVersion6LargePacket = 0;
    }

    // Non-GSO packets must not exceed MTU
    if (!State->Send.OffloadOptions.OffloadIpVersion4LargePacket &&
        !State->Send.OffloadOptions.OffloadIpVersion6LargePacket) {
        ULONG   MaximumFrameSize;

        MacQueryMaximumFrameSize(Mac, &MaximumFrameSize);
        
        if (Fragment->Length > MaximumFrameSize) {
            status = STATUS_INVALID_PARAMETER;
            goto fail5;
        }
    }

    if (State->Send.OffloadOptions.OffloadIpVersion4HeaderChecksum) {
        PIP_HEADER  IpHeader;

        ASSERT(Info->IpHeader.Length != 0);
        IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

        ASSERT3U(IpHeader->Version, ==, 4);
        IpHeader->Version4.Checksum = ChecksumIpVersion4Header(StartVa, Info);
    }

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    ASSERT(State->Count != 0);
    --State->Count;

    RemoveEntryList(&Fragment->ListEntry);
    RtlZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY));

    Fragment->Length = 0;
    Fragment->Offset = 0;

    GranterRevokeAccess(FrontendGetGranter(Frontend),
                        Fragment->Handle);
    Fragment->Handle = NULL;

fail4:
    Error("fail4\n");

    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail3:
    Error("fail3\n");

    Mdl->ByteCount = 0;

fail2:
    Error("fail2\n");

    DECREMENT_PACKET_REFERENCE(Packet);
    Buffer->Context = NULL;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT3U(PACKET_REFERENCE(Packet), ==, 0);

    return status;
}

static FORCEINLINE VOID
__TransmitterRingUnprepareFragments(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;

    while (State->Count != 0) {
        PLIST_ENTRY                     ListEntry;
        PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
        PXENVIF_TRANSMITTER_PACKET      Packet;

        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        Fragment->Length = 0;
        Fragment->Offset = 0;

        GranterRevokeAccess(FrontendGetGranter(Frontend),
                            Fragment->Handle);
        Fragment->Handle = NULL;

        switch (Fragment->Type) {
        case XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER: {
            PXENVIF_TRANSMITTER_BUFFER  Buffer;

            Buffer = Fragment->Context;
            Fragment->Context = NULL;
            Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

            Packet = Buffer->Context;
            Buffer->Context = NULL;

            ASSERT(Buffer->Reference != 0);
            if (--Buffer->Reference == 0)
                __TransmitterPutBuffer(Ring, Buffer);

            break;
        }
        case XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET:
            Packet = Fragment->Context;
            Fragment->Context = NULL;
            Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

            break;

        default:
            Packet = NULL;
            ASSERT(FALSE);
        }

        __TransmitterPutFragment(Ring, Fragment);

        if (Packet != NULL)
            DECREMENT_PACKET_REFERENCE(Packet);
    }
}

static FORCEINLINE NTSTATUS
__TransmitterRingPreparePacket(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
#define OFFSET_EXISTS(_Ring, _Packet, _Type)                                                        \
    ((_Ring)->Transmitter->Offset[XENVIF_TRANSMITTER_PACKET_ ## _Type ## _OFFSET] != 0)

#define OFFSET(_Ring, _Packet, _Type)                                                               \
        ((OFFSET_EXISTS(_Ring, _Packet, _Type)) ?                                                   \
         (PVOID)((PUCHAR)(_Packet) +                                                                \
                 (_Ring)->Transmitter->Offset[XENVIF_TRANSMITTER_PACKET_ ## _Type ## _OFFSET]) :    \
         NULL)

    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PXENVIF_PACKET_INFO             Info;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));
    ASSERT3P(Packet->Next, ==, NULL);

    Transmitter = Ring->Transmitter;

    State = &Ring->State;

    State->Packet = Packet;

    State->Send = Packet->Send;
    RtlZeroMemory(&Packet->Send, sizeof (XENVIF_TRANSMITTER_PACKET_SEND_INFO));

    Payload = &State->Payload;

    ASSERT(OFFSET_EXISTS(Ring, Packet, MDL));
    Payload->Mdl = *(PMDL *)OFFSET(Ring, Packet, MDL);

    if (OFFSET_EXISTS(Ring, Packet, OFFSET))
        Payload->Offset = *(PULONG)OFFSET(Ring, Packet, OFFSET);
    else
        Payload->Offset = 0;

    ASSERT(OFFSET_EXISTS(Ring, Packet, LENGTH));
    Payload->Length = *(PULONG)OFFSET(Ring, Packet, LENGTH);

    InitializeListHead(&State->List);
    ASSERT3U(State->Count, ==, 0);

    status = __TransmitterRingPrepareHeader(Ring);
    if (!NT_SUCCESS(status))
        goto fail1;

    ASSERT3U(State->Count, ==, PACKET_REFERENCE(Packet));

    Info = &State->Info;

    // Is the packet too short?
    if (Info->Length + Payload->Length < ETHERNET_MIN) {
        ULONG   Trailer;
        BOOLEAN SingleFragment;

        Trailer = ETHERNET_MIN - Payload->Length - Info->Length;
        SingleFragment = (Payload->Length == 0) ? TRUE : FALSE;

        status = __TransmitterRingCopyPayload(Ring);

        if (NT_SUCCESS(status)) {
            PLIST_ENTRY                     ListEntry;
            PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
            PXENVIF_TRANSMITTER_BUFFER      Buffer;
            PMDL                            Mdl;
            PUCHAR                          MdlMappedSystemVa;

            // Add padding to the tail buffer
            ListEntry = State->List.Blink;
            Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

            ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
            Buffer = Fragment->Context;

            Mdl = Buffer->Mdl;

            ASSERT3U(Mdl->ByteCount, <=, PAGE_SIZE - Trailer);

            MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
            ASSERT(MdlMappedSystemVa != NULL);

            MdlMappedSystemVa += Mdl->ByteCount;

            RtlZeroMemory(MdlMappedSystemVa, Trailer);
            Mdl->ByteCount += Trailer;

            if (!SingleFragment) {
                ASSERT3P(State->List.Flink, !=, ListEntry);
                Fragment->Length += Trailer;
            }

            // Adjust length of header fragment
            ListEntry = State->List.Flink;
            Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

            Fragment->Length += Trailer;
            ASSERT3U(Fragment->Length, ==, ETHERNET_MIN);
        }
    } else {
        if (Transmitter->AlwaysCopy == 0)
            status = __TransmitterRingGrantPayload(Ring);

        if (Transmitter->AlwaysCopy != 0 ||
            (!NT_SUCCESS(status) && status == STATUS_BUFFER_OVERFLOW)) {
            ASSERT3U(State->Count, ==, PACKET_REFERENCE(Packet));

            status = __TransmitterRingCopyPayload(Ring);
        }
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    ASSERT3U(State->Count, ==, PACKET_REFERENCE(Packet));

    Ring->PacketsPrepared++;
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    __TransmitterRingUnprepareFragments(Ring);

fail1:
    Error("fail1 (%08x)\n", status);

    State->StartVa = NULL;
    RtlZeroMemory(&State->Info, sizeof (XENVIF_PACKET_INFO));

    ASSERT(IsListEmpty(&State->List));
    RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

    RtlZeroMemory(&State->Payload, sizeof (XENVIF_PACKET_PAYLOAD));

    Packet->Send = State->Send;
    RtlZeroMemory(&State->Send, sizeof (XENVIF_TRANSMITTER_PACKET_SEND_INFO));

    State->Packet = NULL;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return status;

#undef  OFFSET
#undef  OFFSET_EXISTS
}

static FORCEINLINE PXENVIF_TRANSMITTER_PACKET
__TransmitterRingUnpreparePacket(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;

    State = &Ring->State;
    Packet = State->Packet;

    // This has the side effect of freeing up resources associated with a pending
    // gratuitous ARP, which is why the call is not conditional on Packet being
    // non-NULL
    __TransmitterRingUnprepareFragments(Ring);
    RtlZeroMemory(&State->Info, sizeof (XENVIF_PACKET_INFO));

    if (Packet == NULL)
        goto done;

    Ring->PacketsUnprepared++;

    ASSERT(IsListEmpty(&State->List));
    RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

    RtlZeroMemory(&State->Payload, sizeof (XENVIF_PACKET_PAYLOAD));

    Packet->Send = State->Send;
    RtlZeroMemory(&State->Send, sizeof (XENVIF_TRANSMITTER_PACKET_SEND_INFO));

    State->Packet = NULL;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

done:
    return Packet;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPrepareArp(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PIPV4_ADDRESS               Address
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_MAC                     Mac;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    PMDL                            Mdl;
    PUCHAR                          MdlMappedSystemVa;
    PETHERNET_UNTAGGED_HEADER       EthernetHeader;
    PARP_HEADER                     ArpHeader;
    ETHERNET_ADDRESS                SenderHardwareAddress;
    IPV4_ADDRESS                    SenderProtocolAddress;
    ETHERNET_ADDRESS                TargetHardwareAddress;
    IPV4_ADDRESS                    TargetProtocolAddress;
    PFN_NUMBER                      Pfn;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    Info("%u.%u.%u.%u\n",
         Address->Byte[0],
         Address->Byte[1],
         Address->Byte[2],
         Address->Byte[3]);

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;
    Mac = FrontendGetMac(Frontend);

    SenderProtocolAddress = *Address;
    TargetProtocolAddress = *Address;
    MacQueryCurrentAddress(Mac, &SenderHardwareAddress);
    MacQueryBroadcastAddress(Mac, &TargetHardwareAddress);

    State = &Ring->State;

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Mdl = Buffer->Mdl;

    MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(MdlMappedSystemVa != NULL);

    EthernetHeader = (PETHERNET_UNTAGGED_HEADER)MdlMappedSystemVa;

    MacQueryBroadcastAddress(Mac, &EthernetHeader->DestinationAddress);
    MacQueryCurrentAddress(Mac, &EthernetHeader->SourceAddress);
    EthernetHeader->TypeOrLength = HTONS(ETHERTYPE_ARP);

    MdlMappedSystemVa += sizeof (ETHERNET_UNTAGGED_HEADER);

    ArpHeader = (PARP_HEADER)MdlMappedSystemVa;

    ArpHeader->HardwareType = HTONS(HARDWARE_ETHER);
    ArpHeader->ProtocolType = HTONS(PROTOCOL_IPV4);
    ArpHeader->HardwareAddressLength = ETHERNET_ADDRESS_LENGTH;
    ArpHeader->ProtocolAddressLength = IPV4_ADDRESS_LENGTH;
    ArpHeader->Operation = HTONS(ARP_REQUEST);

    MdlMappedSystemVa += sizeof (ARP_HEADER);

    RtlCopyMemory(MdlMappedSystemVa, SenderHardwareAddress.Byte, ETHERNET_ADDRESS_LENGTH);
    MdlMappedSystemVa += ETHERNET_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, SenderProtocolAddress.Byte, IPV4_ADDRESS_LENGTH);
    MdlMappedSystemVa += IPV4_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, TargetHardwareAddress.Byte, ETHERNET_ADDRESS_LENGTH);
    MdlMappedSystemVa += ETHERNET_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, TargetProtocolAddress.Byte, IPV4_ADDRESS_LENGTH);
    MdlMappedSystemVa += IPV4_ADDRESS_LENGTH;

    Mdl->ByteCount = (ULONG)(MdlMappedSystemVa - (PUCHAR)MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority));

    Fragment = __TransmitterGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Fragment == NULL)
        goto fail2;

    Fragment->Context = Buffer;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 TRUE,
                                 &Fragment->Handle);
    if (!NT_SUCCESS(status))
        goto fail3;

    Fragment->Offset = 0;
    Fragment->Length = Mdl->ByteCount;

    InitializeListHead(&State->List);

    ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Fragment->ListEntry);
    State->Count++;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
    ASSERT3P(Buffer, ==, Fragment->Context);
    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail2:
    Error("fail2\n");

    Mdl->ByteCount = 0;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPrepareNeighbourAdvertisement(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PIPV6_ADDRESS               Address
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_MAC                     Mac;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
    PXENVIF_TRANSMITTER_BUFFER      Buffer;
    PMDL                            Mdl;
    PUCHAR                          MdlMappedSystemVa;
    PETHERNET_UNTAGGED_HEADER       EthernetHeader;
    PIPV6_HEADER                    IpHeader;
    PICMPV6_HEADER                  IcmpHeader;
    IPV6_ADDRESS                    TargetProtocolAddress;
    ETHERNET_ADDRESS                SenderHardwareAddress;
    USHORT                          PayloadLength;
    ULONG                           Accumulator;
    PFN_NUMBER                      Pfn;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    Info("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
         HTONS(Address->Word[0]),
         HTONS(Address->Word[1]),
         HTONS(Address->Word[2]),
         HTONS(Address->Word[3]),
         HTONS(Address->Word[4]),
         HTONS(Address->Word[5]),
         HTONS(Address->Word[6]),
         HTONS(Address->Word[7]));

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;
    Mac = FrontendGetMac(Frontend);

    TargetProtocolAddress = *Address;
    MacQueryCurrentAddress(Mac, &SenderHardwareAddress);

    State = &Ring->State;

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Mdl = Buffer->Mdl;

    MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Buffer->Mdl, NormalPagePriority);
    ASSERT(MdlMappedSystemVa != NULL);

    EthernetHeader = (PETHERNET_UNTAGGED_HEADER)MdlMappedSystemVa;

    MacQueryBroadcastAddress(Mac, &EthernetHeader->DestinationAddress);
    MacQueryCurrentAddress(Mac, &EthernetHeader->SourceAddress);
    EthernetHeader->TypeOrLength = HTONS(ETHERTYPE_IPV6);

    MdlMappedSystemVa += sizeof (ETHERNET_UNTAGGED_HEADER);

    IpHeader = (PIPV6_HEADER)MdlMappedSystemVa;
    RtlZeroMemory(IpHeader, sizeof (IPV6_HEADER));

    IpHeader->Version = 6;
    IpHeader->NextHeader = IPPROTO_ICMPV6;
    IpHeader->HopLimit = 255;

    RtlCopyMemory(IpHeader->SourceAddress.Byte, 
                  Address,
                  IPV6_ADDRESS_LENGTH);

    // Destination is all-nodes multicast address
    IpHeader->DestinationAddress.Byte[0] = 0xFF;
    IpHeader->DestinationAddress.Byte[1] = 0x02;
    IpHeader->DestinationAddress.Byte[15] = 0x02;

    PayloadLength = 0;
    MdlMappedSystemVa += sizeof (IPV6_HEADER);

    IcmpHeader = (PICMPV6_HEADER)MdlMappedSystemVa;

    IcmpHeader->Type = ICMPV6_TYPE_NA;
    IcmpHeader->Code = 0;
    IcmpHeader->Data = HTONL(0x02); // Override flag

    PayloadLength += sizeof (ICMPV6_HEADER);
    MdlMappedSystemVa += sizeof (ICMPV6_HEADER);

    RtlCopyMemory(MdlMappedSystemVa, TargetProtocolAddress.Byte, IPV6_ADDRESS_LENGTH);

    PayloadLength += IPV6_ADDRESS_LENGTH;
    MdlMappedSystemVa += IPV6_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, SenderHardwareAddress.Byte, ETHERNET_ADDRESS_LENGTH);

    PayloadLength += ETHERNET_ADDRESS_LENGTH;
    MdlMappedSystemVa += ETHERNET_ADDRESS_LENGTH;

    Mdl->ByteCount = (ULONG)(MdlMappedSystemVa - (PUCHAR)MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority));

    // Fix up IP payload length and ICMPv6 checksum
    IpHeader->PayloadLength = HTONS(PayloadLength);

    Accumulator = ChecksumIpVersion6PseudoHeader(&IpHeader->SourceAddress,
                                                 &IpHeader->DestinationAddress,
                                                 PayloadLength,
                                                 IPPROTO_ICMPV6);
    AccumulateChecksum(&Accumulator, IcmpHeader, PayloadLength);

    IcmpHeader->Checksum = (USHORT)~Accumulator;

    Fragment = __TransmitterGetFragment(Ring);

    status = STATUS_NO_MEMORY;
    if (Fragment == NULL)
        goto fail2;

    Fragment->Context = Buffer;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER;
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 TRUE,
                                 &Fragment->Handle);
    if (!NT_SUCCESS(status))
        goto fail3;

    Fragment->Offset = 0;
    Fragment->Length = Mdl->ByteCount;

    InitializeListHead(&State->List);

    ASSERT(IsZeroMemory(&Fragment->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Fragment->ListEntry);
    State->Count++;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    ASSERT3U(Fragment->Type, ==, XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER);
    ASSERT3P(Buffer, ==, Fragment->Context);
    Fragment->Context = NULL;
    Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutFragment(Ring, Fragment);

fail2:
    Error("fail2\n");

    Mdl->ByteCount = 0;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingPostFragments(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
#define RING_SLOTS_AVAILABLE(_Front, _req_prod, _rsp_cons)   \
        (RING_SIZE(_Front) - ((_req_prod) - (_rsp_cons)))

    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_STATE       State;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PXENVIF_PACKET_PAYLOAD          Payload;
    RING_IDX                        req_prod;
    RING_IDX                        rsp_cons;
    ULONG                           Extra;
    ULONG                           PacketLength;
    BOOLEAN                         FirstRequest;
    netif_tx_request_t              *req;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Packet = State->Packet;
    Payload = &State->Payload;

    ASSERT(!IsListEmpty(&State->List));
    ASSERT(State->Count != 0);
    ASSERT3U(State->Count, <=, XEN_NETIF_NR_SLOTS_MIN);
    ASSERT(IMPLY(Packet != NULL, State->Count == PACKET_REFERENCE(Packet)));

    req_prod = Ring->Front.req_prod_pvt;
    rsp_cons = Ring->Front.rsp_cons;

    Extra = (State->Send.OffloadOptions.OffloadIpVersion4LargePacket ||
             State->Send.OffloadOptions.OffloadIpVersion6LargePacket) ?
            1 :
            0;

    ASSERT3U(State->Count + Extra, <=, RING_SIZE(&Ring->Front));

    status = STATUS_ALLOTTED_SPACE_EXCEEDED;
    if (State->Count + Extra > RING_SLOTS_AVAILABLE(&Ring->Front, req_prod, rsp_cons))
        goto fail1;

    req = NULL;

    FirstRequest = TRUE;
    PacketLength = 0;
    while (State->Count != 0) {
        PLIST_ENTRY                     ListEntry;
        PXENVIF_TRANSMITTER_FRAGMENT    Fragment;

        --State->Count;

        ListEntry = RemoveHeadList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Fragment = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_FRAGMENT, ListEntry);

        req = RING_GET_REQUEST(&Ring->Front, req_prod);
        req_prod++;
        Ring->RequestsPosted++;

        req->id = Fragment->Id;
        req->gref = GranterGetReference(FrontendGetGranter(Frontend),
                                        Fragment->Handle);
        req->offset = (USHORT)Fragment->Offset;
        req->size = (USHORT)Fragment->Length;
        req->flags = NETTXF_more_data;

        if (FirstRequest) {
            FirstRequest = FALSE;

            if (State->Send.OffloadOptions.OffloadIpVersion4TcpChecksum ||
                State->Send.OffloadOptions.OffloadIpVersion4UdpChecksum ||
                State->Send.OffloadOptions.OffloadIpVersion6TcpChecksum ||
                State->Send.OffloadOptions.OffloadIpVersion6UdpChecksum)
                req->flags |= NETTXF_csum_blank | NETTXF_data_validated;

            if (State->Send.OffloadOptions.OffloadIpVersion4LargePacket ||
                State->Send.OffloadOptions.OffloadIpVersion6LargePacket) {
                uint8_t                 type;
                uint16_t                size;
                struct netif_extra_info *extra;

                ASSERT(Extra != 0);
                Fragment->Extra = TRUE;

                ASSERT(!(State->Send.OffloadOptions.OffloadIpVersion4LargePacket &&
                         State->Send.OffloadOptions.OffloadIpVersion6LargePacket));
                type = (State->Send.OffloadOptions.OffloadIpVersion4LargePacket) ?
                       XEN_NETIF_GSO_TYPE_TCPV4 :
                       XEN_NETIF_GSO_TYPE_TCPV6;

                ASSERT(State->Send.MaximumSegmentSize != 0);
                size = State->Send.MaximumSegmentSize;

                ASSERT(req->flags & (NETTXF_csum_blank | NETTXF_data_validated));
                req->flags |= NETTXF_extra_info;

                extra = (struct netif_extra_info *)RING_GET_REQUEST(&Ring->Front, req_prod);
                req_prod++;
                Ring->RequestsPosted++;

                extra->type = XEN_NETIF_EXTRA_TYPE_GSO;
                extra->flags = 0;

                extra->u.gso.size = size;
                extra->u.gso.type = type;
                extra->u.gso.pad = 0;
                extra->u.gso.features = 0;
            }

            // The first fragment length is the length of the entire packet
            PacketLength = Fragment->Length;
        }

        // Store a copy of the request in case we need to fake a response ourselves
        ASSERT3U(req->id, <=, XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);
        ASSERT3P(Ring->Pending[req->id], ==, NULL);
        Ring->Pending[req->id] = Fragment;
    }
    ASSERT(!FirstRequest);
    ASSERT(PacketLength != 0);

    ASSERT(req != NULL);
    req->flags &= ~NETTXF_more_data;

    Ring->Front.req_prod_pvt = req_prod;

    ASSERT3U(State->Count, ==, 0);
    RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

    // Set the initial completion information
    if (Packet != NULL) {
        PUCHAR              StartVa;
        PXENVIF_PACKET_INFO Info;
        PETHERNET_HEADER    Header;

        StartVa = State->StartVa;
        Info = &State->Info;

        ASSERT(IsZeroMemory(&Packet->Completion, sizeof (XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO)));

        ASSERT(Info->EthernetHeader.Length != 0);
        Header = (PETHERNET_HEADER)(StartVa + Info->EthernetHeader.Offset);

        Packet->Completion.Type = GET_ETHERNET_ADDRESS_TYPE(&Header->Untagged.DestinationAddress);
        Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_PENDING;
        Packet->Completion.PacketLength = (USHORT)PacketLength;
        Packet->Completion.PayloadLength = (USHORT)Payload->Length;

        State->StartVa = NULL;
        RtlZeroMemory(&State->Info, sizeof (XENVIF_PACKET_INFO));
        RtlZeroMemory(&State->Payload, sizeof (XENVIF_PACKET_PAYLOAD));
        RtlZeroMemory(&State->Send, sizeof (XENVIF_TRANSMITTER_PACKET_SEND_INFO));
        State->Packet = NULL;

        Ring->PacketsSent++;
    }

    ASSERT(IsZeroMemory(&Ring->State, sizeof (XENVIF_TRANSMITTER_STATE)));

    return STATUS_SUCCESS;

fail1:
    return status;

#undef  RING_SLOTS_AVAILABLE
}

static FORCEINLINE VOID
__TransmitterRingFakeResponses(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    RING_IDX                        rsp_prod;
    USHORT                          id;
    ULONG                           Count;

    // This is only called when the backend went away. We need
    // to mimic the behavior of the backend and turn requests into
    // appropriate responses.

    KeMemoryBarrier();

    rsp_prod = Ring->Shared->rsp_prod;

    KeMemoryBarrier();

    Count = 0;
    for (id = 0; id <= XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID; id++) {
        PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
        netif_tx_response_t             *rsp;

        Fragment = Ring->Pending[id];
        Ring->Pending[id] = NULL;

        if (Fragment == NULL)
            continue;

        rsp = RING_GET_RESPONSE(&Ring->Front, rsp_prod);
        rsp_prod++;
        Count++;

        rsp->id = Fragment->Id;
        rsp->status = NETIF_RSP_DROPPED;

        if (Fragment->Extra) {
            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_prod);
            rsp_prod++;
            Count++;

            rsp->status = NETIF_RSP_NULL;
        }
    }

    KeMemoryBarrier();

    Ring->Shared->rsp_prod = rsp_prod;

    KeMemoryBarrier();

    ASSERT3U(Ring->Shared->rsp_prod, ==, Ring->Front.req_prod_pvt);

    if (Count != 0)
        Info("Faked %lu responses\n", Count);
}

static FORCEINLINE VOID
__TransmitterRingCompletePacket(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT(Packet->Completion.Status != XENVIF_TRANSMITTER_PACKET_PENDING);

    if (Packet->Completion.Status != XENVIF_TRANSMITTER_PACKET_OK) {
        FrontendIncrementStatistic(Frontend,
                                   XENVIF_TRANSMITTER_PACKETS_DROPPED,
                                   1);

        if (Packet->Completion.Status == XENVIF_TRANSMITTER_PACKET_ERROR)
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_BACKEND_ERRORS,
                                       1);
    } else {
        ULONG   Length;

        Length = (ULONG)Packet->Completion.PacketLength;

        switch (Packet->Completion.Type) {
        case ETHERNET_ADDRESS_UNICAST:
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_UNICAST_PACKETS,
                                       1);
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_UNICAST_OCTETS,
                                       Length);
            break;
            
        case ETHERNET_ADDRESS_MULTICAST:
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_MULTICAST_PACKETS,
                                       1);
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_MULTICAST_OCTETS,
                                       Length);
            break;

        case ETHERNET_ADDRESS_BROADCAST:
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_BROADCAST_PACKETS,
                                       1);
            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_BROADCAST_OCTETS,
                                       Length);
            break;

        default:
            ASSERT(FALSE);
            break;
        }
    }

    *Ring->Completed.TailPacket = Packet;
    ASSERT3P(Packet->Next, ==, NULL);
    Ring->Completed.TailPacket = &Packet->Next;

    Ring->PacketsCompleted++;
}

static DECLSPEC_NOINLINE VOID
TransmitterRingPoll(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
#define XENVIF_TRANSMITTER_BATCH(_Ring) (RING_SIZE(&(_Ring)->Front) / 4)

    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    for (;;) {
        RING_IDX    rsp_prod;
        RING_IDX    rsp_cons;
        ULONG       Delta;

        KeMemoryBarrier();

        rsp_prod = Ring->Shared->rsp_prod;
        rsp_cons = Ring->Front.rsp_cons;

        KeMemoryBarrier();

        if (rsp_cons == rsp_prod)
            break;

        while (rsp_cons != rsp_prod) {
            netif_tx_response_t             *rsp;
            uint16_t                        id;
            PXENVIF_TRANSMITTER_FRAGMENT    Fragment;
            PXENVIF_TRANSMITTER_PACKET      Packet;

            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_cons);
            rsp_cons++;
            Ring->ResponsesProcessed++;

            Ring->Stopped = FALSE;

            if (rsp->status == NETIF_RSP_NULL)
                continue;

            id = rsp->id;

            ASSERT3U(id, <=, XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);
            Fragment = Ring->Pending[id];
            Ring->Pending[id] = NULL;

            ASSERT(Fragment != NULL);
            ASSERT3U(Fragment->Id, ==, id);

            switch (Fragment->Type) {
            case XENVIF_TRANSMITTER_FRAGMENT_TYPE_BUFFER: {
                PXENVIF_TRANSMITTER_BUFFER  Buffer;

                Buffer = Fragment->Context;
                Fragment->Context = NULL;
                Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

                Packet = Buffer->Context;
                Buffer->Context = NULL;

                ASSERT(Buffer->Reference != 0);
                if (--Buffer->Reference == 0)
                    __TransmitterPutBuffer(Ring, Buffer);

                break;
            }
            case XENVIF_TRANSMITTER_FRAGMENT_TYPE_PACKET:
                Packet = Fragment->Context;
                Fragment->Context = NULL;
                Fragment->Type = XENVIF_TRANSMITTER_FRAGMENT_TYPE_INVALID;

                break;

            default:
                Packet = NULL;
                ASSERT(FALSE);
            }

            Fragment->Length = 0;
            Fragment->Offset = 0;

            GranterRevokeAccess(FrontendGetGranter(Frontend),
                                Fragment->Handle);
            Fragment->Handle = NULL;

            Fragment->Extra = FALSE;
            __TransmitterPutFragment(Ring, Fragment);

            if (Packet == NULL) {
                RtlZeroMemory(rsp, sizeof (netif_tx_response_t));
                continue;
            }

            DECREMENT_PACKET_REFERENCE(Packet);

            if (rsp->status != NETIF_RSP_OKAY &&
                Packet->Completion.Status == XENVIF_TRANSMITTER_PACKET_PENDING) {
                switch (rsp->status) {
                case NETIF_RSP_DROPPED:
                    Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_DROPPED;
                    break;

                case NETIF_RSP_ERROR:
                    Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_ERROR;
                    break;

                default:
                    ASSERT(FALSE);
                    break;
                }
            }

            RtlZeroMemory(rsp, sizeof (netif_tx_response_t));

            if (PACKET_REFERENCE(Packet) != 0)
                continue;

            if (Packet->Completion.Status == XENVIF_TRANSMITTER_PACKET_PENDING)
                Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_OK;

            __TransmitterRingCompletePacket(Ring, Packet);
        }

        KeMemoryBarrier();

        Ring->Front.rsp_cons = rsp_cons;

        Delta = Ring->Front.req_prod_pvt - rsp_cons;
        Delta = __min(Delta, XENVIF_TRANSMITTER_BATCH(Ring));
        Delta = __max(Delta, 1);

        Ring->Shared->rsp_event = rsp_cons + Delta;
    }

#undef XENVIF_TRANSMITTER_BATCH
}

static FORCEINLINE VOID
__TransmitterRingPushRequests(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    BOOLEAN                         Notify;

    if (Ring->RequestsPosted == Ring->RequestsPushed)
        return;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the requests visible to the backend
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Ring->Front, Notify);

#pragma warning (pop)

    if (Notify) {
        PXENVIF_TRANSMITTER Transmitter;
        PXENVIF_FRONTEND    Frontend;

        Transmitter = Ring->Transmitter;
        Frontend = Transmitter->Frontend;

        NotifierSendTx(FrontendGetNotifier(Frontend));
    }

    Ring->RequestsPushed = Ring->RequestsPosted;
}

#define XENVIF_TRANSMITTER_ADVERTISEMENT_COUNT 3

#define XENVIF_TRANSMITTER_LOCK_BIT ((ULONG_PTR)1)

static FORCEINLINE ULONG
__TransmitterReversePacketList(
    IN  PXENVIF_TRANSMITTER_PACKET  *Packet
    )
{
    PXENVIF_TRANSMITTER_PACKET      HeadPacket;
    ULONG                           Count;

    HeadPacket = NULL;
    Count = 0;

    while (*Packet != NULL) {
        PXENVIF_TRANSMITTER_PACKET  Next;

        ASSERT(((ULONG_PTR)*Packet & XENVIF_TRANSMITTER_LOCK_BIT) == 0);

        Next = (*Packet)->Next;

        (*Packet)->Next = HeadPacket;
        HeadPacket = *Packet;

        *Packet = Next;
        Count++;
    }

    *Packet = HeadPacket;

    return Count;
}

static DECLSPEC_NOINLINE VOID
TransmitterRingSwizzle(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ULONG_PTR                       Old;
    ULONG_PTR                       New;
    PXENVIF_TRANSMITTER_PACKET      HeadPacket;
    PXENVIF_TRANSMITTER_PACKET      *TailPacket;
    ULONG                           Count;

    ASSERT3P(Ring->LockThread, ==, KeGetCurrentThread());

    New = XENVIF_TRANSMITTER_LOCK_BIT;    
    Old = (ULONG_PTR)InterlockedExchangePointer(&Ring->Lock, (PVOID)New);

    ASSERT(Old & XENVIF_TRANSMITTER_LOCK_BIT);
    HeadPacket = (PVOID)(Old & ~XENVIF_TRANSMITTER_LOCK_BIT);

    if (HeadPacket == NULL)
        return;

    // Packets are held in the atomic packet list in reverse order
    // so that the most recent is always head of the list. This is
    // necessary to allow addition to the list to be done atomically.

    TailPacket = &HeadPacket->Next;
    Count = __TransmitterReversePacketList(&HeadPacket);
    ASSERT3P(*TailPacket, ==, NULL);

    *(Ring->Queued.TailPacket) = HeadPacket;
    Ring->Queued.TailPacket = TailPacket;
    Ring->PacketsQueued += Count;
}

static DECLSPEC_NOINLINE VOID
TransmitterRingSchedule(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER_STATE       State;

    if(!Ring->Enabled || Ring->Stopped)
        return;

    State = &Ring->State;

    for (;;) {
        PXENVIF_TRANSMITTER_PACKET  Packet;
        NTSTATUS                    status;

        if (State->Count != 0) {
            status = __TransmitterRingPostFragments(Ring);
            if (!NT_SUCCESS(status)) {
                Ring->Stopped = TRUE;
                break;
            }
        }

        if (Ring->RequestsPosted - Ring->RequestsPushed >=
            RING_SIZE(&Ring->Front) / 4)
            __TransmitterRingPushRequests(Ring);

        ASSERT3U(State->Count, ==, 0);

        if (Ring->AddressIndex != 0) {
            ULONG   Index = (--Ring->AddressIndex) % Ring->AddressCount;

            switch (Ring->AddressTable[Index].si_family) {
            case AF_INET: {
                IPV4_ADDRESS    Address;

                RtlCopyMemory(Address.Byte,
                              &Ring->AddressTable[Index].Ipv4.sin_addr.s_addr,
                              IPV4_ADDRESS_LENGTH);

                (VOID) __TransmitterRingPrepareArp(Ring, &Address);

                break;
            }
            case AF_INET6: {
                IPV6_ADDRESS    Address;

                RtlCopyMemory(Address.Byte,
                              &Ring->AddressTable[Index].Ipv6.sin6_addr.s6_addr,
                              IPV6_ADDRESS_LENGTH);

                (VOID) __TransmitterRingPrepareNeighbourAdvertisement(Ring, &Address);

                break;
            }
            default:
                ASSERT(FALSE);
            }

            continue;
        }

        Packet = Ring->Queued.HeadPacket;

        if (Packet == NULL)
            break;

        if (Packet->Next == NULL) {
            Ring->Queued.HeadPacket = NULL;
            Ring->Queued.TailPacket = &Ring->Queued.HeadPacket;
        } else {
            Ring->Queued.HeadPacket = Packet->Next;
            Packet->Next = NULL;
        }

        status = __TransmitterRingPreparePacket(Ring, Packet);
        if (!NT_SUCCESS(status)) {
            PXENVIF_TRANSMITTER Transmitter;
            PXENVIF_FRONTEND    Frontend;

            Transmitter = Ring->Transmitter;
            Frontend = Transmitter->Frontend;

            ASSERT(status != STATUS_BUFFER_OVERFLOW);

            // Fake that we prapared and sent this packet
            Ring->PacketsPrepared++;
            Ring->PacketsSent++;
            Ring->PacketsFaked++;

            Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_DROPPED;

            FrontendIncrementStatistic(Frontend,
                                       XENVIF_TRANSMITTER_FRONTEND_ERRORS,
                                       1);

            __TransmitterRingCompletePacket(Ring, Packet);
        }

        ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
    }

    ASSERT(IMPLY(Ring->Queued.HeadPacket == NULL, Ring->Queued.TailPacket == &Ring->Queued.HeadPacket));

    __TransmitterRingPushRequests(Ring);
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingTryAcquireLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ULONG_PTR                       Old;
    ULONG_PTR                       New;
    BOOLEAN                         Acquired;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeMemoryBarrier();

    Old = (ULONG_PTR)Ring->Lock & ~XENVIF_TRANSMITTER_LOCK_BIT;
    New = Old | XENVIF_TRANSMITTER_LOCK_BIT;

    Acquired = ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock,
                                                             (PVOID)New,
                                                             (PVOID)Old) == Old) ? TRUE : FALSE;

    KeMemoryBarrier();

    if (Acquired) {
        ASSERT3P(Ring->LockThread, ==, NULL);
        Ring->LockThread = KeGetCurrentThread();
        KeMemoryBarrier();
    }

    return Acquired;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingAcquireLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    for (;;) {
        if (__TransmitterRingTryAcquireLock(Ring))
            break;

        _mm_pause();
    }
}

static VOID
TransmitterRingAcquireLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingAcquireLock(Ring);
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingTryReleaseLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    ULONG_PTR                       Old;
    ULONG_PTR                       New;
    BOOLEAN                         Released;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3P(KeGetCurrentThread(), ==, Ring->LockThread);

    Old = XENVIF_TRANSMITTER_LOCK_BIT;
    New = 0;

    Ring->LockThread = NULL;

    KeMemoryBarrier();

    Released = ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock,
                                                             (PVOID)New,
                                                             (PVOID)Old) == Old) ? TRUE : FALSE;

    KeMemoryBarrier();

    if (!Released) {
        ASSERT3P(Ring->LockThread, ==, NULL);
        Ring->LockThread = KeGetCurrentThread();
        KeMemoryBarrier();
    }

    return Released;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__TransmitterRingReleaseLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER_PACKET      HeadPacket;
    PXENVIF_TRANSMITTER_PACKET      *TailPacket;
    
    HeadPacket = NULL;
    TailPacket = &HeadPacket;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    // As lock holder it is our responsibility to drain the atomic
    // packet list into the transmit queue before we actually drop the
    // lock. This may, of course, take a few attempts as another
    // thread could be simuntaneously adding to the list.

    do {
        TransmitterRingSwizzle(Ring);
        TransmitterRingSchedule(Ring);

        *TailPacket = Ring->Completed.HeadPacket;
        TailPacket = Ring->Completed.TailPacket;

        Ring->Completed.HeadPacket = NULL;
        Ring->Completed.TailPacket = &Ring->Completed.HeadPacket;
    } while (!__TransmitterRingTryReleaseLock(Ring));

    if (HeadPacket != NULL) {
        PXENVIF_TRANSMITTER Transmitter;
        PXENVIF_FRONTEND    Frontend;

        Transmitter = Ring->Transmitter;
        Frontend = Transmitter->Frontend;

        VifTransmitterReturnPackets(PdoGetVifContext(FrontendGetPdo(Frontend)),
                                    HeadPacket);
    }
}

static DECLSPEC_NOINLINE VOID
TransmitterRingReleaseLock(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingReleaseLock(Ring);
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define XENVIF_TRANSMITTER_WATCHDOG_PERIOD  30

static NTSTATUS
TransmitterRingWatchdog(
    IN  PXENVIF_THREAD          Self,
    IN  PVOID                   Context
    )
{
    PXENVIF_TRANSMITTER_RING    Ring = Context;
    LARGE_INTEGER               Timeout;
    ULONG                       PacketsQueued;

    Trace("====>\n");

    Timeout.QuadPart = TIME_RELATIVE(TIME_S(XENVIF_TRANSMITTER_WATCHDOG_PERIOD));
    PacketsQueued = 0;

    for (;;) { 
        PKEVENT Event;
        KIRQL   Irql;

        Event = ThreadGetEvent(Self);

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     &Timeout);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        KeRaiseIrql(DISPATCH_LEVEL, &Irql);
        __TransmitterRingAcquireLock(Ring);

        if (Ring->Enabled) {
            if (Ring->PacketsQueued == PacketsQueued &&
                Ring->PacketsCompleted != PacketsQueued) {
                PXENVIF_TRANSMITTER Transmitter;
                PXENVIF_FRONTEND    Frontend;

                Transmitter = Ring->Transmitter;
                Frontend = Transmitter->Frontend;

                XENBUS_DEBUG(Trigger,
                             &Transmitter->DebugInterface,
                             Ring->DebugCallback);

                // Try to move things along
                NotifierSendTx(FrontendGetNotifier(Frontend));
                TransmitterRingPoll(Ring);
            }

            PacketsQueued = Ring->PacketsQueued;
        }

        __TransmitterRingReleaseLock(Ring);
        KeLowerIrql(Irql);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
__TransmitterRingUpdateAddressTable(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PSOCKADDR_INET              Table,
    IN  ULONG                       Count
    )
{
    NTSTATUS                        status;

    __TransmitterRingAcquireLock(Ring);

    if (Ring->AddressCount != 0) {
        Ring->AddressCount = 0;

        ASSERT(Ring->AddressTable != NULL);
        __TransmitterFree(Ring->AddressTable);
        Ring->AddressTable = NULL;
    }

    if (Count == 0)
        goto done;

    Ring->AddressTable = __TransmitterAllocate(sizeof (SOCKADDR_INET) * Count);

    status = STATUS_NO_MEMORY;
    if (Ring->AddressTable == NULL)
        goto fail1;

    RtlCopyMemory(Ring->AddressTable, Table, sizeof (SOCKADDR_INET) * Count);
    Ring->AddressCount = Count;

    // Re-advertize if we were part way through
    if (Ring->AddressIndex != 0)
        Ring->AddressIndex = Ring->AddressCount * 3;

done:
    __TransmitterRingReleaseLock(Ring);

    return;

fail1:
    Error("fail1 (%08x)\n", status);

    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__TransmitterRingAdvertiseAddresses(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingAcquireLock(Ring);
    Ring->AddressIndex = Ring->AddressCount * 3;
    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE NTSTATUS
__TransmitterRingInitialize(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  ULONG                       Index,
    OUT PXENVIF_TRANSMITTER_RING    *Ring
    )
{
    PXENVIF_FRONTEND                Frontend;
    CHAR                            Name[MAXNAMELEN];
    NTSTATUS                        status;

    Frontend = Transmitter->Frontend;

    *Ring = __TransmitterAllocate(sizeof (XENVIF_TRANSMITTER_RING));

    status = STATUS_NO_MEMORY;
    if (*Ring == NULL)
        goto fail1;

    (*Ring)->Transmitter = Transmitter;
    (*Ring)->Index = Index;
    (*Ring)->Queued.TailPacket = &(*Ring)->Queued.HeadPacket;
    (*Ring)->Completed.TailPacket = &(*Ring)->Completed.HeadPacket;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_buffer",
                                FrontendGetPath(Frontend));
    if (!NT_SUCCESS(status))
        goto fail2;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &Transmitter->CacheInterface,
                          Name,
                          sizeof (XENVIF_TRANSMITTER_BUFFER),
                          0,
                          TransmitterBufferCtor,
                          TransmitterBufferDtor,
                          TransmitterRingAcquireLock,
                          TransmitterRingReleaseLock,
                          *Ring,
                          &(*Ring)->BufferCache);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_req_id",
                                FrontendGetPath(Frontend));
    if (!NT_SUCCESS(status))
        goto fail4;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_RANGE_SET(Create,
                              &Transmitter->RangeSetInterface,
                              Name,
                              &(*Ring)->RangeSet);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENBUS_RANGE_SET(Put,
                              &Transmitter->RangeSetInterface,
                              (*Ring)->RangeSet,
                              1,
                              XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_transmitter_fragment",
                                FrontendGetPath(Frontend));
    if (!NT_SUCCESS(status))
        goto fail7;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = XENBUS_CACHE(Create,
                          &Transmitter->CacheInterface,
                          Name,
                          sizeof (XENVIF_TRANSMITTER_FRAGMENT),
                          0,
                          TransmitterFragmentCtor,
                          TransmitterFragmentDtor,
                          TransmitterRingAcquireLock,
                          TransmitterRingReleaseLock,
                          (*Ring),
                          &(*Ring)->FragmentCache);
    if (!NT_SUCCESS(status))
        goto fail8;

    status = ThreadCreate(TransmitterRingWatchdog,
                          *Ring,
                          &(*Ring)->WatchdogThread);
    if (!NT_SUCCESS(status))
        goto fail9;

    return STATUS_SUCCESS;

fail9:
    Error("fail9\n");

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 (*Ring)->FragmentCache);
    (*Ring)->FragmentCache = NULL;

fail8:
    Error("fail8\n");

fail7:
    Error("fail7\n");

    (VOID) XENBUS_RANGE_SET(Get,
                            &Transmitter->RangeSetInterface,
                            (*Ring)->RangeSet,
                            1,
                            XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);

fail6:
    Error("fail6\n");

    XENBUS_RANGE_SET(Destroy,
                     &Transmitter->RangeSetInterface,
                     (*Ring)->RangeSet);
    (*Ring)->RangeSet = NULL;

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 (*Ring)->BufferCache);
    (*Ring)->BufferCache = NULL;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    (*Ring)->Queued.TailPacket = NULL;
    (*Ring)->Completed.TailPacket = NULL;
    (*Ring)->Index = 0;
    (*Ring)->Transmitter = NULL;

    ASSERT(IsZeroMemory(*Ring, sizeof (XENVIF_TRANSMITTER_RING)));
    __TransmitterFree(*Ring);
    *Ring = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingConnect(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PFN_NUMBER                      Pfn;
    CHAR                            Name[MAXNAMELEN];
    NTSTATUS                        status;

    ASSERT(!Ring->Connected);

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Ring->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Ring->Mdl == NULL)
        goto fail1;

    Ring->Shared = MmGetSystemAddressForMdlSafe(Ring->Mdl, NormalPagePriority);
    ASSERT(Ring->Shared != NULL);

    SHARED_RING_INIT(Ring->Shared);
    FRONT_RING_INIT(&Ring->Front, Ring->Shared, PAGE_SIZE);
    ASSERT3P(Ring->Front.sring, ==, Ring->Shared);

    Pfn = MmGetMdlPfnArray(Ring->Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 FALSE,
                                 &Ring->Handle);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                __MODULE__ "|TRANSMITTER[%u]",
                                Ring->Index);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_DEBUG(Register,
                          &Transmitter->DebugInterface,
                          Name,
                          TransmitterRingDebugCallback,
                          Ring,
                          &Ring->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail4;

    Ring->Connected = TRUE;

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

fail3:
    Error("fail3\n");

    GranterRevokeAccess(FrontendGetGranter(Frontend),
                        Ring->Handle);
    Ring->Handle = NULL;

fail2:
    Error("fail2\n");

    RtlZeroMemory(&Ring->Front, sizeof (netif_tx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;
    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingStoreWrite(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    status = XENBUS_STORE(Printf,
                          &Transmitter->StoreInterface,
                          Transaction,
                          FrontendGetPath(Frontend),
                          "tx-ring-ref",
                          "%u",
                          GranterGetReference(FrontendGetGranter(Frontend),
                                              Ring->Handle));

    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__TransmitterRingEnable(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingAcquireLock(Ring);

    ASSERT(!Ring->Enabled);
    Ring->Enabled = TRUE;

    __TransmitterRingReleaseLock(Ring);

    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
__TransmitterRingDisable(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{    
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    PXENVIF_TRANSMITTER_PACKET      Packet;
    PCHAR                           Buffer;
    XenbusState                     State;
    ULONG                           Attempt;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    __TransmitterRingAcquireLock(Ring);

    ASSERT(Ring->Enabled);
    Ring->Enabled = FALSE;

    // Release any fragments associated with a pending packet
    Packet = __TransmitterRingUnpreparePacket(Ring);

    // Put any packet back on the head of the queue
    if (Packet != NULL) {
        ASSERT3P(Packet->Next, ==, NULL);

        Packet->Next = Ring->Queued.HeadPacket;

        if (Ring->Queued.TailPacket == &Ring->Queued.HeadPacket)
            Ring->Queued.TailPacket = &Packet->Next;

        Ring->Queued.HeadPacket = Packet;
    }

    Ring->AddressIndex = 0;

    status = XENBUS_STORE(Read,
                          &Transmitter->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "state",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        State = XenbusStateUnknown;
    } else {
        State = (XenbusState)strtol(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    Attempt = 0;
    ASSERT3U(Ring->RequestsPushed, ==, Ring->RequestsPosted);
    while (Ring->ResponsesProcessed != Ring->RequestsPushed) {
        Attempt++;
        ASSERT(Attempt < 100);

        TransmitterRingPoll(Ring);

        if (State != XenbusStateConnected)
            __TransmitterRingFakeResponses(Ring);

        // We are waiting for a watch event at DISPATCH_LEVEL so
        // it is our responsibility to poll the store ring.
        XENBUS_STORE(Poll,
                     &Transmitter->StoreInterface);

        KeStallExecutionProcessor(1000);    // 1ms
    }

    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__TransmitterRingDisconnect(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    ASSERT(Ring->Connected);
    Ring->Connected = FALSE;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT3U(Ring->ResponsesProcessed, ==, Ring->RequestsPushed);
    ASSERT3U(Ring->RequestsPushed, ==, Ring->RequestsPosted);

    Ring->ResponsesProcessed = 0;
    Ring->RequestsPushed = 0;
    Ring->RequestsPosted = 0;

    XENBUS_DEBUG(Deregister,
                 &Transmitter->DebugInterface,
                 Ring->DebugCallback);
    Ring->DebugCallback = NULL;

    GranterRevokeAccess(FrontendGetGranter(Frontend),
                        Ring->Handle);
    Ring->Handle = NULL;

    RtlZeroMemory(&Ring->Front, sizeof (netif_tx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;
    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

}

static FORCEINLINE VOID
__TransmitterRingTeardown(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT3U(Ring->PacketsCompleted, ==, Ring->PacketsSent);
    ASSERT3U(Ring->PacketsSent, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);
    ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
    ASSERT3U(Ring->PacketsQueued, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);

    Ring->PacketsCompleted = 0;
    Ring->PacketsSent = 0;
    Ring->PacketsCopied = 0;
    Ring->PacketsGranted = 0;
    Ring->PacketsFaked = 0;
    Ring->PacketsUnprepared = 0;
    Ring->PacketsPrepared = 0;
    Ring->PacketsQueued = 0;

    if (Ring->AddressCount != 0) {
        ASSERT(Ring->AddressTable != NULL);
        __TransmitterFree(Ring->AddressTable);
    }

    Ring->AddressTable = NULL;
    Ring->AddressCount = 0;

    ThreadAlert(Ring->WatchdogThread);
    ThreadJoin(Ring->WatchdogThread);
    Ring->WatchdogThread = NULL;

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Ring->FragmentCache);
    Ring->FragmentCache = NULL;

    (VOID) XENBUS_RANGE_SET(Get,
                            &Transmitter->RangeSetInterface,
                            Ring->RangeSet,
                            1,
                            XENVIF_TRANSMITTER_MAXIMUM_FRAGMENT_ID);

    XENBUS_RANGE_SET(Destroy,
                     &Transmitter->RangeSetInterface,
                     Ring->RangeSet);
    Ring->RangeSet = NULL;

    XENBUS_CACHE(Destroy,
                 &Transmitter->CacheInterface,
                 Ring->BufferCache);
    Ring->BufferCache = NULL;

    ASSERT3P(Ring->Queued.TailPacket, ==, &Ring->Queued.HeadPacket);
    Ring->Queued.TailPacket = NULL;

    ASSERT3P(Ring->Completed.TailPacket, ==, &Ring->Completed.HeadPacket);
    Ring->Completed.TailPacket = NULL;

    Ring->Index = 0;
    Ring->Transmitter = NULL;

    ASSERT(IsZeroMemory(Ring, sizeof (XENVIF_TRANSMITTER_RING)));
    __TransmitterFree(Ring);
}

static FORCEINLINE VOID
__TransmitterRingQueuePackets(
    IN  PXENVIF_TRANSMITTER_RING    Ring,
    IN  PXENVIF_TRANSMITTER_PACKET  HeadPacket
    )
{
    PXENVIF_TRANSMITTER_PACKET      *TailPacket;
    ULONG_PTR                       Old;
    ULONG_PTR                       LockBit;
    ULONG_PTR                       New;

    TailPacket = &HeadPacket->Next;
    (VOID) __TransmitterReversePacketList(&HeadPacket);
    ASSERT3P(*TailPacket, ==, NULL);

    do {
        Old = (ULONG_PTR)Ring->Lock;
        LockBit = Old & XENVIF_TRANSMITTER_LOCK_BIT;

        *TailPacket = (PVOID)(Old & ~XENVIF_TRANSMITTER_LOCK_BIT);
        New = (ULONG_PTR)HeadPacket;
        ASSERT((New & XENVIF_TRANSMITTER_LOCK_BIT) == 0);
        New |= LockBit;
    } while ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock, (PVOID)New, (PVOID)Old) != Old);

    // __TransmitterRingReleaseLock() drains the atomic packet list into the transmit queue therefore,
    // after adding to the list we need to attempt to grab and release the lock. If we can't
    // grab it then that's ok because whichever thread is holding it will have to call
    // __TransmitterRingReleaseLock() and will therefore drain the atomic packet list.

    if (__TransmitterRingTryAcquireLock(Ring))
        __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__TransmitterRingAbortPackets(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    PXENVIF_TRANSMITTER_PACKET      Packet;

    __TransmitterRingAcquireLock(Ring);

    TransmitterRingSwizzle(Ring);

    Packet = Ring->Queued.HeadPacket;

    Ring->Queued.HeadPacket = NULL;
    Ring->Queued.TailPacket = &Ring->Queued.HeadPacket;

    while (Packet != NULL) {
        PXENVIF_TRANSMITTER_PACKET  Next;
        
        Next = Packet->Next;
        Packet->Next = NULL;

        // Fake that we prapared and sent this packet
        Ring->PacketsPrepared++;
        Ring->PacketsSent++;
        Ring->PacketsFaked++;

        Packet->Completion.Status = XENVIF_TRANSMITTER_PACKET_DROPPED;

        __TransmitterRingCompletePacket(Ring, Packet);

        Packet = Next;
    }

    ASSERT3U(Ring->PacketsSent, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);
    ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
    ASSERT3U(Ring->PacketsQueued, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);

    ASSERT3P((ULONG_PTR)Ring->Lock, ==, XENVIF_TRANSMITTER_LOCK_BIT);
    __TransmitterRingReleaseLock(Ring);
}

static FORCEINLINE VOID
__TransmitterRingNotify(
    IN  PXENVIF_TRANSMITTER_RING    Ring
    )
{
    __TransmitterRingAcquireLock(Ring);
    TransmitterRingPoll(Ring);
    __TransmitterRingReleaseLock(Ring);
}

static VOID
TransmitterDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_TRANSMITTER Transmitter = Argument;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Transmitter->DebugInterface,
                 "OFFSETS: Offset @ %ld Length @ %ld Mdl @ %ld\n",
                 Transmitter->Offset[XENVIF_TRANSMITTER_PACKET_OFFSET_OFFSET],
                 Transmitter->Offset[XENVIF_TRANSMITTER_PACKET_LENGTH_OFFSET],
                 Transmitter->Offset[XENVIF_TRANSMITTER_PACKET_MDL_OFFSET]);
}

NTSTATUS
TransmitterInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  ULONG               Count,
    OUT PXENVIF_TRANSMITTER *Transmitter
    )
{
    HANDLE                  ParametersKey;
    ULONG                   Index;
    NTSTATUS                status;

    *Transmitter = __TransmitterAllocate(sizeof (XENVIF_TRANSMITTER));

    status = STATUS_NO_MEMORY;
    if (*Transmitter == NULL)
        goto fail1;

    ParametersKey = DriverGetParametersKey();

    (*Transmitter)->DisableIpVersion4Gso = 0;
    (*Transmitter)->DisableIpVersion6Gso = 0;
    (*Transmitter)->AlwaysCopy = 0;

    if (ParametersKey != NULL) {
        ULONG   TransmitterDisableIpVersion4Gso;
        ULONG   TransmitterDisableIpVersion6Gso;
        ULONG   TransmitterAlwaysCopy;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterDisableIpVersion4Gso",
                                         &TransmitterDisableIpVersion4Gso);
        if (NT_SUCCESS(status))
            (*Transmitter)->DisableIpVersion4Gso = TransmitterDisableIpVersion4Gso;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterDisableIpVersion6Gso",
                                         &TransmitterDisableIpVersion6Gso);
        if (NT_SUCCESS(status))
            (*Transmitter)->DisableIpVersion6Gso = TransmitterDisableIpVersion6Gso;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "TransmitterAlwaysCopy",
                                         &TransmitterAlwaysCopy);
        if (NT_SUCCESS(status))
            (*Transmitter)->AlwaysCopy = TransmitterAlwaysCopy;
    }

    InitializeListHead(&(*Transmitter)->List);

    FdoGetDebugInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Transmitter)->DebugInterface);

    FdoGetStoreInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Transmitter)->StoreInterface);

    FdoGetRangeSetInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                            &(*Transmitter)->RangeSetInterface);

    FdoGetCacheInterface(PdoGetFdo(FrontendGetPdo(Frontend)),
                         &(*Transmitter)->CacheInterface);

    (*Transmitter)->Frontend = Frontend;

    status = XENBUS_RANGE_SET(Acquire, &(*Transmitter)->RangeSetInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_CACHE(Acquire, &(*Transmitter)->CacheInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    Index = 0;
    while (Index < Count) {
        PXENVIF_TRANSMITTER_RING    Ring;

        status = __TransmitterRingInitialize(*Transmitter, Index, &Ring);
        if (!NT_SUCCESS(status))
            goto fail4;

        InsertTailList(&(*Transmitter)->List, &Ring->ListEntry);
        Index++;
    }

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    while (!IsListEmpty(&(*Transmitter)->List)) {
        PLIST_ENTRY                 ListEntry;
        PXENVIF_TRANSMITTER_RING    Ring;

        ListEntry = RemoveTailList(&(*Transmitter)->List);
        ASSERT3P(ListEntry, !=, &(*Transmitter)->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

        __TransmitterRingTeardown(Ring);
        --Index;
    }
    ASSERT3U(Index, ==, 0);

    XENBUS_CACHE(Release, &(*Transmitter)->CacheInterface);

fail3:
    Error("fail3\n");

    XENBUS_RANGE_SET(Release, &(*Transmitter)->RangeSetInterface);

fail2:
    Error("fail2\n");

    (*Transmitter)->Frontend = NULL;

    RtlZeroMemory(&(*Transmitter)->CacheInterface,
                  sizeof (XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->RangeSetInterface,
                  sizeof (XENBUS_RANGE_SET_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&(*Transmitter)->List, sizeof (LIST_ENTRY));

    (*Transmitter)->DisableIpVersion4Gso = 0;
    (*Transmitter)->DisableIpVersion6Gso = 0;
    (*Transmitter)->AlwaysCopy = 0;
    
    ASSERT(IsZeroMemory(*Transmitter, sizeof (XENVIF_TRANSMITTER)));
    __TransmitterFree(*Transmitter);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
TransmitterConnect(
    IN  PXENVIF_TRANSMITTER     Transmitter
    )
{
    PXENVIF_FRONTEND            Frontend;
    PLIST_ENTRY                 ListEntry;
    NTSTATUS                    status;

    Frontend = Transmitter->Frontend;

    status = XENBUS_DEBUG(Acquire, &Transmitter->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Acquire, &Transmitter->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    for (ListEntry = Transmitter->List.Flink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Flink) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

        status = __TransmitterRingConnect(Ring);
        if (!NT_SUCCESS(status))
            goto fail3;
    }    

    status = XENBUS_DEBUG(Register,
                          &Transmitter->DebugInterface,
                          __MODULE__ "|TRANSMITTER",
                          TransmitterDebugCallback,
                          Transmitter,
                          &Transmitter->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail4;

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    ListEntry = &Transmitter->List;

fail3:
    Error("fail3\n");

    ListEntry = ListEntry->Blink;

    while (ListEntry != &Transmitter->List) {
        PLIST_ENTRY                 Prev = ListEntry->Blink;
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

        __TransmitterRingDisconnect(Ring);

        ListEntry = Prev;
    }

    XENBUS_STORE(Release, &Transmitter->StoreInterface);

fail2:
    Error("fail2\n");

    XENBUS_DEBUG(Release, &Transmitter->DebugInterface);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
TransmitterStoreWrite(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PLIST_ENTRY                     ListEntry;
    NTSTATUS                        status;

    for (ListEntry = Transmitter->List.Flink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Flink) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

        status = __TransmitterRingStoreWrite(Ring, Transaction);
        if (!NT_SUCCESS(status))
            goto fail1;
    }    

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
TransmitterEnable(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PLIST_ENTRY             ListEntry;

    for (ListEntry = Transmitter->List.Flink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Flink) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

        __TransmitterRingEnable(Ring);
    }    

    return STATUS_SUCCESS;
}

VOID
TransmitterDisable(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PLIST_ENTRY             ListEntry;

    for (ListEntry = Transmitter->List.Blink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Blink) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

        __TransmitterRingDisable(Ring);
    }
}

VOID
TransmitterDisconnect(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PXENVIF_FRONTEND        Frontend;
    PLIST_ENTRY             ListEntry;

    Frontend = Transmitter->Frontend;

    XENBUS_DEBUG(Deregister,
                 &Transmitter->DebugInterface,
                 Transmitter->DebugCallback);
    Transmitter->DebugCallback = NULL;

    for (ListEntry = Transmitter->List.Blink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Blink) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

        __TransmitterRingDisconnect(Ring);
    }

    XENBUS_STORE(Release, &Transmitter->StoreInterface);

    XENBUS_DEBUG(Release, &Transmitter->DebugInterface);
}

VOID
TransmitterTeardown(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    RtlZeroMemory(Transmitter->Offset,
                  sizeof (LONG_PTR) *  XENVIF_TRANSMITTER_PACKET_OFFSET_COUNT); 

    while (!IsListEmpty(&Transmitter->List)) {
        PLIST_ENTRY                 ListEntry;
        PXENVIF_TRANSMITTER_RING    Ring;

        ListEntry = RemoveHeadList(&Transmitter->List);
        ASSERT3P(ListEntry, !=, &Transmitter->List);
        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

        __TransmitterRingTeardown(Ring);
    }

    XENBUS_CACHE(Release, &Transmitter->CacheInterface);

    XENBUS_RANGE_SET(Release, &Transmitter->RangeSetInterface);

    Transmitter->Frontend = NULL;

    RtlZeroMemory(&Transmitter->CacheInterface,
                  sizeof (XENBUS_CACHE_INTERFACE));

    RtlZeroMemory(&Transmitter->RangeSetInterface,
                  sizeof (XENBUS_RANGE_SET_INTERFACE));

    RtlZeroMemory(&Transmitter->StoreInterface,
                  sizeof (XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Transmitter->DebugInterface,
                  sizeof (XENBUS_DEBUG_INTERFACE));

    RtlZeroMemory(&Transmitter->List, sizeof (LIST_ENTRY));

    Transmitter->DisableIpVersion4Gso = 0;
    Transmitter->DisableIpVersion6Gso = 0;
    Transmitter->AlwaysCopy = 0;

    ASSERT(IsZeroMemory(Transmitter, sizeof (XENVIF_TRANSMITTER)));
    __TransmitterFree(Transmitter);
}

VOID
TransmitterUpdateAddressTable(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  SOCKADDR_INET           Table[],
    IN  ULONG                   Count
    )
{
    KIRQL                       Irql;
    PLIST_ENTRY                 ListEntry;
    PXENVIF_TRANSMITTER_RING    Ring;

    // Make sure we don't suspend
    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    // Use the first ring for address advertisment
    ListEntry = Transmitter->List.Flink;
    Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

    __TransmitterRingUpdateAddressTable(Ring, Table, Count);

    KeLowerIrql(Irql);
}

VOID
TransmitterAdvertiseAddresses(
    IN  PXENVIF_TRANSMITTER     Transmitter
    )
{
    PLIST_ENTRY                 ListEntry;
    PXENVIF_TRANSMITTER_RING    Ring;

    // Use the first ring for address advertisment
    ListEntry = Transmitter->List.Flink;
    Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

    __TransmitterRingAdvertiseAddresses(Ring);
}

NTSTATUS
TransmitterSetPacketOffset(
    IN  PXENVIF_TRANSMITTER                 Transmitter,
    IN  XENVIF_TRANSMITTER_PACKET_OFFSET    Type,
    IN  LONG_PTR                            Value
    )
{
    NTSTATUS                                status;

    status = STATUS_INVALID_PARAMETER;
    if (Type >= XENVIF_TRANSMITTER_PACKET_OFFSET_COUNT)
        goto fail1;

    Transmitter->Offset[Type] = Value;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
TransmitterQueuePackets(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  HeadPacket
    )
{
    PLIST_ENTRY                     ListEntry;
    PXENVIF_TRANSMITTER_RING        Ring;

    // We need to hash for a ring eventually. Since there is only a
    // single ring for now, we just use that.
    ListEntry = Transmitter->List.Flink;
    Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

    __TransmitterRingQueuePackets(Ring, HeadPacket);
}

VOID
TransmitterAbortPackets(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PLIST_ENTRY             ListEntry;
    KIRQL                   Irql;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    for (ListEntry = Transmitter->List.Flink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Flink) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

        __TransmitterRingAbortPackets(Ring);
    }    

    KeLowerIrql(Irql);
}

VOID
TransmitterQueryRingSize(
    IN  PXENVIF_TRANSMITTER Transmitter,
    OUT PULONG              Size
    )
{
    UNREFERENCED_PARAMETER(Transmitter);

    *Size = XENVIF_TRANSMITTER_RING_SIZE;
}

VOID
TransmitterNotify(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PLIST_ENTRY             ListEntry;

    for (ListEntry = Transmitter->List.Flink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Flink) {
        PXENVIF_TRANSMITTER_RING    Ring;

        Ring = CONTAINING_RECORD(ListEntry, XENVIF_TRANSMITTER_RING, ListEntry);

        __TransmitterRingNotify(Ring);
    }    
}

VOID
TransmitterQueryOffloadOptions(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS Options
    )
{
    PXENVIF_FRONTEND                Frontend;
    PCHAR                           Buffer;
    NTSTATUS                        status;

    Frontend = Transmitter->Frontend;

    Options->Value = 0;

    Options->OffloadTagManipulation = 1;

    if (Transmitter->DisableIpVersion4Gso == 0) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv4",
                              &Buffer);
    } else {
        Buffer = NULL;
        status = STATUS_NOT_SUPPORTED;
    }

    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion4LargePacket = 0;
    } else {
        Options->OffloadIpVersion4LargePacket = (USHORT)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    if (Transmitter->DisableIpVersion6Gso == 0) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv6",
                              &Buffer);
    } else {
        Buffer = NULL;
        status = STATUS_NOT_SUPPORTED;
    }

    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion6LargePacket = 0;
    } else {
        Options->OffloadIpVersion6LargePacket = (USHORT)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    Options->OffloadIpVersion4HeaderChecksum = 1;

    status = XENBUS_STORE(Read,
                          &Transmitter->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-no-csum-offload",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion4TcpChecksum = 1;
        Options->OffloadIpVersion4UdpChecksum = 1;
    } else {
        BOOLEAN Flag;

        Flag = (BOOLEAN)strtol(Buffer, NULL, 2);

        Options->OffloadIpVersion4TcpChecksum = (Flag) ? 0 : 1;
        Options->OffloadIpVersion4UdpChecksum = (Flag) ? 0 : 1;

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Transmitter->StoreInterface,
                          NULL,
                          FrontendGetBackendPath(Frontend),
                          "feature-ipv6-csum-offload",
                          &Buffer);
    if (!NT_SUCCESS(status)) {
        Options->OffloadIpVersion6TcpChecksum = 0;
        Options->OffloadIpVersion6UdpChecksum = 0;
    } else {
        BOOLEAN Flag;

        Flag = (BOOLEAN)strtol(Buffer, NULL, 2);

        Options->OffloadIpVersion6TcpChecksum = (Flag) ? 1 : 0;
        Options->OffloadIpVersion6UdpChecksum = (Flag) ? 1 : 0;

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }
}

#define XENVIF_TRANSMITTER_MAXIMUM_REQ_SIZE  ((1 << (RTL_FIELD_SIZE(netif_tx_request_t, size) * 8)) - 1)

#define XENVIF_TRANSMITTER_MAXIMUM_TCPV4_PAYLOAD_SIZE   (XENVIF_TRANSMITTER_MAXIMUM_REQ_SIZE -  \
                                                         sizeof (ETHERNET_HEADER) -             \
                                                         MAXIMUM_IPV4_HEADER_LENGTH -           \
                                                         MAXIMUM_TCP_HEADER_LENGTH)

#define XENVIF_TRANSMITTER_MAXIMUM_TCPV6_PAYLOAD_SIZE   (XENVIF_TRANSMITTER_MAXIMUM_REQ_SIZE -  \
                                                         sizeof (ETHERNET_HEADER) -             \
                                                         MAXIMUM_IPV6_HEADER_LENGTH -           \
                                                         MAXIMUM_IPV6_OPTIONS_LENGTH -          \
                                                         MAXIMUM_TCP_HEADER_LENGTH)

VOID
TransmitterQueryLargePacketSize(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  UCHAR                   Version,
    OUT PULONG                  Size
    )
{
    PXENVIF_FRONTEND            Frontend;
    PCHAR                       Buffer;
    ULONG                       OffloadIpLargePacket;
    NTSTATUS                    status;

    Frontend = Transmitter->Frontend;

    if (Version == 4) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv4",
                              &Buffer);
    } else if (Version == 6) {
        status = XENBUS_STORE(Read,
                              &Transmitter->StoreInterface,
                              NULL,
                              FrontendGetBackendPath(Frontend),
                              "feature-gso-tcpv6",
                              &Buffer);
    } else {
        Buffer = NULL;
        status = STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status)) {
        OffloadIpLargePacket = 0;
    } else {
        OffloadIpLargePacket = (ULONG)strtol(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Transmitter->StoreInterface,
                     Buffer);
    }

    // The OffloadParity certification test requires that we have a single LSO size for IPv4 and IPv6 packets
    *Size = (OffloadIpLargePacket) ?
            __min(XENVIF_TRANSMITTER_MAXIMUM_TCPV4_PAYLOAD_SIZE,
                 XENVIF_TRANSMITTER_MAXIMUM_TCPV6_PAYLOAD_SIZE) :
            0;
}
