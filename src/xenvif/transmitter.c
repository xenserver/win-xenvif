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
#include <xen.h>
#include <debug_interface.h>
#include <store_interface.h>
#include <cache_interface.h>
#include <gnttab_interface.h>

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
#include "netio.h"
#include "dbg_print.h"
#include "assert.h"

#ifndef XEN_NETIF_GSO_TYPE_TCPV6
#define XEN_NETIF_GSO_TYPE_TCPV6    2
#endif

#define MAXNAMELEN  128

#define TRANSMITTER_POOL    'NART'

typedef struct _TRANSMITTER_BUFFER {
    PMDL        Mdl;
    PVOID       Context;
    ULONG       Reference;
} TRANSMITTER_BUFFER, *PTRANSMITTER_BUFFER;

typedef enum _TRANSMITTER_TAG_TYPE {
    TAG_TYPE_INVALID = 0,
    TAG_PACKET,
    TAG_BUFFER
} TRANSMITTER_TAG_TYPE, *PTRANSMITTER_TAG_TYPE;

typedef struct _TRANSMITTER_TAG {
    LIST_ENTRY              ListEntry;
    ULONG                   Next;
    TRANSMITTER_TAG_TYPE    Type;
    PVOID                   Context;
    XENVIF_GRANTER_HANDLE   Handle;
    ULONG                   Offset;
    ULONG                   Length;
} TRANSMITTER_TAG, *PTRANSMITTER_TAG;

typedef struct _TRANSMITTER_OFFLOAD_STATISTICS {
    ULONGLONG   TagManipulation;
    ULONGLONG   IpVersion4LargePacket;
    ULONGLONG   IpVersion6LargePacket;
    ULONGLONG   IpVersion4HeaderChecksum;
    ULONGLONG   IpVersion4TcpChecksum;
    ULONGLONG   IpVersion6TcpChecksum;
    ULONGLONG   IpVersion4UdpChecksum;
    ULONGLONG   IpVersion6UdpChecksum;
} TRANSMITTER_OFFLOAD_STATISTICS, *PTRANSMITTER_OFFLOAD_STATISTICS;

typedef struct _TRANSMITTER_STATE {
    PXENVIF_TRANSMITTER_PACKET  Packet;
    XENVIF_SEND_INFO            Send;
    PUCHAR                      StartVa;
    XENVIF_PACKET_INFO          Info;
    XENVIF_PACKET_PAYLOAD       Payload;
    LIST_ENTRY                  List;
    ULONG                       Count;
} TRANSMITTER_STATE, *PTRANSMITTER_STATE;

#define TRANSMITTER_RING_SIZE   (__CONST_RING_SIZE(netif_tx, PAGE_SIZE))
#define MAXIMUM_TAG_COUNT       (TRANSMITTER_RING_SIZE * 2)

#define TAG_INDEX_INVALID       0xFFFFFFFF

#define REQ_ID_INTEGRITY_CHECK  0xF000

typedef struct _TRANSMITTER_PACKET_LIST {
    PXENVIF_TRANSMITTER_PACKET  HeadPacket;
    PXENVIF_TRANSMITTER_PACKET  *TailPacket;
} TRANSMITTER_PACKET_LIST, *PTRANSMITTER_PACKET_LIST;

typedef struct _TRANSMITTER_RING {
    PXENVIF_TRANSMITTER                     Transmitter;
    LIST_ENTRY                              ListEntry;
    PXENBUS_CACHE                           BufferCache;
    PMDL                                    Mdl;
    netif_tx_front_ring_t                   Front;
    netif_tx_sring_t                        *Shared;
    XENVIF_GRANTER_HANDLE                   Handle;
    BOOLEAN                                 Connected;
    BOOLEAN                                 Enabled;
    BOOLEAN                                 Stopped;
    PXENVIF_TRANSMITTER_PACKET              Lock;
    PKTHREAD                                LockThread;
    TRANSMITTER_PACKET_LIST                 Queued;
    TRANSMITTER_STATE                       State;
    ULONG                                   PacketsQueued;
    ULONG                                   PacketsGranted;
    ULONG                                   PacketsCopied;
    ULONG                                   PacketsFaked;
    ULONG                                   PacketsUnprepared;
    ULONG                                   PacketsPrepared;
    ULONG                                   HeadFreeTag;
    TRANSMITTER_TAG                         Tag[MAXIMUM_TAG_COUNT];
    netif_tx_request_t                      Pending[MAXIMUM_TAG_COUNT];
    ULONG                                   RequestsPosted;
    ULONG                                   RequestsPushed;
    ULONG                                   ResponsesProcessed;
    ULONG                                   PacketsSent;
    TRANSMITTER_PACKET_LIST                 Completed;
    ULONG                                   PacketsCompleted;
    PSOCKADDR_INET                          AddressTable;
    ULONG                                   AddressCount;
    ULONG                                   AddressIndex;
    PXENVIF_THREAD                          Thread;
    XENVIF_TRANSMITTER_PACKET_STATISTICS    PacketStatistics;
    XENVIF_HEADER_STATISTICS                HeaderStatistics;
    TRANSMITTER_OFFLOAD_STATISTICS          OffloadStatistics;
} TRANSMITTER_RING, *PTRANSMITTER_RING;

struct _XENVIF_TRANSMITTER {
    PXENVIF_FRONTEND                    Frontend;
    LIST_ENTRY                          List;
    XENVIF_TRANSMITTER_PACKET_METADATA  Metadata;

    ULONG                               DisableIpVersion4Gso;
    ULONG                               DisableIpVersion6Gso;
    ULONG                               AlwaysCopy;

    PXENBUS_DEBUG_INTERFACE             DebugInterface;
    PXENBUS_STORE_INTERFACE             StoreInterface;
    PXENBUS_CACHE_INTERFACE             CacheInterface;
    PXENVIF_VIF_INTERFACE               VifInterface;

    PXENBUS_DEBUG_CALLBACK              DebugCallback;
};

#define MAX_SKB_FRAGS   18

static FORCEINLINE PVOID
__TransmitterAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, TRANSMITTER_POOL);
}

static FORCEINLINE VOID
__TransmitterFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, TRANSMITTER_POOL);
}

static NTSTATUS
TransmitterBufferCtor(
    IN  PVOID           Argument,
    IN  PVOID           Object
    )
{
    PTRANSMITTER_BUFFER Buffer = Object;
    PMDL		        Mdl;
    PUCHAR		        MdlMappedSystemVa;
    NTSTATUS	        status;

    UNREFERENCED_PARAMETER(Argument);

    ASSERT(IsZeroMemory(Buffer, sizeof (TRANSMITTER_BUFFER)));

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

    ASSERT(IsZeroMemory(Buffer, sizeof (TRANSMITTER_BUFFER)));

    return status;
}

static VOID
TransmitterBufferDtor(
    IN  PVOID           Argument,
    IN  PVOID           Object
    )
{
    PTRANSMITTER_BUFFER Buffer = Object;
    PMDL                Mdl;

    UNREFERENCED_PARAMETER(Argument);

    Mdl = Buffer->Mdl;
    Buffer->Mdl = NULL;

    Mdl->ByteCount = PAGE_SIZE;

    __FreePage(Mdl);
    ExFreePool(Mdl);

    ASSERT(IsZeroMemory(Buffer, sizeof (TRANSMITTER_BUFFER)));
}

static FORCEINLINE PTRANSMITTER_BUFFER
__TransmitterGetBuffer(
    IN  PTRANSMITTER_RING   Ring
    )
{
    PXENVIF_TRANSMITTER     Transmitter;
    PTRANSMITTER_BUFFER     Buffer;

    Transmitter = Ring->Transmitter;

    Buffer = CACHE(Get,
                   Transmitter->CacheInterface,
                   Ring->BufferCache,
                   TRUE);

    ASSERT(IMPLY(Buffer != NULL, Buffer->Mdl->ByteCount == 0));

    return Buffer;
}

static FORCEINLINE VOID
__TransmitterPutBuffer(
    IN  PTRANSMITTER_RING   Ring,
    IN  PTRANSMITTER_BUFFER Buffer
    )
{
    PXENVIF_TRANSMITTER     Transmitter;

    Transmitter = Ring->Transmitter;

    ASSERT3U(Buffer->Reference, ==, 0);
    ASSERT3P(Buffer->Context, ==, NULL);

    Buffer->Mdl->ByteCount = 0;

    CACHE(Put,
          Transmitter->CacheInterface,
          Ring->BufferCache,
          Buffer,
          TRUE);
}

static FORCEINLINE PTRANSMITTER_TAG
__TransmitterGetTag(
    IN  PTRANSMITTER_RING   Ring
    )
{
    ULONG                   Index;
    PTRANSMITTER_TAG        Tag;

    Index = Ring->HeadFreeTag;
    ASSERT3U(Index, <, MAXIMUM_TAG_COUNT);

    Tag = &Ring->Tag[Index];
    Ring->HeadFreeTag = Tag->Next;
    Tag->Next = TAG_INDEX_INVALID;

    return Tag;
}

static FORCEINLINE
__TransmitterPutTag(
    IN  PTRANSMITTER_RING   Ring,
    IN  PTRANSMITTER_TAG    Tag
    )
{
    ULONG                   Index;

    ASSERT3U(Tag->Length, ==, 0);
    ASSERT3U(Tag->Offset, ==, 0);
    ASSERT3U(Tag->Type, ==, TAG_TYPE_INVALID);
    ASSERT3P(Tag->Context, ==, NULL);

    Index = (ULONG)(Tag - &Ring->Tag[0]);
    ASSERT3U(Index, <, MAXIMUM_TAG_COUNT);

    ASSERT3U(Tag->Next, ==, TAG_INDEX_INVALID);
    Tag->Next = Ring->HeadFreeTag;
    Ring->HeadFreeTag = Index;
}

static FORCEINLINE VOID
__RingDebugCallback(
    IN  PTRANSMITTER_RING   Ring
    )
{
    PXENVIF_TRANSMITTER     Transmitter;

    Transmitter = Ring->Transmitter;

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "0x%p [%s]\n",
          Ring,
          (Ring->Enabled) ? "ENABLED" : "DISABLED");

    // Dump front ring
    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "FRONT: req_prod_pvt = %u rsp_cons = %u nr_ents = %u sring = %p\n",
          Ring->Front.req_prod_pvt,
          Ring->Front.rsp_cons,
          Ring->Front.nr_ents,
          Ring->Front.sring);

    // Dump shared ring
    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
          Ring->Shared->req_prod,
          Ring->Shared->req_event,
          Ring->Shared->rsp_prod,
          Ring->Shared->rsp_event);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "RequestsPosted = %u RequestsPushed = %u ResponsesProcessed = %u\n",
          Ring->RequestsPosted,
          Ring->RequestsPushed,
          Ring->ResponsesProcessed);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "State:\n");

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Packet = %p\n",
          Ring->State.Packet);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Count = %u\n",
          Ring->State.Count);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "PacketsGranted = %u PacketsCopied = %u PacketsFaked = %u\n",
          Ring->PacketsGranted,
          Ring->PacketsCopied,
          Ring->PacketsFaked);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "PacketsQueued = %u PacketsPrepared = %u PacketsUnprepared = %u PacketsSent = %u PacketsCompleted = %u\n",
          Ring->PacketsQueued,
          Ring->PacketsPrepared,
          Ring->PacketsUnprepared,
          Ring->PacketsSent,
          Ring->PacketsCompleted);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "PacketStatistics:\n");

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Drop = %u\n",
          Ring->PacketStatistics.Drop);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- BackendError = %u\n",
          Ring->PacketStatistics.BackendError);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- FrontendError = %u\n",
          Ring->PacketStatistics.FrontendError);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Unicast = %u\n",
          Ring->PacketStatistics.Unicast);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- UnicastBytes = %u\n",
          Ring->PacketStatistics.UnicastBytes);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Multicast = %u\n",
          Ring->PacketStatistics.Multicast);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- MulticastBytes = %u\n",
          Ring->PacketStatistics.MulticastBytes);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Broadcast = %u\n",
          Ring->PacketStatistics.Broadcast);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- BroadcastBytes = %u\n",
          Ring->PacketStatistics.BroadcastBytes);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "HeaderStatistics:\n");

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Tagged = %u\n",
          Ring->HeaderStatistics.Tagged);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- LLC = %u\n",
          Ring->HeaderStatistics.LLC);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Ip Version4 = %u\n",
          Ring->HeaderStatistics.IpVersion4);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Ip Version6 = %u\n",
          Ring->HeaderStatistics.IpVersion6);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Ip Options = %u\n",
          Ring->HeaderStatistics.IpOptions);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Tcp = %u\n",
          Ring->HeaderStatistics.Tcp);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Tcp Options = %u\n",
          Ring->HeaderStatistics.TcpOptions);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- Udp = %u\n",
          Ring->HeaderStatistics.Udp);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "OffloadStatistics:\n");

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- TagManipulation = %u\n",
          Ring->OffloadStatistics.TagManipulation);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- IpVersion4LargePacket = %u\n",
          Ring->OffloadStatistics.IpVersion4LargePacket);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- IpVersion6LargePacket = %u\n",
          Ring->OffloadStatistics.IpVersion6LargePacket);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- IpVersion4HeaderChecksum = %u\n",
          Ring->OffloadStatistics.IpVersion4HeaderChecksum);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- IpVersion4TcpChecksum = %u\n",
          Ring->OffloadStatistics.IpVersion4TcpChecksum);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- IpVersion6TcpChecksum = %u\n",
          Ring->OffloadStatistics.IpVersion6TcpChecksum);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- IpVersion4UdpChecksum = %u\n",
          Ring->OffloadStatistics.IpVersion4UdpChecksum);

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "- IpVersion6UdpChecksum = %u\n",
          Ring->OffloadStatistics.IpVersion6UdpChecksum);

    if (Ring->AddressCount != 0) {
        ULONG   Index;

        for (Index = 0; Index < Ring->AddressCount; Index++) {
            switch (Ring->AddressTable[Index].si_family) {
            case AF_INET: {
                IPV4_ADDRESS    Address;

                RtlCopyMemory(Address.Byte,
                              &Ring->AddressTable[Index].Ipv4.sin_addr.s_addr,
                              IPV4_ADDRESS_LENGTH);

                DEBUG(Printf,
                      Transmitter->DebugInterface,
                      Transmitter->DebugCallback,
                      "AddressTable[%u]: %u.%u.%u.%u\n",
                      Index,
                      Address.Byte[0],
                      Address.Byte[1],
                      Address.Byte[2],
                      Address.Byte[3]);
                break;
            }
            case AF_INET6: {
                IPV6_ADDRESS    Address;

                RtlCopyMemory(Address.Byte,
                              &Ring->AddressTable[Index].Ipv6.sin6_addr.s6_addr,
                              IPV6_ADDRESS_LENGTH);

                DEBUG(Printf,
                      Transmitter->DebugInterface,
                      Transmitter->DebugCallback,
                      "AddressTable[%u]: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
                      Index,
                      NTOHS(Address.Word[0]),
                      NTOHS(Address.Word[1]),
                      NTOHS(Address.Word[2]),
                      NTOHS(Address.Word[3]),
                      NTOHS(Address.Word[4]),
                      NTOHS(Address.Word[5]),
                      NTOHS(Address.Word[6]),
                      NTOHS(Address.Word[7]));
                break;
            }
            }
        }
    }
}

static BOOLEAN
TransmitterPullup(
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
            (*Reference)++;                                         \
        } while (FALSE)

#define DECREMENT_PACKET_REFERENCE(_Packet)                         \
        do {                                                        \
            PULONG_PTR Reference = (PULONG_PTR)&(_Packet)->Next;    \
                                                                    \
            ASSERT(*Reference != 0);                                \
            --(*Reference);                                         \
        } while (FALSE)

#define PACKET_REFERENCE(_Packet)                                   \
        (*(PULONG_PTR)&(_Packet)->Next)

static FORCEINLINE NTSTATUS
__RingCopyPayload(
    IN  PTRANSMITTER_RING       Ring
    )
{
    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_FRONTEND            Frontend;
    PTRANSMITTER_STATE          State;
    PXENVIF_TRANSMITTER_PACKET  Packet;
    XENVIF_PACKET_PAYLOAD       Payload;
    PTRANSMITTER_TAG            Tag;
    PTRANSMITTER_BUFFER         Buffer;
    NTSTATUS                    status;

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
        TransmitterPullup(NULL, MdlMappedSystemVa, &Payload, Length);

        Mdl->ByteCount = Length;

        Tag = __TransmitterGetTag(Ring);

        Tag->Type = TAG_BUFFER;
        Tag->Context = Buffer;
        Buffer->Reference++;

        Pfn = MmGetMdlPfnArray(Mdl)[0];

        status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                     Pfn,
                                     TRUE,
                                     &Tag->Handle);
        if (!NT_SUCCESS(status))
            goto fail2;

        Tag->Offset = 0;
        Tag->Length = Mdl->ByteCount;

        ASSERT(IsZeroMemory(&Tag->ListEntry, sizeof (LIST_ENTRY)));
        InsertTailList(&State->List, &Tag->ListEntry);
        State->Count++;

        ASSERT3U(State->Count, <=, MAX_SKB_FRAGS + 1);
    }

    Ring->PacketsCopied++;
    return STATUS_SUCCESS;

fail2:
    if (status != STATUS_INSUFFICIENT_RESOURCES)
        Error("fail2\n");

    ASSERT3U(Tag->Type, ==, TAG_BUFFER);
    ASSERT3P(Buffer, ==, Tag->Context);
    Tag->Context = NULL;
    Tag->Type = TAG_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutTag(Ring, Tag);

    ASSERT3P(Buffer->Context, ==, Packet);
    Buffer->Context = NULL;        

    DECREMENT_PACKET_REFERENCE(Packet);

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    if (status != STATUS_INSUFFICIENT_RESOURCES)
        Error("fail1 (%08x)\n", status);

    while (PACKET_REFERENCE(Packet) != 1) {
        PLIST_ENTRY         ListEntry;

        ASSERT(State->Count != 0);
        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Tag = CONTAINING_RECORD(ListEntry, TRANSMITTER_TAG, ListEntry);

        Tag->Length = 0;
        Tag->Offset = 0;

        GranterRevokeAccess(FrontendGetGranter(Frontend),
                            Tag->Handle);
        Tag->Handle = NULL;

        ASSERT3U(Tag->Type, ==, TAG_BUFFER);
        Buffer = Tag->Context;
        Tag->Context = NULL;
        Tag->Type = TAG_TYPE_INVALID;

        ASSERT(Buffer->Reference != 0);
        --Buffer->Reference;

        __TransmitterPutTag(Ring, Tag);

        ASSERT3P(Buffer->Context, ==, Packet);
        Buffer->Context = NULL;        

        DECREMENT_PACKET_REFERENCE(Packet);

        __TransmitterPutBuffer(Ring, Buffer);
    }

    return status;
}

static FORCEINLINE NTSTATUS
__RingGrantPayload(
    IN  PTRANSMITTER_RING       Ring
    )
{
    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_FRONTEND            Frontend;
    PTRANSMITTER_STATE          State;
    PXENVIF_TRANSMITTER_PACKET  Packet;
    PXENVIF_PACKET_PAYLOAD      Payload;
    PMDL                        Mdl;
    ULONG                       Offset;
    ULONG                       Length;
    PTRANSMITTER_TAG            Tag;
    NTSTATUS                    status;

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

            Tag = __TransmitterGetTag(Ring);

            Tag->Type = TAG_PACKET;
            Tag->Context = Packet;
            INCREMENT_PACKET_REFERENCE(Packet);

            Pfn = MmGetMdlPfnArray(Mdl)[MdlOffset / PAGE_SIZE];
            PageOffset = MdlOffset & (PAGE_SIZE - 1);
            PageLength = __min(MdlLength, PAGE_SIZE - PageOffset);

            status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                         Pfn,
                                         TRUE,
                                         &Tag->Handle);
            if (!NT_SUCCESS(status))
                goto fail1;

            Tag->Offset = PageOffset;
            Tag->Length = PageLength;

            ASSERT(IsZeroMemory(&Tag->ListEntry, sizeof (LIST_ENTRY)));
            InsertTailList(&State->List, &Tag->ListEntry);
            State->Count++;

            Tag = NULL;

            // Bounce the packet if it is too highly fragmented
            status = STATUS_BUFFER_OVERFLOW;
            if (State->Count > MAX_SKB_FRAGS + 1)
                goto fail2;

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

fail2:
fail1:
    if (status != STATUS_INSUFFICIENT_RESOURCES &&
        status != STATUS_BUFFER_OVERFLOW)
        Error("fail1 (%08x)\n", status);

    if (Tag != NULL) {
        Tag->Context = NULL;
        Tag->Type = TAG_TYPE_INVALID;

        DECREMENT_PACKET_REFERENCE(Packet);

        __TransmitterPutTag(Ring, Tag);
    }

    while (PACKET_REFERENCE(Packet) != 1) {
        PLIST_ENTRY         ListEntry;

        ASSERT(State->Count != 0);
        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Tag = CONTAINING_RECORD(ListEntry, TRANSMITTER_TAG, ListEntry);

        Tag->Length = 0;
        Tag->Offset = 0;

        GranterRevokeAccess(FrontendGetGranter(Frontend),
                            Tag->Handle);
        Tag->Handle = NULL;

        Tag->Context = NULL;
        Tag->Type = TAG_TYPE_INVALID;

        DECREMENT_PACKET_REFERENCE(Packet);

        __TransmitterPutTag(Ring, Tag);
    }

    return status;
}

static FORCEINLINE NTSTATUS
__RingPrepareHeader(
    IN  PTRANSMITTER_RING       Ring
    )
{
    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_MAC                 Mac;
    PTRANSMITTER_STATE          State;
    PXENVIF_TRANSMITTER_PACKET  Packet;
    PXENVIF_PACKET_PAYLOAD      Payload;
    PXENVIF_PACKET_INFO         Info;
    PTRANSMITTER_TAG            Tag;
    PTRANSMITTER_BUFFER         Buffer;
    PMDL                        Mdl;
    PUCHAR                      StartVa;
    PFN_NUMBER                  Pfn;
    PETHERNET_HEADER            EthernetHeader;
    NTSTATUS                    status;

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

    status = ParsePacket(StartVa, TransmitterPullup, NULL, &Ring->HeaderStatistics, Payload, Info);
    if (!NT_SUCCESS(status))
        goto fail2;

    State->StartVa = StartVa;

    Mdl->ByteCount = Info->Length;

    Tag = __TransmitterGetTag(Ring);

    Tag->Context = Buffer;
    Tag->Type = TAG_BUFFER;
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 TRUE,
                                 &Tag->Handle);
    if (!NT_SUCCESS(status))
        goto fail3;

    Tag->Offset = 0;
    Tag->Length = Mdl->ByteCount + Payload->Length;

    ASSERT(IsZeroMemory(&Tag->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Tag->ListEntry);
    State->Count++;

    ASSERT(Info->EthernetHeader.Length != 0);
    EthernetHeader = (PETHERNET_HEADER)(StartVa + Info->EthernetHeader.Offset);        

    if (State->Send.OffloadOptions.OffloadTagManipulation) {
        ULONG   Offset;

        Ring->OffloadStatistics.TagManipulation++;

        ASSERT(!ETHERNET_HEADER_IS_TAGGED(EthernetHeader));

        Offset = FIELD_OFFSET(ETHERNET_TAGGED_HEADER, Tag);

        RtlMoveMemory((PUCHAR)EthernetHeader + Offset + sizeof (ETHERNET_TAG),
                      (PUCHAR)EthernetHeader + Offset,
                      Mdl->ByteCount - Offset);

        // Insert the tag
        EthernetHeader->Tagged.Tag.ProtocolID = HTONS(ETHERTYPE_TPID);
        EthernetHeader->Tagged.Tag.ControlInformation = HTONS(State->Send.TagControlInformation);
        ASSERT(ETHERNET_HEADER_IS_TAGGED(EthernetHeader));

        Ring->HeaderStatistics.Tagged++;

        Mdl->ByteCount += sizeof (ETHERNET_TAG);
        Tag->Length += sizeof (ETHERNET_TAG);

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

        ASSERT(!Info->Flags.IsAFragment);

        Ring->OffloadStatistics.IpVersion4LargePacket++;

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

        ASSERT(!Info->Flags.IsAFragment);

        Ring->OffloadStatistics.IpVersion6LargePacket++;

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

        MaximumFrameSize = MacGetMaximumFrameSize(Mac);
        
        if (Tag->Length > MaximumFrameSize) {
            status = STATUS_INVALID_PARAMETER;
            goto fail4;
        }
    }

    if (State->Send.OffloadOptions.OffloadIpVersion4HeaderChecksum) {
        PIP_HEADER  IpHeader;

        ASSERT(Info->IpHeader.Length != 0);
        IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

        ASSERT3U(IpHeader->Version, ==, 4);
        IpHeader->Version4.Checksum = ChecksumIpVersion4Header(StartVa, Info);

        Ring->OffloadStatistics.IpVersion4HeaderChecksum++;
    }

    if (State->Send.OffloadOptions.OffloadIpVersion4TcpChecksum) {
        ASSERT(!Info->Flags.IsAFragment);
        Ring->OffloadStatistics.IpVersion4TcpChecksum++;
    }

    if (State->Send.OffloadOptions.OffloadIpVersion6TcpChecksum) {
        ASSERT(!Info->Flags.IsAFragment);
        Ring->OffloadStatistics.IpVersion6TcpChecksum++;
    }

    if (State->Send.OffloadOptions.OffloadIpVersion4UdpChecksum) {
        ASSERT(!Info->Flags.IsAFragment);
        Ring->OffloadStatistics.IpVersion4UdpChecksum++;
    }

    if (State->Send.OffloadOptions.OffloadIpVersion6UdpChecksum) {
        ASSERT(!Info->Flags.IsAFragment);
        Ring->OffloadStatistics.IpVersion6UdpChecksum++;
    }

    return STATUS_SUCCESS;

fail4:
    if (status != STATUS_INVALID_PARAMETER)
        Error("fail4\n");

    ASSERT(State->Count != 0);
    --State->Count;

    RemoveEntryList(&Tag->ListEntry);
    RtlZeroMemory(&Tag->ListEntry, sizeof (LIST_ENTRY));

    Tag->Length = 0;
    Tag->Offset = 0;

    GranterRevokeAccess(FrontendGetGranter(Frontend),
                        Tag->Handle);
    Tag->Handle = NULL;

fail3:
    if (status != STATUS_INSUFFICIENT_RESOURCES &&
        status != STATUS_INVALID_PARAMETER)
        Error("fail3\n");

    Tag->Context = NULL;
    Tag->Type = TAG_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutTag(Ring, Tag);

    Mdl->ByteCount = 0;

fail2:
    if (status != STATUS_INSUFFICIENT_RESOURCES &&
        status != STATUS_INVALID_PARAMETER)
        Error("fail2\n");

    DECREMENT_PACKET_REFERENCE(Packet);
    Buffer->Context = NULL;

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    if (status != STATUS_INSUFFICIENT_RESOURCES &&
        status != STATUS_INVALID_PARAMETER)
        Error("fail1 (%08x)\n", status);

    ASSERT3U(PACKET_REFERENCE(Packet), ==, 0);

    return status;
}

static FORCEINLINE VOID
__RingUnprepareTags(
    IN  PTRANSMITTER_RING   Ring
    )
{
    PXENVIF_TRANSMITTER     Transmitter;
    PXENVIF_FRONTEND        Frontend;
    PTRANSMITTER_STATE      State;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;

    while (State->Count != 0) {
        PLIST_ENTRY                 ListEntry;
        PTRANSMITTER_TAG            Tag;
        PXENVIF_TRANSMITTER_PACKET  Packet;

        --State->Count;

        ListEntry = RemoveTailList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Tag = CONTAINING_RECORD(ListEntry, TRANSMITTER_TAG, ListEntry);

        Tag->Length = 0;
        Tag->Offset = 0;

        GranterRevokeAccess(FrontendGetGranter(Frontend),
                            Tag->Handle);
        Tag->Handle = NULL;

        switch (Tag->Type) {
        case TAG_BUFFER: {
            PTRANSMITTER_BUFFER Buffer;

            Buffer = Tag->Context;
            Tag->Context = NULL;
            Tag->Type = TAG_TYPE_INVALID;

            Packet = Buffer->Context;
            Buffer->Context = NULL;

            ASSERT(Buffer->Reference != 0);
            if (--Buffer->Reference == 0)
                __TransmitterPutBuffer(Ring, Buffer);

            break;
        }
        case TAG_PACKET:
            Packet = Tag->Context;
            Tag->Context = NULL;
            Tag->Type = TAG_TYPE_INVALID;

            break;

        default:
            Packet = NULL;
            ASSERT(FALSE);
        }

        __TransmitterPutTag(Ring, Tag);

        if (Packet != NULL)
            DECREMENT_PACKET_REFERENCE(Packet);
    }
}

static FORCEINLINE NTSTATUS
__RingPreparePacket(
    IN  PTRANSMITTER_RING           Ring,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
#define METADATA_EXISTS(_Ring, _Packet, _Type)                                          \
        ((_Ring)->Transmitter->Metadata. _Type ## Offset != 0)

#define METADATA(_Ring, _Packet, _Type)                                                 \
        ((METADATA_EXISTS(_Ring, _Packet, _Type)) ?                                     \
         (PVOID)((PUCHAR)(_Packet) + (_Ring)->Transmitter->Metadata. _Type ## Offset) : \
         NULL)

    PXENVIF_TRANSMITTER             Transmitter;
    PTRANSMITTER_STATE              State;
    PXENVIF_PACKET_PAYLOAD          Payload;
    PXENVIF_PACKET_INFO             Info;
    NTSTATUS                        status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (TRANSMITTER_STATE)));
    ASSERT3P(Packet->Next, ==, NULL);

    Transmitter = Ring->Transmitter;

    State = &Ring->State;

    State->Packet = Packet;

    State->Send = Packet->Send;
    RtlZeroMemory(&Packet->Send, sizeof (XENVIF_SEND_INFO));

    Payload = &State->Payload;

    ASSERT(METADATA_EXISTS(Ring, Packet, Mdl));
    Payload->Mdl = *(PMDL *)METADATA(Ring, Packet, Mdl);

    if (METADATA_EXISTS(Ring, Packet, Offset))
        Payload->Offset = *(PULONG)METADATA(Ring, Packet, Offset);
    else
        Payload->Offset = 0;

    ASSERT(METADATA_EXISTS(Ring, Packet, Length));
    Payload->Length = *(PULONG)METADATA(Ring, Packet, Length);

    InitializeListHead(&State->List);
    ASSERT3U(State->Count, ==, 0);

    status = __RingPrepareHeader(Ring);
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

        status = __RingCopyPayload(Ring);

        if (NT_SUCCESS(status)) {
            PLIST_ENTRY         ListEntry;
            PTRANSMITTER_TAG    Tag;
            PTRANSMITTER_BUFFER Buffer;
            PMDL                Mdl;
            PUCHAR              MdlMappedSystemVa;

            // Add padding to the tail buffer
            ListEntry = State->List.Blink;
            Tag = CONTAINING_RECORD(ListEntry, TRANSMITTER_TAG, ListEntry);

            ASSERT3U(Tag->Type, ==, TAG_BUFFER);
            Buffer = Tag->Context;

            Mdl = Buffer->Mdl;

            ASSERT3U(Mdl->ByteCount, <=, PAGE_SIZE - Trailer);

            MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
            ASSERT(MdlMappedSystemVa != NULL);

            MdlMappedSystemVa += Mdl->ByteCount;

            RtlZeroMemory(MdlMappedSystemVa, Trailer);
            Mdl->ByteCount += Trailer;

            if (!SingleFragment) {
                ASSERT3P(State->List.Flink, !=, ListEntry);
                Tag->Length += Trailer;
            }

            // Adjust length of header tag
            ListEntry = State->List.Flink;
            Tag = CONTAINING_RECORD(ListEntry, TRANSMITTER_TAG, ListEntry);

            Tag->Length += Trailer;
            ASSERT3U(Tag->Length, ==, ETHERNET_MIN);
        }
    } else {
        if (Transmitter->AlwaysCopy == 0)
            status = __RingGrantPayload(Ring);

        if (Transmitter->AlwaysCopy != 0 ||
            (!NT_SUCCESS(status) && status == STATUS_BUFFER_OVERFLOW)) {
            ASSERT3U(State->Count, ==, PACKET_REFERENCE(Packet));

            status = __RingCopyPayload(Ring);
        }
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    ASSERT3U(State->Count, ==, PACKET_REFERENCE(Packet));

    Ring->PacketsPrepared++;
    return STATUS_SUCCESS;

fail2:
    if (status != STATUS_INSUFFICIENT_RESOURCES &&
        status != STATUS_INVALID_PARAMETER)
        Error("fail2\n");

    __RingUnprepareTags(Ring);

fail1:
    if (status != STATUS_INSUFFICIENT_RESOURCES &&
        status != STATUS_INVALID_PARAMETER)
        Error("fail1 (%08x)\n", status);

    State->StartVa = NULL;
    RtlZeroMemory(&State->Info, sizeof (XENVIF_PACKET_INFO));

    ASSERT(IsListEmpty(&State->List));
    RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

    RtlZeroMemory(&State->Payload, sizeof (XENVIF_PACKET_PAYLOAD));

    Packet->Send = State->Send;
    RtlZeroMemory(&State->Send, sizeof (XENVIF_SEND_INFO));

    State->Packet = NULL;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (TRANSMITTER_STATE)));

    return status;

#undef  METADATA
#undef  METADATA_EXISTS
}

static FORCEINLINE PXENVIF_TRANSMITTER_PACKET
__RingUnpreparePacket(
    IN  PTRANSMITTER_RING       Ring
    )
{
    PTRANSMITTER_STATE          State;
    PXENVIF_TRANSMITTER_PACKET  Packet;

    State = &Ring->State;
    Packet = State->Packet;

    // This has the side effect of freeing up resources associated with a pending
    // gratuitous ARP, which is why the call is not conditional on Packet being
    // non-NULL
    __RingUnprepareTags(Ring);
    RtlZeroMemory(&State->Info, sizeof (XENVIF_PACKET_INFO));

    if (Packet == NULL)
        goto done;

    Ring->PacketsUnprepared++;

    ASSERT(IsListEmpty(&State->List));
    RtlZeroMemory(&State->List, sizeof (LIST_ENTRY));

    RtlZeroMemory(&State->Payload, sizeof (XENVIF_PACKET_PAYLOAD));

    Packet->Send = State->Send;
    RtlZeroMemory(&State->Send, sizeof (XENVIF_SEND_INFO));

    State->Packet = NULL;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (TRANSMITTER_STATE)));

done:
    return Packet;
}

static FORCEINLINE NTSTATUS
__RingPrepareGratuitousArp(
    IN  PTRANSMITTER_RING       Ring,
    IN  PIPV4_ADDRESS           Address
    )
{
    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_MAC                 Mac;
    PTRANSMITTER_STATE          State;
    PTRANSMITTER_TAG            Tag;
    PTRANSMITTER_BUFFER         Buffer;
    PMDL                        Mdl;
    PUCHAR                      MdlMappedSystemVa;
    PETHERNET_UNTAGGED_HEADER   EthernetHeader;
    PARP_HEADER                 ArpHeader;
    PETHERNET_ADDRESS           SenderHardwareAddress;
    PIPV4_ADDRESS               SenderProtocolAddress;
    PETHERNET_ADDRESS           TargetHardwareAddress;
    PIPV4_ADDRESS               TargetProtocolAddress;
    PFN_NUMBER                  Pfn;
    NTSTATUS                    status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (TRANSMITTER_STATE)));

    Info("%u.%u.%u.%u\n",
         Address->Byte[0],
         Address->Byte[1],
         Address->Byte[2],
         Address->Byte[3]);

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;
    Mac = FrontendGetMac(Frontend);

    TargetProtocolAddress = SenderProtocolAddress = Address;
    SenderHardwareAddress = MacGetCurrentAddress(Mac);
    TargetHardwareAddress = MacGetBroadcastAddress(Mac);

    State = &Ring->State;

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Mdl = Buffer->Mdl;

    MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(MdlMappedSystemVa != NULL);

    EthernetHeader = (PETHERNET_UNTAGGED_HEADER)MdlMappedSystemVa;

    RtlCopyMemory(EthernetHeader->DestinationAddress.Byte, MacGetBroadcastAddress(Mac), ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(EthernetHeader->SourceAddress.Byte, MacGetCurrentAddress(Mac), ETHERNET_ADDRESS_LENGTH);
    EthernetHeader->TypeOrLength = HTONS(ETHERTYPE_ARP);

    MdlMappedSystemVa += sizeof (ETHERNET_UNTAGGED_HEADER);

    ArpHeader = (PARP_HEADER)MdlMappedSystemVa;

    ArpHeader->HardwareType = HTONS(HARDWARE_ETHER);
    ArpHeader->ProtocolType = HTONS(PROTOCOL_IPV4);
    ArpHeader->HardwareAddressLength = ETHERNET_ADDRESS_LENGTH;
    ArpHeader->ProtocolAddressLength = IPV4_ADDRESS_LENGTH;
    ArpHeader->Operation = HTONS(ARP_REQUEST);

    MdlMappedSystemVa += sizeof (ARP_HEADER);

    RtlCopyMemory(MdlMappedSystemVa, SenderHardwareAddress->Byte, ETHERNET_ADDRESS_LENGTH);
    MdlMappedSystemVa += ETHERNET_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, SenderProtocolAddress->Byte, IPV4_ADDRESS_LENGTH);
    MdlMappedSystemVa += IPV4_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, TargetHardwareAddress->Byte, ETHERNET_ADDRESS_LENGTH);
    MdlMappedSystemVa += ETHERNET_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, TargetProtocolAddress->Byte, IPV4_ADDRESS_LENGTH);
    MdlMappedSystemVa += IPV4_ADDRESS_LENGTH;

    Mdl->ByteCount = (ULONG)(MdlMappedSystemVa - (PUCHAR)MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority));

    Tag = __TransmitterGetTag(Ring);

    Tag->Context = Buffer;
    Tag->Type = TAG_BUFFER;
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 TRUE,
                                 &Tag->Handle);
    if (!NT_SUCCESS(status))
        goto fail2;

    Tag->Offset = 0;
    Tag->Length = Mdl->ByteCount;

    InitializeListHead(&State->List);

    ASSERT(IsZeroMemory(&Tag->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Tag->ListEntry);
    State->Count++;

    return STATUS_SUCCESS;

fail2:
    if (status != STATUS_INSUFFICIENT_RESOURCES)
        Error("fail2\n");

    ASSERT3U(Tag->Type, ==, TAG_BUFFER);
    ASSERT3P(Buffer, ==, Tag->Context);
    Tag->Context = NULL;
    Tag->Type = TAG_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutTag(Ring, Tag);

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    if (status != STATUS_INSUFFICIENT_RESOURCES)
        Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Ring->State, sizeof (TRANSMITTER_STATE)));

    return status;
}

static FORCEINLINE NTSTATUS
__RingPrepareNeighbourAdvertisement(
    IN  PTRANSMITTER_RING       Ring,
    IN  PIPV6_ADDRESS           Address
    )
{
    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_MAC                 Mac;
    PTRANSMITTER_STATE          State;
    PTRANSMITTER_TAG            Tag;
    PTRANSMITTER_BUFFER         Buffer;
    PMDL                        Mdl;
    PUCHAR                      MdlMappedSystemVa;
    PETHERNET_UNTAGGED_HEADER   EthernetHeader;
    PIPV6_HEADER                IpHeader;
    PICMPV6_HEADER              IcmpHeader;
    PIPV6_ADDRESS               TargetProtocolAddress;
    PETHERNET_ADDRESS           SenderHardwareAddress;
    USHORT                      PayloadLength;
    ULONG                       Accumulator;
    PFN_NUMBER                  Pfn;
    NTSTATUS                    status;

    ASSERT(IsZeroMemory(&Ring->State, sizeof (TRANSMITTER_STATE)));

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

    TargetProtocolAddress = Address;
    SenderHardwareAddress = MacGetCurrentAddress(Mac);

    State = &Ring->State;

    Buffer = __TransmitterGetBuffer(Ring);

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto fail1;

    Mdl = Buffer->Mdl;

    MdlMappedSystemVa = MmGetSystemAddressForMdlSafe(Buffer->Mdl, NormalPagePriority);
    ASSERT(MdlMappedSystemVa != NULL);

    EthernetHeader = (PETHERNET_UNTAGGED_HEADER)MdlMappedSystemVa;

    RtlCopyMemory(EthernetHeader->DestinationAddress.Byte, MacGetBroadcastAddress(Mac), ETHERNET_ADDRESS_LENGTH);
    RtlCopyMemory(EthernetHeader->SourceAddress.Byte, MacGetCurrentAddress(Mac), ETHERNET_ADDRESS_LENGTH);
    EthernetHeader->TypeOrLength = HTONS(ETHERTYPE_IPV6);

    MdlMappedSystemVa += sizeof (ETHERNET_UNTAGGED_HEADER);

    IpHeader = (PIPV6_HEADER)MdlMappedSystemVa;
    RtlZeroMemory(IpHeader, sizeof (IPV6_HEADER));

    IpHeader->Version = 6;
    IpHeader->NextHeader = IPPROTO_ICMPV6;
    IpHeader->HopLimit = 255;

    RtlCopyMemory(IpHeader->SourceAddress.Byte, Address, IPV6_ADDRESS_LENGTH);

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

    RtlCopyMemory(MdlMappedSystemVa, TargetProtocolAddress->Byte, IPV6_ADDRESS_LENGTH);

    PayloadLength += IPV6_ADDRESS_LENGTH;
    MdlMappedSystemVa += IPV6_ADDRESS_LENGTH;

    RtlCopyMemory(MdlMappedSystemVa, SenderHardwareAddress->Byte, ETHERNET_ADDRESS_LENGTH);

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

    Tag = __TransmitterGetTag(Ring);

    Tag->Context = Buffer;
    Tag->Type = TAG_BUFFER;
    Buffer->Reference++;

    Pfn = MmGetMdlPfnArray(Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 TRUE,
                                 &Tag->Handle);
    if (!NT_SUCCESS(status))
        goto fail2;

    Tag->Offset = 0;
    Tag->Length = Mdl->ByteCount;

    InitializeListHead(&State->List);

    ASSERT(IsZeroMemory(&Tag->ListEntry, sizeof (LIST_ENTRY)));
    InsertTailList(&State->List, &Tag->ListEntry);
    State->Count++;

    return STATUS_SUCCESS;

fail2:
    if (status != STATUS_INSUFFICIENT_RESOURCES)
        Error("fail2\n");

    ASSERT3U(Tag->Type, ==, TAG_BUFFER);
    ASSERT3P(Buffer, ==, Tag->Context);
    Tag->Context = NULL;
    Tag->Type = TAG_TYPE_INVALID;

    ASSERT(Buffer->Reference != 0);
    --Buffer->Reference;

    __TransmitterPutTag(Ring, Tag);

    __TransmitterPutBuffer(Ring, Buffer);

fail1:
    if (status != STATUS_INSUFFICIENT_RESOURCES)
        Error("fail1 (%08x)\n", status);

    ASSERT(IsZeroMemory(&Ring->State, sizeof (TRANSMITTER_STATE)));

    return status;
}

static FORCEINLINE NTSTATUS
__RingPostTags(
    IN  PTRANSMITTER_RING       Ring
    )
{
#define RING_SLOTS_AVAILABLE(_Front, _req_prod, _rsp_cons)   \
        (RING_SIZE(_Front) - ((_req_prod) - (_rsp_cons)))

    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_FRONTEND            Frontend;
    PTRANSMITTER_STATE          State;
    PXENVIF_TRANSMITTER_PACKET  Packet;
    PXENVIF_PACKET_PAYLOAD      Payload;
    RING_IDX                    req_prod;
    RING_IDX                    rsp_cons;
    ULONG                       Extra;
    ULONG                       PacketLength;
    BOOLEAN                     FirstRequest;
    netif_tx_request_t          *req;
    NTSTATUS                    status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    State = &Ring->State;
    Packet = State->Packet;
    Payload = &State->Payload;

    ASSERT(!IsListEmpty(&State->List));
    ASSERT(State->Count != 0);
    ASSERT3U(State->Count, <=, MAX_SKB_FRAGS + 1);
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
        PLIST_ENTRY         ListEntry;
        PTRANSMITTER_TAG    Tag;
        uint16_t            id;

        --State->Count;

        ListEntry = RemoveHeadList(&State->List);
        ASSERT3P(ListEntry, !=, &State->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Tag = CONTAINING_RECORD(ListEntry, TRANSMITTER_TAG, ListEntry);

        req = RING_GET_REQUEST(&Ring->Front, req_prod);
        req_prod++;
        Ring->RequestsPosted++;

        id = (USHORT)(Tag - &Ring->Tag[0]);

        req->id = id | REQ_ID_INTEGRITY_CHECK;
        req->gref = GranterGetReference(FrontendGetGranter(Frontend),
                                        Tag->Handle);
        req->offset = (USHORT)Tag->Offset;
        req->size = (USHORT)Tag->Length;
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

            // The first tag length is the length of the entire packet
            PacketLength = Tag->Length;
        }

        // Store a copy of the request in case we need to fake a response ourselves
        ASSERT3U(id, <, MAXIMUM_TAG_COUNT);
        ASSERT(IsZeroMemory(&Ring->Pending[id], sizeof (netif_tx_request_t)));
        Ring->Pending[id] = *req;
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

        ASSERT(IsZeroMemory(&Packet->Completion, sizeof (XENVIF_COMPLETION_INFO)));

        ASSERT(Info->EthernetHeader.Length != 0);
        Header = (PETHERNET_HEADER)(StartVa + Info->EthernetHeader.Offset);

        Packet->Completion.Type = GET_ETHERNET_ADDRESS_TYPE(&Header->Untagged.DestinationAddress);
        Packet->Completion.Status = PACKET_PENDING;
        Packet->Completion.PacketLength = (USHORT)PacketLength;
        Packet->Completion.PayloadLength = (USHORT)Payload->Length;

        State->StartVa = NULL;
        RtlZeroMemory(&State->Info, sizeof (XENVIF_PACKET_INFO));
        RtlZeroMemory(&State->Payload, sizeof (XENVIF_PACKET_PAYLOAD));
        RtlZeroMemory(&State->Send, sizeof (XENVIF_SEND_INFO));
        State->Packet = NULL;

        Ring->PacketsSent++;
    }

    ASSERT(IsZeroMemory(&Ring->State, sizeof (TRANSMITTER_STATE)));

    return STATUS_SUCCESS;

fail1:
    return status;

#undef  RING_SLOTS_AVAILABLE
}

static FORCEINLINE VOID
__RingFakeResponses(
    IN  PTRANSMITTER_RING   Ring
    )
{
    RING_IDX                rsp_prod;
    USHORT                  id;
    ULONG                   Count;

    // This is only called when the backend went away. We need
    // to mimic the behavior of the backend and turn requests into
    // appropriate responses.

    KeMemoryBarrier();

    rsp_prod = Ring->Shared->rsp_prod;

    KeMemoryBarrier();

    Count = 0;
    for (id = 0; id < MAXIMUM_TAG_COUNT; id++) {
        netif_tx_request_t  *req;
        netif_tx_response_t *rsp;

        req = &Ring->Pending[id];
        if (req->id == 0)
            continue;

        ASSERT3U((req->id & REQ_ID_INTEGRITY_CHECK), ==, REQ_ID_INTEGRITY_CHECK);
        ASSERT3U((req->id & ~REQ_ID_INTEGRITY_CHECK), ==, id);

        rsp = RING_GET_RESPONSE(&Ring->Front, rsp_prod);
        rsp_prod++;
        Count++;

        rsp->id = req->id;
        rsp->status = NETIF_RSP_DROPPED;

        if (req->flags & NETTXF_extra_info) {
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
__RingReleaseTag(
    IN  PTRANSMITTER_RING   Ring,
    IN  PTRANSMITTER_TAG    Tag
    )
{
    PXENVIF_TRANSMITTER     Transmitter;
    PXENVIF_FRONTEND        Frontend;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    Tag->Length = 0;
    Tag->Offset = 0;

    GranterRevokeAccess(FrontendGetGranter(Frontend),
                        Tag->Handle);
    Tag->Handle = NULL;

    __TransmitterPutTag(Ring, Tag);
}

static FORCEINLINE VOID
__RingCompletePacket(
    IN  PTRANSMITTER_RING           Ring,
    IN  PXENVIF_TRANSMITTER_PACKET  Packet
    )
{
    ASSERT(Packet->Completion.Status != PACKET_PENDING);

    if (Packet->Completion.Status != PACKET_OK) {
        Ring->PacketStatistics.Drop++;

        if (Packet->Completion.Status == PACKET_ERROR)
            Ring->PacketStatistics.BackendError++;
    } else {
        ULONG   Length;

        Length = (ULONG)Packet->Completion.PacketLength;

        switch (Packet->Completion.Type) {
        case ETHERNET_ADDRESS_UNICAST:
            Ring->PacketStatistics.Unicast++;
            Ring->PacketStatistics.UnicastBytes += Length;
            break;
            
        case ETHERNET_ADDRESS_MULTICAST:
            Ring->PacketStatistics.Multicast++;
            Ring->PacketStatistics.MulticastBytes += Length;
            break;

        case ETHERNET_ADDRESS_BROADCAST:
            Ring->PacketStatistics.Broadcast++;
            Ring->PacketStatistics.BroadcastBytes += Length;
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

#define TRANSMITTER_BATCH(_Ring)   (RING_SIZE(&(_Ring)->Front) / 4)

static DECLSPEC_NOINLINE VOID
RingPoll(
    IN  PTRANSMITTER_RING   Ring
    )
{
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
            netif_tx_response_t         *rsp;
            uint16_t                    id;
            netif_tx_request_t          *req;
            PTRANSMITTER_TAG            Tag;
            PXENVIF_TRANSMITTER_PACKET  Packet;

            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_cons);
            rsp_cons++;
            Ring->ResponsesProcessed++;

            Ring->Stopped = FALSE;

            if (rsp->status == NETIF_RSP_NULL)
                continue;

            ASSERT3U((rsp->id & REQ_ID_INTEGRITY_CHECK), ==, REQ_ID_INTEGRITY_CHECK);
            id = rsp->id & ~REQ_ID_INTEGRITY_CHECK;

            ASSERT3U(id, <, MAXIMUM_TAG_COUNT);
            req = &Ring->Pending[id];

            ASSERT3U(req->id, ==, rsp->id);
            RtlZeroMemory(req, sizeof (netif_tx_request_t));

            Tag = &Ring->Tag[id];

            switch (Tag->Type) {
            case TAG_BUFFER: {
                PTRANSMITTER_BUFFER  Buffer;

                Buffer = Tag->Context;
                Tag->Context = NULL;
                Tag->Type = TAG_TYPE_INVALID;

                Packet = Buffer->Context;
                Buffer->Context = NULL;

                ASSERT(Buffer->Reference != 0);
                if (--Buffer->Reference == 0)
                    __TransmitterPutBuffer(Ring, Buffer);

                break;
            }
            case TAG_PACKET:
                Packet = Tag->Context;
                Tag->Context = NULL;
                Tag->Type = TAG_TYPE_INVALID;

                break;

            default:
                Packet = NULL;
                ASSERT(FALSE);
            }

            __RingReleaseTag(Ring, Tag);
            Tag = NULL;

            if (Packet == NULL) {
                RtlZeroMemory(rsp, sizeof (netif_tx_response_t));
                continue;
            }

            DECREMENT_PACKET_REFERENCE(Packet);

            if (rsp->status != NETIF_RSP_OKAY &&
                Packet->Completion.Status == PACKET_PENDING) {
                switch (rsp->status) {
                case NETIF_RSP_DROPPED:
                    Packet->Completion.Status = PACKET_DROPPED;
                    break;

                case NETIF_RSP_ERROR:
                    Packet->Completion.Status = PACKET_ERROR;
                    break;

                default:
                    ASSERT(FALSE);
                    break;
                }
            }

            RtlZeroMemory(rsp, sizeof (netif_tx_response_t));

            if (PACKET_REFERENCE(Packet) != 0)
                continue;

            if (Packet->Completion.Status == PACKET_PENDING)
                Packet->Completion.Status = PACKET_OK;

            __RingCompletePacket(Ring, Packet);
        }

        KeMemoryBarrier();

        Ring->Front.rsp_cons = rsp_cons;

        Delta = Ring->Front.req_prod_pvt - rsp_cons;
        Delta = __min(Delta, TRANSMITTER_BATCH(Ring));
        Delta = __max(Delta, 1);

        Ring->Shared->rsp_event = rsp_cons + Delta;
    }
}

static FORCEINLINE VOID
__RingPushRequests(
    IN  PTRANSMITTER_RING   Ring
    )
{
    BOOLEAN                 Notify;

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

#define TRANSMITTER_ADVERTISEMENT_COUNT 3

#define LOCK_BIT    ((ULONG_PTR)1)

static FORCEINLINE ULONG
__RingReversePacketList(
    IN  PXENVIF_TRANSMITTER_PACKET  *Packet
    )
{
    PXENVIF_TRANSMITTER_PACKET  HeadPacket;
    ULONG                       Count;

    HeadPacket = NULL;
    Count = 0;

    while (*Packet != NULL) {
        PXENVIF_TRANSMITTER_PACKET  Next;

        ASSERT(((ULONG_PTR)*Packet & LOCK_BIT) == 0);

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
RingSwizzle(
    IN  PTRANSMITTER_RING       Ring
    )
{
    ULONG_PTR                   Old;
    ULONG_PTR                   New;
    PXENVIF_TRANSMITTER_PACKET  HeadPacket;
    PXENVIF_TRANSMITTER_PACKET  *TailPacket;
    ULONG                       Count;

    ASSERT3P(Ring->LockThread, ==, KeGetCurrentThread());

    New = LOCK_BIT;    
    Old = (ULONG_PTR)InterlockedExchangePointer(&Ring->Lock, (PVOID)New);

    ASSERT(Old & LOCK_BIT);
    HeadPacket = (PVOID)(Old & ~LOCK_BIT);

    if (HeadPacket == NULL)
        return;

    // Packets are held in the atomic packet list in reverse order
    // so that the most recent is always head of the list. This is
    // necessary to allow addition to the list to be done atomically.

    TailPacket = &HeadPacket->Next;
    Count = __RingReversePacketList(&HeadPacket);
    ASSERT3P(*TailPacket, ==, NULL);

    *(Ring->Queued.TailPacket) = HeadPacket;
    Ring->Queued.TailPacket = TailPacket;
    Ring->PacketsQueued += Count;
}

static DECLSPEC_NOINLINE VOID
RingSchedule(
    IN  PTRANSMITTER_RING   Ring
    )
{
    PTRANSMITTER_STATE      State;

    if(!Ring->Enabled || Ring->Stopped)
        return;

    State = &Ring->State;

    for (;;) {
        PXENVIF_TRANSMITTER_PACKET  Packet;
        NTSTATUS                    status;

        if (State->Count != 0) {
            status = __RingPostTags(Ring);
            if (!NT_SUCCESS(status)) {
                Ring->Stopped = TRUE;
                break;
            }
        }

        if (Ring->RequestsPosted - Ring->RequestsPushed >=
            RING_SIZE(&Ring->Front) / 4)
            __RingPushRequests(Ring);

        ASSERT3U(State->Count, ==, 0);

        if (Ring->AddressIndex != 0) {
            ULONG   Index = (--Ring->AddressIndex) % Ring->AddressCount;

            switch (Ring->AddressTable[Index].si_family) {
            case AF_INET: {
                IPV4_ADDRESS    Address;

                RtlCopyMemory(Address.Byte,
                              &Ring->AddressTable[Index].Ipv4.sin_addr.s_addr,
                              IPV4_ADDRESS_LENGTH);

                (VOID) __RingPrepareGratuitousArp(Ring, &Address);

                break;
            }
            case AF_INET6: {
                IPV6_ADDRESS    Address;

                RtlCopyMemory(Address.Byte,
                              &Ring->AddressTable[Index].Ipv6.sin6_addr.s6_addr,
                              IPV6_ADDRESS_LENGTH);

                (VOID) __RingPrepareNeighbourAdvertisement(Ring, &Address);

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

        status = __RingPreparePacket(Ring, Packet);
        if (!NT_SUCCESS(status)) {
            ASSERT(status != STATUS_BUFFER_OVERFLOW);

            // Fake that we prapared and sent this packet
            Ring->PacketsPrepared++;
            Ring->PacketsSent++;
            Ring->PacketsFaked++;

            Packet->Completion.Status = PACKET_DROPPED;

            Ring->PacketStatistics.FrontendError++;

            __RingCompletePacket(Ring, Packet);
        }

        ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
    }

    ASSERT(IMPLY(Ring->Queued.HeadPacket == NULL, Ring->Queued.TailPacket == &Ring->Queued.HeadPacket));

    __RingPushRequests(Ring);
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__RingTryAcquireLock(
    IN  PTRANSMITTER_RING   Ring
    )
{
    ULONG_PTR               Old;
    ULONG_PTR               New;
    BOOLEAN                 Acquired;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeMemoryBarrier();

    Old = (ULONG_PTR)Ring->Lock & ~LOCK_BIT;
    New = Old | LOCK_BIT;

    Acquired = ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock, (PVOID)New, (PVOID)Old) == Old) ? TRUE : FALSE;

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
__RingAcquireLock(
    IN  PTRANSMITTER_RING   Ring
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    for (;;) {
        if (__RingTryAcquireLock(Ring))
            break;
    }
}

static DECLSPEC_NOINLINE VOID
RingAcquireLock(
    IN  PTRANSMITTER_RING   Ring
    )
{
    __RingAcquireLock(Ring);
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__RingTryReleaseLock(
    IN  PTRANSMITTER_RING   Ring
    )
{
    ULONG_PTR               Old;
    ULONG_PTR               New;
    BOOLEAN                 Released;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3P(KeGetCurrentThread(), ==, Ring->LockThread);

    Old = LOCK_BIT;
    New = 0;

    Ring->LockThread = NULL;

    KeMemoryBarrier();

    Released = ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock, (PVOID)New, (PVOID)Old) == Old) ? TRUE : FALSE;

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
__RingReleaseLock(
    IN  PTRANSMITTER_RING       Ring
    )
{
    PXENVIF_TRANSMITTER_PACKET  HeadPacket;
    PXENVIF_TRANSMITTER_PACKET  *TailPacket;

    HeadPacket = NULL;
    TailPacket = &HeadPacket;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    // As lock holder it is our responsibility to drain the atomic
    // packet list into the transmit queue before we actually drop the
    // lock. This may, of course, take a few attempts as another
    // thread could be simuntaneously adding to the list.

    do {
        RingSwizzle(Ring);
        RingSchedule(Ring);

        *TailPacket = Ring->Completed.HeadPacket;
        TailPacket = Ring->Completed.TailPacket;

        Ring->Completed.HeadPacket = NULL;
        Ring->Completed.TailPacket = &Ring->Completed.HeadPacket;
    } while (!__RingTryReleaseLock(Ring));

    if (HeadPacket != NULL) {
        PXENVIF_TRANSMITTER Transmitter;

        Transmitter = Ring->Transmitter;

        VifCompletePackets(Transmitter->VifInterface, HeadPacket);
    }
}

static DECLSPEC_NOINLINE VOID
RingReleaseLock(
    IN  PTRANSMITTER_RING   Ring
    )
{
    __RingReleaseLock(Ring);
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define RING_PERIOD         30000

static NTSTATUS
RingWatchdog(
    IN  PXENVIF_THREAD  Self,
    IN  PVOID           Context
    )
{
    PTRANSMITTER_RING   Ring = Context;
    LARGE_INTEGER       Timeout;
    ULONG               PacketsQueued;

    Trace("====>\n");

    Timeout.QuadPart = TIME_RELATIVE(TIME_MS(RING_PERIOD));
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
        __RingAcquireLock(Ring);

        if (Ring->Enabled) {
            if (Ring->PacketsQueued == PacketsQueued &&
                Ring->PacketsCompleted != PacketsQueued) {
                PXENVIF_TRANSMITTER Transmitter;
                PXENVIF_FRONTEND    Frontend;

                Transmitter = Ring->Transmitter;
                Frontend = Transmitter->Frontend;

                DEBUG(Printf,
                      Transmitter->DebugInterface,
                      Transmitter->DebugCallback,
                      "WATCHDOG: %s\n",
                      FrontendGetPath(Frontend));

                DEBUG(Printf,
                      Transmitter->DebugInterface,
                      Transmitter->DebugCallback,
                      "FRONT: req_prod_pvt = %u rsp_cons = %u nr_ents = %u sring = %p\n",
                      Ring->Front.req_prod_pvt,
                      Ring->Front.rsp_cons,
                      Ring->Front.nr_ents,
                      Ring->Front.sring);

                DEBUG(Printf,
                      Transmitter->DebugInterface,
                      Transmitter->DebugCallback,
                      "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
                      Ring->Shared->req_prod,
                      Ring->Shared->req_event,
                      Ring->Shared->rsp_prod,
                      Ring->Shared->rsp_event);

                DEBUG(Printf,
                      Transmitter->DebugInterface,
                      Transmitter->DebugCallback,
                      "RequestsPosted = %u RequestsPushed = %u ResponsesProcessed = %u\n",
                      Ring->RequestsPosted,
                      Ring->RequestsPushed,
                      Ring->ResponsesProcessed);

                // Try to move things along
                NotifierSendTx(FrontendGetNotifier(Frontend));
                RingPoll(Ring);
            }

            PacketsQueued = Ring->PacketsQueued;
        }

        __RingReleaseLock(Ring);
        KeLowerIrql(Irql);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
}

static FORCEINLINE NTSTATUS
__RingDumpAddressTable(
    IN  PTRANSMITTER_RING       Ring
    )
{
    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_FRONTEND            Frontend;
    PXENBUS_STORE_TRANSACTION   Transaction;
    ULONG                       Index;
    ULONG                       IpVersion4Count;
    ULONG                       IpVersion6Count;
    NTSTATUS                    status;

    __RingAcquireLock(Ring);

    status = STATUS_SUCCESS;
    if (!Ring->Connected)
        goto done;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT(Transmitter->StoreInterface != NULL);

    status = STORE(TransactionStart,
                   Transmitter->StoreInterface,
                   &Transaction);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = STORE(Remove,
                   Transmitter->StoreInterface,
                   Transaction,
                   FrontendGetPrefix(Frontend),
                   "ip");
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND)
        goto fail2;

    status = STORE(Remove,
                   Transmitter->StoreInterface,
                   Transaction,
                   FrontendGetPrefix(Frontend),
                   "ipv4");
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND)
        goto fail3;

    status = STORE(Remove,
                   Transmitter->StoreInterface,
                   Transaction,
                   FrontendGetPrefix(Frontend),
                   "ipv6");
    if (!NT_SUCCESS(status) &&
        status != STATUS_OBJECT_NAME_NOT_FOUND)
        goto fail4;

    IpVersion4Count = 0;
    IpVersion6Count = 0;

    for (Index = 0; Index < Ring->AddressCount; Index++) {
        switch (Ring->AddressTable[Index].si_family) {
        case AF_INET: {
            IPV4_ADDRESS    Address;
            CHAR            Node[sizeof ("ipv4/XXXXXXXX/addr")];

            RtlCopyMemory(Address.Byte,
                          &Ring->AddressTable[Index].Ipv4.sin_addr.s_addr,
                          IPV4_ADDRESS_LENGTH);

            status = RtlStringCbPrintfA(Node,
                                        sizeof (Node),
                                        "ipv4/%u/addr",
                                        IpVersion4Count);
            ASSERT(NT_SUCCESS(status));

            status = STORE(Printf,
                           Transmitter->StoreInterface,
                           Transaction,
                           FrontendGetPrefix(Frontend),
                           Node,
                           "%u.%u.%u.%u",
                           Address.Byte[0],
                           Address.Byte[1],
                           Address.Byte[2],
                           Address.Byte[3]);
            if (!NT_SUCCESS(status))
                goto fail5;

            if (IpVersion4Count == 0) {
                status = STORE(Printf,
                               Transmitter->StoreInterface,
                               Transaction,
                               FrontendGetPrefix(Frontend),
                               "ip",
                               "%u.%u.%u.%u",
                               Address.Byte[0],
                               Address.Byte[1],
                               Address.Byte[2],
                               Address.Byte[3]);
                if (!NT_SUCCESS(status))
                    goto fail6;
            }

            IpVersion4Count++;
            break;
        }
        case AF_INET6: {
            IPV6_ADDRESS    Address;
            CHAR            Node[sizeof ("ipv6/XXXXXXXX/addr")];

            RtlCopyMemory(Address.Byte,
                          &Ring->AddressTable[Index].Ipv6.sin6_addr.s6_addr,
                          IPV6_ADDRESS_LENGTH);

            status = RtlStringCbPrintfA(Node,
                                        sizeof (Node),
                                        "ipv6/%u/addr",
                                        IpVersion6Count);
            ASSERT(NT_SUCCESS(status));

            status = STORE(Printf,
                           Transmitter->StoreInterface,
                           Transaction,
                           FrontendGetPrefix(Frontend),
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
                goto fail5;

            IpVersion6Count++;
            break;
        }
        default:
            break;
        }
    }

    status = STORE(TransactionEnd,
                   Transmitter->StoreInterface,
                   Transaction,
                   TRUE);

done:
    __RingReleaseLock(Ring);

    return status;

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

    (VOID) STORE(TransactionEnd,
                 Transmitter->StoreInterface,
                 Transaction,
                 FALSE);

fail1:
    Error("fail1 (%08x)\n", status);

    __RingReleaseLock(Ring);

    return status;
}

static FORCEINLINE VOID
__RingUpdateAddressTable(
    IN  PTRANSMITTER_RING   Ring,
    IN  PSOCKADDR_INET      Table,
    IN  ULONG               Count
    )
{
    ULONG                   Attempt;
    NTSTATUS                status;

    __RingAcquireLock(Ring);

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
    __RingReleaseLock(Ring);

    Attempt = 0;
    do {
        status = __RingDumpAddressTable(Ring);
    } while (status == STATUS_RETRY && ++Attempt <= 10);

    return;

fail1:
    Error("fail1 (%08x)\n", status);

    __RingReleaseLock(Ring);
}

static FORCEINLINE VOID
__RingAdvertizeAddresses(
    IN  PTRANSMITTER_RING   Ring
    )
{
    __RingAcquireLock(Ring);
    Ring->AddressIndex = Ring->AddressCount * 3;
    __RingReleaseLock(Ring);
}

static FORCEINLINE NTSTATUS
__RingInitialize(
    IN  PXENVIF_TRANSMITTER Transmitter,
    OUT PTRANSMITTER_RING   *Ring
    )
{
    PXENVIF_FRONTEND        Frontend;
    NTSTATUS                status;

    Frontend = Transmitter->Frontend;

    *Ring = __TransmitterAllocate(sizeof (TRANSMITTER_RING));

    status = STATUS_NO_MEMORY;
    if (*Ring == NULL)
        goto fail1;

    (*Ring)->Transmitter = Transmitter;
    (*Ring)->Queued.TailPacket = &(*Ring)->Queued.HeadPacket;
    (*Ring)->Completed.TailPacket = &(*Ring)->Completed.HeadPacket;

    status = ThreadCreate(RingWatchdog,
                          *Ring,
                          &(*Ring)->Thread);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    (*Ring)->Queued.TailPacket = NULL;
    (*Ring)->Completed.TailPacket = NULL;
    (*Ring)->Transmitter = NULL;

    ASSERT(IsZeroMemory(*Ring, sizeof (TRANSMITTER_RING)));
    __TransmitterFree(*Ring);
    *Ring = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__RingConnect(
    IN  PTRANSMITTER_RING   Ring
    )
{
    PXENVIF_TRANSMITTER     Transmitter;
    PXENVIF_FRONTEND        Frontend;
    ULONG                   Index;
    PFN_NUMBER              Pfn;
    CHAR                    Name[MAXNAMELEN];
    NTSTATUS                status;

    ASSERT(!Ring->Connected);

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s_buffer",
                                FrontendGetPath(Frontend));
    if (!NT_SUCCESS(status))
        goto fail1;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = CACHE(Create,
                   Transmitter->CacheInterface,
                   Name,
                   sizeof (TRANSMITTER_BUFFER),
                   0,
                   TransmitterBufferCtor,
                   TransmitterBufferDtor,
                   RingAcquireLock,
                   RingReleaseLock,
                   Ring,
                   &Ring->BufferCache);
    if (!NT_SUCCESS(status))
        goto fail2;

    Ring->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Ring->Mdl == NULL)
        goto fail3;

    Ring->Shared = MmGetSystemAddressForMdlSafe(Ring->Mdl, NormalPagePriority);
    ASSERT(Ring->Shared != NULL);

    SHARED_RING_INIT(Ring->Shared);
    FRONT_RING_INIT(&Ring->Front, Ring->Shared, PAGE_SIZE);
    ASSERT3P(Ring->Front.sring, ==, Ring->Shared);

    Ring->HeadFreeTag = TAG_INDEX_INVALID;
    for (Index = 0; Index < MAXIMUM_TAG_COUNT; Index++) {
        PTRANSMITTER_TAG Tag = &Ring->Tag[Index];

        Tag->Next = Ring->HeadFreeTag;
        Ring->HeadFreeTag = Index;
    }

    Pfn = MmGetMdlPfnArray(Ring->Mdl)[0];

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 FALSE,
                                 &Ring->Handle);
    if (!NT_SUCCESS(status))
        goto fail4;

    Ring->Connected = TRUE;

    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");

    while (Ring->HeadFreeTag != TAG_INDEX_INVALID) {
        PTRANSMITTER_TAG    Tag = &Ring->Tag[Ring->HeadFreeTag];

        Ring->HeadFreeTag = Tag->Next;
        Tag->Next = 0;
    }
    Ring->HeadFreeTag = 0;

    RtlZeroMemory(&Ring->Front, sizeof (netif_tx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;
    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

fail3:
    Error("fail3\n");

    CACHE(Destroy,
          Transmitter->CacheInterface,
          Ring->BufferCache);
    Ring->BufferCache = NULL;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__RingStoreWrite(
    IN  PTRANSMITTER_RING           Ring,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_TRANSMITTER             Transmitter;
    PXENVIF_FRONTEND                Frontend;
    NTSTATUS                        status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    status = STORE(Printf,
                   Transmitter->StoreInterface,
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
__RingEnable(
    IN  PTRANSMITTER_RING   Ring
    )
{
    __RingAcquireLock(Ring);

    ASSERT(!Ring->Enabled);
    Ring->Enabled = TRUE;

    __RingReleaseLock(Ring);

    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
__RingDisable(
    IN  PTRANSMITTER_RING       Ring
    )
{    
    PXENVIF_TRANSMITTER         Transmitter;
    PXENVIF_FRONTEND            Frontend;
    PXENVIF_TRANSMITTER_PACKET  Packet;
    PCHAR                       Buffer;
    XenbusState                 State;
    ULONG                       Attempt;
    NTSTATUS                    status;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    __RingAcquireLock(Ring);

    ASSERT(Ring->Enabled);
    Ring->Enabled = FALSE;

    // Release any tags associated with a pending packet
    Packet = __RingUnpreparePacket(Ring);

    // Put any packet back on the head of the queue
    if (Packet != NULL) {
        ASSERT3P(Packet->Next, ==, NULL);

        Packet->Next = Ring->Queued.HeadPacket;

        if (Ring->Queued.TailPacket == &Ring->Queued.HeadPacket)
            Ring->Queued.TailPacket = &Packet->Next;

        Ring->Queued.HeadPacket = Packet;
    }

    Ring->AddressIndex = 0;

    status = STORE(Read,
                   Transmitter->StoreInterface,
                   NULL,
                   FrontendGetBackendPath(Frontend),
                   "state",
                   &Buffer);
    if (!NT_SUCCESS(status)) {
        State = XenbusStateUnknown;
    } else {
        State = (XenbusState)strtol(Buffer, NULL, 10);

        STORE(Free,
              Transmitter->StoreInterface,
              Buffer);
    }

    Attempt = 0;
    ASSERT3U(Ring->RequestsPushed, ==, Ring->RequestsPosted);
    while (Ring->ResponsesProcessed != Ring->RequestsPushed) {
        Attempt++;
        ASSERT(Attempt < 100);

        RingPoll(Ring);

        if (State != XenbusStateConnected)
            __RingFakeResponses(Ring);

        KeStallExecutionProcessor(10000);   // 10 ms
    }

    __RingReleaseLock(Ring);
}

static FORCEINLINE VOID
__RingDisconnect(
    IN  PTRANSMITTER_RING   Ring
    )
{
    PXENVIF_TRANSMITTER     Transmitter;
    PXENVIF_FRONTEND        Frontend;
    ULONG                   Count;

    ASSERT(Ring->Connected);
    Ring->Connected = FALSE;

    Transmitter = Ring->Transmitter;
    Frontend = Transmitter->Frontend;

    ASSERT3U(Ring->ResponsesProcessed, ==, Ring->RequestsPushed);
    ASSERT3U(Ring->RequestsPushed, ==, Ring->RequestsPosted);

    Ring->ResponsesProcessed = 0;
    Ring->RequestsPushed = 0;
    Ring->RequestsPosted = 0;

    GranterRevokeAccess(FrontendGetGranter(Frontend),
                        Ring->Handle);
    Ring->Handle = NULL;

    Count = 0;
    while (Ring->HeadFreeTag != TAG_INDEX_INVALID) {
        ULONG               Index = Ring->HeadFreeTag;
        PTRANSMITTER_TAG    Tag = &Ring->Tag[Index];

        Ring->HeadFreeTag = Tag->Next;
        Tag->Next = 0;

        Count++;
    }
    ASSERT3U(Count, ==, MAXIMUM_TAG_COUNT);

    Ring->HeadFreeTag = 0;

    RtlZeroMemory(&Ring->Front, sizeof (netif_tx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;
    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

    CACHE(Destroy,
          Transmitter->CacheInterface,
          Ring->BufferCache);
    Ring->BufferCache = NULL;
}

static FORCEINLINE VOID
__RingTeardown(
    IN  PTRANSMITTER_RING   Ring
    )
{
    PXENVIF_TRANSMITTER     Transmitter;
    PXENVIF_FRONTEND        Frontend;

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

    RtlZeroMemory(&Ring->HeaderStatistics, sizeof (XENVIF_HEADER_STATISTICS));
    RtlZeroMemory(&Ring->OffloadStatistics, sizeof (TRANSMITTER_OFFLOAD_STATISTICS));
    RtlZeroMemory(&Ring->PacketStatistics, sizeof (XENVIF_TRANSMITTER_PACKET_STATISTICS));

    if (Ring->AddressCount != 0) {
        ASSERT(Ring->AddressTable != NULL);
        __TransmitterFree(Ring->AddressTable);
    }

    Ring->AddressTable = NULL;
    Ring->AddressCount = 0;

    ThreadAlert(Ring->Thread);
    ThreadJoin(Ring->Thread);
    Ring->Thread = NULL;

    ASSERT3P(Ring->Queued.TailPacket, ==, &Ring->Queued.HeadPacket);
    Ring->Queued.TailPacket = NULL;

    ASSERT3P(Ring->Completed.TailPacket, ==, &Ring->Completed.HeadPacket);
    Ring->Completed.TailPacket = NULL;

    Ring->Transmitter = NULL;

    ASSERT(IsZeroMemory(Ring, sizeof (TRANSMITTER_RING)));
    __TransmitterFree(Ring);
}

static FORCEINLINE VOID
__RingQueuePackets(
    IN  PTRANSMITTER_RING           Ring,
    IN  PXENVIF_TRANSMITTER_PACKET  HeadPacket
    )
{
    PXENVIF_TRANSMITTER_PACKET      *TailPacket;
    ULONG_PTR                       Old;
    ULONG_PTR                       LockBit;
    ULONG_PTR                       New;

    TailPacket = &HeadPacket->Next;
    (VOID) __RingReversePacketList(&HeadPacket);
    ASSERT3P(*TailPacket, ==, NULL);

    do {
        Old = (ULONG_PTR)Ring->Lock;
        LockBit = Old & LOCK_BIT;

        *TailPacket = (PVOID)(Old & ~LOCK_BIT);
        New = (ULONG_PTR)HeadPacket;
        ASSERT((New & LOCK_BIT) == 0);
        New |= LockBit;
    } while ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock, (PVOID)New, (PVOID)Old) != Old);

    // __RingReleaseLock() drains the atomic packet list into the transmit queue therefore,
    // after adding to the list we need to attempt to grab and release the lock. If we can't
    // grab it then that's ok because whichever thread is holding it will have to call
    // __RingReleaseLock() and will therefore drain the atomic packet list.

    if (!__RingTryAcquireLock(Ring))
        return;

    __RingReleaseLock(Ring);
}

static FORCEINLINE VOID
__RingAbortPackets(
    IN  PTRANSMITTER_RING       Ring
    )
{
    PXENVIF_TRANSMITTER_PACKET  Packet;

    __RingAcquireLock(Ring);

    RingSwizzle(Ring);

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

        Packet->Completion.Status = PACKET_DROPPED;

        __RingCompletePacket(Ring, Packet);

        Packet = Next;
    }

    ASSERT3U(Ring->PacketsSent, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);
    ASSERT3U(Ring->PacketsPrepared, ==, Ring->PacketsCopied + Ring->PacketsGranted + Ring->PacketsFaked);
    ASSERT3U(Ring->PacketsQueued, ==, Ring->PacketsPrepared - Ring->PacketsUnprepared);

    ASSERT3P((ULONG_PTR)Ring->Lock, ==, LOCK_BIT);
    __RingReleaseLock(Ring);
}

static FORCEINLINE VOID
__RingNotify(
    IN  PTRANSMITTER_RING   Ring
    )
{
    __RingAcquireLock(Ring);

    RingPoll(Ring);

    __RingReleaseLock(Ring);
}

static FORCEINLINE VOID
__RingAddPacketStatistics(
    IN      PTRANSMITTER_RING                       Ring,
    IN OUT  PXENVIF_TRANSMITTER_PACKET_STATISTICS   Statistics
    )
{
    // Don't bother locking

    Statistics->Drop += Ring->PacketStatistics.Drop;
    Statistics->BackendError += Ring->PacketStatistics.BackendError;
    Statistics->FrontendError += Ring->PacketStatistics.FrontendError;
    Statistics->Unicast += Ring->PacketStatistics.Unicast;
    Statistics->UnicastBytes += Ring->PacketStatistics.UnicastBytes;
    Statistics->Multicast += Ring->PacketStatistics.Multicast;
    Statistics->MulticastBytes += Ring->PacketStatistics.MulticastBytes;
    Statistics->Broadcast += Ring->PacketStatistics.Broadcast;
    Statistics->BroadcastBytes += Ring->PacketStatistics.BroadcastBytes;
}

static FORCEINLINE ULONG
__RingGetSize(
    IN  PTRANSMITTER_RING   Ring
    )
{
    UNREFERENCED_PARAMETER(Ring);

    return TRANSMITTER_RING_SIZE;
}

static VOID
TransmitterDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_TRANSMITTER Transmitter = Argument;
    PLIST_ENTRY         ListEntry;

    UNREFERENCED_PARAMETER(Crashing);

    for (ListEntry = Transmitter->List.Flink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Flink) {
        PTRANSMITTER_RING    Ring;

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        __RingDebugCallback(Ring);
    }    

    DEBUG(Printf,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback,
          "METADATA: Offset @ %ld Length @ %ld Mdl @ %ld\n",
          Transmitter->Metadata.OffsetOffset,
          Transmitter->Metadata.LengthOffset,
          Transmitter->Metadata.MdlOffset);
}

NTSTATUS
TransmitterInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  ULONG               Count,
    OUT PXENVIF_TRANSMITTER *Transmitter
    )
{
    HANDLE                  ParametersKey;
    ULONG                   Done;
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

    (*Transmitter)->CacheInterface = FrontendGetCacheInterface(Frontend);

    CACHE(Acquire, (*Transmitter)->CacheInterface);

    (*Transmitter)->Frontend = Frontend;

    Done = 0;
    while (Done < Count) {
        PTRANSMITTER_RING   Ring;

        status = __RingInitialize(*Transmitter, &Ring);
        if (!NT_SUCCESS(status))
            goto fail2;

        InsertTailList(&(*Transmitter)->List, &Ring->ListEntry);
        Done++;
    }

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");    

    (*Transmitter)->Frontend = NULL;

    while (!IsListEmpty(&(*Transmitter)->List)) {
        PLIST_ENTRY         ListEntry;
        PTRANSMITTER_RING   Ring;

        ListEntry = RemoveTailList(&(*Transmitter)->List);
        ASSERT3P(ListEntry, !=, &(*Transmitter)->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        __RingTeardown(Ring);
        --Done;
    }
    ASSERT3U(Done, ==, 0);

    CACHE(Release, (*Transmitter)->CacheInterface);
    (*Transmitter)->CacheInterface = NULL;

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
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PXENVIF_FRONTEND        Frontend;
    PLIST_ENTRY             ListEntry;
    PTRANSMITTER_RING       Ring;
    ULONG                   Attempt;
    NTSTATUS                status;

    Frontend = Transmitter->Frontend;

    Transmitter->StoreInterface = FrontendGetStoreInterface(Frontend);

    STORE(Acquire, Transmitter->StoreInterface);

    for (ListEntry = Transmitter->List.Flink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Flink) {

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        status = __RingConnect(Ring);
        if (!NT_SUCCESS(status))
            goto fail1;
    }    

    Transmitter->DebugInterface = FrontendGetDebugInterface(Frontend);

    DEBUG(Acquire, Transmitter->DebugInterface);

    status = DEBUG(Register,
                   Transmitter->DebugInterface,
                   __MODULE__ "|TRANSMITTER",
                   TransmitterDebugCallback,
                   Transmitter,
                   &Transmitter->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail2;

    ListEntry = Transmitter->List.Flink;
    Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

    Attempt = 0;
    do {
        status = __RingDumpAddressTable(Ring);
    } while (status == STATUS_RETRY && ++Attempt <= 10);

    Transmitter->VifInterface = FrontendGetVifInterface(Frontend);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    DEBUG(Release, Transmitter->DebugInterface);
    Transmitter->DebugInterface = NULL;

    ListEntry = &Transmitter->List;

fail1:
    Error("fail1 (%08x)\n", status);

    ListEntry = ListEntry->Blink;

    while (ListEntry != &Transmitter->List) {
        PLIST_ENTRY         Prev = ListEntry->Blink;

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        __RingDisconnect(Ring);

        ListEntry = Prev;
    }

    STORE(Release, Transmitter->StoreInterface);
    Transmitter->StoreInterface = NULL;

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
        PTRANSMITTER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        status = __RingStoreWrite(Ring, Transaction);
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
        PTRANSMITTER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        __RingEnable(Ring);
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
        PTRANSMITTER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        __RingDisable(Ring);
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

    Transmitter->VifInterface = NULL;

    DEBUG(Deregister,
          Transmitter->DebugInterface,
          Transmitter->DebugCallback);
    Transmitter->DebugCallback = NULL;

    DEBUG(Release, Transmitter->DebugInterface);
    Transmitter->DebugInterface = NULL;

    for (ListEntry = Transmitter->List.Blink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Blink) {
        PTRANSMITTER_RING    Ring;

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        __RingDisconnect(Ring);
    }

    STORE(Remove,
          Transmitter->StoreInterface,
          NULL,
          FrontendGetPrefix(Frontend),
          "ip");

    STORE(Remove,
          Transmitter->StoreInterface,
          NULL,
          FrontendGetPrefix(Frontend),
          "ipv4");

    STORE(Remove,
          Transmitter->StoreInterface,
          NULL,
          FrontendGetPrefix(Frontend),
          "ipv6");

    STORE(Release, Transmitter->StoreInterface);
    Transmitter->StoreInterface = NULL;
}

VOID
TransmitterTeardown(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    RtlZeroMemory(&Transmitter->Metadata, sizeof (XENVIF_TRANSMITTER_PACKET_METADATA));

    while (!IsListEmpty(&Transmitter->List)) {
        PLIST_ENTRY         ListEntry;
        PTRANSMITTER_RING   Ring;

        ListEntry = RemoveHeadList(&Transmitter->List);
        ASSERT3P(ListEntry, !=, &Transmitter->List);
        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        __RingTeardown(Ring);
    }

    Transmitter->Frontend = NULL;

    CACHE(Release, Transmitter->CacheInterface);
    Transmitter->CacheInterface = NULL;

    RtlZeroMemory(&Transmitter->List, sizeof (LIST_ENTRY));

    Transmitter->DisableIpVersion4Gso = 0;
    Transmitter->DisableIpVersion6Gso = 0;
    Transmitter->AlwaysCopy = 0;

    ASSERT(IsZeroMemory(Transmitter, sizeof (XENVIF_TRANSMITTER)));
    __TransmitterFree(Transmitter);
}

VOID
TransmitterUpdateAddressTable(
    IN  PXENVIF_TRANSMITTER Transmitter,
    IN  SOCKADDR_INET       Table[],
    IN  ULONG               Count
    )
{
    KIRQL                   Irql;
    PLIST_ENTRY             ListEntry;
    PTRANSMITTER_RING       Ring;

    // Make sure we don't suspend
    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    // Use the first ring for address advertisment
    ListEntry = Transmitter->List.Flink;
    Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

    __RingUpdateAddressTable(Ring, Table, Count);

    KeLowerIrql(Irql);
}

VOID
TransmitterAdvertizeAddresses(
    IN  PXENVIF_TRANSMITTER Transmitter
    )
{
    PLIST_ENTRY             ListEntry;
    PTRANSMITTER_RING       Ring;

    // Use the first ring for address advertisment
    ListEntry = Transmitter->List.Flink;
    Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

    __RingAdvertizeAddresses(Ring);
}

VOID
TransmitterSetPacketMetadata(
    IN  PXENVIF_TRANSMITTER                 Transmitter,
    IN  XENVIF_TRANSMITTER_PACKET_METADATA  Metadata
    )
{
    Transmitter->Metadata = Metadata;
}

VOID
TransmitterQueuePackets(
    IN  PXENVIF_TRANSMITTER         Transmitter,
    IN  PXENVIF_TRANSMITTER_PACKET  HeadPacket
    )
{
    PLIST_ENTRY                     ListEntry;
    PTRANSMITTER_RING               Ring;

    // We need to hash for a ring eventually. Since there is only a
    // single ring for now, we just use that.
    ListEntry = Transmitter->List.Flink;
    Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

    __RingQueuePackets(Ring, HeadPacket);
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
        PTRANSMITTER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        __RingAbortPackets(Ring);
    }    

    KeLowerIrql(Irql);
}

VOID
TransmitterGetPacketStatistics(
    IN  PXENVIF_TRANSMITTER                     Transmitter,
    OUT PXENVIF_TRANSMITTER_PACKET_STATISTICS   Statistics
    )
{
    PLIST_ENTRY                                 ListEntry;

    RtlZeroMemory(Statistics, sizeof (XENVIF_TRANSMITTER_PACKET_STATISTICS));

    for (ListEntry = Transmitter->List.Flink;
         ListEntry != &Transmitter->List;
         ListEntry = ListEntry->Flink) {
        PTRANSMITTER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        __RingAddPacketStatistics(Ring, Statistics);
    }    
}

ULONG
TransmitterGetRingSize(
    IN  PXENVIF_TRANSMITTER Transitter
    )
{
    PLIST_ENTRY             ListEntry;
    PTRANSMITTER_RING       Ring;

    // Use the first ring
    ListEntry = Transitter->List.Flink;
    Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

    return __RingGetSize(Ring);
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
        PTRANSMITTER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, TRANSMITTER_RING, ListEntry);

        __RingNotify(Ring);
    }    
}

VOID
TransmitterGetOffloadOptions(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    OUT PXENVIF_OFFLOAD_OPTIONS Options
    )
{
    PXENVIF_FRONTEND            Frontend;
    PCHAR                       Buffer;
    NTSTATUS                    status;

    Frontend = Transmitter->Frontend;

    Options->Value = 0;

    Options->OffloadTagManipulation = 1;

    if (Transmitter->DisableIpVersion4Gso == 0) {
        status = STORE(Read,
                       Transmitter->StoreInterface,
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

        STORE(Free,
              Transmitter->StoreInterface,
              Buffer);
    }

    if (Transmitter->DisableIpVersion6Gso == 0) {
        status = STORE(Read,
                       Transmitter->StoreInterface,
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

        STORE(Free,
              Transmitter->StoreInterface,
              Buffer);
    }

    Options->OffloadIpVersion4HeaderChecksum = 1;

    status = STORE(Read,
                   Transmitter->StoreInterface,
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

        STORE(Free,
              Transmitter->StoreInterface,
              Buffer);
    }

    status = STORE(Read,
                   Transmitter->StoreInterface,
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

        STORE(Free,
              Transmitter->StoreInterface,
              Buffer);
    }
}

#define MAXIMUM_TX_REQ_SIZE         ((1 << (RTL_FIELD_SIZE(netif_tx_request_t, size) * 8)) - 1)

#define MAXIMUM_TCPV4_PAYLOAD_SIZE    (MAXIMUM_TX_REQ_SIZE -          \
                                       sizeof (ETHERNET_HEADER) -     \
                                       MAXIMUM_IPV4_HEADER_LENGTH -   \
                                       MAXIMUM_TCP_HEADER_LENGTH)

#define MAXIMUM_TCPV6_PAYLOAD_SIZE    (MAXIMUM_TX_REQ_SIZE -          \
                                       sizeof (ETHERNET_HEADER) -     \
                                       MAXIMUM_IPV6_HEADER_LENGTH -   \
                                       MAXIMUM_IPV6_OPTIONS_LENGTH -  \
                                       MAXIMUM_TCP_HEADER_LENGTH)

ULONG
TransmitterGetLargePacketSize(
    IN  PXENVIF_TRANSMITTER     Transmitter,
    IN  UCHAR                   Version
    )
{
    PXENVIF_FRONTEND            Frontend;
    PCHAR                       Buffer;
    ULONG                       OffloadIpLargePacket;
    NTSTATUS                    status;

    Frontend = Transmitter->Frontend;

    if (Version == 4) {
        status = STORE(Read,
                       Transmitter->StoreInterface,
                       NULL,
                       FrontendGetBackendPath(Frontend),
                       "feature-gso-tcpv4",
                       &Buffer);
    } else if (Version == 6) {
        status = STORE(Read,
                       Transmitter->StoreInterface,
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

        STORE(Free,
              Transmitter->StoreInterface,
              Buffer);
    }

    // The OffloadParity certification test requires that we have a single LSO size for IPv4 and IPv6 packets
    return (OffloadIpLargePacket) ? __min(MAXIMUM_TCPV4_PAYLOAD_SIZE, MAXIMUM_TCPV6_PAYLOAD_SIZE) : 0;
}
