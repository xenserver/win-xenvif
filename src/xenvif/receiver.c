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
#include <gnttab_interface.h>

// This should be in public/io/netif.h
#define _NETRXF_gso_prefix     (4)
#define  NETRXF_gso_prefix     (1U<<_NETRXF_gso_prefix)

#include "ethernet.h"
#include "tcpip.h"
#include "pdo.h"
#include "frontend.h"
#include "pool.h"
#include "checksum.h"
#include "parse.h"
#include "mac.h"
#include "vif.h"
#include "receiver.h"
#include "driver.h"
#include "log.h"
#include "assert.h"

#define RECEIVER_POOL    'ECER'

typedef struct _RECEIVER_TAG {
    LIST_ENTRY  ListEntry;
    ULONG       Next;
    PVOID       Context;
    ULONG       Reference;
} RECEIVER_TAG, *PRECEIVER_TAG;

typedef struct _RECEIVER_OFFLOAD_STATISTICS {
    ULONGLONG   IpVersion4LargePacketSegment;
    ULONGLONG   IpVersion6LargePacketSegment;
    ULONGLONG   IpVersion4HeaderChecksumCalculated;
    ULONGLONG   IpVersion4HeaderChecksumSucceeded;
    ULONGLONG   IpVersion4HeaderChecksumFailed;
    ULONGLONG   IpVersion4HeaderChecksumPresent;
    ULONGLONG   IpVersion4TcpChecksumCalculated;
    ULONGLONG   IpVersion4TcpChecksumSucceeded;
    ULONGLONG   IpVersion4TcpChecksumFailed;
    ULONGLONG   IpVersion4TcpChecksumPresent;
    ULONGLONG   IpVersion6TcpChecksumCalculated;
    ULONGLONG   IpVersion6TcpChecksumSucceeded;
    ULONGLONG   IpVersion6TcpChecksumFailed;
    ULONGLONG   IpVersion6TcpChecksumPresent;
    ULONGLONG   IpVersion4UdpChecksumCalculated;
    ULONGLONG   IpVersion4UdpChecksumSucceeded;
    ULONGLONG   IpVersion4UdpChecksumFailed;
    ULONGLONG   IpVersion4UdpChecksumPresent;
    ULONGLONG   IpVersion6UdpChecksumCalculated;
    ULONGLONG   IpVersion6UdpChecksumSucceeded;
    ULONGLONG   IpVersion6UdpChecksumFailed;
    ULONGLONG   IpVersion6UdpChecksumPresent;
    ULONGLONG   TagRemoved;
} RECEIVER_OFFLOAD_STATISTICS, *PRECEIVER_OFFLOAD_STATISTICS;

#define PROTOCOL0_RING_SIZE (__CONST_RING_SIZE(netif_rx, PAGE_SIZE))
#define MAXIMUM_TAG_COUNT   (PROTOCOL0_RING_SIZE * 2)

#define TAG_INDEX_INVALID       0xFFFFFFFF

typedef struct _RECEIVER_RING_PROTOCOL0 {
    netif_rx_front_ring_t   Front;
    netif_rx_sring_t        *Shared;
    ULONG                   Reference;
    ULONG                   HeadFreeTag;
    RECEIVER_TAG            Tag[MAXIMUM_TAG_COUNT];
    netif_rx_request_t      Pending[MAXIMUM_TAG_COUNT];
    ULONG                   RequestsPosted;
    ULONG                   RequestsPushed;
    ULONG                   ResponsesProcessed;
} RECEIVER_RING_PROTOCOL0, *PRECEIVER_RING_PROTOCOL0;

#define PROTOCOL1_RING_SIZE     (__CONST_RING_SIZE(netif_tx, PAGE_SIZE))
#define MAXIMUM_OPERATION_COUNT ((MAX_SKB_FRAGS + 1) * 2)

typedef struct _RECEIVER_RING_PROTOCOL1 {
    netif_tx_back_ring_t            Back;
    netif_tx_sring_t                *Shared;
    ULONG                           Reference;
    LIST_ENTRY                      List;
    XENBUS_GNTTAB_COPY_OPERATION    Operation[MAXIMUM_OPERATION_COUNT];
    ULONG                           RequestsProcessed;
    ULONG                           ResponsesPosted;
    ULONG                           ResponsesPushed;
} RECEIVER_RING_PROTOCOL1, *PRECEIVER_RING_PROTOCOL1;

typedef NTSTATUS (*RECEIVER_RING_CONNECT)(PRECEIVER_RING);
typedef NTSTATUS (*RECEIVER_RING_STORE_WRITE)(PRECEIVER_RING, PXENBUS_STORE_TRANSACTION);
typedef NTSTATUS (*RECEIVER_RING_ENABLE)(PRECEIVER_RING);
typedef VOID     (*RECEIVER_RING_POLL)(PRECEIVER_RING, PLIST_ENTRY, PULONG);
typedef VOID     (*RECEIVER_RING_DISABLE)(PRECEIVER_RING);
typedef VOID     (*RECEIVER_RING_DISCONNECT)(PRECEIVER_RING);
typedef VOID     (*RECEIVER_RING_DEBUG_CALLBACK)(PRECEIVER_RING);
typedef ULONG    (*RECEIVER_RING_GET_SIZE)(PRECEIVER_RING);

typedef struct _RECEIVER_RING_OPERATIONS {
    RECEIVER_RING_CONNECT           Connect;
    RECEIVER_RING_STORE_WRITE       StoreWrite;
    RECEIVER_RING_ENABLE            Enable;
    RECEIVER_RING_POLL              Poll;
    RECEIVER_RING_DISABLE           Disable;
    RECEIVER_RING_DISCONNECT        Disconnect;
    RECEIVER_RING_DEBUG_CALLBACK    DebugCallback;
    RECEIVER_RING_GET_SIZE          GetSize;
} RECEIVER_RING_OPERATIONS, *PRECEIVER_RING_OPERATIONS;

#pragma warning(push)
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

typedef struct _RECEIVER_RING {
    PXENVIF_RECEIVER                    Receiver;
    LIST_ENTRY                          ListEntry;
    KSPIN_LOCK                          Lock;
    PXENVIF_POOL                        PacketPool;
    PMDL                                Mdl;
    union {
        RECEIVER_RING_PROTOCOL0         Protocol0;
        RECEIVER_RING_PROTOCOL1         Protocol1;
    };
    BOOLEAN                             Enabled;
    BOOLEAN                             Stopped;
    PRECEIVER_RING_OPERATIONS           Operations;
    XENVIF_OFFLOAD_OPTIONS              OffloadOptions;
    XENVIF_RECEIVER_PACKET_STATISTICS   PacketStatistics;
    XENVIF_HEADER_STATISTICS            HeaderStatistics;
    RECEIVER_OFFLOAD_STATISTICS         OffloadStatistics;
    LIST_ENTRY                          PacketList;
} RECEIVER_RING, *PRECEIVER_RING;

#pragma warning(pop)

struct _XENVIF_RECEIVER {
    PXENVIF_FRONTEND            Frontend;
    ULONG                       Protocol;
    LIST_ENTRY                  List;
    LONG                        Loaned;
    LONG                        Returned;
    KEVENT                      Event;

    PXENBUS_DEBUG_INTERFACE     DebugInterface;
    PXENBUS_STORE_INTERFACE     StoreInterface;
    PXENBUS_GNTTAB_INTERFACE    GnttabInterface;
    PXENVIF_VIF_INTERFACE       VifInterface;

    PXENBUS_DEBUG_CALLBACK      DebugCallback;
};

#define REQ_ID_INTEGRITY_CHECK  0xF000

static FORCEINLINE PVOID
__ReceiverAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, RECEIVER_POOL);
}

static FORCEINLINE VOID
__ReceiverFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, RECEIVER_POOL);
}

static NTSTATUS
ReceiverPacketCtor(
    IN  PVOID               Argument,
    IN  PVOID               Object
    )
{
    PXENVIF_RECEIVER_PACKET Packet = Object;
    PMDL		            Mdl;
    PUCHAR  		        StartVa;
    NTSTATUS		        status;

    UNREFERENCED_PARAMETER(Argument);

    ASSERT(IsZeroMemory(Packet, sizeof (XENVIF_RECEIVER_PACKET)));

    Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Mdl == NULL)
	goto fail1;

    StartVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(StartVa != NULL);
    RtlFillMemory(StartVa, PAGE_SIZE, 0xAA);

    ASSERT3U(Mdl->ByteOffset, ==, 0);
    Mdl->StartVa = StartVa;
    Mdl->ByteCount = 0;

    Packet->Mdl = *Mdl;
    Packet->__Pfn = MmGetMdlPfnArray(Mdl)[0];

    ExFreePool(Mdl);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);
    
    ASSERT(IsZeroMemory(Packet, sizeof (XENVIF_RECEIVER_PACKET)));

    return status;
}

static VOID
ReceiverPacketDtor(
    IN  PVOID               Argument,
    IN  PVOID               Object
    )
{
    PXENVIF_RECEIVER_PACKET Packet = Object;
    PMDL                    Mdl;

    UNREFERENCED_PARAMETER(Argument);

    Mdl = &Packet->Mdl;

    Mdl->ByteCount = PAGE_SIZE;

    __FreePage(Mdl);

    RtlZeroMemory(Mdl, sizeof (MDL) + sizeof (PFN_NUMBER));

    ASSERT(IsZeroMemory(Packet, sizeof (XENVIF_RECEIVER_PACKET)));
}

static FORCEINLINE PXENVIF_RECEIVER_PACKET
__RingGetPacket(
    IN  PRECEIVER_RING      Ring,
    IN  BOOLEAN             Locked
    )
{
    PXENVIF_RECEIVER_PACKET Packet;

    Packet = PoolGet(Ring->PacketPool, Locked);

    ASSERT(Packet == NULL || IsZeroMemory(Packet, FIELD_OFFSET(XENVIF_RECEIVER_PACKET, Mdl)));

    return Packet;
}

static FORCEINLINE VOID
__RingPutPacket(
    IN  PRECEIVER_RING          Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet,
    IN  BOOLEAN                 Locked
    )
{
    PMDL                        Mdl = &Packet->Mdl;

    RtlZeroMemory(Packet, FIELD_OFFSET(XENVIF_RECEIVER_PACKET, Mdl));

    Mdl->MappedSystemVa = Mdl->StartVa;
    Mdl->ByteOffset = 0;
    Mdl->ByteCount = 0;
    ASSERT3P(Mdl->Next, ==, NULL);

    PoolPut(Ring->PacketPool, Packet, Locked);
}

static FORCEINLINE PMDL
__RingGetMdl(
    IN  PRECEIVER_RING      Ring,
    IN  BOOLEAN             Locked
    )
{
    PXENVIF_RECEIVER_PACKET Packet;

    Packet = __RingGetPacket(Ring, Locked);
    if (Packet == NULL)
        return NULL;

    return &Packet->Mdl;
}

static FORCEINLINE VOID
__RingPutMdl(
    IN  PRECEIVER_RING      Ring,
    IN  PMDL                Mdl,
    IN  BOOLEAN             Locked
    )
{
    PXENVIF_RECEIVER_PACKET Packet;

    Packet = CONTAINING_RECORD(Mdl, XENVIF_RECEIVER_PACKET, Mdl);
    __RingPutPacket(Ring, Packet, Locked);
}

static DECLSPEC_NOINLINE VOID
PacketProcessTag(
    IN  PXENVIF_RECEIVER_PACKET         Packet,
    IN  PXENVIF_OFFLOAD_OPTIONS         OffloadOptions,
    IN  PRECEIVER_OFFLOAD_STATISTICS    OffloadStatistics
    )
{
    PXENVIF_PACKET_INFO                 Info;
    ULONG                               PayloadLength;
    PUCHAR                              StartVa;
    PETHERNET_HEADER                    EthernetHeader;
    ULONG                               Offset;

    Info = &Packet->Info;

    PayloadLength = Packet->Length - Info->Length;

    StartVa = MmGetSystemAddressForMdlSafe(&Packet->Mdl, NormalPagePriority);
    ASSERT(StartVa != NULL);
    StartVa += Packet->Offset;

    ASSERT(Info->EthernetHeader.Length != 0);
    EthernetHeader = (PETHERNET_HEADER)(StartVa + Info->EthernetHeader.Offset);

    if (!ETHERNET_HEADER_IS_TAGGED(EthernetHeader) ||
        OffloadOptions->OffloadTagManipulation == 0)
        return;

    Packet->TagControlInformation = NTOHS(EthernetHeader->Tagged.Tag.ControlInformation);

    Offset = FIELD_OFFSET(ETHERNET_TAGGED_HEADER, Tag);
    RtlMoveMemory((PUCHAR)EthernetHeader + sizeof (ETHERNET_TAG),
                  (PUCHAR)EthernetHeader,
                  Offset);

    // Fix up the packet information
    Packet->Offset += sizeof (ETHERNET_TAG);
    Packet->Length -= sizeof (ETHERNET_TAG);

    Info->EthernetHeader.Length -= sizeof (ETHERNET_TAG);

    if (Info->IpHeader.Length != 0)
        Info->IpHeader.Offset -= sizeof (ETHERNET_TAG);

    if (Info->IpOptions.Length != 0)
        Info->IpOptions.Offset -= sizeof (ETHERNET_TAG);

    if (Info->UdpHeader.Length != 0)
        Info->UdpHeader.Offset -= sizeof (ETHERNET_TAG);

    if (Info->TcpHeader.Length != 0)
        Info->TcpHeader.Offset -= sizeof (ETHERNET_TAG);

    if (Info->TcpOptions.Length != 0)
        Info->TcpOptions.Offset -= sizeof (ETHERNET_TAG);

    Info->Length -= sizeof (ETHERNET_TAG);

    StartVa = MmGetSystemAddressForMdlSafe(&Packet->Mdl, NormalPagePriority);
    ASSERT(StartVa != NULL);
    StartVa += Packet->Offset;

    EthernetHeader = (PETHERNET_HEADER)(StartVa + Info->EthernetHeader.Offset);
    ASSERT(!ETHERNET_HEADER_IS_TAGGED(EthernetHeader));

    ASSERT3U(PayloadLength, ==, Packet->Length - Info->Length);

    OffloadStatistics->TagRemoved++;
}

static DECLSPEC_NOINLINE VOID
PacketProcessChecksum(
    IN  PXENVIF_RECEIVER_PACKET         Packet,
    IN  PXENVIF_OFFLOAD_OPTIONS         OffloadOptions,
    IN  PRECEIVER_OFFLOAD_STATISTICS    OffloadStatistics
    )
{
    PXENVIF_PACKET_INFO                 Info;
    XENVIF_PACKET_PAYLOAD               Payload;
    uint16_t                            flags;
    PUCHAR                              StartVa;
    PIP_HEADER                          IpHeader;
    BOOLEAN                             IsAFragment;

    Info = &Packet->Info;

    Payload.Mdl = &Packet->Mdl;
    Payload.Offset = Info->Length;
    Payload.Length = Packet->Length - Info->Length;

    ASSERT3U(Payload.Offset, <=, Payload.Mdl->ByteCount);

    // The payload may be in a separate fragment
    if (Payload.Offset == Payload.Mdl->ByteCount) {
        Payload.Mdl = Payload.Mdl->Next;
        Payload.Offset = 0;
    }

    flags = (uint16_t)(ULONG_PTR)Packet->Cookie;

    if (Info->IpHeader.Length == 0)
        return;

    StartVa = MmGetSystemAddressForMdlSafe(&Packet->Mdl, NormalPagePriority);
    ASSERT(StartVa != NULL);
    StartVa += Packet->Offset;

    IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);

    if (IpHeader->Version == 4) {
        BOOLEAN OffloadChecksum;

        if (OffloadOptions->OffloadIpVersion4HeaderChecksum)
            OffloadChecksum = TRUE;
        else
            OffloadChecksum = FALSE;

        // IP header checksums are always present and not validated

        if (OffloadChecksum) {
            USHORT  Embedded;
            USHORT  Calculated;

            Embedded = IpHeader->Version4.Checksum;

            Calculated = ChecksumIpVersion4Header(StartVa, Info);
            OffloadStatistics->IpVersion4HeaderChecksumCalculated++;

            if (Embedded == Calculated) {
                Packet->Flags.IpChecksumSucceeded = 1;
                OffloadStatistics->IpVersion4HeaderChecksumSucceeded++;
            } else {
                Packet->Flags.IpChecksumFailed = 1;
                OffloadStatistics->IpVersion4HeaderChecksumFailed++;
            }
        }

        if (!OffloadChecksum ||
            OffloadOptions->NeedChecksumValue ||
            DriverParameters.ReceiverCalculateChecksums) {  // Checksum must be present
            Packet->Flags.IpChecksumPresent = 1;
            OffloadStatistics->IpVersion4HeaderChecksumPresent++;
        } else {
            IpHeader->Version4.Checksum = 0;
        }

        IsAFragment = IPV4_IS_A_FRAGMENT(NTOHS(IpHeader->Version4.FragmentOffsetAndFlags)) ? TRUE : FALSE;
    } else {
        ASSERT3U(IpHeader->Version, ==, 6);

        IsAFragment = FALSE;  // No fragmentation in IPv6
    }

    if (Info->TcpHeader.Length != 0 && !IsAFragment) {
        PTCP_HEADER     TcpHeader;
        BOOLEAN         OffloadChecksum;

        TcpHeader = (PTCP_HEADER)(StartVa + Info->TcpHeader.Offset);

        if (IpHeader->Version == 4 && OffloadOptions->OffloadIpVersion4TcpChecksum)
            OffloadChecksum = TRUE;
        else if (IpHeader->Version == 6 && OffloadOptions->OffloadIpVersion6TcpChecksum)
            OffloadChecksum = TRUE;
        else
            OffloadChecksum = FALSE;

        if (OffloadChecksum) {
            if (flags & NETRXF_data_validated) {    // Checksum may not be present but it is validated
                Packet->Flags.TcpChecksumSucceeded = 1;

                if (IpHeader->Version == 4)
                    OffloadStatistics->IpVersion4TcpChecksumSucceeded++;
                else
                    OffloadStatistics->IpVersion6TcpChecksumSucceeded++;

            } else {                                // Checksum is present but is not validated
                USHORT  Embedded;
                USHORT  Calculated;

                ASSERT(~flags & NETRXF_csum_blank);

                Embedded = TcpHeader->Checksum;

                Calculated = ChecksumPseudoHeader(StartVa, Info);
                Calculated = ChecksumTcpPacket(StartVa, Info, Calculated, &Payload);

                if (IpHeader->Version == 4)
                    OffloadStatistics->IpVersion4TcpChecksumCalculated++;
                else
                    OffloadStatistics->IpVersion6TcpChecksumCalculated++;

                if (Embedded == Calculated) {
                    Packet->Flags.TcpChecksumSucceeded = 1;

                    if (IpHeader->Version == 4)
                        OffloadStatistics->IpVersion4TcpChecksumSucceeded++;
                    else
                        OffloadStatistics->IpVersion6TcpChecksumSucceeded++;

                } else {
                    Packet->Flags.TcpChecksumFailed = 1;

                    if (IpHeader->Version == 4)
                        OffloadStatistics->IpVersion4TcpChecksumFailed++;
                    else
                        OffloadStatistics->IpVersion6TcpChecksumFailed++;
                }
            }
        }
        
        if (!OffloadChecksum ||
            OffloadOptions->NeedChecksumValue ||
            DriverParameters.ReceiverCalculateChecksums) {  // Checksum must be present
            if (flags & NETRXF_csum_blank) {                // Checksum is not present
                USHORT  Calculated;

                Calculated = ChecksumPseudoHeader(StartVa, Info);
                Calculated = ChecksumTcpPacket(StartVa, Info, Calculated, &Payload);

                if (IpHeader->Version == 4)
                    OffloadStatistics->IpVersion4TcpChecksumCalculated++;
                else
                    OffloadStatistics->IpVersion6TcpChecksumCalculated++;

                TcpHeader->Checksum = Calculated;
            }

            Packet->Flags.TcpChecksumPresent = 1;

            if (IpHeader->Version == 4)
                OffloadStatistics->IpVersion4TcpChecksumPresent++;
            else
                OffloadStatistics->IpVersion6TcpChecksumPresent++;
        } else {
            TcpHeader->Checksum = 0;
        }

    } else if (Info->UdpHeader.Length != 0 && !IsAFragment) {
        PUDP_HEADER     UdpHeader;
        BOOLEAN         OffloadChecksum;

        UdpHeader = (PUDP_HEADER)(StartVa + Info->UdpHeader.Offset);

        if (IpHeader->Version == 4 && OffloadOptions->OffloadIpVersion4UdpChecksum)
            OffloadChecksum = TRUE;
        else if (IpHeader->Version == 6 && OffloadOptions->OffloadIpVersion6UdpChecksum)
            OffloadChecksum = TRUE;
        else
            OffloadChecksum = FALSE;

        if (OffloadChecksum) {
            if (flags & NETRXF_data_validated) {    // Checksum may not be present but it is validated
                Packet->Flags.UdpChecksumSucceeded = 1;

                if (IpHeader->Version == 4)
                    OffloadStatistics->IpVersion4UdpChecksumSucceeded++;
                else
                    OffloadStatistics->IpVersion6UdpChecksumSucceeded++;

            } else {                                // Checksum is present but is not validated
                USHORT  Embedded;
                USHORT  Calculated;

                ASSERT(~flags & NETRXF_csum_blank);

                Embedded = UdpHeader->Checksum;

                Calculated = ChecksumPseudoHeader(StartVa, Info);
                Calculated = ChecksumUdpPacket(StartVa, Info, Calculated, &Payload);

                if (IpHeader->Version == 4)
                    OffloadStatistics->IpVersion4UdpChecksumCalculated++;
                else
                    OffloadStatistics->IpVersion6UdpChecksumCalculated++;

                if (Embedded == Calculated) {
                    Packet->Flags.UdpChecksumSucceeded = 1;

                    if (IpHeader->Version == 4)
                        OffloadStatistics->IpVersion4UdpChecksumSucceeded++;
                    else
                        OffloadStatistics->IpVersion6UdpChecksumSucceeded++;

                } else {
                    Packet->Flags.UdpChecksumFailed = 1;

                    if (IpHeader->Version == 4)
                        OffloadStatistics->IpVersion4UdpChecksumFailed++;
                    else
                        OffloadStatistics->IpVersion6UdpChecksumFailed++;

                }
            }

        }

        if (!OffloadChecksum ||
            OffloadOptions->NeedChecksumValue ||
            DriverParameters.ReceiverCalculateChecksums) {  // Checksum must be present
            if (flags & NETRXF_csum_blank) {                // Checksum is not present
                USHORT  Calculated;

                Calculated = ChecksumPseudoHeader(StartVa, Info);
                Calculated = ChecksumUdpPacket(StartVa, Info, Calculated, &Payload);

                if (IpHeader->Version == 4)
                    OffloadStatistics->IpVersion4UdpChecksumCalculated++;
                else
                    OffloadStatistics->IpVersion6UdpChecksumCalculated++;

                UdpHeader->Checksum = Calculated;
            }

            Packet->Flags.UdpChecksumPresent = 1;

            if (IpHeader->Version == 4)
                OffloadStatistics->IpVersion4UdpChecksumPresent++;
            else
                OffloadStatistics->IpVersion6UdpChecksumPresent++;
        } else {
            UdpHeader->Checksum = 0;
        }
    }
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__RingAcquireLock(
    IN  PRECEIVER_RING  Ring
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Ring->Lock);
}

static DECLSPEC_NOINLINE VOID
RingAcquireLock(
    IN  PRECEIVER_RING  Ring
    )
{
    __RingAcquireLock(Ring);
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__RingReleaseLock(
    IN  PRECEIVER_RING  Ring
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

#pragma prefast(disable:26110)
    KeReleaseSpinLockFromDpcLevel(&Ring->Lock);
}

static DECLSPEC_NOINLINE VOID
RingReleaseLock(
    IN  PRECEIVER_RING  Ring
    )
{
    __RingReleaseLock(Ring);
}

static FORCEINLINE VOID
__RingStop(
    IN  PRECEIVER_RING  Ring
    )
{
    Info("<===>\n");

    Ring->Stopped = TRUE;
}

static FORCEINLINE VOID
__RingStart(
    IN  PRECEIVER_RING  Ring
    )
{
    Ring->Stopped = FALSE;
}

static FORCEINLINE BOOLEAN
__RingIsStopped(
    IN  PRECEIVER_RING  Ring
    )
{
    return Ring->Stopped;
}

static FORCEINLINE VOID
__RingReturnPacket(
    IN  PRECEIVER_RING          Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet,
    IN  BOOLEAN                 Locked
    )
{
    PMDL                        Mdl;

    Mdl = &Packet->Mdl;

    while (Mdl != NULL) {
        PMDL    Next;

        Next = Mdl->Next;
        Mdl->Next = NULL;

        __RingPutMdl(Ring, Mdl, Locked);

        Mdl = Next;
    }

    if (__RingIsStopped(Ring)) {
        KIRQL   Irql;

        KeRaiseIrql(DISPATCH_LEVEL, &Irql);

        if (!Locked)
            __RingAcquireLock(Ring);

        if (__RingIsStopped(Ring)) {
            PXENVIF_RECEIVER    Receiver;
            PXENVIF_FRONTEND    Frontend;

            __RingStart(Ring);

            Receiver = Ring->Receiver;
            Frontend = Receiver->Frontend;

            NotifierTrigger(FrontendGetNotifier(Frontend));
        }

        if (!Locked)
            __RingReleaseLock(Ring);

        KeLowerIrql(Irql);
    }
}

static BOOLEAN
ReceiverPullup(
    IN      PVOID                   Argument,
    IN      PUCHAR                  DestinationVa,
    IN OUT  PXENVIF_PACKET_PAYLOAD  Payload,
    IN      ULONG                   Length
    )
{
    PMDL                            Mdl;

    Mdl = Payload->Mdl;
    ASSERT3U(Payload->Offset, ==, 0);

    if (Payload->Length < Length)
        goto fail1;

    Payload->Length -= Length;

    while (Length != 0) {
        PUCHAR  SourceVa;
        ULONG   CopyLength;

        SourceVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        ASSERT(SourceVa != NULL);

        CopyLength = __min(Mdl->ByteCount, Length);

        RtlCopyMemory(DestinationVa, SourceVa, CopyLength);

        DestinationVa += CopyLength;

        Mdl->ByteOffset += CopyLength;
        Mdl->MappedSystemVa = (PUCHAR)Mdl->MappedSystemVa + CopyLength;
        Length -= CopyLength;

        Mdl->ByteCount -= CopyLength;
        if (Mdl->ByteCount == 0) {
            PRECEIVER_RING  Ring = Argument;
            PMDL            Next;

            Next = Mdl->Next;
            Mdl->Next = NULL;

            __RingPutMdl(Ring, Mdl, TRUE);

            Mdl = Next;
        }
    }

    Payload->Mdl = Mdl;

    return TRUE;

fail1:
    Error("fail1\n");

    return FALSE;
}

static FORCEINLINE VOID
__RingPullupPacket(
    IN  PRECEIVER_RING          Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PUCHAR                      StartVa;
    XENVIF_PACKET_PAYLOAD       Payload;
    ULONG                       Length;

    StartVa = MmGetSystemAddressForMdlSafe(&Packet->Mdl, NormalPagePriority);
    ASSERT(StartVa != NULL);

    Payload.Mdl = Packet->Mdl.Next;
    Payload.Offset = 0;
    Payload.Length = Packet->Length - Packet->Mdl.ByteCount;

    Length = __min(Payload.Length, PAGE_SIZE - Packet->Mdl.ByteCount);

    Packet->Mdl.Next = NULL;

    (VOID) ReceiverPullup(Ring, StartVa + Packet->Mdl.ByteCount, &Payload, Length);
    Packet->Mdl.ByteCount += Length;

    if (Payload.Length != 0) {
        ASSERT(Payload.Mdl != NULL);
        Packet->Mdl.Next = Payload.Mdl;
    }
}

static FORCEINLINE PXENVIF_RECEIVER_PACKET
__RingBuildSegment(
    IN  PRECEIVER_RING          Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet,
    IN  ULONG                   SegmentSize,
    IN  PXENVIF_PACKET_PAYLOAD  Payload
    )
{
    PXENVIF_PACKET_INFO         Info;
    PXENVIF_RECEIVER_PACKET     Segment;
    PMDL                        Mdl;
    PUCHAR                      InfoVa;
    PUCHAR                      StartVa;
    PIP_HEADER                  IpHeader;
    PTCP_HEADER                 TcpHeader;
    ULONG                       Seq;
    NTSTATUS                    status;

    Info = &Packet->Info;

    InfoVa = MmGetSystemAddressForMdlSafe(&Packet->Mdl, NormalPagePriority);
    ASSERT(InfoVa != NULL);
    InfoVa += Packet->Offset;

    Segment = __RingGetPacket(Ring, TRUE);

    status = STATUS_NO_MEMORY;
    if (Segment == NULL)
        goto fail1;

    Segment->Offset = Packet->Offset;

    Mdl = &Segment->Mdl;

    StartVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
    ASSERT(StartVa != NULL);
    StartVa += Segment->Offset;

    Mdl->ByteCount = Segment->Offset;

    // Copy in the header
    RtlCopyMemory(StartVa, InfoVa, Info->Length);
    Mdl->ByteCount += Info->Length;

    Segment->Info = Packet->Info;
    Segment->Cookie = Packet->Cookie;

    // Adjust the info for the next segment
    IpHeader = (PIP_HEADER)(InfoVa + Info->IpHeader.Offset);
    if (IpHeader->Version == 4) {
        USHORT  PacketID;
        USHORT  PacketLength;

        PacketID = NTOHS(IpHeader->Version4.PacketID);
        IpHeader->Version4.PacketID = HTONS(PacketID + 1);

        PacketLength = NTOHS(IpHeader->Version4.PacketLength);
        IpHeader->Version4.PacketLength = HTONS(PacketLength - (USHORT)SegmentSize);
    } else {
        USHORT  PayloadLength;

        ASSERT3U(IpHeader->Version, ==, 6);

        PayloadLength = NTOHS(IpHeader->Version6.PayloadLength);
        IpHeader->Version6.PayloadLength = HTONS(PayloadLength - (USHORT)SegmentSize);
    }

    TcpHeader = (PTCP_HEADER)(InfoVa + Info->TcpHeader.Offset);

    Seq = NTOHL(TcpHeader->Seq);
    TcpHeader->Seq = HTONL(Seq + SegmentSize);

    TcpHeader->Flags &= ~TCP_CWR;

    // Adjust the segment IP header
    IpHeader = (PIP_HEADER)(StartVa + Info->IpHeader.Offset);
    if (IpHeader->Version == 4) {
        ULONG   Length;

        Length = Info->IpHeader.Length +
                 Info->IpOptions.Length + 
                 Info->TcpHeader.Length + 
                 Info->TcpOptions.Length + 
                 SegmentSize;

        IpHeader->Version4.PacketLength = HTONS((USHORT)Length);
        IpHeader->Version4.Checksum = ChecksumIpVersion4Header(StartVa, Info);

        Ring->OffloadStatistics.IpVersion4LargePacketSegment++;
    } else {
        ULONG   Length;

        ASSERT3U(IpHeader->Version, ==, 6);

        Length = Info->IpOptions.Length + 
                 Info->TcpHeader.Length + 
                 Info->TcpOptions.Length + 
                 SegmentSize;

        IpHeader->Version6.PayloadLength = HTONS((USHORT)Length);

        Ring->OffloadStatistics.IpVersion6LargePacketSegment++;
    }

    // Adjust the segment TCP header
    TcpHeader = (PTCP_HEADER)(StartVa + Info->TcpHeader.Offset);

    TcpHeader->Flags &= ~(TCP_PSH | TCP_FIN);

    // Copy in the payload
    for (;;) {
        ULONG   Length;

        Mdl->Next = __RingGetMdl(Ring, TRUE);
            
        status = STATUS_NO_MEMORY;
        if (Mdl->Next == NULL)
            goto fail2;

        Mdl = Mdl->Next;
        StartVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
        ASSERT(StartVa != NULL);

        Length = __min(SegmentSize - Segment->Length, PAGE_SIZE);
        ASSERT(Length != 0);

        (VOID) ReceiverPullup(Ring, StartVa, Payload, Length);
        Mdl->ByteCount += Length;
        Segment->Length += Length;

        ASSERT3U(Segment->Length, <=, SegmentSize);
        if (Segment->Length == SegmentSize)
            break;

        ASSERT3U(Mdl->ByteCount, ==, PAGE_SIZE);
    }

    Segment->Length += Info->Length;

    return Segment;

fail2:
    Error("fail2\n");

    if (IpHeader->Version == 4) {
        --Ring->OffloadStatistics.IpVersion4LargePacketSegment;
    } else {
        ASSERT3U(IpHeader->Version, ==, 6);
        --Ring->OffloadStatistics.IpVersion6LargePacketSegment;
    }

    Mdl = Segment->Mdl.Next;
    Segment->Mdl.Next = NULL;

    while (Mdl != NULL) {
        PMDL    Next;

        Next = Mdl->Next;
        Mdl->Next = NULL;

        __RingPutMdl(Ring, Mdl, TRUE);

        Mdl = Next;
    }

    __RingPutPacket(Ring, Segment, TRUE);

fail1:
    Error("fail1 (%08x)\n", status);
    
    return NULL;
}

static FORCEINLINE VOID
__RingProcessLargePacket(
    IN  PRECEIVER_RING          Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet,
    OUT PLIST_ENTRY             List
    )
{
    BOOLEAN                     Offload;
    PXENVIF_PACKET_INFO         Info;
    uint16_t                    flags;
    XENVIF_PACKET_PAYLOAD       Payload;
    PUCHAR                      InfoVa;
    PIP_HEADER                  IpHeader;
    ULONG                       Length;
    NTSTATUS                    status;

    Info = &Packet->Info;
    
    flags = (uint16_t)(ULONG_PTR)Packet->Cookie;
    ASSERT(flags & NETRXF_csum_blank);
    ASSERT(flags & NETRXF_data_validated);

    Payload.Mdl = Packet->Mdl.Next;
    Payload.Offset = 0;
    Payload.Length = Packet->Length - Info->Length;

    Packet->Mdl.Next = NULL;

    InfoVa = MmGetSystemAddressForMdlSafe(&Packet->Mdl, NormalPagePriority);
    ASSERT(InfoVa != NULL);
    InfoVa += Packet->Offset;

    IpHeader = (PIP_HEADER)(InfoVa + Info->IpHeader.Offset);

    if (IpHeader->Version == 4) {
        Offload = (Ring->OffloadOptions.OffloadIpVersion4LargePacket) ? TRUE : FALSE;
    } else {
        ASSERT3U(IpHeader->Version, ==, 6);
        Offload = (Ring->OffloadOptions.OffloadIpVersion6LargePacket) ? TRUE : FALSE;
    }

    if (IpHeader->Version == 4) {
        USHORT  PacketLength;

        PacketLength = NTOHS(IpHeader->Version4.PacketLength);
        
        Length = (ULONG)PacketLength -
                 Info->TcpOptions.Length -
                 Info->TcpHeader.Length -
                 Info->IpOptions.Length - 
                 Info->IpHeader.Length;
    } else {
        USHORT  PayloadLength;

        ASSERT3U(IpHeader->Version, ==, 6);

        PayloadLength = NTOHS(IpHeader->Version6.PayloadLength);

        Length = (ULONG)PayloadLength -
                 Info->TcpOptions.Length -
                 Info->TcpHeader.Length -
                 Info->IpOptions.Length;
    }

    while (Length > 0) {
        ULONG                   SegmentSize;
        PXENVIF_RECEIVER_PACKET Segment;

        if (Offload &&
            Ring->OffloadOptions.NeedLargePacketSplit == 0)
            break;

        SegmentSize = __min(Length, Packet->MaximumSegmentSize);

        Segment = __RingBuildSegment(Ring, Packet, SegmentSize, &Payload);

        status = STATUS_NO_MEMORY;
        if (Segment == NULL)
            goto fail1;

        ASSERT3U(Length, >=, SegmentSize);
        Length -= SegmentSize;

        ASSERT(IsZeroMemory(&Segment->ListEntry, sizeof (LIST_ENTRY)));
        InsertTailList(List, &Segment->ListEntry);

        if (Offload) {
            ASSERT(Ring->OffloadOptions.NeedLargePacketSplit);
            break;
        }
    }

    if (Length != 0) {
        ASSERT(Payload.Mdl != NULL);

        if (IpHeader->Version == 4) {
            USHORT  PacketLength;

            PacketLength = NTOHS(IpHeader->Version4.PacketLength);
        
            ASSERT3U(Length,
                     ==,
                     (ULONG)PacketLength -
                     Info->TcpOptions.Length -
                     Info->TcpHeader.Length -
                     Info->IpOptions.Length - 
                     Info->IpHeader.Length);

            IpHeader->Version4.Checksum = ChecksumIpVersion4Header(InfoVa, Info);

            Ring->OffloadStatistics.IpVersion4LargePacketSegment++;
        } else {
            USHORT  PayloadLength;

            ASSERT3U(IpHeader->Version, ==, 6);

            PayloadLength = NTOHS(IpHeader->Version6.PayloadLength);

            ASSERT3U(Length,
                     ==,
                     (ULONG)PayloadLength -
                     Info->TcpOptions.Length -
                     Info->TcpHeader.Length -
                     Info->IpOptions.Length);

            Ring->OffloadStatistics.IpVersion6LargePacketSegment++;
        }

        Packet->Mdl.Next = Payload.Mdl;
        Packet->Length = Info->Length + Payload.Length;

        if (Payload.Length < Packet->MaximumSegmentSize)
            Packet->MaximumSegmentSize = 0;

        if (DriverParameters.ReceiverAlwaysPullup != 0)
            __RingPullupPacket(Ring, Packet);

        ASSERT(IsZeroMemory(&Packet->ListEntry, sizeof (LIST_ENTRY)));
        InsertTailList(List, &Packet->ListEntry);
    } else {
        __RingPutPacket(Ring, Packet, TRUE);
    }

    return;

fail1:
    Error("fail1 (%08x)\n", status);

    if (Payload.Length != 0) {
        PMDL    Mdl = Payload.Mdl;

        ASSERT(Mdl != NULL);

        while (Mdl != NULL) {
            PMDL    Next;

            Next = Mdl->Next;
            Mdl->Next = NULL;

            __RingPutMdl(Ring, Mdl, TRUE);

            Mdl = Next;
        }
    }

    __RingPutPacket(Ring, Packet, TRUE);
        
    Ring->PacketStatistics.Drop++;
}

static FORCEINLINE VOID
__RingProcessPacket(
    IN  PRECEIVER_RING          Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet,
    OUT PLIST_ENTRY             List
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    ULONG                       Length;
    USHORT                      MaximumSegmentSize;
    PVOID                       Cookie;
    XENVIF_PACKET_PAYLOAD       Payload;
    PXENVIF_PACKET_INFO         Info;
    PUCHAR                      StartVa;
    PETHERNET_HEADER            EthernetHeader;
    PETHERNET_ADDRESS           DestinationAddress;
    ETHERNET_ADDRESS_TYPE       Type;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    ASSERT3U(Packet->Offset, ==, 0);
    Length = Packet->Length;
    MaximumSegmentSize = Packet->MaximumSegmentSize;
    Cookie = Packet->Cookie;

    // Clean the packet metadata since this structure now becomes payload
    RtlZeroMemory(Packet, FIELD_OFFSET(XENVIF_RECEIVER_PACKET, Mdl));

    Payload.Mdl = &Packet->Mdl;
    Payload.Offset = 0;
    Payload.Length = Length;

    // Get a new packet structure that will just contain the header after parsing
    Packet = __RingGetPacket(Ring, TRUE);

    status = STATUS_NO_MEMORY;
    if (Packet == NULL) {
        Ring->PacketStatistics.FrontendError++;
        goto fail1;
    }

    // Copy in the extracted metadata
    Packet->Offset = DriverParameters.ReceiverIpAlignOffset;
    Packet->Length = Length;
    Packet->MaximumSegmentSize = MaximumSegmentSize;
    Packet->Cookie = Cookie;

    StartVa = MmGetSystemAddressForMdlSafe(&Packet->Mdl, NormalPagePriority);
    ASSERT(StartVa != NULL);
    StartVa += Packet->Offset;

    Packet->Mdl.ByteCount = Packet->Offset;

    Info = &Packet->Info;

    status = ParsePacket(StartVa, ReceiverPullup, Ring, &Ring->HeaderStatistics, &Payload, Info);
    if (!NT_SUCCESS(status)) {
        Ring->PacketStatistics.FrontendError++;
        goto fail2;
    }

    ASSERT3U(Packet->Length, ==, Info->Length + Payload.Length);

    Packet->Mdl.ByteCount += Info->Length;

    if (Payload.Length != 0) {
        ASSERT(Payload.Mdl != NULL);
        Packet->Mdl.Next = Payload.Mdl;
    }

    ASSERT(Info->EthernetHeader.Length != 0);
    EthernetHeader = (PETHERNET_HEADER)(StartVa + Info->EthernetHeader.Offset);

    DestinationAddress = &EthernetHeader->DestinationAddress;

    status = STATUS_UNSUCCESSFUL;
    if (!MacApplyFilters(FrontendGetMac(Frontend),
                         DestinationAddress))
        goto fail3;

    Type = GET_ETHERNET_ADDRESS_TYPE(DestinationAddress);

    switch (Type) {
    case ETHERNET_ADDRESS_UNICAST:
        Ring->PacketStatistics.Unicast++;
        Ring->PacketStatistics.UnicastBytes += Packet->Length;
        break;
            
    case ETHERNET_ADDRESS_MULTICAST:
        Ring->PacketStatistics.Multicast++;
        Ring->PacketStatistics.MulticastBytes += Packet->Length;
        break;

    case ETHERNET_ADDRESS_BROADCAST:
        Ring->PacketStatistics.Broadcast++;
        Ring->PacketStatistics.BroadcastBytes += Packet->Length;
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    if (Packet->MaximumSegmentSize != 0) {
        __RingProcessLargePacket(Ring, Packet, List);
    } else {
        // Certain HCK tests (e.g. the NDISTest 2c_Priority test) are
        // sufficiently brain-dead that they cannot cope with
        // multi-fragment packets, or at least packets where headers are
        // in different fragments. All these tests seem to use IPX packets
        // and, in practice, little else uses LLC so pull up all LLC
        // packets into a single fragment.
        if (Info->LLCSnapHeader.Length != 0 ||
            DriverParameters.ReceiverAlwaysPullup != 0)
            __RingPullupPacket(Ring, Packet);

        ASSERT(IsZeroMemory(&Packet->ListEntry, sizeof (LIST_ENTRY)));
        InsertTailList(List, &Packet->ListEntry);
    }

    return;

fail3:
    Packet->Mdl.Next = NULL;
    __RingPutPacket(Ring, Packet, TRUE);

fail2:
fail1:
    if (Payload.Length != 0) {
        PMDL    Mdl = Payload.Mdl;

        ASSERT(Mdl != NULL);

        while (Mdl != NULL) {
            PMDL    Next;

            Next = Mdl->Next;
            Mdl->Next = NULL;

            __RingPutMdl(Ring, Mdl, TRUE);

            Mdl = Next;
        }
    }
        
    Ring->PacketStatistics.Drop++;
}

static VOID
RingProcessPackets(
    IN      PRECEIVER_RING  Ring,
    OUT     PLIST_ENTRY     List,
    OUT     PULONG          Count
    )
{
    PLIST_ENTRY             ListEntry;

    while (!IsListEmpty(&Ring->PacketList)) {
        PXENVIF_RECEIVER_PACKET Packet;

        ListEntry = RemoveHeadList(&Ring->PacketList);
        ASSERT3P(ListEntry, !=, &Ring->PacketList);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Packet = CONTAINING_RECORD(ListEntry, XENVIF_RECEIVER_PACKET, ListEntry);
        __RingProcessPacket(Ring, Packet, List);
    }

    for (ListEntry = List->Flink;
         ListEntry != List;
         ListEntry = ListEntry->Flink) {
        PXENVIF_RECEIVER_PACKET Packet;

        Packet = CONTAINING_RECORD(ListEntry, XENVIF_RECEIVER_PACKET, ListEntry);

        PacketProcessTag(Packet,
                         &Ring->OffloadOptions,
                         &Ring->OffloadStatistics);

        PacketProcessChecksum(Packet,
                              &Ring->OffloadOptions,
                              &Ring->OffloadStatistics);

        Packet->Cookie = Ring;

        (*Count)++;
    }
}

static FORCEINLINE PRECEIVER_TAG
__Protocol0GetTag(
    IN  PRECEIVER_RING          Ring
    )
{
    PRECEIVER_RING_PROTOCOL0    Protocol0;
    ULONG                       Index;
    PRECEIVER_TAG               Tag;

    Protocol0 = &Ring->Protocol0;

    Index = Protocol0->HeadFreeTag;
    ASSERT3U(Index, <, MAXIMUM_TAG_COUNT);

    Tag = &Protocol0->Tag[Index];
    Protocol0->HeadFreeTag = Tag->Next;
    Tag->Next = TAG_INDEX_INVALID;

    return Tag;
}

static FORCEINLINE
__Protocol0PutTag(
    IN  PRECEIVER_RING          Ring,
    IN  PRECEIVER_TAG           Tag
    )
{
    PRECEIVER_RING_PROTOCOL0    Protocol0;
    ULONG                       Index;

    Protocol0 = &Ring->Protocol0;

    ASSERT3P(Tag->Context, ==, NULL);

    Index = (ULONG)(Tag - &Protocol0->Tag[0]);
    ASSERT3U(Index, <, MAXIMUM_TAG_COUNT);

    ASSERT3U(Tag->Next, ==, TAG_INDEX_INVALID);
    Tag->Next = Protocol0->HeadFreeTag;
    Protocol0->HeadFreeTag = Index;
}

static FORCEINLINE PRECEIVER_TAG
__Protocol0PreparePacket(
    IN  PRECEIVER_RING  Ring,
    IN  PMDL            Mdl
    )
{
    PXENVIF_RECEIVER    Receiver;
    PXENVIF_FRONTEND    Frontend;
    PRECEIVER_TAG       Tag;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Tag = __Protocol0GetTag(Ring);

    Tag->Context = Mdl;

    GNTTAB(PermitForeignAccess,
           Receiver->GnttabInterface,
           Tag->Reference,
           FrontendGetBackendDomain(Frontend),
           GNTTAB_ENTRY_FULL_PAGE,
           MmGetMdlPfnArray(Mdl)[0],
           FALSE);

    return Tag;
}

static VOID
Protocol0ReleaseTag(
    IN  PRECEIVER_RING  Ring,
    IN  PRECEIVER_TAG   Tag
    )
{
    PXENVIF_RECEIVER    Receiver;

    Receiver = Ring->Receiver;

    GNTTAB(RevokeForeignAccess,
           Receiver->GnttabInterface,
           Tag->Reference);

    __Protocol0PutTag(Ring, Tag);
}

static FORCEINLINE VOID
__Protocol0PushRequests(
    IN  PRECEIVER_RING          Ring
    )
{
    PRECEIVER_RING_PROTOCOL0    Protocol0;
    BOOLEAN                     Notify;

    Protocol0 = &Ring->Protocol0;

    if (Protocol0->RequestsPosted == Protocol0->RequestsPushed)
        return;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the requests visible to the backend
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Protocol0->Front, Notify);

#pragma warning (pop)

    if (Notify) {
        PXENVIF_RECEIVER    Receiver;
        PXENVIF_FRONTEND    Frontend;

        Receiver = Ring->Receiver;
        Frontend = Receiver->Frontend;

        NotifierSend(FrontendGetNotifier(Frontend));
    }

    Protocol0->RequestsPushed = Protocol0->RequestsPosted;
}

static VOID
Protocol0Fill(
    IN  PRECEIVER_RING          Ring
    )
{
    PRECEIVER_RING_PROTOCOL0    Protocol0;
    RING_IDX                    req_prod;
    RING_IDX                    rsp_cons;

    Protocol0 = &Ring->Protocol0;

    req_prod = Protocol0->Front.req_prod_pvt;
    rsp_cons = Protocol0->Front.rsp_cons;

    while (req_prod - rsp_cons < RING_SIZE(&Protocol0->Front)) {
        PXENVIF_RECEIVER_PACKET Packet;
        PRECEIVER_TAG           Tag;
        netif_rx_request_t      *req;
        uint16_t                id;

        Packet = __RingGetPacket(Ring, TRUE);

        if (Packet == NULL) {
            __RingStop(Ring);
            break;
        }

        Tag = __Protocol0PreparePacket(Ring, &Packet->Mdl);
        ASSERT(Tag != NULL);

        req = RING_GET_REQUEST(&Protocol0->Front, req_prod);
        req_prod++;
        Protocol0->RequestsPosted++;

        id = (USHORT)(Tag - &Protocol0->Tag[0]);
        ASSERT3U(id, <, MAXIMUM_TAG_COUNT);

        req->id = id | REQ_ID_INTEGRITY_CHECK;
        req->gref = Tag->Reference;

        // Store a copy of the request in case we need to fake a response ourselves
        ASSERT(IsZeroMemory(&Protocol0->Pending[id], sizeof (netif_rx_request_t)));
        Protocol0->Pending[id] = *req;
    }

    Protocol0->Front.req_prod_pvt = req_prod;

    __Protocol0PushRequests(Ring);
}

#define PROTOCOL0_BATCH(_Ring) (RING_SIZE(&(_Ring)->Protocol0.Front) / 4)

static DECLSPEC_NOINLINE VOID
Protocol0Poll(
    IN  PRECEIVER_RING          Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PRECEIVER_RING_PROTOCOL0    Protocol0;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Protocol0 = &Ring->Protocol0;

    for (;;) {
        BOOLEAN                 Error;
        PXENVIF_RECEIVER_PACKET Packet;
        uint16_t                flags;
        USHORT                  MaximumSegmentSize;
        PMDL                    TailMdl;
        RING_IDX                rsp_prod;
        RING_IDX                rsp_cons;

        Error = FALSE;
        Packet = NULL;
        flags = 0;
        MaximumSegmentSize = 0;
        TailMdl = NULL;

        KeMemoryBarrier();

        rsp_prod = Protocol0->Shared->rsp_prod;
        rsp_cons = Protocol0->Front.rsp_cons;

        KeMemoryBarrier();

        if (rsp_cons == rsp_prod)
            break;

        while (rsp_cons != rsp_prod) {
            netif_rx_response_t *rsp;
            uint16_t            id;
            netif_rx_request_t  *req;
            PRECEIVER_TAG       Tag;
            PMDL                Mdl;
            RING_IDX            req_prod;

            rsp = RING_GET_RESPONSE(&Protocol0->Front, rsp_cons);
            rsp_cons++;
            Protocol0->ResponsesProcessed++;

            ASSERT3U((rsp->id & REQ_ID_INTEGRITY_CHECK), ==, REQ_ID_INTEGRITY_CHECK);
            id = rsp->id & ~REQ_ID_INTEGRITY_CHECK;

            ASSERT3U(id, <, MAXIMUM_TAG_COUNT);
            req = &Protocol0->Pending[id];

            ASSERT3U(req->id, ==, rsp->id);
            RtlZeroMemory(req, sizeof (netif_rx_request_t));

            Tag = &Protocol0->Tag[id];

            Mdl = Tag->Context;
            Tag->Context = NULL;

            Protocol0ReleaseTag(Ring, Tag);
            Tag = NULL;

            ASSERT(Mdl != NULL);

            if (rsp->status < 0)
                Error = TRUE;

            if (rsp->flags & NETRXF_gso_prefix) {
                __RingPutMdl(Ring, Mdl, TRUE);

                flags = NETRXF_gso_prefix;
                MaximumSegmentSize = rsp->offset;

                ASSERT(rsp->flags & NETRXF_more_data);
                continue;
            } else {
                Mdl->ByteOffset = rsp->offset;
                Mdl->MappedSystemVa = (PUCHAR)Mdl->StartVa + rsp->offset;
                Mdl->ByteCount = rsp->status;
            }

            if (Packet == NULL) {   // SOP
                Packet = CONTAINING_RECORD(Mdl, XENVIF_RECEIVER_PACKET, Mdl);

                ASSERT3P(TailMdl, ==, NULL);
                TailMdl = Mdl;

                ASSERT3U((flags & ~NETRXF_gso_prefix), ==, 0);
                flags |= rsp->flags;

                Packet->Length = Mdl->ByteCount;
            } else {
                ASSERT3P(Mdl->Next, ==, NULL);

                ASSERT(TailMdl != NULL);
                TailMdl->Next = Mdl;
                TailMdl = Mdl;

                flags |= rsp->flags;

                Packet->Length += Mdl->ByteCount;
            }

            if (~rsp->flags & NETRXF_more_data) {  // EOP
                ASSERT(Packet != NULL);
                ASSERT3P(Packet->Cookie, ==, NULL);

                if (Error) {
                    Ring->PacketStatistics.BackendError++;

                    __RingReturnPacket(Ring, Packet, TRUE);
                } else {
                    if (flags & NETRXF_gso_prefix) {
                        ASSERT(MaximumSegmentSize != 0);
                        Packet->MaximumSegmentSize = MaximumSegmentSize;
                    }

                    Packet->Cookie = (PVOID)(flags & (NETRXF_csum_blank | NETRXF_data_validated));

                    ASSERT(IsZeroMemory(&Packet->ListEntry, sizeof (LIST_ENTRY)));
                    InsertTailList(&Ring->PacketList, &Packet->ListEntry);
                }

                Error = FALSE;
                Packet = NULL;
                flags = 0;
                MaximumSegmentSize = 0;
                TailMdl = NULL;
            }

            KeMemoryBarrier();

            req_prod = Protocol0->Front.req_prod_pvt;

            if (req_prod - rsp_cons < PROTOCOL0_BATCH(Ring) &&
                !__RingIsStopped(Ring)) {
                Protocol0->Front.rsp_cons = rsp_cons;
                Protocol0Fill(Ring);
            }
        }
        ASSERT(!Error);
        ASSERT3P(Packet, ==, NULL);
        ASSERT3U(flags, ==, 0);
        ASSERT3U(MaximumSegmentSize, ==, 0);
        ASSERT3P(TailMdl, ==, NULL);

        KeMemoryBarrier();

        Protocol0->Front.rsp_cons = rsp_cons;
        Protocol0->Shared->rsp_event = rsp_cons + 1;
    }

    if (!__RingIsStopped(Ring))
        Protocol0Fill(Ring);
}

static FORCEINLINE VOID
__Protocol0Empty(
    IN  PRECEIVER_RING          Ring
    )
{
    PRECEIVER_RING_PROTOCOL0    Protocol0;
    RING_IDX                    rsp_cons;
    RING_IDX                    rsp_prod;
    uint16_t                    id;

    Protocol0 = &Ring->Protocol0;

    KeMemoryBarrier();

    // Clean up any unprocessed responses
    rsp_prod = Protocol0->Shared->rsp_prod;
    rsp_cons = Protocol0->Front.rsp_cons;

    KeMemoryBarrier();

    while (rsp_cons != rsp_prod) {
        netif_rx_response_t *rsp;
        netif_rx_request_t  *req;
        PRECEIVER_TAG       Tag;
        PMDL                Mdl;

        rsp = RING_GET_RESPONSE(&Protocol0->Front, rsp_cons);
        rsp_cons++;
        Protocol0->ResponsesProcessed++;

        ASSERT3U((rsp->id & REQ_ID_INTEGRITY_CHECK), ==, REQ_ID_INTEGRITY_CHECK);
        id = rsp->id & ~REQ_ID_INTEGRITY_CHECK;

        ASSERT3U(id, <, MAXIMUM_TAG_COUNT);
        req = &Protocol0->Pending[id];

        ASSERT3U(req->id, ==, rsp->id);
        RtlZeroMemory(req, sizeof (netif_rx_request_t));

        Tag = &Protocol0->Tag[id];

        Mdl = Tag->Context;
        Tag->Context = NULL;

        Protocol0ReleaseTag(Ring, Tag);

        __RingPutMdl(Ring, Mdl, TRUE);

        RtlZeroMemory(rsp, sizeof (netif_rx_response_t));
    }

    Protocol0->Front.rsp_cons = rsp_cons;

    // Clean up any pending requests
    for (id = 0; id < MAXIMUM_TAG_COUNT; id++) {
        netif_rx_request_t  *req;
        PRECEIVER_TAG       Tag;
        PMDL                Mdl;

        req = &Protocol0->Pending[id];
        if (req->id == 0)
            continue;

        --Protocol0->RequestsPosted;
        --Protocol0->RequestsPushed;

        ASSERT3U((req->id & REQ_ID_INTEGRITY_CHECK), ==, REQ_ID_INTEGRITY_CHECK);
        ASSERT3U((req->id & ~REQ_ID_INTEGRITY_CHECK), ==, id);

        RtlZeroMemory(req, sizeof (netif_rx_request_t));

        Tag = &Protocol0->Tag[id];

        Mdl = Tag->Context;
        Tag->Context = NULL;

        Protocol0ReleaseTag(Ring, Tag);

        __RingPutMdl(Ring, Mdl, TRUE);

        RtlZeroMemory(req, sizeof (netif_rx_request_t));
    }
}

static DECLSPEC_NOINLINE VOID
Protocol0DebugCallback(
    IN  PRECEIVER_RING       Ring
    )
{
    PXENVIF_RECEIVER         Receiver;
    PRECEIVER_RING_PROTOCOL0 Protocol0;

    Receiver = Ring->Receiver;
    Protocol0 = &Ring->Protocol0;

    // Dump front ring
    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "FRONT: req_prod_pvt = %u rsp_cons = %u nr_ents = %u sring = %p\n",
          Protocol0->Front.req_prod_pvt,
          Protocol0->Front.rsp_cons,
          Protocol0->Front.nr_ents,
          Protocol0->Front.sring);

    // Dump shared ring
    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
          Protocol0->Shared->req_prod,
          Protocol0->Shared->req_event,
          Protocol0->Shared->rsp_prod,
          Protocol0->Shared->rsp_event);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "RequestsPosted = %u RequestsPushed = %u ResponsesProcessed = %u\n",
          Protocol0->RequestsPosted,
          Protocol0->RequestsPushed,
          Protocol0->ResponsesProcessed);
}

static DECLSPEC_NOINLINE NTSTATUS
Protocol0Connect(
    IN  PRECEIVER_RING          Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PRECEIVER_RING_PROTOCOL0    Protocol0;
    ULONG                       Index;
    PFN_NUMBER                  Pfn;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Ring->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Ring->Mdl == NULL)
	goto fail1;

    Protocol0 = &Ring->Protocol0;
    ASSERT(IsZeroMemory(Protocol0, sizeof (RECEIVER_RING_PROTOCOL0)));

    Protocol0->Shared = MmGetSystemAddressForMdlSafe(Ring->Mdl, NormalPagePriority);
    ASSERT(Protocol0->Shared != NULL);

    SHARED_RING_INIT(Protocol0->Shared);
    FRONT_RING_INIT(&Protocol0->Front, Protocol0->Shared, PAGE_SIZE);
    ASSERT3P(Protocol0->Front.sring, ==, Protocol0->Shared);

    Receiver->GnttabInterface = FrontendGetGnttabInterface(Frontend);

    GNTTAB(Acquire, Receiver->GnttabInterface);

    status = GNTTAB(Get,
                    Receiver->GnttabInterface,
                    &Protocol0->Reference);
    if (!NT_SUCCESS(status))
        goto fail2;

    Protocol0->HeadFreeTag = TAG_INDEX_INVALID;
    for (Index = 0; Index < MAXIMUM_TAG_COUNT; Index++) {
        PRECEIVER_TAG   Tag = &Protocol0->Tag[Index];

        status = GNTTAB(Get,
                        Receiver->GnttabInterface,
                        &Tag->Reference);
        if (!NT_SUCCESS(status))
            goto fail3;

        Tag->Next = Protocol0->HeadFreeTag;
        Protocol0->HeadFreeTag = Index;
    }

    Pfn = MmGetMdlPfnArray(Ring->Mdl)[0];
    
    GNTTAB(PermitForeignAccess,
           Receiver->GnttabInterface,
           Protocol0->Reference,
           FrontendGetBackendDomain(Frontend),
           GNTTAB_ENTRY_FULL_PAGE,
           Pfn,
           FALSE);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    while (Protocol0->HeadFreeTag != TAG_INDEX_INVALID) {
        PRECEIVER_TAG   Tag = &Protocol0->Tag[Protocol0->HeadFreeTag];

        Protocol0->HeadFreeTag = Tag->Next;
        Tag->Next = 0;

        GNTTAB(Put,
               Receiver->GnttabInterface,
               Tag->Reference);
        Tag->Reference = 0;
    }
    Protocol0->HeadFreeTag = 0;

    GNTTAB(Put,
           Receiver->GnttabInterface,
           Protocol0->Reference);
    Protocol0->Reference = 0;

fail2:
    Error("fail2\n");

    GNTTAB(Release, Receiver->GnttabInterface);
    Receiver->GnttabInterface = NULL;

    RtlZeroMemory(&Protocol0->Front, sizeof (netif_rx_front_ring_t));
    RtlZeroMemory(Protocol0->Shared, PAGE_SIZE);

    Protocol0->Shared = NULL;
    ASSERT(IsZeroMemory(Protocol0, sizeof (RECEIVER_RING_PROTOCOL0)));

    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;


fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
Protocol0StoreWrite(
    IN  PRECEIVER_RING              Ring,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_RECEIVER                Receiver;
    PXENVIF_FRONTEND                Frontend;
    PRECEIVER_RING_PROTOCOL0        Protocol0;
    NTSTATUS                        status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Protocol0 = &Ring->Protocol0;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "rx-ring-ref",
                   "%u",
                   Protocol0->Reference);

    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
Protocol0Enable(
    IN  PRECEIVER_RING          Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PRECEIVER_RING_PROTOCOL0    Protocol0;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Protocol0 = &Ring->Protocol0;

    Protocol0Fill(Ring);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (RING_FREE_REQUESTS(&Protocol0->Front) != 0)
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE ULONG
Protocol0GetSize(
    IN  PRECEIVER_RING  Ring
    )
{
    UNREFERENCED_PARAMETER(Ring);

    return PROTOCOL0_RING_SIZE;
}

static DECLSPEC_NOINLINE VOID
Protocol0Disable(
    IN  PRECEIVER_RING  Ring
    )
{    
    UNREFERENCED_PARAMETER(Ring);
}

static DECLSPEC_NOINLINE VOID
Protocol0Disconnect(
    IN  PRECEIVER_RING          Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PRECEIVER_RING_PROTOCOL0    Protocol0;
    ULONG                       Count;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Protocol0 = &Ring->Protocol0;

    __Protocol0Empty(Ring);

    ASSERT3U(Protocol0->ResponsesProcessed, ==, Protocol0->RequestsPushed);
    ASSERT3U(Protocol0->RequestsPushed, ==, Protocol0->RequestsPosted);

    Protocol0->ResponsesProcessed = 0;
    Protocol0->RequestsPushed = 0;
    Protocol0->RequestsPosted = 0;

    GNTTAB(RevokeForeignAccess,
           Receiver->GnttabInterface,
           Protocol0->Reference);

    Count = 0;
    while (Protocol0->HeadFreeTag != TAG_INDEX_INVALID) {
        ULONG           Index = Protocol0->HeadFreeTag;
        PRECEIVER_TAG   Tag = &Protocol0->Tag[Index];

        Protocol0->HeadFreeTag = Tag->Next;
        Tag->Next = 0;

        GNTTAB(Put,
               Receiver->GnttabInterface,
               Tag->Reference);
        Tag->Reference = 0;

        Count++;
    }
    ASSERT3U(Count, ==, MAXIMUM_TAG_COUNT);

    Protocol0->HeadFreeTag = 0;

    GNTTAB(Put,
           Receiver->GnttabInterface,
           Protocol0->Reference);
    Protocol0->Reference = 0;

    GNTTAB(Release, Receiver->GnttabInterface);
    Receiver->GnttabInterface = NULL;

    RtlZeroMemory(&Protocol0->Front, sizeof (netif_rx_front_ring_t));
    RtlZeroMemory(Protocol0->Shared, PAGE_SIZE);

    Protocol0->Shared = NULL;
    ASSERT(IsZeroMemory(Protocol0, sizeof (RECEIVER_RING_PROTOCOL0)));

    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;
}

static RECEIVER_RING_OPERATIONS  Protocol0Operations = {
    Protocol0Connect,
    Protocol0StoreWrite,
    Protocol0Enable,
    Protocol0Poll,
    Protocol0Disable,
    Protocol0Disconnect,
    Protocol0DebugCallback,
    Protocol0GetSize
};

static DECLSPEC_NOINLINE NTSTATUS
Protocol1Connect(
    IN  PRECEIVER_RING          Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_FRONTEND            Frontend;
    PRECEIVER_RING_PROTOCOL1    Protocol1;
    ULONG                       Index;
    PFN_NUMBER                  Pfn;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Ring->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Ring->Mdl == NULL)
	goto fail1;

    Protocol1 = &Ring->Protocol1;
    ASSERT(IsZeroMemory(Protocol1, sizeof (RECEIVER_RING_PROTOCOL1)));

    Protocol1->Shared = MmGetSystemAddressForMdlSafe(Ring->Mdl, NormalPagePriority);
    ASSERT(Protocol1->Shared != NULL);

    SHARED_RING_INIT(Protocol1->Shared);
    BACK_RING_INIT(&Protocol1->Back, Protocol1->Shared, PAGE_SIZE);
    ASSERT3P(Protocol1->Back.sring, ==, Protocol1->Shared);

    Receiver->GnttabInterface = FrontendGetGnttabInterface(Frontend);

    GNTTAB(Acquire, Receiver->GnttabInterface);

    status = GNTTAB(Get,
                    Receiver->GnttabInterface,
                    &Protocol1->Reference);
    if (!NT_SUCCESS(status))
        goto fail2;

    InitializeListHead(&Protocol1->List);
    for (Index = 0; Index < MAXIMUM_OPERATION_COUNT; Index++) {
        PXENBUS_GNTTAB_COPY_OPERATION   Operation = &Protocol1->Operation[Index];

        InsertTailList(&Protocol1->List, &Operation->ListEntry);
    }

    Pfn = (PFN_NUMBER)(MmGetPhysicalAddress(Protocol1->Shared).QuadPart >> PAGE_SHIFT);
    
    GNTTAB(PermitForeignAccess,
           Receiver->GnttabInterface,
           Protocol1->Reference,
           FrontendGetBackendDomain(Frontend),
           GNTTAB_ENTRY_FULL_PAGE,
           Pfn,
           FALSE);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    GNTTAB(Release, Receiver->GnttabInterface);
    Receiver->GnttabInterface = NULL;

    RtlZeroMemory(&Protocol1->Back, sizeof (netif_tx_back_ring_t));
    RtlZeroMemory(Protocol1->Shared, PAGE_SIZE);

    Protocol1->Shared = NULL;
    ASSERT(IsZeroMemory(Protocol1, sizeof (RECEIVER_RING_PROTOCOL1)));

    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE PXENBUS_GNTTAB_COPY_OPERATION
__Protocol1GetOperation(
    IN  PRECEIVER_RING              Ring
    )
{
    PRECEIVER_RING_PROTOCOL1        Protocol1;
    PLIST_ENTRY                     ListEntry;
    PXENBUS_GNTTAB_COPY_OPERATION   Operation;

    Protocol1 = &Ring->Protocol1;

    ListEntry = RemoveHeadList(&Protocol1->List);
    ASSERT3P(ListEntry, !=, &Protocol1->List);

    RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

    Operation = CONTAINING_RECORD(ListEntry, XENBUS_GNTTAB_COPY_OPERATION, ListEntry);

    return Operation;
}

static FORCEINLINE VOID
__Protocol1PutOperation(
    IN  PRECEIVER_RING                  Ring,
    IN  PXENBUS_GNTTAB_COPY_OPERATION   Operation
    )
{
    PRECEIVER_RING_PROTOCOL1            Protocol1;

    Protocol1 = &Ring->Protocol1;

    ASSERT(IsZeroMemory(&Operation->ListEntry, sizeof (LIST_ENTRY)));

    RtlZeroMemory(Operation, sizeof (XENBUS_GNTTAB_COPY_OPERATION));
    InsertHeadList(&Protocol1->List, &Operation->ListEntry);
}

static DECLSPEC_NOINLINE NTSTATUS
Protocol1Enable(
    IN  PRECEIVER_RING  Ring
    )
{
    UNREFERENCED_PARAMETER(Ring);

    return STATUS_SUCCESS;
}

static FORCEINLINE ULONG
Protocol1GetSize(
    IN  PRECEIVER_RING  Ring
    )
{
    UNREFERENCED_PARAMETER(Ring);

    return PROTOCOL1_RING_SIZE;
}

static DECLSPEC_NOINLINE NTSTATUS
Protocol1StoreWrite(
    IN  PRECEIVER_RING              Ring,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_RECEIVER                Receiver;
    PXENVIF_FRONTEND                Frontend;
    PRECEIVER_RING_PROTOCOL1        Protocol1;
    NTSTATUS                        status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Protocol1 = &Ring->Protocol1;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "rx-ring-ref",
                   "%u",
                   Protocol1->Reference);

    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__Protocol1BuildOperations(
    IN      PRECEIVER_RING          Ring,
    IN      netif_tx_request_t      *req,
    IN      ULONG                   nr_reqs,
    OUT     PXENVIF_RECEIVER_PACKET *Packet,
    IN OUT  PLIST_ENTRY             List,
    OUT     PULONG                  Count
    )
{
    PXENVIF_RECEIVER                Receiver;
    PXENVIF_FRONTEND                Frontend;
    ULONG                           Index;
    ULONG                           Length;
    PMDL                            Mdl;
    ULONG                           MdlOffset;
    ULONG                           MdlByteCount;
    uint16_t                        flags;
    netif_tx_request_t              current;
    PXENBUS_GNTTAB_COPY_OPERATION   Operation;
    NTSTATUS                        status;

    ASSERT(req != NULL);
    ASSERT(nr_reqs != 0);
    ASSERT(~req[nr_reqs - 1].flags & NETTXF_more_data);

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    // The first request specifies the total packet length. Sample it and
    // then adjust it to match all other requests in specifying it's fragment
    // size.
    Length = req[0].size;
    Index = 1;

    if (req[0].flags & NETTXF_extra_info) {
        struct netif_extra_info *extra;

        ASSERT3U(nr_reqs, >=, 2);
        extra = (struct netif_extra_info *)&req[1];

        ASSERT3U(extra->type, ==, XEN_NETIF_EXTRA_TYPE_GSO);
        ASSERT(extra->u.gso.type == XEN_NETIF_GSO_TYPE_TCPV4 ||
               extra->u.gso.type == XEN_NETIF_GSO_TYPE_TCPV6);

        Index++;
    }

    while (Index < nr_reqs) {
        ASSERT3U(req[0].size, >, req[Index].size);
        req[0].size = req[0].size - req[Index].size;

        Index++;
    }

    *Packet = __RingGetPacket(Ring, TRUE);

    status = STATUS_NO_MEMORY;
    if (*Packet == NULL)
        goto fail1;

    (*Packet)->Offset = 0;
    (*Packet)->Length = Length;

    Mdl = &(*Packet)->Mdl;

    ASSERT3P((*Packet)->Cookie, ==, NULL);

    // Unfortunately NETTXF_... don't match NETRXF_...
    flags = 0;
    if (req[0].flags & NETTXF_csum_blank)
        flags |= NETRXF_csum_blank;
    if (req[0].flags & NETTXF_data_validated)
        flags |= NETRXF_data_validated;

    (*Packet)->Cookie = (PVOID)flags;

    ASSERT3U(Mdl->ByteCount, ==, 0);

    MdlOffset = 0;
    MdlByteCount = PAGE_SIZE;   // Remaining byte count

    Index = 0;
    *Count = 0;

    current = req[Index];

    while (Length != 0) {
        USHORT  SourceLength;
        USHORT  DestLength;
        USHORT  CopyLength;

        if (current.size == 0) {
            Index++;

            if (current.flags & NETTXF_extra_info) {
                struct netif_extra_info *extra;

                ASSERT3U(Index, ==, 1);

                extra = (struct netif_extra_info *)&req[Index];

                ASSERT3U(extra->type, ==, XEN_NETIF_EXTRA_TYPE_GSO);

                (*Packet)->MaximumSegmentSize = extra->u.gso.size;
                ASSERT((*Packet)->MaximumSegmentSize != 0);

                Index++;
            }

            current = req[Index];
        }
        ASSERT(current.size != 0);

        if (MdlByteCount == 0) {
            PXENVIF_RECEIVER_PACKET NextPacket;
            PMDL                    NextMdl;

            NextPacket = __RingGetPacket(Ring, TRUE);

            status = STATUS_NO_MEMORY;
            if (NextPacket == NULL)
                goto fail2;

            NextMdl = &NextPacket->Mdl;
            
            ASSERT3P(Mdl->Next, ==, NULL);
            Mdl->Next = NextMdl;
            Mdl = NextMdl;

            MdlOffset = 0;
            MdlByteCount = PAGE_SIZE;
        }

        Operation = __Protocol1GetOperation(Ring);

        Operation->RemoteDomain = FrontendGetBackendDomain(Frontend);
        Operation->RemoteReference = current.gref;
        Operation->RemoteOffset = current.offset;

        SourceLength = current.size;

        ASSERT3U(MdlOffset, <, PAGE_SIZE);
        Operation->Pfn = MmGetMdlPfnArray(Mdl)[0];
        Operation->Offset = (uint16_t)MdlOffset;

        DestLength = (USHORT)__min(MdlByteCount, PAGE_SIZE - MdlOffset);

        CopyLength = __min(SourceLength, DestLength);

        Operation->Length = CopyLength;

        Mdl->ByteCount += CopyLength;

        current.offset = current.offset + CopyLength;
        ASSERT3U(current.size, >=, CopyLength);
        current.size = current.size - CopyLength;

        MdlOffset += CopyLength;
        ASSERT3U(MdlByteCount, >=, CopyLength);
        MdlByteCount -= CopyLength;

        ASSERT3U(Length, >=, CopyLength);
        Length -= CopyLength;

        ASSERT(IsZeroMemory(&Operation->ListEntry, sizeof (LIST_ENTRY)));
        InsertTailList(List, &Operation->ListEntry);
        (*Count)++;
    }
    ASSERT3U(current.size, ==, 0);
    ASSERT(IMPLY(current.flags & NETTXF_extra_info, Index == nr_reqs - 2));
    ASSERT(IMPLY(~current.flags & NETTXF_extra_info, Index == nr_reqs - 1));

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    (*Packet)->Cookie = NULL;
    __RingReturnPacket(Ring, *Packet, TRUE);
            
fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE VOID
__Protocol1DisposeOperations(
    IN      PRECEIVER_RING  Ring,
    IN OUT  PLIST_ENTRY     List,
    IN      ULONG           Count
    )
{
    while (!IsListEmpty(List)) {
        PLIST_ENTRY                     ListEntry;
        PXENBUS_GNTTAB_COPY_OPERATION   Operation;

        ListEntry = RemoveTailList(List);
        ASSERT3P(ListEntry, !=, List);

        --Count;

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Operation = CONTAINING_RECORD(ListEntry, XENBUS_GNTTAB_COPY_OPERATION, ListEntry);

        __Protocol1PutOperation(Ring, Operation);
    }
    ASSERT3U(Count, ==, 0);
}

static FORCEINLINE VOID
__Protocol1PostResponses(
    IN  PRECEIVER_RING          Ring,
    IN  netif_tx_request_t      *req,
    IN  ULONG                   nr_reqs,
    IN  NTSTATUS                status
    )
{
    PRECEIVER_RING_PROTOCOL1    Protocol1;
    RING_IDX                    rsp_prod;

    Protocol1 = &Ring->Protocol1;

    rsp_prod = Protocol1->Back.rsp_prod_pvt;

    while (nr_reqs != 0) {
        netif_tx_response_t *rsp;

        rsp = RING_GET_RESPONSE(&Protocol1->Back, rsp_prod);
        rsp_prod++;
        Protocol1->ResponsesPosted++;

        rsp->id = req->id;
        rsp->status = NT_SUCCESS(status) ? NETIF_RSP_OKAY : NETIF_RSP_ERROR;

        if (req->flags & NETTXF_extra_info) {
            rsp = RING_GET_RESPONSE(&Protocol1->Back, rsp_prod);
            rsp_prod++;
            Protocol1->ResponsesPosted++;

            rsp->status = NETIF_RSP_NULL;

            req++;
            --nr_reqs;
        }

        req++;
        --nr_reqs;
    }

    Protocol1->Back.rsp_prod_pvt = rsp_prod;
}

static FORCEINLINE VOID
__Protocol1PushResponses(
    IN  PRECEIVER_RING          Ring
    )
{
    PRECEIVER_RING_PROTOCOL1    Protocol1;
    BOOLEAN                     Notify;

    Protocol1 = &Ring->Protocol1;

    if (Protocol1->ResponsesPosted == Protocol1->ResponsesPushed)
        return;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the responses visible to the backend
    RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&Protocol1->Back, Notify);

#pragma warning (pop)

    if (Notify) {
        PXENVIF_RECEIVER    Receiver;
        PXENVIF_FRONTEND    Frontend;

        Receiver = Ring->Receiver;
        Frontend = Receiver->Frontend;

        NotifierSend(FrontendGetNotifier(Frontend));
    }

    Protocol1->ResponsesPushed = Protocol1->ResponsesPosted;
}

static DECLSPEC_NOINLINE VOID
Protocol1Poll(
    IN  PRECEIVER_RING          Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PRECEIVER_RING_PROTOCOL1    Protocol1;

    Receiver = Ring->Receiver;

    Protocol1 = &Ring->Protocol1;

    for (;;) {
        RING_IDX    req_prod;
        RING_IDX    req_cons;
        RING_IDX    rsp_prod;

        if (__RingIsStopped(Ring))
            break;

        KeMemoryBarrier();

        req_prod = Protocol1->Shared->req_prod;
        req_cons = Protocol1->Back.req_cons;

        KeMemoryBarrier();

        if (req_cons == req_prod)
            break;

        while (req_cons != req_prod) {
            netif_tx_request_t              req[MAX_SKB_FRAGS + 2];
            ULONG                           nr_reqs;
            PXENVIF_RECEIVER_PACKET         Packet;
            LIST_ENTRY                      List;
            ULONG                           Count;
            NTSTATUS                        status;

            RtlZeroMemory(req, sizeof (req));

            nr_reqs = 0;
            for (;;) {
                uint16_t    flags;

                ASSERT3U(nr_reqs, <, MAX_SKB_FRAGS + 2);

                req[nr_reqs] = *RING_GET_REQUEST(&Protocol1->Back, req_cons + nr_reqs);

                flags = req[nr_reqs].flags;
                nr_reqs++;

                if (flags & NETTXF_extra_info) {
                    req[nr_reqs] = *RING_GET_REQUEST(&Protocol1->Back, req_cons + nr_reqs);

                    nr_reqs++;
                }

                if (~flags & NETTXF_more_data)
                    break;
            }

            InitializeListHead(&List);

            status = __Protocol1BuildOperations(Ring, req, nr_reqs, &Packet, &List, &Count);
            if (!NT_SUCCESS(status)) {
                __RingStop(Ring);
                break;
            }

            req_cons += nr_reqs;
            Protocol1->RequestsProcessed += nr_reqs;

            Protocol1->Back.req_cons = req_cons;

            status = GNTTAB(Copy,
                            Receiver->GnttabInterface,
                            &List,
                            Count);

            __Protocol1DisposeOperations(Ring, &List, Count);

            if (NT_SUCCESS(status)) {
                ASSERT(IsZeroMemory(&Packet->ListEntry, sizeof (LIST_ENTRY)));
                InsertTailList(&Ring->PacketList, &Packet->ListEntry);
            } else {
                Ring->PacketStatistics.BackendError++;

                Packet->Cookie = NULL;
                __RingReturnPacket(Ring, Packet, TRUE);
            }

            __Protocol1PostResponses(Ring,
                                     req,
                                     nr_reqs,
                                     status);

            rsp_prod = Protocol1->Back.rsp_prod_pvt;
            ASSERT3U(rsp_prod, ==, req_cons);

            KeMemoryBarrier();
        }

        Protocol1->Shared->req_event = req_cons + 1;

        KeMemoryBarrier();

        __Protocol1PushResponses(Ring);
    }
}

static DECLSPEC_NOINLINE VOID
Protocol1Disable(
    IN  PRECEIVER_RING  Ring
    )
{    
    UNREFERENCED_PARAMETER(Ring);
}

static DECLSPEC_NOINLINE VOID
Protocol1Disconnect(
    IN  PRECEIVER_RING          Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PRECEIVER_RING_PROTOCOL1    Protocol1;
    ULONG                       Count;

    Receiver = Ring->Receiver;

    Protocol1 = &Ring->Protocol1;

    ASSERT3U(Protocol1->ResponsesPushed, ==, Protocol1->ResponsesPosted);
    ASSERT3U(Protocol1->ResponsesPosted, ==, Protocol1->RequestsProcessed);

    Protocol1->RequestsProcessed = 0;
    Protocol1->ResponsesPushed = 0;
    Protocol1->ResponsesPosted = 0;

    GNTTAB(RevokeForeignAccess,
           Receiver->GnttabInterface,
           Protocol1->Reference);

    Count = MAXIMUM_OPERATION_COUNT;
    while (!IsListEmpty(&Protocol1->List)) {
        PLIST_ENTRY                     ListEntry;

        ListEntry = RemoveHeadList(&Protocol1->List);
        ASSERT3P(ListEntry, !=, &Protocol1->List);

        --Count;

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));
    }
    ASSERT3U(Count, ==, 0);

    RtlZeroMemory(&Protocol1->List, sizeof (LIST_ENTRY));

    GNTTAB(Put,
           Receiver->GnttabInterface,
           Protocol1->Reference);
    Protocol1->Reference = 0;

    GNTTAB(Release, Receiver->GnttabInterface);
    Receiver->GnttabInterface = NULL;

    RtlZeroMemory(&Protocol1->Back, sizeof (netif_tx_back_ring_t));
    RtlZeroMemory(Protocol1->Shared, PAGE_SIZE);

    Protocol1->Shared = NULL;
    ASSERT(IsZeroMemory(Protocol1, sizeof (RECEIVER_RING_PROTOCOL1)));

    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;
}

static DECLSPEC_NOINLINE VOID
Protocol1DebugCallback(
    IN  PRECEIVER_RING       Ring
    )
{
    PXENVIF_RECEIVER         Receiver;
    PRECEIVER_RING_PROTOCOL1 Protocol1;

    Receiver = Ring->Receiver;
    Protocol1 = &Ring->Protocol1;

    // Dump back ring
    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "BACK: rsp_prod_pvt = %u req_cons = %u nr_ents = %u sring = %p\n",
          Protocol1->Back.rsp_prod_pvt,
          Protocol1->Back.req_cons,
          Protocol1->Back.nr_ents,
          Protocol1->Back.sring);

    // Dump shared ring
    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
          Protocol1->Shared->req_prod,
          Protocol1->Shared->req_event,
          Protocol1->Shared->rsp_prod,
          Protocol1->Shared->rsp_event);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "RequestsProcessed = %u ResponsesPosted = %u ResponsesPushed = %u\n",
          Protocol1->RequestsProcessed,
          Protocol1->ResponsesPosted,
          Protocol1->ResponsesPushed);
}

static RECEIVER_RING_OPERATIONS  Protocol1Operations = {
    Protocol1Connect,
    Protocol1StoreWrite,
    Protocol1Enable,
    Protocol1Poll,
    Protocol1Disable,
    Protocol1Disconnect,
    Protocol1DebugCallback,
    Protocol1GetSize
};

static PRECEIVER_RING_OPERATIONS RingOperations[] = {
    &Protocol0Operations,
    &Protocol1Operations
};

#define SUPPORTED_PROTOCOLS \
        (sizeof (RingOperations) / sizeof (RingOperations[0]))

C_ASSERT((RECEIVER_MINIMUM_PROTOCOL + SUPPORTED_PROTOCOLS - 1) == RECEIVER_MAXIMUM_PROTOCOL);

static FORCEINLINE VOID
__RingDebugCallback(
    IN  PRECEIVER_RING          Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    ULONG                       Allocated;
    ULONG                       MaximumAllocated;
    ULONG                       Count;
    ULONG                       MinimumCount;
    PRECEIVER_RING_OPERATIONS   Operations;

    Receiver = Ring->Receiver;

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "0x%p [%s][%s]\n",
          Ring,
          (Ring->Enabled) ? "ENABLED" : "DISABLED",
          (__RingIsStopped(Ring)) ? "STOPPED" : "RUNNING");

    PoolGetStatistics(Ring->PacketPool,
                      &Allocated,
                      &MaximumAllocated,
                      &Count,
                      &MinimumCount);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "PACKET POOL: Allocated = %u (Maximum = %u)\n",
          Allocated,
          MaximumAllocated);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "PACKET POOL: Count = %u (Minimum = %u)\n",
          Count,
          MinimumCount);

    Operations = Ring->Operations;
    if (Operations != NULL)
        Operations->DebugCallback(Ring);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "OffloadOptions = %02x\n",
          Ring->OffloadOptions.Value);

    if (Ring->OffloadOptions.OffloadTagManipulation)
        DEBUG(Printf,
              Receiver->DebugInterface,
              Receiver->DebugCallback,
              "- TAG MANIPULATION\n");

    if (Ring->OffloadOptions.OffloadIpVersion4LargePacket)
        DEBUG(Printf,
              Receiver->DebugInterface,
              Receiver->DebugCallback,
              "- IPV4 LARGE PACKET\n");

    if (Ring->OffloadOptions.OffloadIpVersion6LargePacket)
        DEBUG(Printf,
              Receiver->DebugInterface,
              Receiver->DebugCallback,
              "- IPV6 LARGE PACKET\n");

    if (Ring->OffloadOptions.OffloadIpVersion4HeaderChecksum)
        DEBUG(Printf,
              Receiver->DebugInterface,
              Receiver->DebugCallback,
              "- IPV4 HEADER CHECKSUM\n");

    if (Ring->OffloadOptions.OffloadIpVersion4TcpChecksum)
        DEBUG(Printf,
              Receiver->DebugInterface,
              Receiver->DebugCallback,
              "- IPV4 TCP CHECKSUM\n");

    if (Ring->OffloadOptions.OffloadIpVersion4UdpChecksum)
        DEBUG(Printf,
              Receiver->DebugInterface,
              Receiver->DebugCallback,
              "- IPV4 UDP CHECKSUM\n");

    if (Ring->OffloadOptions.OffloadIpVersion6TcpChecksum)
        DEBUG(Printf,
              Receiver->DebugInterface,
              Receiver->DebugCallback,
              "- IPV6 TCP CHECKSUM\n");

    if (Ring->OffloadOptions.OffloadIpVersion6UdpChecksum)
        DEBUG(Printf,
              Receiver->DebugInterface,
              Receiver->DebugCallback,
              "- IPV6 UDP CHECKSUM\n");

    if (Ring->OffloadOptions.NeedChecksumValue)
        DEBUG(Printf,
              Receiver->DebugInterface,
              Receiver->DebugCallback,
              "- NEED CHECKSUM VALUE\n");

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "PacketStatistics:\n");

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Drop = %u\n",
          Ring->PacketStatistics.Drop);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- BackendError = %u\n",
          Ring->PacketStatistics.BackendError);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- FrontendError = %u\n",
          Ring->PacketStatistics.FrontendError);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Unicast = %u\n",
          Ring->PacketStatistics.Unicast);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- UnicastBytes = %u\n",
          Ring->PacketStatistics.UnicastBytes);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Multicast = %u\n",
          Ring->PacketStatistics.Multicast);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- MulticastBytes = %u\n",
          Ring->PacketStatistics.MulticastBytes);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Broadcast = %u\n",
          Ring->PacketStatistics.Broadcast);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- BroadcastBytes = %u\n",
          Ring->PacketStatistics.BroadcastBytes);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "HeaderStatistics:\n");

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Tagged = %u\n",
          Ring->HeaderStatistics.Tagged);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- LLC = %u\n",
          Ring->HeaderStatistics.LLC);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Ip Version4 = %u\n",
          Ring->HeaderStatistics.IpVersion4);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Ip Version6 = %u\n",
          Ring->HeaderStatistics.IpVersion6);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Ip Options = %u\n",
          Ring->HeaderStatistics.IpOptions);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Tcp = %u\n",
          Ring->HeaderStatistics.Tcp);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Tcp Options = %u\n",
          Ring->HeaderStatistics.TcpOptions);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- Udp = %u\n",
          Ring->HeaderStatistics.Udp);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "OffloadStatistics:\n");

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4LargePacketSegment = %u\n",
          Ring->OffloadStatistics.IpVersion4LargePacketSegment);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion6LargePacketSegment = %u\n",
          Ring->OffloadStatistics.IpVersion6LargePacketSegment);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4HeaderChecksumCalculated = %u\n",
          Ring->OffloadStatistics.IpVersion4HeaderChecksumCalculated);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4HeaderChecksumSucceeded = %u\n",
          Ring->OffloadStatistics.IpVersion4HeaderChecksumSucceeded);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4HeaderChecksumFailed = %u\n",
          Ring->OffloadStatistics.IpVersion4HeaderChecksumFailed);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4HeaderChecksumPresent = %u\n",
          Ring->OffloadStatistics.IpVersion4HeaderChecksumPresent);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4TcpChecksumCalculated = %u\n",
          Ring->OffloadStatistics.IpVersion4TcpChecksumCalculated);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4TcpChecksumSucceeded = %u\n",
          Ring->OffloadStatistics.IpVersion4TcpChecksumSucceeded);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4TcpChecksumFailed = %u\n",
          Ring->OffloadStatistics.IpVersion4TcpChecksumFailed);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4TcpChecksumPresent = %u\n",
          Ring->OffloadStatistics.IpVersion4TcpChecksumPresent);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion6TcpChecksumCalculated = %u\n",
          Ring->OffloadStatistics.IpVersion6TcpChecksumCalculated);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion6TcpChecksumSucceeded = %u\n",
          Ring->OffloadStatistics.IpVersion6TcpChecksumSucceeded);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion6TcpChecksumFailed = %u\n",
          Ring->OffloadStatistics.IpVersion6TcpChecksumFailed);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion6TcpChecksumPresent = %u\n",
          Ring->OffloadStatistics.IpVersion6TcpChecksumPresent);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4UdpChecksumCalculated = %u\n",
          Ring->OffloadStatistics.IpVersion4UdpChecksumCalculated);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4UdpChecksumSucceeded = %u\n",
          Ring->OffloadStatistics.IpVersion4UdpChecksumSucceeded);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4UdpChecksumFailed = %u\n",
          Ring->OffloadStatistics.IpVersion4UdpChecksumFailed);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion4UdpChecksumPresent = %u\n",
          Ring->OffloadStatistics.IpVersion4UdpChecksumPresent);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion6UdpChecksumCalculated = %u\n",
          Ring->OffloadStatistics.IpVersion6UdpChecksumCalculated);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion6UdpChecksumSucceeded = %u\n",
          Ring->OffloadStatistics.IpVersion6UdpChecksumSucceeded);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion6UdpChecksumFailed = %u\n",
          Ring->OffloadStatistics.IpVersion6UdpChecksumFailed);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion6UdpChecksumPresent = %u\n",
          Ring->OffloadStatistics.IpVersion6UdpChecksumPresent);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- TagRemoved = %u\n",
          Ring->OffloadStatistics.TagRemoved);
}

static FORCEINLINE NTSTATUS
__RingInitialize(
    IN  PXENVIF_RECEIVER    Receiver,
    OUT PRECEIVER_RING      *Ring
    )
{
    NTSTATUS                status;

    *Ring = __ReceiverAllocate(sizeof (RECEIVER_RING));

    status = STATUS_NO_MEMORY;
    if (Ring == NULL)
        goto fail1;

    KeInitializeSpinLock(&(*Ring)->Lock);

    status = PoolInitialize("ReceiverPacket",
                            sizeof (XENVIF_RECEIVER_PACKET),
                            ReceiverPacketCtor,
                            ReceiverPacketDtor,
                            RingAcquireLock,
                            RingReleaseLock,
                            *Ring,
                            &(*Ring)->PacketPool);
    if (!NT_SUCCESS(status))
        goto fail2;

    InitializeListHead(&(*Ring)->PacketList);

    (*Ring)->Receiver = Receiver;

    return STATUS_SUCCESS;

fail2:
    RtlZeroMemory(&(*Ring)->Lock, sizeof (KSPIN_LOCK));

    ASSERT(IsZeroMemory(*Ring, sizeof (RECEIVER_RING)));
    __ReceiverFree(*Ring);
    *Ring = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__RingConnect(
    IN  PRECEIVER_RING          Ring
    )
{
    PXENVIF_RECEIVER            Receiver;
    PRECEIVER_RING_OPERATIONS   Operations;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;

    Info("Protocol %d\n", Receiver->Protocol);

    ASSERT3P(Ring->Operations, ==, NULL);
    ASSERT3U(Receiver->Protocol - RECEIVER_MINIMUM_PROTOCOL, <=, SUPPORTED_PROTOCOLS);
    Ring->Operations = Operations = RingOperations[Receiver->Protocol - RECEIVER_MINIMUM_PROTOCOL];
    ASSERT(Operations != NULL);

    status = Operations->Connect(Ring);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    Ring->Operations = NULL;

    return status;
}

static FORCEINLINE NTSTATUS
__RingStoreWrite(
    IN  PRECEIVER_RING              Ring,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PRECEIVER_RING_OPERATIONS       Operations;
    NTSTATUS                        status;

    Operations = Ring->Operations;
    ASSERT(Operations != NULL);

    status = Operations->StoreWrite(Ring, Transaction);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__RingEnable(
    IN  PRECEIVER_RING          Ring
    )
{
    PRECEIVER_RING_OPERATIONS   Operations;
    NTSTATUS                    status;

    __RingAcquireLock(Ring);

    ASSERT(!Ring->Enabled);

    Operations = Ring->Operations;
    ASSERT(Operations != NULL);

    status = Operations->Enable(Ring);
    if (!NT_SUCCESS(status))
        goto fail1;

    Ring->Enabled = TRUE;

    __RingReleaseLock(Ring);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    __RingReleaseLock(Ring);

    return status;
}

static FORCEINLINE ULONG
__RingGetSize(
    IN  PRECEIVER_RING  Ring
    )
{
    PRECEIVER_RING_OPERATIONS   Operations;

    Operations = Ring->Operations;
    ASSERT(Operations != NULL);

    return Operations->GetSize(Ring);
}

static FORCEINLINE VOID
__RingPoll(
    IN  PRECEIVER_RING          Ring
    )
{
    PRECEIVER_RING_OPERATIONS   Operations;

    if (!(Ring->Enabled))
        return;

    Operations = Ring->Operations;
    ASSERT(Operations != NULL);

    Operations->Poll(Ring);
}

static FORCEINLINE VOID
__RingDisable(
    IN  PRECEIVER_RING          Ring
    )
{    
    PRECEIVER_RING_OPERATIONS   Operations;

    __RingAcquireLock(Ring);

    ASSERT(Ring->Enabled);

    Ring->Enabled = FALSE;
    Ring->Stopped = FALSE;

    Operations = Ring->Operations;
    ASSERT(Operations != NULL);

    Operations->Disable(Ring);

    __RingReleaseLock(Ring);
}

static FORCEINLINE VOID
__RingDisconnect(
    IN  PRECEIVER_RING          Ring
    )
{
    PRECEIVER_RING_OPERATIONS   Operations;

    Operations = Ring->Operations;
    ASSERT(Operations != NULL);

    Operations->Disconnect(Ring);

    Ring->Operations = NULL;
}

static FORCEINLINE VOID
__RingTeardown(
    IN  PRECEIVER_RING  Ring
    )
{
    Ring->Receiver = NULL;

    Ring->OffloadOptions.Value = 0;

    RtlZeroMemory(&Ring->HeaderStatistics, sizeof (XENVIF_HEADER_STATISTICS));
    RtlZeroMemory(&Ring->OffloadStatistics, sizeof (RECEIVER_OFFLOAD_STATISTICS));
    RtlZeroMemory(&Ring->PacketStatistics, sizeof (XENVIF_RECEIVER_PACKET_STATISTICS));

    ASSERT(IsListEmpty(&Ring->PacketList));
    RtlZeroMemory(&Ring->PacketList, sizeof (LIST_ENTRY));

    PoolTeardown(Ring->PacketPool);
    Ring->PacketPool = NULL;

    RtlZeroMemory(&Ring->Lock, sizeof (KSPIN_LOCK));

    ASSERT(IsZeroMemory(Ring, sizeof (RECEIVER_RING)));
    __ReceiverFree(Ring);
}

static FORCEINLINE VOID
__RingNotify(
    IN  PRECEIVER_RING  Ring
    )
{
    PXENVIF_RECEIVER    Receiver;
    PXENVIF_FRONTEND    Frontend;
    LIST_ENTRY          List;
    ULONG               Count;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    InitializeListHead(&List);
    Count = 0;

    __RingAcquireLock(Ring);

    __RingPoll(Ring);

    RingProcessPackets(Ring, &List, &Count);
    ASSERT(EQUIV(IsListEmpty(&List), Count == 0));
    ASSERT(IsListEmpty(&Ring->PacketList));

    // We need to bump Loaned before dropping the lock to avoid VifDisable()
    // returning prematurely.
    if (!IsListEmpty(&List))
        __InterlockedAdd(&Receiver->Loaned, Count);

    __RingReleaseLock(Ring);

    if (!IsListEmpty(&List))
        VifReceivePackets(Receiver->VifInterface, &List);

    ASSERT(IsListEmpty(&List));
}

static FORCEINLINE VOID
__RingSetOffloadOptions(
    IN  PRECEIVER_RING          Ring,
    IN  XENVIF_OFFLOAD_OPTIONS  Options
    )
{
    KIRQL                       Irql;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    __RingAcquireLock(Ring);
    Ring->OffloadOptions = Options;
    __RingReleaseLock(Ring);

    KeLowerIrql(Irql);
}

static FORCEINLINE VOID
__RingAddPacketStatistics(
    IN      PRECEIVER_RING                      Ring,
    IN OUT  PXENVIF_RECEIVER_PACKET_STATISTICS  Statistics
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

static VOID
ReceiverDebugCallback(
    IN  PVOID           Argument,
    IN  BOOLEAN         Crashing
    )
{
    PXENVIF_RECEIVER    Receiver = Argument;
    PLIST_ENTRY         ListEntry;

    UNREFERENCED_PARAMETER(Crashing);

    for (ListEntry = Receiver->List.Flink;
         ListEntry != &Receiver->List;
         ListEntry = ListEntry->Flink) {
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingDebugCallback(Ring);
    }    

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "Loaned = %d Returned = %d\n",
          Receiver->Loaned,
          Receiver->Returned);
}

NTSTATUS
ReceiverInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    IN  ULONG               Count,
    OUT PXENVIF_RECEIVER    *Receiver
    )
{
    ULONG                   Done;
    NTSTATUS                status;

    *Receiver = __ReceiverAllocate(sizeof (XENVIF_RECEIVER));

    status = STATUS_NO_MEMORY;
    if (*Receiver == NULL)
        goto fail1;

    InitializeListHead(&(*Receiver)->List);
    KeInitializeEvent(&(*Receiver)->Event, NotificationEvent, FALSE);

    Done = 0;
    while (Done < Count) {
        PRECEIVER_RING   Ring;

        status = __RingInitialize(*Receiver, &Ring);
        if (!NT_SUCCESS(status))
            goto fail2;

        InsertTailList(&(*Receiver)->List, &Ring->ListEntry);
        Done++;
    }

    (*Receiver)->Frontend = Frontend;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    while (!IsListEmpty(&(*Receiver)->List)) {
        PLIST_ENTRY     ListEntry;
        PRECEIVER_RING  Ring;

        ListEntry = RemoveTailList(&(*Receiver)->List);
        ASSERT3P(ListEntry, !=, &(*Receiver)->List);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingTeardown(Ring);

        --Done;
    }
    ASSERT3U(Done, ==, 0);

    RtlZeroMemory(&(*Receiver)->Event, sizeof (KEVENT));
    RtlZeroMemory(&(*Receiver)->List, sizeof (LIST_ENTRY));

    ASSERT(IsZeroMemory(*Receiver, sizeof (XENVIF_RECEIVER)));
    __ReceiverFree(*Receiver);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE VOID
__ReceiverSetGsoFeatureFlag(
    IN  PXENVIF_RECEIVER        Receiver
    )
{
    PXENVIF_FRONTEND            Frontend;

    Frontend = Receiver->Frontend;

    (VOID) STORE(Printf,
                 Receiver->StoreInterface,
                 NULL,
                 FrontendGetPath(Frontend),
                 "feature-gso-tcpv4-prefix",
                 "%u",
                 (Receiver->Protocol == 0) ? TRUE : FALSE);

    (VOID) STORE(Printf,
                 Receiver->StoreInterface,
                 NULL,
                 FrontendGetPath(Frontend),
                 "feature-gso-tcpv6-prefix",
                 "%u",
                 (Receiver->Protocol == 0) ? TRUE : FALSE);

    (VOID) STORE(Printf,
                 Receiver->StoreInterface,
                 NULL,
                 FrontendGetPath(Frontend),
                 "feature-gso-tcpv4",
                 "%u",
                 (Receiver->Protocol == 1) ? TRUE : FALSE);

    (VOID) STORE(Printf,
                 Receiver->StoreInterface,
                 NULL,
                 FrontendGetPath(Frontend),
                 "feature-gso-tcpv6",
                 "%u",
                 (Receiver->Protocol == 1) ? TRUE : FALSE);
}

NTSTATUS
ReceiverConnect(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PXENVIF_FRONTEND        Frontend;
    PLIST_ENTRY             ListEntry;
    PCHAR                   Buffer;
    ULONG                   MinimumProtocol;
    ULONG                   MaximumProtocol;
    NTSTATUS                status;

    Frontend = Receiver->Frontend;

    Receiver->StoreInterface = FrontendGetStoreInterface(Frontend);

    STORE(Acquire, Receiver->StoreInterface);

    status = STORE(Read,
                   Receiver->StoreInterface,
                   NULL,
                   FrontendGetBackendPath(Frontend),
                   "min-rx-protocol",
                   &Buffer);
    if (!NT_SUCCESS(status)) {
        MinimumProtocol = 0;
    } else {
        MinimumProtocol = (ULONG)strtol(Buffer, NULL, 10);

        STORE(Free,
              Receiver->StoreInterface,
              Buffer);
    }

    status = STORE(Read,
                   Receiver->StoreInterface,
                   NULL,
                   FrontendGetBackendPath(Frontend),
                   "max-rx-protocol",
                   &Buffer);
    if (!NT_SUCCESS(status)) {
        MaximumProtocol = 0;
    } else {
        MaximumProtocol = (ULONG)strtol(Buffer, NULL, 10);

        STORE(Free,
              Receiver->StoreInterface,
              Buffer);
    }

    MinimumProtocol = __max(MinimumProtocol, RECEIVER_MINIMUM_PROTOCOL);
    MaximumProtocol = __min(MaximumProtocol, DriverParameters.ReceiverMaximumProtocol);

    status = STATUS_NOT_SUPPORTED;
    if (MaximumProtocol < MinimumProtocol)
        goto fail1;

    Receiver->Protocol = MaximumProtocol;

    for (ListEntry = Receiver->List.Flink;
         ListEntry != &Receiver->List;
         ListEntry = ListEntry->Flink) {
        PRECEIVER_RING  Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        status = __RingConnect(Ring);
        if (!NT_SUCCESS(status))
            goto fail2;
    }    

    __ReceiverSetGsoFeatureFlag(Receiver);

    Receiver->DebugInterface = FrontendGetDebugInterface(Frontend);

    DEBUG(Acquire, Receiver->DebugInterface);

    status = DEBUG(Register,
                   Receiver->DebugInterface,
                   __MODULE__ "|RECEIVER",
                   ReceiverDebugCallback,
                   Receiver,
                   &Receiver->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail3;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    DEBUG(Release, Receiver->DebugInterface);
    Receiver->DebugInterface = NULL;

    ListEntry = &Receiver->List;

fail2:
    Error("fail2\n");

    ListEntry = ListEntry->Blink;

    while (ListEntry != &Receiver->List) {
        PLIST_ENTRY      Prev = ListEntry->Blink;
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingDisconnect(Ring);

        ListEntry = Prev;
    }

fail1:
    Error("fail1 (%08x)\n", status);

    Receiver->Protocol = 0;

    STORE(Release, Receiver->StoreInterface);
    Receiver->StoreInterface = NULL;

    return status;
}

NTSTATUS
ReceiverStoreWrite(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_FRONTEND                Frontend;
    PLIST_ENTRY                     ListEntry;
    NTSTATUS                        status;

    Frontend = Receiver->Frontend;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "request-rx-copy",
                   "%u",
                   TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "feature-sg",
                   "%u",
                   TRUE);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "feature-no-csum-offload",
                   "%u",
                   FALSE);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "feature-ipv6-csum-offload",
                   "%u",
                   TRUE);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "feature-rx-notify",
                   "%u",
                   TRUE);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "rx-protocol",
                   "%u",
                   Receiver->Protocol);
    if (!NT_SUCCESS(status))
        goto fail6;

    for (ListEntry = Receiver->List.Flink;
         ListEntry != &Receiver->List;
         ListEntry = ListEntry->Flink) {
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        status = __RingStoreWrite(Ring, Transaction);
        if (!NT_SUCCESS(status))
            goto fail7;
    }    

    return STATUS_SUCCESS;

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

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ReceiverEnable(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PXENVIF_FRONTEND        Frontend;
    PLIST_ENTRY             ListEntry;
    NTSTATUS                status;

    Frontend = Receiver->Frontend;

    Receiver->VifInterface = FrontendGetVifInterface(Frontend);

    for (ListEntry = Receiver->List.Flink;
         ListEntry != &Receiver->List;
         ListEntry = ListEntry->Flink) {
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        status = __RingEnable(Ring);
        if (!NT_SUCCESS(status))
            goto fail1;
    }    

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    ListEntry = ListEntry->Blink;

    while (ListEntry != &Receiver->List) {
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingDisable(Ring);
    }

    Receiver->VifInterface = NULL;

    return status;
}

VOID
ReceiverDisable(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PLIST_ENTRY             ListEntry;

    for (ListEntry = Receiver->List.Blink;
         ListEntry != &Receiver->List;
         ListEntry = ListEntry->Blink) {
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingDisable(Ring);
    }

    Receiver->VifInterface = NULL;
}

VOID
ReceiverDisconnect(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PLIST_ENTRY             ListEntry;

    DEBUG(Deregister,
          Receiver->DebugInterface,
          Receiver->DebugCallback);
    Receiver->DebugCallback = NULL;

    DEBUG(Release, Receiver->DebugInterface);
    Receiver->DebugInterface = NULL;

    for (ListEntry = Receiver->List.Blink; ListEntry != &Receiver->List; ListEntry = ListEntry->Blink) {
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingDisconnect(Ring);
    }

    Receiver->Protocol = 0;

    STORE(Release, Receiver->StoreInterface);
    Receiver->StoreInterface = NULL;
}

VOID
ReceiverTeardown(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    ASSERT3U(Receiver->Returned, ==, Receiver->Loaned);
    Receiver->Loaned = 0;
    Receiver->Returned = 0;

    Receiver->Frontend = NULL;

    while (!IsListEmpty(&Receiver->List)) {
        PLIST_ENTRY     ListEntry;
        PRECEIVER_RING  Ring;

        ListEntry = RemoveTailList(&Receiver->List);
        ASSERT3P(ListEntry, !=, &Receiver->List);
        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingTeardown(Ring);
    }

    RtlZeroMemory(&Receiver->Event, sizeof (KEVENT));
    RtlZeroMemory(&Receiver->List, sizeof (LIST_ENTRY));

    ASSERT(IsZeroMemory(Receiver, sizeof (XENVIF_RECEIVER)));
    __ReceiverFree(Receiver);
}

NTSTATUS
ReceiverSetOffloadOptions(
    IN  PXENVIF_RECEIVER        Receiver,
    IN  XENVIF_OFFLOAD_OPTIONS  Options
    )
{
    PLIST_ENTRY                 ListEntry;

    if (DriverParameters.ReceiverAllowGsoPackets == 0) {
        Options.OffloadIpVersion4LargePacket = 0;
        Options.OffloadIpVersion6LargePacket = 0;
    }

    for (ListEntry = Receiver->List.Flink;
         ListEntry != &Receiver->List;
         ListEntry = ListEntry->Flink) {
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingSetOffloadOptions(Ring, Options);
    }    

    return STATUS_SUCCESS;
}

VOID
ReceiverGetPacketStatistics(
    IN  PXENVIF_RECEIVER                    Receiver,
    OUT PXENVIF_RECEIVER_PACKET_STATISTICS  Statistics
    )
{
    PLIST_ENTRY                             ListEntry;

    RtlZeroMemory(Statistics, sizeof (XENVIF_RECEIVER_PACKET_STATISTICS));

    for (ListEntry = Receiver->List.Flink;
         ListEntry != &Receiver->List;
         ListEntry = ListEntry->Flink) {
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingAddPacketStatistics(Ring, Statistics);
    }    
}

ULONG
ReceiverGetRingSize(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PLIST_ENTRY             ListEntry;
    PRECEIVER_RING          Ring;

    // Use the first ring
    ListEntry = Receiver->List.Flink;
    Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

    return __RingGetSize(Ring);
}

VOID
ReceiverReturnPacket(
    IN  PXENVIF_RECEIVER        Receiver,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PRECEIVER_RING              Ring;
    LONG                        Loaned;
    LONG                        Returned;

    Ring = Packet->Cookie;
    Packet->Cookie = NULL;

    __RingReturnPacket(Ring, Packet, FALSE);

    Returned = InterlockedIncrement(&Receiver->Returned);

    // Make sure Loaned is not sampled before Returned
    KeMemoryBarrier();

    Loaned = Receiver->Loaned;

    ASSERT3S(Loaned - Returned, >=, 0);

    KeSetEvent(&Receiver->Event, 0, FALSE);
}

VOID
ReceiverWaitForPackets(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    LONG                    Loaned;

    ASSERT3U(KeGetCurrentIrql(), <, DISPATCH_LEVEL);

    Loaned = Receiver->Loaned;

    while (Receiver->Returned != Loaned) {
        Trace("waiting for packets\n");

        (VOID) KeWaitForSingleObject(&Receiver->Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        KeClearEvent(&Receiver->Event);

        ASSERT3U(Loaned, ==, Receiver->Loaned);

        KeMemoryBarrier();
    }
}

VOID
ReceiverNotify(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PLIST_ENTRY             ListEntry;

    for (ListEntry = Receiver->List.Flink;
         ListEntry != &Receiver->List;
         ListEntry = ListEntry->Flink) {
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingNotify(Ring);
    }    
}
