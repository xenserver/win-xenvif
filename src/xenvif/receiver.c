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

// This should be in public/io/netif.h
#define _NETRXF_gso_prefix     (4)
#define  NETRXF_gso_prefix     (1U<<_NETRXF_gso_prefix)

#include "ethernet.h"
#include "tcpip.h"
#include "pdo.h"
#include "registry.h"
#include "frontend.h"
#include "pool.h"
#include "checksum.h"
#include "parse.h"
#include "granter.h"
#include "notifier.h"
#include "mac.h"
#include "vif.h"
#include "receiver.h"
#include "thread.h"
#include "driver.h"
#include "dbg_print.h"
#include "assert.h"

#define RECEIVER_POOL    'ECER'

typedef struct _RECEIVER_TAG {
    LIST_ENTRY              ListEntry;
    ULONG                   Next;
    PVOID                   Context;
    XENVIF_GRANTER_HANDLE   Handle;
} RECEIVER_TAG, *PRECEIVER_TAG;

typedef struct _RECEIVER_OFFLOAD_STATISTICS {
    ULONGLONG   IpVersion4LargePacket;
    ULONGLONG   IpVersion6LargePacket;
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

#define RECEIVER_RING_SIZE  (__CONST_RING_SIZE(netif_rx, PAGE_SIZE))
#define MAXIMUM_TAG_COUNT   (RECEIVER_RING_SIZE * 2)

#define TAG_INDEX_INVALID       0xFFFFFFFF

#pragma warning(push)
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

typedef struct _RECEIVER_RING {
    PXENVIF_RECEIVER                    Receiver;
    LIST_ENTRY                          ListEntry;
    KSPIN_LOCK                          Lock;
    PXENVIF_POOL                        PacketPool;
    PMDL                                Mdl;
    netif_rx_front_ring_t               Front;
    netif_rx_sring_t                    *Shared;
    XENVIF_GRANTER_HANDLE               Handle;
    ULONG                               HeadFreeTag;
    RECEIVER_TAG                        Tag[MAXIMUM_TAG_COUNT];
    netif_rx_request_t                  Pending[MAXIMUM_TAG_COUNT];
    ULONG                               RequestsPosted;
    ULONG                               RequestsPushed;
    ULONG                               ResponsesProcessed;
    BOOLEAN                             Enabled;
    BOOLEAN                             Stopped;
    XENVIF_OFFLOAD_OPTIONS              OffloadOptions;
    PXENVIF_THREAD                      Thread;
    XENVIF_RECEIVER_PACKET_STATISTICS   PacketStatistics;
    XENVIF_HEADER_STATISTICS            HeaderStatistics;
    RECEIVER_OFFLOAD_STATISTICS         OffloadStatistics;
    LIST_ENTRY                          PacketList;
} RECEIVER_RING, *PRECEIVER_RING;

#pragma warning(pop)

struct _XENVIF_RECEIVER {
    PXENVIF_FRONTEND            Frontend;
    LIST_ENTRY                  List;
    LONG                        Loaned;
    LONG                        Returned;
    KEVENT                      Event;

    ULONG                       CalculateChecksums;
    ULONG                       AllowGsoPackets;
    ULONG                       DisableIpVersion4Gso;
    ULONG                       DisableIpVersion6Gso;
    ULONG                       IpAlignOffset;
    ULONG                       AlwaysPullup;

    PXENBUS_DEBUG_INTERFACE     DebugInterface;
    PXENBUS_STORE_INTERFACE     StoreInterface;
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
RingProcessTag(
    IN  PRECEIVER_RING           Ring,
    IN  PXENVIF_RECEIVER_PACKET  Packet
    )
{
    PXENVIF_PACKET_INFO          Info;
    ULONG                        PayloadLength;
    PUCHAR                       StartVa;
    PETHERNET_HEADER             EthernetHeader;
    ULONG                        Offset;

    Info = &Packet->Info;

    PayloadLength = Packet->Length - Info->Length;

    StartVa = MmGetSystemAddressForMdlSafe(&Packet->Mdl, NormalPagePriority);
    ASSERT(StartVa != NULL);
    StartVa += Packet->Offset;

    ASSERT(Info->EthernetHeader.Length != 0);
    EthernetHeader = (PETHERNET_HEADER)(StartVa + Info->EthernetHeader.Offset);

    if (!ETHERNET_HEADER_IS_TAGGED(EthernetHeader) ||
        Ring->OffloadOptions.OffloadTagManipulation == 0)
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

    ASSERT3U(PayloadLength, ==, Packet->Length - Info->Length);

    Ring->OffloadStatistics.TagRemoved++;
}

static DECLSPEC_NOINLINE VOID
RingProcessChecksum(
    IN  PRECEIVER_RING          Ring,
    IN  PXENVIF_RECEIVER_PACKET Packet
    )
{
    PXENVIF_RECEIVER            Receiver;
    PXENVIF_PACKET_INFO         Info;
    XENVIF_PACKET_PAYLOAD       Payload;
    uint16_t                    flags;
    PUCHAR                      StartVa;
    PIP_HEADER                  IpHeader;

    Receiver = Ring->Receiver;

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

        if (Ring->OffloadOptions.OffloadIpVersion4HeaderChecksum)
            OffloadChecksum = TRUE;
        else
            OffloadChecksum = FALSE;

        // IP header checksums are always present and not validated

        if (OffloadChecksum) {
            USHORT  Embedded;
            USHORT  Calculated;

            Embedded = IpHeader->Version4.Checksum;

            Calculated = ChecksumIpVersion4Header(StartVa, Info);
            Ring->OffloadStatistics.IpVersion4HeaderChecksumCalculated++;

            if (ChecksumVerify(Calculated, Embedded)) {
                Packet->Flags.IpChecksumSucceeded = 1;
                Ring->OffloadStatistics.IpVersion4HeaderChecksumSucceeded++;
            } else {
                Packet->Flags.IpChecksumFailed = 1;
                Ring->OffloadStatistics.IpVersion4HeaderChecksumFailed++;
            }
        }

        if (!OffloadChecksum ||
            Ring->OffloadOptions.NeedChecksumValue ||
            Receiver->CalculateChecksums) { // Checksum must be present
            Packet->Flags.IpChecksumPresent = 1;
            Ring->OffloadStatistics.IpVersion4HeaderChecksumPresent++;
        } else {
            IpHeader->Version4.Checksum = 0;
        }
    }

    if (Info->TcpHeader.Length != 0 && !Info->Flags.IsAFragment) {
        PTCP_HEADER     TcpHeader;
        BOOLEAN         OffloadChecksum;

        TcpHeader = (PTCP_HEADER)(StartVa + Info->TcpHeader.Offset);

        if (IpHeader->Version == 4 && Ring->OffloadOptions.OffloadIpVersion4TcpChecksum)
            OffloadChecksum = TRUE;
        else if (IpHeader->Version == 6 && Ring->OffloadOptions.OffloadIpVersion6TcpChecksum)
            OffloadChecksum = TRUE;
        else
            OffloadChecksum = FALSE;

        if (OffloadChecksum) {
            if (flags & NETRXF_data_validated) {    // Checksum may not be present but it is validated
                Packet->Flags.TcpChecksumSucceeded = 1;

                if (IpHeader->Version == 4)
                    Ring->OffloadStatistics.IpVersion4TcpChecksumSucceeded++;
                else
                    Ring->OffloadStatistics.IpVersion6TcpChecksumSucceeded++;

            } else {                                // Checksum is present but is not validated
                USHORT  Embedded;
                USHORT  Calculated;

                ASSERT(~flags & NETRXF_csum_blank);

                Embedded = TcpHeader->Checksum;

                Calculated = ChecksumPseudoHeader(StartVa, Info);
                Calculated = ChecksumTcpPacket(StartVa, Info, Calculated, &Payload);

                if (IpHeader->Version == 4) {
                    Ring->OffloadStatistics.IpVersion4TcpChecksumCalculated++;

                    if (ChecksumVerify(Calculated, Embedded)) {
                        Packet->Flags.TcpChecksumSucceeded = 1;

                        Ring->OffloadStatistics.IpVersion4TcpChecksumSucceeded++;
                    } else {
                        Packet->Flags.TcpChecksumFailed = 1;

                        Ring->OffloadStatistics.IpVersion4TcpChecksumFailed++;
                    }
                } else {
                    Ring->OffloadStatistics.IpVersion6TcpChecksumCalculated++;

                    if (ChecksumVerify(Calculated, Embedded)) {
                        Packet->Flags.TcpChecksumSucceeded = 1;

                        Ring->OffloadStatistics.IpVersion6TcpChecksumSucceeded++;
                    } else {
                        Packet->Flags.TcpChecksumFailed = 1;

                        Ring->OffloadStatistics.IpVersion6TcpChecksumFailed++;
                    }
                }
            }
        }
        
        if (!OffloadChecksum ||
            Ring->OffloadOptions.NeedChecksumValue ||
            Receiver->CalculateChecksums) {     // Checksum must be present
            if (flags & NETRXF_csum_blank) {    // Checksum is not present
                USHORT  Calculated;

                Calculated = ChecksumPseudoHeader(StartVa, Info);
                Calculated = ChecksumTcpPacket(StartVa, Info, Calculated, &Payload);

                if (IpHeader->Version == 4)
                    Ring->OffloadStatistics.IpVersion4TcpChecksumCalculated++;
                else
                    Ring->OffloadStatistics.IpVersion6TcpChecksumCalculated++;

                TcpHeader->Checksum = Calculated;
            }

            Packet->Flags.TcpChecksumPresent = 1;

            if (IpHeader->Version == 4)
                Ring->OffloadStatistics.IpVersion4TcpChecksumPresent++;
            else
                Ring->OffloadStatistics.IpVersion6TcpChecksumPresent++;
        }
    } else if (Info->UdpHeader.Length != 0 && !Info->Flags.IsAFragment) {
        PUDP_HEADER     UdpHeader;
        BOOLEAN         OffloadChecksum;

        UdpHeader = (PUDP_HEADER)(StartVa + Info->UdpHeader.Offset);

        if (IpHeader->Version == 4 && Ring->OffloadOptions.OffloadIpVersion4UdpChecksum)
            OffloadChecksum = TRUE;
        else if (IpHeader->Version == 6 && Ring->OffloadOptions.OffloadIpVersion6UdpChecksum)
            OffloadChecksum = TRUE;
        else
            OffloadChecksum = FALSE;

        if (OffloadChecksum) {
            if (flags & NETRXF_data_validated) {    // Checksum may not be present but it is validated
                Packet->Flags.UdpChecksumSucceeded = 1;

                if (IpHeader->Version == 4)
                    Ring->OffloadStatistics.IpVersion4UdpChecksumSucceeded++;
                else
                    Ring->OffloadStatistics.IpVersion6UdpChecksumSucceeded++;

            } else {                                // Checksum is present but is not validated
                USHORT  Embedded;
                USHORT  Calculated;

                ASSERT(~flags & NETRXF_csum_blank);

                Embedded = UdpHeader->Checksum;

                Calculated = ChecksumPseudoHeader(StartVa, Info);
                Calculated = ChecksumUdpPacket(StartVa, Info, Calculated, &Payload);

                if (IpHeader->Version == 4) {
                    Ring->OffloadStatistics.IpVersion4UdpChecksumCalculated++;

                    if (Embedded == 0) {    // Tolarate zero checksum for IPv4/UDP
                        Packet->Flags.UdpChecksumSucceeded = 1;

                        Ring->OffloadStatistics.IpVersion4UdpChecksumSucceeded++;
                    } else {
                        if (ChecksumVerify(Calculated, Embedded)) {
                            Packet->Flags.UdpChecksumSucceeded = 1;

                            Ring->OffloadStatistics.IpVersion4UdpChecksumSucceeded++;
                        } else {
                            Packet->Flags.UdpChecksumFailed = 1;

                            Ring->OffloadStatistics.IpVersion4UdpChecksumFailed++;
                        }
                    }
                } else {
                    Ring->OffloadStatistics.IpVersion6UdpChecksumCalculated++;

                    if (ChecksumVerify(Calculated, Embedded)) {
                        Packet->Flags.UdpChecksumSucceeded = 1;

                        Ring->OffloadStatistics.IpVersion6UdpChecksumSucceeded++;
                    } else {
                        Packet->Flags.UdpChecksumFailed = 1;

                        Ring->OffloadStatistics.IpVersion6UdpChecksumFailed++;
                    }
                }
            }
        }

        if (!OffloadChecksum ||
            Ring->OffloadOptions.NeedChecksumValue ||
            Receiver->CalculateChecksums) {     // Checksum must be present
            if (flags & NETRXF_csum_blank) {    // Checksum is not present
                USHORT  Calculated;

                Calculated = ChecksumPseudoHeader(StartVa, Info);
                Calculated = ChecksumUdpPacket(StartVa, Info, Calculated, &Payload);

                if (IpHeader->Version == 4)
                    Ring->OffloadStatistics.IpVersion4UdpChecksumCalculated++;
                else
                    Ring->OffloadStatistics.IpVersion6UdpChecksumCalculated++;

                UdpHeader->Checksum = Calculated;
            }

            Packet->Flags.UdpChecksumPresent = 1;

            if (IpHeader->Version == 4)
                Ring->OffloadStatistics.IpVersion4UdpChecksumPresent++;
            else
                Ring->OffloadStatistics.IpVersion6UdpChecksumPresent++;
        }
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
        ULONG   PacketLength;

        PacketLength = Info->IpHeader.Length +
                       Info->IpOptions.Length + 
                       Info->TcpHeader.Length + 
                       Info->TcpOptions.Length + 
                       SegmentSize;

        IpHeader->Version4.PacketLength = HTONS((USHORT)PacketLength);
        IpHeader->Version4.Checksum = ChecksumIpVersion4Header(StartVa, Info);

        Ring->OffloadStatistics.IpVersion4LargePacketSegment++;
    } else {
        ULONG   PayloadLength;

        ASSERT3U(IpHeader->Version, ==, 6);

        PayloadLength = Info->IpOptions.Length + 
                        Info->TcpHeader.Length + 
                        Info->TcpOptions.Length + 
                        SegmentSize;

        IpHeader->Version6.PayloadLength = HTONS((USHORT)PayloadLength);

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
    PXENVIF_RECEIVER            Receiver;
    BOOLEAN                     Offload;
    PXENVIF_PACKET_INFO         Info;
    uint16_t                    flags;
    XENVIF_PACKET_PAYLOAD       Payload;
    PUCHAR                      InfoVa;
    PIP_HEADER                  IpHeader;
    ULONG                       Length;
    NTSTATUS                    status;

    Receiver = Ring->Receiver;

    Info = &Packet->Info;
    ASSERT(Info->IpHeader.Offset != 0);
    ASSERT(Info->TcpHeader.Offset != 0);
    
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

        Ring->OffloadStatistics.IpVersion4LargePacket++;
    } else {
        USHORT  PayloadLength;

        ASSERT3U(IpHeader->Version, ==, 6);

        PayloadLength = NTOHS(IpHeader->Version6.PayloadLength);

        Length = (ULONG)PayloadLength -
                 Info->TcpOptions.Length -
                 Info->TcpHeader.Length -
                 Info->IpOptions.Length;

        Ring->OffloadStatistics.IpVersion6LargePacket++;
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
            ASSERT(Ring->OffloadOptions.NeedLargePacketSplit != 0);
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

        if (Receiver->AlwaysPullup != 0)
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
    PXENVIF_MAC                 Mac;
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
    Mac = FrontendGetMac(Frontend);

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
    Packet->Offset = Receiver->IpAlignOffset;
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
        ULONG   MaximumFrameSize;

        MaximumFrameSize = MacGetMaximumFrameSize(Mac);

        if (Packet->Length > MaximumFrameSize)
            goto fail4;
        
        // Certain HCK tests (e.g. the NDISTest 2c_Priority test) are
        // sufficiently brain-dead that they cannot cope with
        // multi-fragment packets, or at least packets where headers are
        // in different fragments. All these tests seem to use IPX packets
        // and, in practice, little else uses LLC so pull up all LLC
        // packets into a single fragment.
        if (Info->LLCSnapHeader.Length != 0 ||
            Receiver->AlwaysPullup != 0)
            __RingPullupPacket(Ring, Packet);

        ASSERT(IsZeroMemory(&Packet->ListEntry, sizeof (LIST_ENTRY)));
        InsertTailList(List, &Packet->ListEntry);
    }

    return;

fail4:
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

        RingProcessTag(Ring, Packet);
        RingProcessChecksum(Ring, Packet);

        Packet->Cookie = Ring;

        (*Count)++;
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
    PXENVIF_RECEIVER    Receiver;
    PXENVIF_FRONTEND    Frontend;
    LIST_ENTRY          List;
    ULONG               Count;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    InitializeListHead(&List);
    Count = 0;

    RingProcessPackets(Ring, &List, &Count);
    ASSERT(EQUIV(IsListEmpty(&List), Count == 0));
    ASSERT(IsListEmpty(&Ring->PacketList));

    // We need to bump Loaned before dropping the lock to avoid VifDisable()
    // returning prematurely.
    if (!IsListEmpty(&List))
        __InterlockedAdd(&Receiver->Loaned, Count);

#pragma prefast(disable:26110)
    KeReleaseSpinLockFromDpcLevel(&Ring->Lock);

    if (!IsListEmpty(&List))
        VifReceivePackets(Receiver->VifInterface, &List);

    ASSERT(IsListEmpty(&List));
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

            NotifierTriggerRx(FrontendGetNotifier(Frontend));
        }

        if (!Locked)
            __RingReleaseLock(Ring);

        KeLowerIrql(Irql);
    }
}

static FORCEINLINE PRECEIVER_TAG
__RingGetTag(
    IN  PRECEIVER_RING  Ring
    )
{
    ULONG               Index;
    PRECEIVER_TAG       Tag;

    Index = Ring->HeadFreeTag;
    ASSERT3U(Index, <, MAXIMUM_TAG_COUNT);

    Tag = &Ring->Tag[Index];
    Ring->HeadFreeTag = Tag->Next;
    Tag->Next = TAG_INDEX_INVALID;

    return Tag;
}

static FORCEINLINE
__RingPutTag(
    IN  PRECEIVER_RING  Ring,
    IN  PRECEIVER_TAG   Tag
    )
{
    ULONG               Index;

    ASSERT3P(Tag->Context, ==, NULL);

    Index = (ULONG)(Tag - &Ring->Tag[0]);
    ASSERT3U(Index, <, MAXIMUM_TAG_COUNT);

    ASSERT3U(Tag->Next, ==, TAG_INDEX_INVALID);
    Tag->Next = Ring->HeadFreeTag;
    Ring->HeadFreeTag = Index;
}

static FORCEINLINE PRECEIVER_TAG
__RingPreparePacket(
    IN  PRECEIVER_RING  Ring,
    IN  PMDL            Mdl
    )
{
    PXENVIF_RECEIVER    Receiver;
    PXENVIF_FRONTEND    Frontend;
    PRECEIVER_TAG       Tag;
    NTSTATUS            status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Tag = __RingGetTag(Ring);

    Tag->Context = Mdl;

    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 MmGetMdlPfnArray(Mdl)[0],
                                 FALSE,
                                 &Tag->Handle);
    if (!NT_SUCCESS(status))
        goto fail1;

    return Tag;

fail1:
    Error("fail1 (%08x)\n", status);

    Tag->Context = NULL;

    __RingPutTag(Ring, Tag);
    
    return NULL;
}

static VOID
RingReleaseTag(
    IN  PRECEIVER_RING  Ring,
    IN  PRECEIVER_TAG   Tag
    )
{
    PXENVIF_RECEIVER    Receiver;
    PXENVIF_FRONTEND    Frontend;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    GranterRevokeAccess(FrontendGetGranter(Frontend),
                        Tag->Handle);
    Tag->Handle = NULL;

    __RingPutTag(Ring, Tag);
}

static FORCEINLINE VOID
__RingPushRequests(
    IN  PRECEIVER_RING  Ring
    )
{
    BOOLEAN             Notify;

    if (Ring->RequestsPosted == Ring->RequestsPushed)
        return;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the requests visible to the backend
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Ring->Front, Notify);

#pragma warning (pop)

    if (Notify) {
        PXENVIF_RECEIVER    Receiver;
        PXENVIF_FRONTEND    Frontend;

        Receiver = Ring->Receiver;
        Frontend = Receiver->Frontend;

        NotifierSendRx(FrontendGetNotifier(Frontend));
    }

    Ring->RequestsPushed = Ring->RequestsPosted;
}

static VOID
RingFill(
    IN  PRECEIVER_RING  Ring
    )
{
    PXENVIF_RECEIVER    Receiver;
    PXENVIF_FRONTEND    Frontend;
    RING_IDX            req_prod;
    RING_IDX            rsp_cons;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    KeMemoryBarrier();

    req_prod = Ring->Front.req_prod_pvt;
    rsp_cons = Ring->Front.rsp_cons;

    KeMemoryBarrier();

    while (req_prod - rsp_cons < RING_SIZE(&Ring->Front)) {
        PXENVIF_RECEIVER_PACKET Packet;
        PRECEIVER_TAG           Tag;
        netif_rx_request_t      *req;
        uint16_t                id;

        Packet = __RingGetPacket(Ring, TRUE);

        if (Packet == NULL) {
            __RingStop(Ring);
            break;
        }

        Tag = __RingPreparePacket(Ring, &Packet->Mdl);
        
        if (Tag == NULL) {
            __RingPutPacket(Ring, Packet, TRUE);
            break;
        }

        req = RING_GET_REQUEST(&Ring->Front, req_prod);
        req_prod++;
        Ring->RequestsPosted++;

        id = (USHORT)(Tag - &Ring->Tag[0]);
        ASSERT3U(id, <, MAXIMUM_TAG_COUNT);

        req->id = id | REQ_ID_INTEGRITY_CHECK;
        req->gref = GranterGetReference(FrontendGetGranter(Frontend),
                                        Tag->Handle);

        // Store a copy of the request in case we need to fake a response ourselves
        ASSERT(IsZeroMemory(&Ring->Pending[id], sizeof (netif_rx_request_t)));
        Ring->Pending[id] = *req;
    }

    KeMemoryBarrier();

    Ring->Front.req_prod_pvt = req_prod;

    __RingPushRequests(Ring);
}

static FORCEINLINE VOID
__RingEmpty(
    IN  PRECEIVER_RING  Ring
    )
{
    RING_IDX            rsp_cons;
    RING_IDX            rsp_prod;
    uint16_t            id;

    KeMemoryBarrier();

    // Clean up any unprocessed responses
    rsp_prod = Ring->Shared->rsp_prod;
    rsp_cons = Ring->Front.rsp_cons;

    KeMemoryBarrier();

    while (rsp_cons != rsp_prod) {
        netif_rx_response_t *rsp;
        netif_rx_request_t  *req;
        PRECEIVER_TAG       Tag;
        PMDL                Mdl;

        rsp = RING_GET_RESPONSE(&Ring->Front, rsp_cons);
        rsp_cons++;
        Ring->ResponsesProcessed++;

        ASSERT3U((rsp->id & REQ_ID_INTEGRITY_CHECK), ==, REQ_ID_INTEGRITY_CHECK);
        id = rsp->id & ~REQ_ID_INTEGRITY_CHECK;

        ASSERT3U(id, <, MAXIMUM_TAG_COUNT);
        req = &Ring->Pending[id];

        ASSERT3U(req->id, ==, rsp->id);
        RtlZeroMemory(req, sizeof (netif_rx_request_t));

        Tag = &Ring->Tag[id];

        Mdl = Tag->Context;
        Tag->Context = NULL;

        RingReleaseTag(Ring, Tag);

        __RingPutMdl(Ring, Mdl, TRUE);

        RtlZeroMemory(rsp, sizeof (netif_rx_response_t));
    }

    Ring->Front.rsp_cons = rsp_cons;

    // Clean up any pending requests
    for (id = 0; id < MAXIMUM_TAG_COUNT; id++) {
        netif_rx_request_t  *req;
        PRECEIVER_TAG       Tag;
        PMDL                Mdl;

        req = &Ring->Pending[id];
        if (req->id == 0)
            continue;

        --Ring->RequestsPosted;
        --Ring->RequestsPushed;

        ASSERT3U((req->id & REQ_ID_INTEGRITY_CHECK), ==, REQ_ID_INTEGRITY_CHECK);
        ASSERT3U((req->id & ~REQ_ID_INTEGRITY_CHECK), ==, id);

        RtlZeroMemory(req, sizeof (netif_rx_request_t));

        Tag = &Ring->Tag[id];

        Mdl = Tag->Context;
        Tag->Context = NULL;

        RingReleaseTag(Ring, Tag);

        __RingPutMdl(Ring, Mdl, TRUE);

        RtlZeroMemory(req, sizeof (netif_rx_request_t));
    }
}

static FORCEINLINE VOID
__RingDebugCallback(
    IN  PRECEIVER_RING  Ring
    )
{
    PXENVIF_RECEIVER    Receiver;
    ULONG               Allocated;
    ULONG               MaximumAllocated;
    ULONG               Count;
    ULONG               MinimumCount;

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

    // Dump front ring
    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "FRONT: req_prod_pvt = %u rsp_cons = %u nr_ents = %u sring = %p\n",
          Ring->Front.req_prod_pvt,
          Ring->Front.rsp_cons,
          Ring->Front.nr_ents,
          Ring->Front.sring);

    // Dump shared ring
    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
          Ring->Shared->req_prod,
          Ring->Shared->req_event,
          Ring->Shared->rsp_prod,
          Ring->Shared->rsp_event);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "RequestsPosted = %u RequestsPushed = %u ResponsesProcessed = %u\n",
          Ring->RequestsPosted,
          Ring->RequestsPushed,
          Ring->ResponsesProcessed);

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
          "- IpVersion4LargePacket = %u\n",
          Ring->OffloadStatistics.IpVersion4LargePacket);

    DEBUG(Printf,
          Receiver->DebugInterface,
          Receiver->DebugCallback,
          "- IpVersion6LargePacket = %u\n",
          Ring->OffloadStatistics.IpVersion6LargePacket);

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

static DECLSPEC_NOINLINE VOID
RingPoll(
    IN  PRECEIVER_RING  Ring
    )
{
#define RING_BATCH(_Ring) (RING_SIZE(&(_Ring)->Front) / 4)

    PXENVIF_RECEIVER    Receiver;
    PXENVIF_FRONTEND    Frontend;

    if (!(Ring->Enabled))
        return;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

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

        rsp_prod = Ring->Shared->rsp_prod;
        rsp_cons = Ring->Front.rsp_cons;

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

            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_cons);
            rsp_cons++;
            Ring->ResponsesProcessed++;

            ASSERT3U((rsp->id & REQ_ID_INTEGRITY_CHECK), ==, REQ_ID_INTEGRITY_CHECK);
            id = rsp->id & ~REQ_ID_INTEGRITY_CHECK;

            ASSERT3U(id, <, MAXIMUM_TAG_COUNT);
            req = &Ring->Pending[id];

            ASSERT3U(req->id, ==, rsp->id);
            RtlZeroMemory(req, sizeof (netif_rx_request_t));

            Tag = &Ring->Tag[id];

            Mdl = Tag->Context;
            Tag->Context = NULL;

            RingReleaseTag(Ring, Tag);
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

            req_prod = Ring->Front.req_prod_pvt;

            if (req_prod - rsp_cons < RING_BATCH(Ring) &&
                !__RingIsStopped(Ring)) {
                Ring->Front.rsp_cons = rsp_cons;
                RingFill(Ring);
            }
        }
        ASSERT(!Error);
        ASSERT3P(Packet, ==, NULL);
        ASSERT3U(flags, ==, 0);
        ASSERT3U(MaximumSegmentSize, ==, 0);
        ASSERT3P(TailMdl, ==, NULL);

        KeMemoryBarrier();

        Ring->Front.rsp_cons = rsp_cons;
        Ring->Shared->rsp_event = rsp_cons + 1;
    }

    if (!__RingIsStopped(Ring))
        RingFill(Ring);

#undef  RING_BATCH
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
    PRECEIVER_RING      Ring = Context;
    LARGE_INTEGER       Timeout;
    RING_IDX            rsp_prod;
    RING_IDX            rsp_cons;

    Trace("====>\n");

    Timeout.QuadPart = TIME_RELATIVE(TIME_MS(RING_PERIOD));

    rsp_prod = 0;
    rsp_cons = 0;

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
            KeMemoryBarrier();

            if (Ring->Shared->rsp_prod != rsp_prod &&
                Ring->Front.rsp_cons == rsp_cons) {
                PXENVIF_RECEIVER    Receiver;
                PXENVIF_FRONTEND    Frontend;

                Receiver = Ring->Receiver;
                Frontend = Receiver->Frontend;

                DEBUG(Printf,
                      Receiver->DebugInterface,
                      Receiver->DebugCallback,
                      "WATCHDOG: %s\n",
                      FrontendGetPath(Frontend));

                // Dump front ring
                DEBUG(Printf,
                      Receiver->DebugInterface,
                      Receiver->DebugCallback,
                      "FRONT: req_prod_pvt = %u rsp_cons = %u nr_ents = %u sring = %p\n",
                      Ring->Front.req_prod_pvt,
                      Ring->Front.rsp_cons,
                      Ring->Front.nr_ents,
                      Ring->Front.sring);

                // Dump shared ring
                DEBUG(Printf,
                      Receiver->DebugInterface,
                      Receiver->DebugCallback,
                      "SHARED: req_prod = %u req_event = %u rsp_prod = %u rsp_event = %u\n",
                      Ring->Shared->req_prod,
                      Ring->Shared->req_event,
                      Ring->Shared->rsp_prod,
                      Ring->Shared->rsp_event);

                DEBUG(Printf,
                      Receiver->DebugInterface,
                      Receiver->DebugCallback,
                      "RequestsPosted = %u RequestsPushed = %u ResponsesProcessed = %u\n",
                      Ring->RequestsPosted,
                      Ring->RequestsPushed,
                      Ring->ResponsesProcessed);

                // Try to move things along
                RingPoll(Ring);
                NotifierSendRx(FrontendGetNotifier(Frontend));
            }

            KeMemoryBarrier();

            rsp_prod = Ring->Shared->rsp_prod;
            rsp_cons = Ring->Front.rsp_cons;
        }

        __RingReleaseLock(Ring);
        KeLowerIrql(Irql);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;
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

    status = ThreadCreate(RingWatchdog,
                          *Ring,
                          &(*Ring)->Thread);
    if (!NT_SUCCESS(status))
        goto fail3;

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    (*Ring)->Receiver = NULL;

    RtlZeroMemory(&(*Ring)->PacketList, sizeof (LIST_ENTRY));

    PoolTeardown((*Ring)->PacketPool);
    (*Ring)->PacketPool = NULL;

fail2:
    Error("fail2\n");

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
    IN  PRECEIVER_RING  Ring
    )
{
    PXENVIF_RECEIVER    Receiver;
    PXENVIF_FRONTEND    Frontend;
    ULONG               Index;
    PFN_NUMBER          Pfn;
    NTSTATUS            status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    Ring->Mdl = __AllocatePage();

    status = STATUS_NO_MEMORY;
    if (Ring->Mdl == NULL)
        goto fail1;

    Ring->Shared = MmGetSystemAddressForMdlSafe(Ring->Mdl, NormalPagePriority);
    ASSERT(Ring->Shared != NULL);

    SHARED_RING_INIT(Ring->Shared);
    FRONT_RING_INIT(&Ring->Front, Ring->Shared, PAGE_SIZE);
    ASSERT3P(Ring->Front.sring, ==, Ring->Shared);

    Ring->HeadFreeTag = TAG_INDEX_INVALID;
    for (Index = 0; Index < MAXIMUM_TAG_COUNT; Index++) {
        PRECEIVER_TAG   Tag = &Ring->Tag[Index];

        Tag->Next = Ring->HeadFreeTag;
        Ring->HeadFreeTag = Index;
    }

    Pfn = MmGetMdlPfnArray(Ring->Mdl)[0];
    
    status = GranterPermitAccess(FrontendGetGranter(Frontend),
                                 Pfn,
                                 FALSE,
                                 &Ring->Handle);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    while (Ring->HeadFreeTag != TAG_INDEX_INVALID) {
        PRECEIVER_TAG   Tag = &Ring->Tag[Ring->HeadFreeTag];

        Ring->HeadFreeTag = Tag->Next;
        Tag->Next = 0;
    }
    Ring->HeadFreeTag = 0;

    RtlZeroMemory(&Ring->Front, sizeof (netif_rx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;

    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__RingStoreWrite(
    IN  PRECEIVER_RING              Ring,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_RECEIVER                Receiver;
    PXENVIF_FRONTEND                Frontend;
    NTSTATUS                        status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "rx-ring-ref",
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
    IN  PRECEIVER_RING  Ring
    )
{
    PXENVIF_RECEIVER    Receiver;
    PXENVIF_FRONTEND    Frontend;
    NTSTATUS            status;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    __RingAcquireLock(Ring);

    ASSERT(!Ring->Enabled);

    RingFill(Ring);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (RING_FREE_REQUESTS(&Ring->Front) != 0)
        goto fail1;

    Ring->Enabled = TRUE;

    __RingReleaseLock(Ring);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    __RingReleaseLock(Ring);

    return status;
}

static FORCEINLINE VOID
__RingDisable(
    IN  PRECEIVER_RING  Ring
    )
{    
    __RingAcquireLock(Ring);

    ASSERT(Ring->Enabled);

    Ring->Enabled = FALSE;
    Ring->Stopped = FALSE;

    __RingReleaseLock(Ring);
}

static FORCEINLINE VOID
__RingDisconnect(
    IN  PRECEIVER_RING  Ring
    )
{
    PXENVIF_RECEIVER    Receiver;
    PXENVIF_FRONTEND    Frontend;
    ULONG               Count;

    Receiver = Ring->Receiver;
    Frontend = Receiver->Frontend;

    __RingEmpty(Ring);

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
        ULONG           Index = Ring->HeadFreeTag;
        PRECEIVER_TAG   Tag = &Ring->Tag[Index];

        Ring->HeadFreeTag = Tag->Next;
        Tag->Next = 0;

        Count++;
    }
    ASSERT3U(Count, ==, MAXIMUM_TAG_COUNT);

    Ring->HeadFreeTag = 0;

    RtlZeroMemory(&Ring->Front, sizeof (netif_rx_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE);

    Ring->Shared = NULL;

    __FreePage(Ring->Mdl);
    Ring->Mdl = NULL;
}

static FORCEINLINE VOID
__RingTeardown(
    IN  PRECEIVER_RING  Ring
    )
{
    Ring->OffloadOptions.Value = 0;

    RtlZeroMemory(&Ring->HeaderStatistics, sizeof (XENVIF_HEADER_STATISTICS));
    RtlZeroMemory(&Ring->OffloadStatistics, sizeof (RECEIVER_OFFLOAD_STATISTICS));
    RtlZeroMemory(&Ring->PacketStatistics, sizeof (XENVIF_RECEIVER_PACKET_STATISTICS));

    ThreadAlert(Ring->Thread);
    ThreadJoin(Ring->Thread);
    Ring->Thread = NULL;

    Ring->Receiver = NULL;

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
    __RingAcquireLock(Ring);

    RingPoll(Ring);

    __RingReleaseLock(Ring);
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
    HANDLE                  ParametersKey;
    ULONG                   Done;
    NTSTATUS                status;

    *Receiver = __ReceiverAllocate(sizeof (XENVIF_RECEIVER));

    status = STATUS_NO_MEMORY;
    if (*Receiver == NULL)
        goto fail1;

    ParametersKey = DriverGetParametersKey();

    (*Receiver)->CalculateChecksums = 1;
    (*Receiver)->AllowGsoPackets = 1;
    (*Receiver)->DisableIpVersion4Gso = 0;
    (*Receiver)->DisableIpVersion6Gso = 0;
    (*Receiver)->IpAlignOffset = 0;
    (*Receiver)->AlwaysPullup = 0;

    if (ParametersKey != NULL) {
        ULONG   ReceiverCalculateChecksums;
        ULONG   ReceiverAllowGsoPackets;
        ULONG   ReceiverDisableIpVersion4Gso;
        ULONG   ReceiverDisableIpVersion6Gso;
        ULONG   ReceiverIpAlignOffset;
        ULONG   ReceiverAlwaysPullup;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverCalculateChecksums",
                                         &ReceiverCalculateChecksums);
        if (NT_SUCCESS(status))
            (*Receiver)->CalculateChecksums = ReceiverCalculateChecksums;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverAllowGsoPackets",
                                         &ReceiverAllowGsoPackets);
        if (NT_SUCCESS(status))
            (*Receiver)->AllowGsoPackets = ReceiverAllowGsoPackets;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverDisableIpVersion4Gso",
                                         &ReceiverDisableIpVersion4Gso);
        if (NT_SUCCESS(status))
            (*Receiver)->DisableIpVersion4Gso = ReceiverDisableIpVersion4Gso;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverDisableIpVersion6Gso",
                                         &ReceiverDisableIpVersion6Gso);
        if (NT_SUCCESS(status))
            (*Receiver)->DisableIpVersion6Gso = ReceiverDisableIpVersion6Gso;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverIpAlignOffset",
                                         &ReceiverIpAlignOffset);
        if (NT_SUCCESS(status))
            (*Receiver)->IpAlignOffset = ReceiverIpAlignOffset;

        status = RegistryQueryDwordValue(ParametersKey,
                                         "ReceiverAlwaysPullup",
                                         &ReceiverAlwaysPullup);
        if (NT_SUCCESS(status))
            (*Receiver)->AlwaysPullup = ReceiverAlwaysPullup;
    }

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

    (*Receiver)->CalculateChecksums = 0;
    (*Receiver)->AllowGsoPackets = 0;
    (*Receiver)->DisableIpVersion4Gso = 0;
    (*Receiver)->DisableIpVersion6Gso = 0;
    (*Receiver)->IpAlignOffset = 0;
    (*Receiver)->AlwaysPullup = 0;

    ASSERT(IsZeroMemory(*Receiver, sizeof (XENVIF_RECEIVER)));
    __ReceiverFree(*Receiver);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
ReceiverConnect(
    IN  PXENVIF_RECEIVER    Receiver
    )
{
    PXENVIF_FRONTEND        Frontend;
    PLIST_ENTRY             ListEntry;
    NTSTATUS                status;

    Frontend = Receiver->Frontend;

    Receiver->StoreInterface = FrontendGetStoreInterface(Frontend);

    STORE(Acquire, Receiver->StoreInterface);

    for (ListEntry = Receiver->List.Flink;
         ListEntry != &Receiver->List;
         ListEntry = ListEntry->Flink) {
        PRECEIVER_RING  Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        status = __RingConnect(Ring);
        if (!NT_SUCCESS(status))
            goto fail1;
    }    

    Receiver->DebugInterface = FrontendGetDebugInterface(Frontend);

    DEBUG(Acquire, Receiver->DebugInterface);

    status = DEBUG(Register,
                   Receiver->DebugInterface,
                   __MODULE__ "|RECEIVER",
                   ReceiverDebugCallback,
                   Receiver,
                   &Receiver->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    DEBUG(Release, Receiver->DebugInterface);
    Receiver->DebugInterface = NULL;

    ListEntry = &Receiver->List;

fail1:
    Error("fail1 (%08x)\n", status);

    ListEntry = ListEntry->Blink;

    while (ListEntry != &Receiver->List) {
        PLIST_ENTRY      Prev = ListEntry->Blink;
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        __RingDisconnect(Ring);

        ListEntry = Prev;
    }

    STORE(Release, Receiver->StoreInterface);
    Receiver->StoreInterface = NULL;

    return status;
}

static FORCEINLINE NTSTATUS
__ReceiverSetGsoFeatureFlag(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_FRONTEND                Frontend;
    NTSTATUS                        status;

    Frontend = Receiver->Frontend;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "feature-gso-tcpv4-prefix",
                   "%u",
                   (Receiver->DisableIpVersion4Gso == 0) ? TRUE : FALSE);
    if (!NT_SUCCESS(status))
        goto fail1;


    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "feature-gso-tcpv6-prefix",
                   "%u",
                   (Receiver->DisableIpVersion6Gso == 0) ? TRUE : FALSE);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE NTSTATUS
__ReceiverSetChecksumFeatureFlag(
    IN  PXENVIF_RECEIVER            Receiver,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    PXENVIF_FRONTEND                Frontend;
    NTSTATUS                        status;

    Frontend = Receiver->Frontend;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "feature-no-csum-offload",
                   "%u",
                   FALSE);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = STORE(Printf,
                   Receiver->StoreInterface,
                   Transaction,
                   FrontendGetPath(Frontend),
                   "feature-ipv6-csum-offload",
                   "%u",
                   TRUE);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

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
                   "feature-rx-notify",
                   "%u",
                   TRUE);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = __ReceiverSetGsoFeatureFlag(Receiver, Transaction);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = __ReceiverSetChecksumFeatureFlag(Receiver, Transaction);
    if (!NT_SUCCESS(status))
        goto fail5;

    for (ListEntry = Receiver->List.Flink;
         ListEntry != &Receiver->List;
         ListEntry = ListEntry->Flink) {
        PRECEIVER_RING   Ring;

        Ring = CONTAINING_RECORD(ListEntry, RECEIVER_RING, ListEntry);

        status = __RingStoreWrite(Ring, Transaction);
        if (!NT_SUCCESS(status))
            goto fail6;
    }    

    return STATUS_SUCCESS;

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

    Receiver->CalculateChecksums = 0;
    Receiver->AllowGsoPackets = 0;
    Receiver->DisableIpVersion4Gso = 0;
    Receiver->DisableIpVersion6Gso = 0;
    Receiver->IpAlignOffset = 0;
    Receiver->AlwaysPullup = 0;

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

    if (Receiver->AllowGsoPackets == 0) {
        Warning("RECEIVER GSO DISALLOWED\n");
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
    UNREFERENCED_PARAMETER(Receiver);

    return RECEIVER_RING_SIZE;
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
