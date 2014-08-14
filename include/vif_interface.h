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

#ifndef _XENVIF_VIF_INTERFACE_H
#define _XENVIF_VIF_INTERFACE_H

#ifndef _WINDLL

#include <ifdef.h>
#include <ethernet.h>

struct  _XENVIF_PACKET_HEADER_V1 {
    ULONG   Offset;
    ULONG   Length;
};

struct _XENVIF_PACKET_INFO_V1 {
    ULONG                           Length;
    USHORT                          TagControlInformation;
    BOOLEAN                         IsAFragment;
    struct _XENVIF_PACKET_HEADER_V1 EthernetHeader;
    struct _XENVIF_PACKET_HEADER_V1 LLCSnapHeader;
    struct _XENVIF_PACKET_HEADER_V1 IpHeader;
    struct _XENVIF_PACKET_HEADER_V1 IpOptions;
    struct _XENVIF_PACKET_HEADER_V1 TcpHeader;
    struct _XENVIF_PACKET_HEADER_V1 TcpOptions;
    struct _XENVIF_PACKET_HEADER_V1 UdpHeader;
};

typedef struct _XENVIF_PACKET_INFO_V1   XENVIF_PACKET_INFO, *PXENVIF_PACKET_INFO;

#pragma warning(push)
#pragma warning(disable:4214)   // nonstandard extension used : bit field types other than int
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

struct _XENVIF_PACKET_CHECKSUM_FLAGS_V1 {
    union {
        struct {
            ULONG   IpChecksumSucceeded:1;
            ULONG   IpChecksumFailed:1;
            ULONG   IpChecksumPresent:1;
            ULONG   TcpChecksumSucceeded:1;
            ULONG   TcpChecksumFailed:1;
            ULONG   TcpChecksumPresent:1;
            ULONG   UdpChecksumSucceeded:1;
            ULONG   UdpChecksumFailed:1;
            ULONG   UdpChecksumPresent:1;
            ULONG   Reserved:23;
        };

        ULONG   Value;
    };
};

typedef struct _XENVIF_PACKET_CHECKSUM_FLAGS_V1 XENVIF_PACKET_CHECKSUM_FLAGS, *PXENVIF_PACKET_CHECKSUM_FLAGS;

#pragma warning(pop)

struct _XENVIF_RECEIVER_PACKET_V1 {
    LIST_ENTRY                              ListEntry;
    struct _XENVIF_PACKET_INFO_V1           *Info;
    ULONG                                   Offset;
    ULONG                                   Length;
    struct _XENVIF_PACKET_CHECKSUM_FLAGS_V1 Flags;
    USHORT                                  MaximumSegmentSize;
    PVOID                                   Cookie;
    MDL                                     Mdl;
    PFN_NUMBER                              __Pfn;
};

typedef struct _XENVIF_RECEIVER_PACKET_V1 XENVIF_RECEIVER_PACKET, *PXENVIF_RECEIVER_PACKET;

#pragma warning(push)
#pragma warning(disable:4214)   // nonstandard extension used : bit field types other than int
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

struct _XENVIF_VIF_OFFLOAD_OPTIONS_V1 {
    union {
        struct {
            USHORT  OffloadTagManipulation:1;
            USHORT  OffloadIpVersion4LargePacket:1;
            USHORT  OffloadIpVersion4HeaderChecksum:1;
            USHORT  OffloadIpVersion4TcpChecksum:1;
            USHORT  OffloadIpVersion4UdpChecksum:1;
            USHORT  OffloadIpVersion6LargePacket:1;
            USHORT  OffloadIpVersion6TcpChecksum:1;
            USHORT  OffloadIpVersion6UdpChecksum:1;
            USHORT  NeedChecksumValue:1;
            USHORT  NeedLargePacketSplit:1;
            USHORT  Reserved:6;
        };

        USHORT  Value;
    };
};

typedef struct _XENVIF_VIF_OFFLOAD_OPTIONS_V1 XENVIF_VIF_OFFLOAD_OPTIONS, *PXENVIF_VIF_OFFLOAD_OPTIONS;

#pragma warning(pop)

// To fit into the reserved space in NDIS_PACKET and NET_BUFFER structures the XENVIF_TRANSMITTER_PACKET
// structure must be at most the size of 3 pointer types.

#pragma pack(push, 1) 
struct _XENVIF_TRANSMITTER_PACKET_SEND_INFO_V1 {
    XENVIF_VIF_OFFLOAD_OPTIONS  OffloadOptions;
    USHORT                      MaximumSegmentSize;     // Only used if OffloadOptions.OffloadIpVersion[4|6]LargePacket is set
    USHORT                      TagControlInformation;  // Only used if OffloadOptions.OffloadTagManipulation is set
};

typedef struct _XENVIF_TRANSMITTER_PACKET_SEND_INFO_V1 XENVIF_TRANSMITTER_PACKET_SEND_INFO, *PXENVIF_TRANSMITTER_PACKET_SEND_INFO;

struct _XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO_V1 {
    UCHAR   Type;
    UCHAR   Status;

#define XENVIF_TRANSMITTER_PACKET_PENDING   1
#define XENVIF_TRANSMITTER_PACKET_OK        2
#define XENVIF_TRANSMITTER_PACKET_DROPPED   3
#define XENVIF_TRANSMITTER_PACKET_ERROR     4

    USHORT  PacketLength;
    USHORT  PayloadLength;
};

typedef struct _XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO_V1 XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO, *PXENVIF_TRANSMITTER_PACKET_COMPLETION_INFO;

#pragma warning(push)
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

struct _XENVIF_TRANSMITTER_PACKET_V1 {
    struct _XENVIF_TRANSMITTER_PACKET_V1                        *Next;
    union {
        struct _XENVIF_TRANSMITTER_PACKET_SEND_INFO_V1          Send;
        struct _XENVIF_TRANSMITTER_PACKET_COMPLETION_INFO_V1    Completion;
    };
};

typedef struct _XENVIF_TRANSMITTER_PACKET_V1 XENVIF_TRANSMITTER_PACKET, *PXENVIF_TRANSMITTER_PACKET;

#pragma warning(pop)

#pragma pack(pop) 

C_ASSERT(sizeof (struct _XENVIF_TRANSMITTER_PACKET_V1) <= (3 * sizeof (PVOID)));

typedef enum _XENVIF_TRANSMITTER_PACKET_OFFSET {
    XENVIF_TRANSMITTER_PACKET_OFFSET_OFFSET = 0,
    XENVIF_TRANSMITTER_PACKET_LENGTH_OFFSET,
    XENVIF_TRANSMITTER_PACKET_MDL_OFFSET,
    XENVIF_TRANSMITTER_PACKET_OFFSET_COUNT
} XENVIF_TRANSMITTER_PACKET_OFFSET, *PXENVIF_TRANSMITTER_PACKET_OFFSET;

typedef enum _XENVIF_VIF_STATISTIC {
    XENVIF_TRANSMITTER_PACKETS_DROPPED = 0,
    XENVIF_TRANSMITTER_BACKEND_ERRORS,
    XENVIF_TRANSMITTER_FRONTEND_ERRORS,
    XENVIF_TRANSMITTER_UNICAST_PACKETS,
    XENVIF_TRANSMITTER_UNICAST_OCTETS,
    XENVIF_TRANSMITTER_MULTICAST_PACKETS,
    XENVIF_TRANSMITTER_MULTICAST_OCTETS,
    XENVIF_TRANSMITTER_BROADCAST_PACKETS,
    XENVIF_TRANSMITTER_BROADCAST_OCTETS,
    XENVIF_RECEIVER_PACKETS_DROPPED,
    XENVIF_RECEIVER_BACKEND_ERRORS,
    XENVIF_RECEIVER_FRONTEND_ERRORS,
    XENVIF_RECEIVER_UNICAST_PACKETS,
    XENVIF_RECEIVER_UNICAST_OCTETS,
    XENVIF_RECEIVER_MULTICAST_PACKETS,
    XENVIF_RECEIVER_MULTICAST_OCTETS,
    XENVIF_RECEIVER_BROADCAST_PACKETS,
    XENVIF_RECEIVER_BROADCAST_OCTETS,
    XENVIF_VIF_STATISTIC_COUNT
} XENVIF_VIF_STATISTIC, *PXENVIF_VIF_STATISTIC;

typedef enum _XENVIF_MAC_FILTER_LEVEL {
    XENVIF_MAC_FILTER_NONE = 0,
    XENVIF_MAC_FILTER_MATCHING = 1,
    XENVIF_MAC_FILTER_ALL = 2
} XENVIF_MAC_FILTER_LEVEL, *PXENVIF_MAC_FILTER_LEVEL;

typedef enum _XENVIF_VIF_CALLBACK_TYPE {
    XENVIF_TRANSMITTER_RETURN_PACKETS = 0,
    XENVIF_RECEIVER_QUEUE_PACKETS,
    XENVIF_MAC_STATE_CHANGE
} XENVIF_VIF_CALLBACK_TYPE, *PXENVIF_VIF_CALLBACK_TYPE;

typedef NTSTATUS
(*XENVIF_VIF_ACQUIRE)(
    IN  PINTERFACE  Interface
    );

typedef VOID
(*XENVIF_VIF_RELEASE)(
    IN  PINTERFACE  Interface
    );

typedef VOID
(*XENVIF_VIF_CALLBACK)(
    IN  PVOID                       Argument,
    IN  XENVIF_VIF_CALLBACK_TYPE    Type,
    ...
    );

typedef NTSTATUS
(*XENVIF_VIF_ENABLE)(
    IN  PINTERFACE          Interface,
    IN  XENVIF_VIF_CALLBACK Callback,
    IN  PVOID               Argument OPTIONAL
    );

typedef VOID
(*XENVIF_VIF_DISABLE)(
    IN  PINTERFACE  Interface
    );

typedef NTSTATUS
(*XENVIF_VIF_QUERY_STATISTIC)(
    IN  PINTERFACE              Interface,
    IN  XENVIF_VIF_STATISTIC    Index,
    OUT PULONGLONG              Value
    );

typedef VOID
(*XENVIF_VIF_RECEIVER_RETURN_PACKETS)(
    IN  PINTERFACE  Interface,
    IN  PLIST_ENTRY List
    );

typedef NTSTATUS
(*XENVIF_VIF_TRANSMITTER_SET_PACKET_OFFSET)(
    IN  PINTERFACE                          Interface,
    IN  XENVIF_TRANSMITTER_PACKET_OFFSET    Type,
    IN  LONG_PTR                            Value
    );

typedef NTSTATUS
(*XENVIF_VIF_TRANSMITTER_QUEUE_PACKETS)(
    IN  PINTERFACE                  Interface,
    IN  PXENVIF_TRANSMITTER_PACKET  Head
    );

typedef VOID
(*XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS)(
    IN  PINTERFACE                  Interface,
    OUT PXENVIF_VIF_OFFLOAD_OPTIONS Options
    );

typedef VOID
(*XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS)(
    IN  PINTERFACE                  Interface,
    IN  XENVIF_VIF_OFFLOAD_OPTIONS  Options
    );

typedef VOID
(*XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE)(
    IN  PINTERFACE  Interface,
    IN  UCHAR       Version,
    OUT PULONG      Size
    );

typedef VOID
(*XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE)(
    IN  PINTERFACE  Interface,
    OUT PULONG      Size
    );

typedef VOID
(*XENVIF_VIF_RECEIVER_QUERY_RING_SIZE)(
    IN  PINTERFACE  Interface,
    OUT PULONG      Size
    );

typedef VOID
(*XENVIF_VIF_MAC_QUERY_STATE)(
    IN  PINTERFACE                  Interface,
    OUT PNET_IF_MEDIA_CONNECT_STATE MediaConnectState OPTIONAL,
    OUT PULONG64                    LinkSpeed OPTIONAL,
    OUT PNET_IF_MEDIA_DUPLEX_STATE  MediaDuplexState OPTIONAL
    );

typedef VOID
(*XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE)(
    IN  PINTERFACE  Interface,
    OUT PULONG      Size
    );

typedef VOID
(*XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS)(
    IN  PINTERFACE          Interface,
    OUT PETHERNET_ADDRESS   Address
    );

typedef VOID
(*XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS)(
    IN  PINTERFACE          Interface,
    OUT PETHERNET_ADDRESS   Address
    );

typedef NTSTATUS
(*XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES)(
    IN      PINTERFACE          Interface,
    OUT     PETHERNET_ADDRESS   Address OPTIONAL,
    IN OUT  PULONG              Count
    );

typedef NTSTATUS
(*XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES)(
    IN  PINTERFACE          Interface,
    IN  PETHERNET_ADDRESS   Address OPTIONAL,
    IN  ULONG               Count
    );

typedef NTSTATUS
(*XENVIF_VIF_MAC_SET_FILTER_LEVEL)(
    IN  PINTERFACE              Interface,
    IN  ETHERNET_ADDRESS_TYPE   Type,
    IN  XENVIF_MAC_FILTER_LEVEL Level
    );

typedef NTSTATUS
(*XENVIF_VIF_MAC_QUERY_FILTER_LEVEL)(
    IN  PINTERFACE                  Interface,
    IN  ETHERNET_ADDRESS_TYPE       Type,
    OUT PXENVIF_MAC_FILTER_LEVEL    Level
    );

// {76F279CD-CA11-418B-92E8-C57F77DE0E2E}
DEFINE_GUID(GUID_XENVIF_VIF_INTERFACE, 
0x76f279cd, 0xca11, 0x418b, 0x92, 0xe8, 0xc5, 0x7f, 0x77, 0xde, 0xe, 0x2e);

struct _XENVIF_VIF_INTERFACE_V1 {
    INTERFACE                                       Interface;
    XENVIF_VIF_ACQUIRE                              Acquire;
    XENVIF_VIF_RELEASE                              Release;
    XENVIF_VIF_ENABLE                               Enable;
    XENVIF_VIF_DISABLE                              Disable;
    XENVIF_VIF_QUERY_STATISTIC                      QueryStatistic;
    XENVIF_VIF_RECEIVER_RETURN_PACKETS              ReceiverReturnPackets;
    XENVIF_VIF_RECEIVER_SET_OFFLOAD_OPTIONS         ReceiverSetOffloadOptions;
    XENVIF_VIF_RECEIVER_QUERY_RING_SIZE             ReceiverQueryRingSize;
    XENVIF_VIF_TRANSMITTER_SET_PACKET_OFFSET        TransmitterSetPacketOffset;
    XENVIF_VIF_TRANSMITTER_QUEUE_PACKETS            TransmitterQueuePackets;
    XENVIF_VIF_TRANSMITTER_QUERY_OFFLOAD_OPTIONS    TransmitterQueryOffloadOptions;
    XENVIF_VIF_TRANSMITTER_QUERY_LARGE_PACKET_SIZE  TransmitterQueryLargePacketSize;
    XENVIF_VIF_TRANSMITTER_QUERY_RING_SIZE          TransmitterQueryRingSize;
    XENVIF_VIF_MAC_QUERY_STATE                      MacQueryState;
    XENVIF_VIF_MAC_QUERY_MAXIMUM_FRAME_SIZE         MacQueryMaximumFrameSize;
    XENVIF_VIF_MAC_QUERY_PERMANENT_ADDRESS          MacQueryPermanentAddress;
    XENVIF_VIF_MAC_QUERY_CURRENT_ADDRESS            MacQueryCurrentAddress;
    XENVIF_VIF_MAC_QUERY_MULTICAST_ADDRESSES        MacQueryMulticastAddresses;
    XENVIF_VIF_MAC_SET_MULTICAST_ADDRESSES          MacSetMulticastAddresses;
    XENVIF_VIF_MAC_SET_FILTER_LEVEL                 MacSetFilterLevel;
    XENVIF_VIF_MAC_QUERY_FILTER_LEVEL               MacQueryFilterLevel;
};

typedef struct _XENVIF_VIF_INTERFACE_V1 XENVIF_VIF_INTERFACE, *PXENVIF_VIF_INTERFACE;

#define XENVIF_VIF(_Method, _Interface, ...)    \
    (_Interface)-> ## _Method((PINTERFACE)(_Interface), __VA_ARGS__)

#endif  // _WINDLL

#define XENVIF_VIF_INTERFACE_VERSION_MIN    1
#define XENVIF_VIF_INTERFACE_VERSION_MAX    1

#endif  // _XENVIF_INTERFACE_H
