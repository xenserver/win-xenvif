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

#include <ifdef.h>
#include <ethernet.h>

#define MAX_SKB_FRAGS   ((65536/PAGE_SIZE) + 2)

typedef UCHAR   XENVIF_PACKET_STATUS, *PXENVIF_PACKET_STATUS;

#define PACKET_STATUS_INVALID   0
#define PACKET_PENDING          1
#define PACKET_OK               2
#define PACKET_DROPPED          3
#define PACKET_ERROR            4

typedef struct  _XENVIF_PACKET_HEADER {
    ULONG   Offset;
    ULONG   Length;
} XENVIF_PACKET_HEADER, *PXENVIF_PACKET_HEADER;

typedef struct _XENVIF_PACKET_INFO {
    XENVIF_PACKET_HEADER    EthernetHeader;
    XENVIF_PACKET_HEADER    LLCSnapHeader;
    XENVIF_PACKET_HEADER    IpHeader;
    XENVIF_PACKET_HEADER    IpOptions;
    XENVIF_PACKET_HEADER    TcpHeader;
    XENVIF_PACKET_HEADER    TcpOptions;
    XENVIF_PACKET_HEADER    UdpHeader;
    ULONG                   Length;
} XENVIF_PACKET_INFO, *PXENVIF_PACKET_INFO;

#pragma warning(push)
#pragma warning(disable:4214)   // nonstandard extension used : bit field types other than int
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

typedef struct _XENVIF_CHECKSUM_FLAGS {
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
} XENVIF_CHECKSUM_FLAGS, *PXENVIF_CHECKSUM_FLAGS;

#pragma warning(pop)

typedef struct _XENVIF_RECEIVER_PACKET {
    LIST_ENTRY              ListEntry;
    ULONG                   Offset;
    ULONG                   Length;
    XENVIF_PACKET_INFO      Info;
    XENVIF_CHECKSUM_FLAGS   Flags;
    USHORT                  TagControlInformation;
    USHORT                  MaximumSegmentSize;
    PVOID                   Cookie;
    MDL                     Mdl;
    PFN_NUMBER              __Pfn;
} XENVIF_RECEIVER_PACKET, *PXENVIF_RECEIVER_PACKET;

typedef struct _XENVIF_RECEIVER_PACKET_STATISTICS {
    ULONGLONG   Drop;
    ULONGLONG   BackendError;
    ULONGLONG   FrontendError;
    ULONGLONG   Unicast;
    ULONGLONG   UnicastBytes;
    ULONGLONG   Multicast;
    ULONGLONG   MulticastBytes;
    ULONGLONG   Broadcast;
    ULONGLONG   BroadcastBytes;
} XENVIF_RECEIVER_PACKET_STATISTICS, *PXENVIF_RECEIVER_PACKET_STATISTICS;

#pragma warning(push)
#pragma warning(disable:4214)   // nonstandard extension used : bit field types other than int
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

typedef struct _XENVIF_OFFLOAD_OPTIONS {
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
} XENVIF_OFFLOAD_OPTIONS, *PXENVIF_OFFLOAD_OPTIONS;

#pragma warning(pop)

typedef struct _XENVIF_TRANSMITTER_PACKET   XENVIF_TRANSMITTER_PACKET, *PXENVIF_TRANSMITTER_PACKET;

// To fit into the reserved space in NDIS_PACKET and NET_BUFFER structures the XENVIF_TRANSMITTER_PACKET
// structure must be at most the size of 3 pointer types.

#pragma pack(push, 1) 
typedef struct _XENVIF_SEND_INFO {
    XENVIF_OFFLOAD_OPTIONS  OffloadOptions;
    USHORT                  MaximumSegmentSize;     // Only used if OffloadOptions.OffloadIpVersion[4|6}LargePacket is set
    USHORT                  TagControlInformation;  // Only used if OffloadOptions.OffloadTagManipulation is set
} XENVIF_SEND_INFO, *PXENVIF_SEND_INFO;

typedef struct _XENVIF_COMPLETION_INFO {
    UCHAR                   Type;
    XENVIF_PACKET_STATUS    Status;
    USHORT                  PacketLength;
    USHORT                  PayloadLength;
} XENVIF_COMPLETION_INFO, *PXENVIF_COMPLETION_INFO;

#pragma warning(push)
#pragma warning(disable:4201)   // nonstandard extension used : nameless struct/union

struct _XENVIF_TRANSMITTER_PACKET {
    PXENVIF_TRANSMITTER_PACKET  Next;
    union {
        XENVIF_SEND_INFO        Send;
        XENVIF_COMPLETION_INFO  Completion;
    };
};

#pragma warning(pop)

#pragma pack(pop) 

C_ASSERT(sizeof (XENVIF_TRANSMITTER_PACKET) <= (3 * sizeof (PVOID)));

// Because we're so tight on space in the XENVIF_TRANSMITTER_PACKET structure, certain packet metadata
// needs to be accessed via magic offsets
typedef struct _XENVIF_TRANSMITTER_PACKET_METADATA {
    LONG_PTR    OffsetOffset;
    LONG_PTR    LengthOffset;
    LONG_PTR    MdlOffset;
} XENVIF_TRANSMITTER_PACKET_METADATA, *PXENVIF_TRANSMITTER_PACKET_METADATA;

typedef struct _XENVIF_TRANSMITTER_PACKET_STATISTICS {
    ULONG   Drop;
    ULONG   BackendError;
    ULONG   FrontendError;
    ULONG   Unicast;
    ULONG   UnicastBytes;
    ULONG   Multicast;
    ULONG   MulticastBytes;
    ULONG   Broadcast;
    ULONG   BroadcastBytes;
} XENVIF_TRANSMITTER_PACKET_STATISTICS, *PXENVIF_TRANSMITTER_PACKET_STATISTICS;

typedef struct _XENVIF_PACKET_STATISTICS {
    XENVIF_RECEIVER_PACKET_STATISTICS       Receiver;
    XENVIF_TRANSMITTER_PACKET_STATISTICS    Transmitter;
} XENVIF_PACKET_STATISTICS, *PXENVIF_PACKET_STATISTICS;

#define MAXIMUM_MULTICAST_ADDRESS_COUNT 32  // Minimum number to pass WHQL

typedef enum _XENVIF_MAC_FILTER_LEVEL {
    MAC_FILTER_NONE = 0,
    MAC_FILTER_MATCHING = 1,
    MAC_FILTER_ALL = 2
} XENVIF_MAC_FILTER_LEVEL, *PXENVIF_MAC_FILTER_LEVEL;

typedef struct _XENVIF_MEDIA_STATE {
    NET_IF_MEDIA_CONNECT_STATE  MediaConnectState;
    ULONG64                     LinkSpeed;
    NET_IF_MEDIA_DUPLEX_STATE   MediaDuplexState;
} XENVIF_MEDIA_STATE, *PXENVIF_MEDIA_STATE;

typedef enum XENVIF_CALLBACK_TYPE {
    XENVIF_CALLBACK_TYPE_INVALID = 0,
    XENVIF_CALLBACK_COMPLETE_PACKETS,
    XENVIF_CALLBACK_RECEIVE_PACKETS,
    XENVIF_CALLBACK_MEDIA_STATE_CHANGE
} XENVIF_CALLBACK_TYPE, *PXENVIF_CALLBACK_TYPE;

#define DEFINE_VIF_OPERATIONS                                                                   \
        VIF_OPERATION(VOID,                                                                     \
                      Acquire,                                                                  \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT  Context                                          \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      Release,                                                                  \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT  Context                                          \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(NTSTATUS,                                                                 \
                      Enable,                                                                   \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT  Context,                                         \
                      IN  VOID                 (*Function)(PVOID, XENVIF_CALLBACK_TYPE, ...),   \
                      IN  PVOID                Argument OPTIONAL                                \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      Disable,                                                                  \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT  Context                                          \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      QueryPacketStatistics,                                                    \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT       Context,                                    \
                      OUT PXENVIF_PACKET_STATISTICS Statistics                                  \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      UpdatePacketMetadata,                                                     \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT                   Context,                        \
                      IN  PXENVIF_TRANSMITTER_PACKET_METADATA   Metadata                        \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      ReturnPacket,                                                             \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT       Context,                                    \
                      IN  PXENVIF_RECEIVER_PACKET   Packet                                      \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(NTSTATUS,                                                                 \
                      QueuePackets,                                                             \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT           Context,                                \
                      IN  PXENVIF_TRANSMITTER_PACKET    HeadPacket                              \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      QueryOffloadOptions,                                                      \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT       Context,                                    \
                      OUT PXENVIF_OFFLOAD_OPTIONS   Options                                     \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      UpdateOffloadOptions,                                                     \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT       Context,                                    \
                      IN  XENVIF_OFFLOAD_OPTIONS    Options                                     \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      QueryLargePacketSize,                                                     \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT   Context,                                        \
                      IN  UCHAR                 Version,                                        \
                      OUT PULONG                Size                                            \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      QueryMediaState,                                                          \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT           Context,                                \
                      OUT PNET_IF_MEDIA_CONNECT_STATE   MediaConnectState OPTIONAL,             \
                      OUT PULONG64                      LinkSpeed OPTIONAL,                     \
                      OUT PNET_IF_MEDIA_DUPLEX_STATE    MediaDuplexState OPTIONAL               \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      QueryMaximumFrameSize,                                                    \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT   Context,                                        \
                      OUT PULONG                Size                                            \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      QueryPermanentAddress,                                                    \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT   Context,                                        \
                      OUT PETHERNET_ADDRESS     Address                                         \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      QueryCurrentAddress,                                                      \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT   Context,                                        \
                      OUT PETHERNET_ADDRESS     Address                                         \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(NTSTATUS,                                                                 \
                      UpdateCurrentAddress,                                                     \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT   Context,                                        \
                      IN  PETHERNET_ADDRESS     Address                                         \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(NTSTATUS,                                                                 \
                      QueryMulticastAddresses,                                                  \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT   Context,                                        \
                      OUT PETHERNET_ADDRESS     Address OPTIONAL,                               \
                      OUT PULONG                Count                                           \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(NTSTATUS,                                                                 \
                      UpdateMulticastAddresses,                                                 \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT   Context,                                        \
                      IN  PETHERNET_ADDRESS     Address,                                        \
                      IN  ULONG                 Count                                           \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      QueryFilterLevel,                                                         \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT       Context,                                    \
                      IN  ETHERNET_ADDRESS_TYPE     Type,                                       \
                      OUT PXENVIF_MAC_FILTER_LEVEL  Level                                       \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(NTSTATUS,                                                                 \
                      UpdateFilterLevel,                                                        \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT       Context,                                    \
                      IN  ETHERNET_ADDRESS_TYPE     Type,                                       \
                      IN  XENVIF_MAC_FILTER_LEVEL   Level                                       \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      QueryReceiverRingSize,                                                    \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT       Context,                                    \
                      OUT PULONG                    Size                                        \
                      )                                                                         \
                      )                                                                         \
        VIF_OPERATION(VOID,                                                                     \
                      QueryTransmitterRingSize,                                                 \
                      (                                                                         \
                      IN  PXENVIF_VIF_CONTEXT       Context,                                    \
                      OUT PULONG                    Size                                        \
                      )                                                                         \
                      )

typedef struct _XENVIF_VIF_CONTEXT  XENVIF_VIF_CONTEXT, *PXENVIF_VIF_CONTEXT;

#define VIF_OPERATION(_Type, _Name, _Arguments) \
        _Type (*VIF_ ## _Name) _Arguments;

typedef struct _XENVIF_VIF_OPERATIONS {
    DEFINE_VIF_OPERATIONS
} XENVIF_VIF_OPERATIONS, *PXENVIF_VIF_OPERATIONS;

#undef VIF_OPERATION

typedef struct _XENVIF_VIF_INTERFACE XENVIF_VIF_INTERFACE, *PXENVIF_VIF_INTERFACE;

// {BAA55367-D5CD-4fab-8A2D-BB40476795C3}
DEFINE_GUID(GUID_VIF_INTERFACE, 
            0xbaa55367,
            0xd5cd,
            0x4fab,
            0x8a,
            0x2d,
            0xbb,
            0x40,
            0x47,
            0x67,
            0x95,
            0xc3);

#define VIF_INTERFACE_VERSION    12

#define VIF_OPERATIONS(_Interface) \
        (PXENVIF_VIF_OPERATIONS *)((ULONG_PTR)(_Interface))

#define VIF_CONTEXT(_Interface) \
        (PXENVIF_VIF_CONTEXT *)((ULONG_PTR)(_Interface) + sizeof (PVOID))

#define VIF(_Operation, _Interface, ...) \
        (*VIF_OPERATIONS(_Interface))->VIF_ ## _Operation((*VIF_CONTEXT(_Interface)), __VA_ARGS__)

#endif  // _XENVIF_INTERFACE_H

