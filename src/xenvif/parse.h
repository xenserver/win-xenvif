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

#ifndef _XENVIF_PARSE_H
#define _XENVIF_PARSE_H

#include <vif_interface.h>

typedef struct _XENVIF_HEADER_STATISTICS {
    ULONGLONG   Tagged;
    ULONGLONG   LLC;
    ULONGLONG   IpVersion4;
    ULONGLONG   IpVersion6;
    ULONGLONG   IpOptions;
    ULONGLONG   Tcp;
    ULONGLONG   TcpOptions;
    ULONGLONG   Udp;
} XENVIF_HEADER_STATISTICS, *PXENVIF_HEADER_STATISTICS;

typedef struct _XENVIF_PACKET_PAYLOAD {
    PMDL    Mdl;
    ULONG   Offset;
    ULONG   Length;
} XENVIF_PACKET_PAYLOAD, *PXENVIF_PACKET_PAYLOAD;

extern NTSTATUS
ParsePacket(
    IN      PUCHAR                      StartVa,
    IN      BOOLEAN                     (*Pullup)(PVOID, PUCHAR, PXENVIF_PACKET_PAYLOAD, ULONG),
    IN      PVOID                       Argument,
    IN OUT  PXENVIF_HEADER_STATISTICS   Statistics,
    IN OUT  PXENVIF_PACKET_PAYLOAD      Payload,
    OUT     PXENVIF_PACKET_INFO         Info
    );

#endif  // _XENVIF_PARSE_H
