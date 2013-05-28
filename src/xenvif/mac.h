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

#ifndef _XENVIF_MAC_H
#define _XENVIF_MAC_H

#include <ntddk.h>
#include <ethernet.h>
#include <vif_interface.h>

#include "frontend.h"

typedef struct _XENVIF_MAC XENVIF_MAC, *PXENVIF_MAC;

extern NTSTATUS
MacInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_MAC         *Mac
    );

extern NTSTATUS
MacConnect(
    IN  PXENVIF_MAC    Mac
    );

extern NTSTATUS
MacEnable(
    IN  PXENVIF_MAC    Mac
    );

extern VOID
MacDisable(
    IN  PXENVIF_MAC    Mac
    );

extern VOID
MacDisconnect(
    IN  PXENVIF_MAC    Mac
    );

extern VOID
MacTeardown(
    IN  PXENVIF_MAC    Mac
    );

extern PKEVENT
MacGetEvent(
    IN  PXENVIF_MAC     Mac
    );

extern ULONG
MacGetLinkSpeed(
    IN  PXENVIF_MAC     Mac
    );

extern BOOLEAN
MacGetLinkState(
    IN  PXENVIF_MAC     Mac
    );

extern ULONG
MacGetMaximumFrameSize(
    IN  PXENVIF_MAC Mac
    );

extern PETHERNET_ADDRESS
MacGetPermanentAddress(
    IN  PXENVIF_MAC         Mac
    );

extern PETHERNET_ADDRESS
MacGetCurrentAddress(
    IN  PXENVIF_MAC         Mac
    );

extern NTSTATUS
MacSetCurrentAddress(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   Address
    );

extern PETHERNET_ADDRESS
MacGetMulticastAddresses(
    IN  PXENVIF_MAC         Mac,
    OUT PULONG              Count
    );

extern NTSTATUS
MacSetMulticastAddresses(
    IN  PXENVIF_MAC         Mac,
    IN  ETHERNET_ADDRESS    Address[],
    IN  ULONG               Count
    );

extern PETHERNET_ADDRESS
MacGetBroadcastAddress(
    IN  PXENVIF_MAC         Mac
    );

extern NTSTATUS
MacSetFilterLevel(
    IN  PXENVIF_MAC             Mac,
    IN  ETHERNET_ADDRESS_TYPE   Type,
    IN  XENVIF_MAC_FILTER_LEVEL Level
    );

extern XENVIF_MAC_FILTER_LEVEL
MacGetFilterLevel(
    IN  PXENVIF_MAC             Mac,
    IN  ETHERNET_ADDRESS_TYPE   Type
    );

extern BOOLEAN
MacApplyFilters(
    IN  PXENVIF_MAC         Mac,
    IN  PETHERNET_ADDRESS   DestinationAddress
    );

#endif  // _XENVIF_MAC_H
