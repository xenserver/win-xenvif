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

#ifndef _XENVIF_VIF_H
#define _XENVIF_VIF_H

#include <ntddk.h>
#include <vif_interface.h>

#include "fdo.h"

struct _XENVIF_VIF_INTERFACE {
    PXENVIF_VIF_OPERATIONS  Operations;
    PXENVIF_VIF_CONTEXT     Context;
};

C_ASSERT(FIELD_OFFSET(XENVIF_VIF_INTERFACE, Operations) == (ULONG_PTR)VIF_OPERATIONS(NULL));
C_ASSERT(FIELD_OFFSET(XENVIF_VIF_INTERFACE, Context) == (ULONG_PTR)VIF_CONTEXT(NULL));

extern NTSTATUS
VifInitialize(
    IN  PXENVIF_PDO                 Pdo,
    OUT PXENVIF_VIF_INTERFACE       Interface
    );

extern VOID
VifTeardown(
    IN OUT  PXENVIF_VIF_INTERFACE   Interface
    );

extern VOID
VifCompletePackets(
    IN  PXENVIF_VIF_INTERFACE       Interface,
    IN  PXENVIF_TRANSMITTER_PACKET  HeadPacket
    );

extern VOID
VifReceivePackets(
    IN  PXENVIF_VIF_INTERFACE   Interface,
    IN  PLIST_ENTRY             List
    );

#endif  // _XENVIF_VIF_H

