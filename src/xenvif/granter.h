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

#ifndef _XENVIF_GRANTER_H
#define _XENVIF_GRANTER_H

#include <ntddk.h>
#include <gnttab_interface.h>

typedef struct _XENVIF_GRANTER  XENVIF_GRANTER, *PXENVIF_GRANTER;

typedef PVOID XENVIF_GRANTER_HANDLE, *PXENVIF_GRANTER_HANDLE;

NTSTATUS
GranterInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_GRANTER     *Granter
    );

NTSTATUS
GranterConnect(
    IN  PXENVIF_GRANTER     Granter
    );

NTSTATUS
GranterEnable(
    IN  PXENVIF_GRANTER     Granter
    );

NTSTATUS
GranterPermitAccess(
    IN  PXENVIF_GRANTER         Granter,
    IN  PFN_NUMBER              Pfn,
    IN  BOOLEAN                 ReadOnly,
    OUT PXENVIF_GRANTER_HANDLE  Handle
    );

VOID
GranterRevokeAccess(
    IN  PXENVIF_GRANTER         Granter,
    IN  XENVIF_GRANTER_HANDLE   Handle
    );

ULONG
GranterGetReference(
    IN  PXENVIF_GRANTER         Granter,
    IN  XENVIF_GRANTER_HANDLE   Handle
    );

VOID
GranterDisable(
    IN  PXENVIF_GRANTER Granter
    );

VOID
GranterDisconnect(
    IN  PXENVIF_GRANTER Granter
    );

VOID
GranterTeardown(
    IN  PXENVIF_GRANTER Granter
    );

#endif  // _XENVIF_GRANTER_H
