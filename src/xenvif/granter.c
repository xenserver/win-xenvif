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
#include <evtchn_interface.h>
#include <store_interface.h>

#include "pdo.h"
#include "frontend.h"
#include "granter.h"
#include "dbg_print.h"
#include "assert.h"

struct _XENVIF_GRANTER {
    PXENVIF_FRONTEND            Frontend;

    PXENBUS_GNTTAB_INTERFACE    GnttabInterface;
};

#define GRANTER_POOL    'NARG'

static FORCEINLINE PVOID
__GranterAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, GRANTER_POOL);
}

static FORCEINLINE VOID
__GranterFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, GRANTER_POOL);
}

NTSTATUS
GranterInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_GRANTER     *Granter
    )
{
    NTSTATUS                status;

    *Granter = __GranterAllocate(sizeof (XENVIF_GRANTER));

    status = STATUS_NO_MEMORY;
    if (*Granter == NULL)
        goto fail1;

    (*Granter)->Frontend = Frontend;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
GranterConnect(
    IN  PXENVIF_GRANTER     Granter
    )
{
    PXENVIF_FRONTEND        Frontend;

    Frontend = Granter->Frontend;

    Granter->GnttabInterface = FrontendGetGnttabInterface(Frontend);

    GNTTAB(Acquire, Granter->GnttabInterface);

    return STATUS_SUCCESS;
}

NTSTATUS
GranterEnable(
    IN  PXENVIF_GRANTER     Granter
    )
{
    UNREFERENCED_PARAMETER(Granter);

    return STATUS_SUCCESS;
}

NTSTATUS
GranterGet(
    IN  PXENVIF_GRANTER         Granter,
    OUT PXENVIF_GRANTER_HANDLE  Handle
    )
{
    ULONG                       Reference;
    NTSTATUS                    status;

    status = GNTTAB(Get,
                    Granter->GnttabInterface,
                    &Reference);
    if (!NT_SUCCESS(status))
        goto fail1;

    *Handle = (XENVIF_GRANTER_HANDLE)(ULONG_PTR)Reference;
    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

NTSTATUS
GranterPermitAccess(
    IN  PXENVIF_GRANTER         Granter,
    IN  XENVIF_GRANTER_HANDLE   Handle,
    IN  PFN_NUMBER              Pfn,
    IN  BOOLEAN                 ReadOnly
    )
{
    PXENVIF_FRONTEND            Frontend;
    ULONG_PTR                   Reference;
    NTSTATUS                    status;

    Frontend = Granter->Frontend;

    Reference = (ULONG_PTR)Handle;

    status = GNTTAB(PermitForeignAccess,
                    Granter->GnttabInterface,
                    (ULONG)Reference,
                    FrontendGetBackendDomain(Frontend),
                    GNTTAB_ENTRY_FULL_PAGE,
                    Pfn,
                    ReadOnly);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
GranterRevokeAccess(
    IN  PXENVIF_GRANTER         Granter,
    IN  XENVIF_GRANTER_HANDLE   Handle
    )
{
    ULONG_PTR                   Reference;

    Reference = (ULONG_PTR)Handle;

    (VOID) GNTTAB(RevokeForeignAccess,
                  Granter->GnttabInterface,
                  (ULONG)Reference);
}

VOID
GranterPut(
    IN  PXENVIF_GRANTER         Granter,
    IN  XENVIF_GRANTER_HANDLE   Handle
    )
{
    ULONG_PTR                   Reference;

    Reference = (ULONG_PTR)Handle;

    GNTTAB(Put,
           Granter->GnttabInterface,
           (ULONG)Reference);
}

ULONG
GranterGetReference(
    IN  XENVIF_GRANTER_HANDLE   Handle
    )
{
    return (ULONG)(ULONG_PTR)Handle;
}

VOID
GranterDisable(
    IN  PXENVIF_GRANTER     Granter
    )
{
    UNREFERENCED_PARAMETER(Granter);
}

VOID
GranterDisconnect(
    IN  PXENVIF_GRANTER     Granter
    )
{
    GNTTAB(Release, Granter->GnttabInterface);
    Granter->GnttabInterface = NULL;
}

VOID
GranterTeardown(
    IN  PXENVIF_GRANTER     Granter
    )
{
    Granter->Frontend = NULL;

    ASSERT(IsZeroMemory(Granter, sizeof (XENVIF_GRANTER)));

    __GranterFree(Granter);
}
