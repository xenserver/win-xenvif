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
    KSPIN_LOCK                  Lock;
    PXENBUS_GNTTAB_INTERFACE    GnttabInterface;
    PXENBUS_GNTTAB_CACHE        Cache;
};

#define GRANTER_POOL    'NARG'

#define MAXNAMELEN  128

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

static VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
GranterAcquireLock(
    IN  PVOID               Argument
    )
{
    PXENVIF_GRANTER         Granter = Argument;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&Granter->Lock);
}

static VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
GranterReleaseLock(
    IN  PVOID               Argument
    )
{
    PXENVIF_GRANTER         Granter = Argument;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeReleaseSpinLockFromDpcLevel(&Granter->Lock);
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

    (*Granter)->GnttabInterface = FrontendGetGnttabInterface(Frontend);

    GNTTAB(Acquire, (*Granter)->GnttabInterface);

    KeInitializeSpinLock(&(*Granter)->Lock);

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
    CHAR                    Name[MAXNAMELEN];
    ULONG                   Index;
    NTSTATUS                status;

    Frontend = Granter->Frontend;

    status = RtlStringCbPrintfA(Name,
                                sizeof (Name),
                                "%s",
                                FrontendGetPath(Frontend));
    if (!NT_SUCCESS(status))
        goto fail1;

    for (Index = 0; Name[Index] != '\0'; Index++)
        if (Name[Index] == '/')
            Name[Index] = '_';

    status = GNTTAB(CreateCache,
                    Granter->GnttabInterface,
                    Name,
                    0,
                    GranterAcquireLock,
                    GranterReleaseLock,
                    Granter,
                    &Granter->Cache);
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
GranterEnable(
    IN  PXENVIF_GRANTER     Granter
    )
{
    UNREFERENCED_PARAMETER(Granter);

    return STATUS_SUCCESS;
}

NTSTATUS
GranterPermitAccess(
    IN  PXENVIF_GRANTER         Granter,
    IN  PFN_NUMBER              Pfn,
    IN  BOOLEAN                 ReadOnly,
    OUT PXENVIF_GRANTER_HANDLE  Handle
    )
{
    PXENVIF_FRONTEND            Frontend;
    PXENBUS_GNTTAB_DESCRIPTOR   Descriptor;
    NTSTATUS                    status;

    Frontend = Granter->Frontend;

    status = GNTTAB(PermitForeignAccess,
                    Granter->GnttabInterface,
                    Granter->Cache,
                    FALSE,
                    FrontendGetBackendDomain(Frontend),
                    Pfn,
                    ReadOnly,
                    &Descriptor);
    if (!NT_SUCCESS(status))
        goto fail1;

    *Handle = Descriptor;
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
    PXENBUS_GNTTAB_DESCRIPTOR   Descriptor = Handle;
    NTSTATUS                    status;

    status = GNTTAB(RevokeForeignAccess,
                    Granter->GnttabInterface,
                    Granter->Cache,
                    FALSE,
                    Descriptor);
    if (!NT_SUCCESS(status))
        goto fail1;

    return;

fail1:
    Error("fail1 (%08x)\n", status);
}

ULONG
GranterGetReference(
    IN  PXENVIF_GRANTER         Granter,
    IN  XENVIF_GRANTER_HANDLE   Handle
    )
{
    PXENBUS_GNTTAB_DESCRIPTOR   Descriptor;

    Descriptor = (PXENBUS_GNTTAB_DESCRIPTOR)Handle;

    return GNTTAB(Reference,
                  Granter->GnttabInterface,
                  Descriptor);
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
    GNTTAB(DestroyCache,
           Granter->GnttabInterface,
           Granter->Cache);
    Granter->Cache = NULL;
}

VOID
GranterTeardown(
    IN  PXENVIF_GRANTER     Granter
    )
{
    Granter->Frontend = NULL;

    RtlZeroMemory(&Granter->Lock, sizeof (KSPIN_LOCK));

    GNTTAB(Release, Granter->GnttabInterface);
    Granter->GnttabInterface = NULL;

    ASSERT(IsZeroMemory(Granter, sizeof (XENVIF_GRANTER)));

    __GranterFree(Granter);
}
