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
#include <aux_klib.h>
#include <util.h>

#include "netio.h"
#include "dbg_print.h"
#include "assert.h"

LONG    NetioReferences;
PVOID   NetioGetUnicastIpAddressTable;
PVOID   NetioNotifyUnicastIpAddressChange;
PVOID   NetioCancelMibChangeNotify2;
PVOID   NetioFreeMibTable;

#define NETIO_TAG   'ITEN'

static FORCEINLINE PVOID
__NetioAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, NETIO_TAG);
}

static FORCEINLINE VOID
__NetioFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, NETIO_TAG);
}

static FORCEINLINE NTSTATUS
__NetioLink(
    IN  PVOID   ImageBase
    )
{
#define MK_PTR(_ImageBase, _Type, _RVA) \
    (_Type)((ULONG_PTR)(_ImageBase) + (_RVA))

    PIMAGE_DOS_HEADER           DosHeader;
    PIMAGE_NT_HEADERS           NtHeaders;
    PIMAGE_OPTIONAL_HEADER      OptionalHeader;
    PIMAGE_DATA_DIRECTORY       Entry;
    PIMAGE_EXPORT_DIRECTORY     Exports;
    PULONG                      AddressOfFunctions;
    PULONG                      AddressOfNames;
    PUSHORT                     AddressOfNameOrdinals;
    ULONG                       Index;
    NTSTATUS                    status;

    Trace("====>\n");

    DosHeader = MK_PTR(ImageBase, PIMAGE_DOS_HEADER, 0);
    ASSERT3U(DosHeader->e_magic, ==, IMAGE_DOS_SIGNATURE);

    NtHeaders = MK_PTR(ImageBase, PIMAGE_NT_HEADERS, DosHeader->e_lfanew);
    ASSERT3U(NtHeaders->Signature, ==, IMAGE_NT_SIGNATURE);

    OptionalHeader = &NtHeaders->OptionalHeader;
    ASSERT3U(OptionalHeader->Magic, ==, IMAGE_NT_OPTIONAL_HDR_MAGIC);

    Entry = &OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    status = STATUS_UNSUCCESSFUL;
    if (Entry->Size == 0)
        goto fail1;

    Exports = MK_PTR(ImageBase, PIMAGE_EXPORT_DIRECTORY,
                     Entry->VirtualAddress);

    status = STATUS_UNSUCCESSFUL;
    if (Exports->NumberOfNames == 0)
        goto fail2;

    AddressOfFunctions = MK_PTR(ImageBase, PULONG,
                                Exports->AddressOfFunctions);
    AddressOfNames = MK_PTR(ImageBase, PULONG,
                            Exports->AddressOfNames);
    AddressOfNameOrdinals = MK_PTR(ImageBase, PUSHORT,
                                   Exports->AddressOfNameOrdinals);

    for (Index = 0; Index < Exports->NumberOfNames; Index++) {
        PCHAR   Name = MK_PTR(ImageBase, PCHAR, AddressOfNames[Index]);
        USHORT  Ordinal = AddressOfNameOrdinals[Index];
        PVOID   Function = MK_PTR(ImageBase, PVOID, AddressOfFunctions[Ordinal]);

        if (strcmp(Name, "GetUnicastIpAddressTable") == 0)
            NetioGetUnicastIpAddressTable = Function;
        else if (strcmp(Name, "NotifyUnicastIpAddressChange") == 0)
            NetioNotifyUnicastIpAddressChange = Function;
        else if (strcmp(Name, "CancelMibChangeNotify2") == 0)
            NetioCancelMibChangeNotify2 = Function;
        else if (strcmp(Name, "FreeMibTable") == 0)
            NetioFreeMibTable = Function;
        else
            continue;

        Info("Netio%s -> %s:%s (%04X) (%p)\n",
             Name,
             MK_PTR(ImageBase, PCHAR, Exports->Name),
             Name,
             Ordinal,
             Function);
    }

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    return status;

#undef  MK_PTR
}

NTSTATUS
NetioInitialize(
    VOID
    )
{
    LONG                        References;
    ULONG                       BufferSize;
    ULONG                       Count;
    PAUX_MODULE_EXTENDED_INFO   QueryInfo;
    ULONG                       Index;
    NTSTATUS                    status;

    References = InterlockedIncrement(&NetioReferences);

    if (References > 1)
        goto done;

    (VOID) AuxKlibInitialize();

    status = AuxKlibQueryModuleInformation(&BufferSize,
                                           sizeof (AUX_MODULE_EXTENDED_INFO),
                                           NULL);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = STATUS_UNSUCCESSFUL;
    if (BufferSize == 0)
        goto fail2;

again:
    Count = BufferSize / sizeof (AUX_MODULE_EXTENDED_INFO);
    QueryInfo = __NetioAllocate(sizeof (AUX_MODULE_EXTENDED_INFO) * Count);

    status = STATUS_NO_MEMORY;
    if (QueryInfo == NULL)
        goto fail3;

    status = AuxKlibQueryModuleInformation(&BufferSize,
                                           sizeof (AUX_MODULE_EXTENDED_INFO),
                                           QueryInfo);
    if (!NT_SUCCESS(status)) {
        if (status != STATUS_BUFFER_TOO_SMALL)
            goto fail4;

        __NetioFree(QueryInfo);
        goto again;
    }

    for (Index = 0; Index < Count; Index++) {
        PCHAR   Name;

        Name = strrchr((const CHAR *)QueryInfo[Index].FullPathName, '\\');
        Name = (Name == NULL) ? (PCHAR)QueryInfo[Index].FullPathName : (Name + 1);

        if (_stricmp(Name, "NETIO.SYS") == 0)
            goto found;
    }

    status = STATUS_RETRY;
    goto fail5;

found:
    status = __NetioLink(QueryInfo[Index].BasicInfo.ImageBase);
    if (!NT_SUCCESS(status))
        goto fail6;

    __NetioFree(QueryInfo);

    if (NetioGetUnicastIpAddressTable == NULL ||
        NetioNotifyUnicastIpAddressChange == NULL ||
        NetioCancelMibChangeNotify2 == NULL ||
        NetioFreeMibTable == NULL)
        goto retry;

done:
    ASSERT(NetioGetUnicastIpAddressTable != NULL);
    ASSERT(NetioNotifyUnicastIpAddressChange != NULL);
    ASSERT(NetioCancelMibChangeNotify2 != NULL);
    ASSERT(NetioFreeMibTable != NULL);

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

fail5:
    Error("fail5\n");

fail4:
    Error("fail4\n");

    __NetioFree(QueryInfo);

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

fail1:
    Error("fail1 (%08x)\n", status);

    (VOID) InterlockedDecrement(&NetioReferences);

    return status;

retry:
    NetioGetUnicastIpAddressTable = NULL;
    NetioNotifyUnicastIpAddressChange = NULL;
    NetioCancelMibChangeNotify2 = NULL;
    NetioFreeMibTable = NULL;

    (VOID) InterlockedDecrement(&NetioReferences);

    return status;
}

VOID
NetioTeardown(
    VOID
    )
{
    LONG    References;

    References = InterlockedDecrement(&NetioReferences);

    ASSERT(References >= 0);
    if (References != 0)
        return;

    NetioGetUnicastIpAddressTable = NULL;
    NetioNotifyUnicastIpAddressChange = NULL;
    NetioCancelMibChangeNotify2 = NULL;
    NetioFreeMibTable = NULL;
}
