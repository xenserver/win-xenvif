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
#include <util.h>

#include "registry.h"
#include "log.h"
#include "assert.h"

#define REGISTRY_POOL 'GERX'

static UNICODE_STRING   RegistryPath;

static FORCEINLINE PVOID
__RegistryAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, REGISTRY_POOL);
}

static FORCEINLINE VOID
__RegistryFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, REGISTRY_POOL);
}

NTSTATUS
RegistryInitialize(
    IN PUNICODE_STRING  Path
    )
{
    NTSTATUS            status;

    ASSERT3P(RegistryPath.Buffer, ==, NULL);

    status = RtlUpcaseUnicodeString(&RegistryPath, Path, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
RegistryTeardown(
    VOID
    )
{
    RtlFreeUnicodeString(&RegistryPath);
    RegistryPath.Buffer = NULL;
    RegistryPath.MaximumLength = RegistryPath.Length = 0;
}

NTSTATUS
RegistryOpenSubKey(
    IN  PCHAR           Name,
    IN  ACCESS_MASK     DesiredAccess,
    OUT PHANDLE         Key
    )
{
    ANSI_STRING         Ansi;
    UNICODE_STRING      Unicode;
    OBJECT_ATTRIBUTES   Attributes;
    HANDLE              ServiceKey;
    NTSTATUS            status;

    RtlInitAnsiString(&Ansi, Name);

    status = RtlAnsiStringToUnicodeString(&Unicode, &Ansi, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;

    InitializeObjectAttributes(&Attributes,
                               &RegistryPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    status = ZwOpenKey(&ServiceKey,
                       KEY_ALL_ACCESS,
                       &Attributes);
    if (!NT_SUCCESS(status))
        goto fail2;

    InitializeObjectAttributes(&Attributes,
                               &Unicode,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               ServiceKey,
                               NULL);

    status = ZwOpenKey(Key,
                       DesiredAccess,
                       &Attributes);
    if (!NT_SUCCESS(status))
        goto fail3;

    ZwClose(ServiceKey);

    RtlFreeUnicodeString(&Unicode);

    return STATUS_SUCCESS;

fail3:
    ZwClose(ServiceKey);

fail2:
    RtlFreeUnicodeString(&Unicode);

fail1:
    return status;
}

NTSTATUS
RegistryCreateSubKey(
    IN  PCHAR           Name
    )
{
    ANSI_STRING         Ansi;
    UNICODE_STRING      Unicode;
    OBJECT_ATTRIBUTES   Attributes;
    HANDLE              ServiceKey;
    HANDLE              Key;
    NTSTATUS            status;

    RtlInitAnsiString(&Ansi, Name);

    status = RtlAnsiStringToUnicodeString(&Unicode, &Ansi, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;

    InitializeObjectAttributes(&Attributes,
                               &RegistryPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    status = ZwOpenKey(&ServiceKey,
                       KEY_ALL_ACCESS,
                       &Attributes);
    if (!NT_SUCCESS(status))
        goto fail2;

    InitializeObjectAttributes(&Attributes,
                               &Unicode,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               ServiceKey,
                               NULL);

    status = ZwCreateKey(&Key,
                         KEY_ALL_ACCESS,
                         &Attributes,
                         0,
                         NULL,
                         REG_OPTION_VOLATILE,
                         NULL
                         );
    if (!NT_SUCCESS(status))
        goto fail3;

    ZwClose(Key);

    ZwClose(ServiceKey);

    RtlFreeUnicodeString(&Unicode);

    return STATUS_SUCCESS;

fail3:
    ZwClose(ServiceKey);

fail2:
    RtlFreeUnicodeString(&Unicode);

fail1:
    return status;
}

NTSTATUS
RegistryDeleteSubKey(
    IN  PCHAR           Name
    )
{
    ANSI_STRING         Ansi;
    UNICODE_STRING      Unicode;
    OBJECT_ATTRIBUTES   Attributes;
    HANDLE              ServiceKey;
    HANDLE              Key;
    NTSTATUS            status;

    RtlInitAnsiString(&Ansi, Name);

    status = RtlAnsiStringToUnicodeString(&Unicode, &Ansi, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;

    InitializeObjectAttributes(&Attributes,
                               &RegistryPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    status = ZwOpenKey(&ServiceKey,
                       KEY_ALL_ACCESS,
                       &Attributes);
    if (!NT_SUCCESS(status))
        goto fail2;

    InitializeObjectAttributes(&Attributes,
                               &Unicode,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               ServiceKey,
                               NULL);

    status = ZwOpenKey(&Key,
                       KEY_ALL_ACCESS,
                       &Attributes);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = ZwDeleteKey(Key);
    if (!NT_SUCCESS(status))
        goto fail4;

    ZwClose(Key);

    ZwClose(ServiceKey);

    RtlFreeUnicodeString(&Unicode);

    return STATUS_SUCCESS;

fail4:
    ZwClose(Key);

fail3:
    ZwClose(ServiceKey);

fail2:
    RtlFreeUnicodeString(&Unicode);

fail1:
    return status;
}


NTSTATUS
RegistryOpenSoftwareKey(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  ACCESS_MASK     DesiredAccess,
    OUT PHANDLE         Key
    )
{
    NTSTATUS            status;

    status = IoOpenDeviceRegistryKey(DeviceObject,
                                     PLUGPLAY_REGKEY_DRIVER,
                                     DesiredAccess,
                                     Key);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    return status;
}

NTSTATUS
RegistryOpenHardwareKey(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  ACCESS_MASK     DesiredAccess,
    OUT PHANDLE         Key
    )
{
    NTSTATUS            status;

    status = IoOpenDeviceRegistryKey(DeviceObject,
                                     PLUGPLAY_REGKEY_DEVICE,
                                     DesiredAccess,
                                     Key);
    if (!NT_SUCCESS(status))
        goto fail1;

    return STATUS_SUCCESS;

fail1:
    return status;
}

NTSTATUS
RegistryQueryDwordValue(
    IN  HANDLE                      Key,
    IN  PCHAR                       Name,
    OUT PULONG                      Value
    )
{
    ANSI_STRING                     Ansi;
    UNICODE_STRING                  Unicode;
    PKEY_VALUE_PARTIAL_INFORMATION  Partial;
    ULONG                           Size;
    NTSTATUS                        status;

    RtlInitAnsiString(&Ansi, Name);

    status = RtlAnsiStringToUnicodeString(&Unicode, &Ansi, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;
        
    status = ZwQueryValueKey(Key,
                             &Unicode,
                             KeyValuePartialInformation,
                             NULL,
                             0,
                             &Size);
    if (status != STATUS_BUFFER_TOO_SMALL)
        goto fail2;

    Partial = __RegistryAllocate(Size);

    status = STATUS_NO_MEMORY;
    if (Partial == NULL)
        goto fail3;

    status = ZwQueryValueKey(Key,
                             &Unicode,
                             KeyValuePartialInformation,
                             Partial,
                             Size,
                             &Size);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = STATUS_INVALID_PARAMETER;
    if (Partial->Type != REG_DWORD ||
        Partial->DataLength != sizeof (ULONG))
        goto fail5;

    *Value = *(PULONG)Partial->Data;            

    __RegistryFree(Partial);

    RtlFreeUnicodeString(&Unicode);

    return STATUS_SUCCESS;

fail5:
fail4:
    __RegistryFree(Partial);

fail3:
fail2:
    RtlFreeUnicodeString(&Unicode);

fail1:
    return status;
}

NTSTATUS
RegistryUpdateDwordValue(
    IN  HANDLE                      Key,
    IN  PCHAR                       Name,
    IN  ULONG                       Value
    )
{
    ANSI_STRING                     Ansi;
    UNICODE_STRING                  Unicode;
    PKEY_VALUE_PARTIAL_INFORMATION  Partial;
    NTSTATUS                        status;

    RtlInitAnsiString(&Ansi, Name);

    status = RtlAnsiStringToUnicodeString(&Unicode, &Ansi, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;
        
    Partial = __RegistryAllocate(FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) +
                                 sizeof (ULONG));

    status = STATUS_NO_MEMORY;
    if (Partial == NULL)
        goto fail2;

    Partial->TitleIndex = 0;
    Partial->Type = REG_DWORD;
    Partial->DataLength = sizeof (ULONG);
    *(PULONG)Partial->Data = Value;            

    status = ZwSetValueKey(Key,
                           &Unicode,
                           Partial->TitleIndex,
                           Partial->Type,
                           Partial->Data,
                           Partial->DataLength);
    if (!NT_SUCCESS(status))
        goto fail3;

    __RegistryFree(Partial);

    RtlFreeUnicodeString(&Unicode);

    return STATUS_SUCCESS;

fail3:
    __RegistryFree(Partial);

fail2:
    RtlFreeUnicodeString(&Unicode);

fail1:

    return status;
}

static PANSI_STRING
RegistrySzToAnsi(
    IN  PWCHAR      Buffer
    )
{
    PANSI_STRING    Ansi;
    ULONG           Length;
    UNICODE_STRING  Unicode;
    NTSTATUS        status;

    Ansi = __RegistryAllocate(sizeof (ANSI_STRING) * 2);

    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    Length = (ULONG)wcslen(Buffer);
    Ansi[0].MaximumLength = (USHORT)(Length + 1) * sizeof (CHAR);
    Ansi[0].Buffer = __RegistryAllocate(Ansi[0].MaximumLength);

    status = STATUS_NO_MEMORY;
    if (Ansi[0].Buffer == NULL)
        goto fail2;

    RtlInitUnicodeString(&Unicode, Buffer);
    status = RtlUnicodeStringToAnsiString(&Ansi[0], &Unicode, FALSE);
    ASSERT(NT_SUCCESS(status));

    Ansi[0].Length = (USHORT)Length * sizeof (CHAR);

    return Ansi;

fail2:
    __RegistryFree(Ansi);

fail1:
    return NULL;
}

static PANSI_STRING
RegistryMultiSzToAnsi(
    IN  PWCHAR      Buffer
    )
{
    PANSI_STRING    Ansi;
    LONG            Index;
    LONG            Count;
    NTSTATUS        status;

    Index = 0;
    Count = 0;
    for (;;) {
        ULONG   Length;

        Length = (ULONG)wcslen(&Buffer[Index]);
        if (Length == 0)
            break;

        Index += Length + 1;
        Count++;
    }

    Ansi = __RegistryAllocate(sizeof (ANSI_STRING) * (Count + 1));

    status = STATUS_NO_MEMORY;
    if (Ansi == NULL)
        goto fail1;

    for (Index = 0; Index < Count; Index++) {
        ULONG           Length;
        UNICODE_STRING  Unicode;

        Length = (ULONG)wcslen(Buffer);
        Ansi[Index].MaximumLength = (USHORT)(Length + 1) * sizeof (CHAR);
        Ansi[Index].Buffer = __RegistryAllocate(Ansi[Index].MaximumLength);

        status = STATUS_NO_MEMORY;
        if (Ansi[Index].Buffer == NULL)
            goto fail2;

        RtlInitUnicodeString(&Unicode, Buffer);

        status = RtlUnicodeStringToAnsiString(&Ansi[Index], &Unicode, FALSE);
        ASSERT(NT_SUCCESS(status));

        Ansi[Index].Length = (USHORT)Length * sizeof (CHAR);
        Buffer += Length + 1;
    }

    return Ansi;

fail2:
    while (--Index >= 0)
        __RegistryFree(Ansi[Index].Buffer);

    __RegistryFree(Ansi);

fail1:
    return NULL;
}

NTSTATUS
RegistryQuerySzValue(
    IN  HANDLE                      Key,
    IN  PCHAR                       Name,
    OUT PANSI_STRING                *Array
    )
{
    ANSI_STRING                     Ansi;
    UNICODE_STRING                  Unicode;
    PKEY_VALUE_PARTIAL_INFORMATION  Value;
    ULONG                           Size;
    NTSTATUS                        status;

    RtlInitAnsiString(&Ansi, Name);

    status = RtlAnsiStringToUnicodeString(&Unicode, &Ansi, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;
        
    status = ZwQueryValueKey(Key,
                             &Unicode,
                             KeyValuePartialInformation,
                             NULL,
                             0,
                             &Size);
    if (status != STATUS_BUFFER_TOO_SMALL)
        goto fail2;

    Value = __RegistryAllocate(Size);

    status = STATUS_NO_MEMORY;
    if (Value == NULL)
        goto fail3;

    status = ZwQueryValueKey(Key,
                             &Unicode,
                             KeyValuePartialInformation,
                             Value,
                             Size,
                             &Size);
    if (!NT_SUCCESS(status))
        goto fail4;

    switch (Value->Type) {
    case REG_SZ:
        status = STATUS_NO_MEMORY;
        *Array = RegistrySzToAnsi((PWCHAR)Value->Data);
        break;

    case REG_MULTI_SZ:
        status = STATUS_NO_MEMORY;
        *Array = RegistryMultiSzToAnsi((PWCHAR)Value->Data);
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        *Array = NULL;
        break;
    }

    if (*Array == NULL)
        goto fail5;

    __RegistryFree(Value);

    RtlFreeUnicodeString(&Unicode);

    return STATUS_SUCCESS;

fail5:
fail4:
    __RegistryFree(Value);

fail3:
fail2:
    RtlFreeUnicodeString(&Unicode);

fail1:
    return status;
}

static PKEY_VALUE_PARTIAL_INFORMATION
RegistryAnsiToSz(
    PANSI_STRING                    Ansi
    )
{
    ULONG                           Length;
    PKEY_VALUE_PARTIAL_INFORMATION  Partial;
    UNICODE_STRING                  Unicode;
    NTSTATUS                        status;

    Length = Ansi->Length + 1;
    Partial = __RegistryAllocate(FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) +
                                 Length * sizeof (WCHAR));

    status = STATUS_NO_MEMORY;
    if (Partial == NULL)
        goto fail1;

    Partial->TitleIndex = 0;
    Partial->Type = REG_SZ;
    Partial->DataLength = Length * sizeof (WCHAR);

    Unicode.MaximumLength = (UCHAR)Partial->DataLength;
    Unicode.Buffer = (PWCHAR)Partial->Data;
    Unicode.Length = 0;

    status = RtlAnsiStringToUnicodeString(&Unicode, Ansi, FALSE);
    if (!NT_SUCCESS(status))
        goto fail2;

    return Partial;

fail2:
    __RegistryFree(Partial);

fail1:
    return NULL;
}

static PKEY_VALUE_PARTIAL_INFORMATION
RegistryAnsiToMultiSz(
    PANSI_STRING                    Ansi
    )
{
    ULONG                           Length;
    ULONG                           Index;
    PKEY_VALUE_PARTIAL_INFORMATION  Partial;
    UNICODE_STRING                  Unicode;
    NTSTATUS                        status;

    Length = 1;
    for (Index = 0; Ansi[Index].Buffer != NULL; Index++)
        Length += Ansi[Index].Length + 1;

    Partial = __RegistryAllocate(FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) +
                               Length * sizeof (WCHAR));

    status = STATUS_NO_MEMORY;
    if (Partial == NULL)
        goto fail1;

    Partial->TitleIndex = 0;
    Partial->Type = REG_MULTI_SZ;
    Partial->DataLength = Length * sizeof (WCHAR);

    Unicode.MaximumLength = (USHORT)Partial->DataLength;
    Unicode.Buffer = (PWCHAR)Partial->Data;
    Unicode.Length = 0;

    for (Index = 0; Ansi[Index].Buffer != NULL; Index++) {
        status = RtlAnsiStringToUnicodeString(&Unicode, &Ansi[Index], FALSE);
        if (!NT_SUCCESS(status))
            goto fail2;

        Length = Unicode.Length / sizeof (WCHAR);

        ASSERT3U(Unicode.MaximumLength, >=, (Length + 1) * sizeof (WCHAR));
        Unicode.MaximumLength -= (USHORT)((Length + 1) * sizeof (WCHAR));
        Unicode.Buffer += Length + 1;
        Unicode.Length = 0;
    }
    *Unicode.Buffer = L'\0';

    return Partial;

fail2:
    __RegistryFree(Partial);

fail1:
    return NULL;
}

NTSTATUS
RegistryUpdateSzValue(
    IN  HANDLE                      Key,
    IN  PCHAR                       Name,
    IN  ULONG                       Type,
    ...
    )
{
    ANSI_STRING                     Ansi;
    UNICODE_STRING                  Unicode;
    va_list                         Arguments;
    PKEY_VALUE_PARTIAL_INFORMATION  Partial;
    NTSTATUS                        status;

    RtlInitAnsiString(&Ansi, Name);

    status = RtlAnsiStringToUnicodeString(&Unicode, &Ansi, TRUE);
    if (!NT_SUCCESS(status))
        goto fail1;
        
    va_start(Arguments, Type);
    switch (Type) {
    case REG_SZ: {
        PANSI_STRING    Argument;

        Argument = va_arg(Arguments, PANSI_STRING);

        status = STATUS_NO_MEMORY;
        Partial = RegistryAnsiToSz(Argument);        
        break;
    }
    case REG_MULTI_SZ: {
        PANSI_STRING    Argument;

        Argument = va_arg(Arguments, PANSI_STRING);

        status = STATUS_NO_MEMORY;
        Partial = RegistryAnsiToMultiSz(Argument);        
        break;
    }
    default:
        status = STATUS_INVALID_PARAMETER;
        Partial = NULL;
        break;
    }
    va_end(Arguments);

    if (Partial == NULL)
        goto fail2;

    status = ZwSetValueKey(Key,
                           &Unicode,
                           Partial->TitleIndex,
                           Partial->Type,
                           Partial->Data,
                           Partial->DataLength);
    if (!NT_SUCCESS(status))
        goto fail3;

    __RegistryFree(Partial);

    RtlFreeUnicodeString(&Unicode);

    return STATUS_SUCCESS;

fail3:
    __RegistryFree(Partial);

fail2:
    RtlFreeUnicodeString(&Unicode);

fail1:
    return status;
}

VOID
RegistryFreeSzValue(
    IN  PANSI_STRING    Array
    )
{
    ULONG               Index;

    if (Array == NULL)
        return;

    for (Index = 0; Array[Index].Buffer != NULL; Index++)
        __RegistryFree(Array[Index].Buffer);

    __RegistryFree(Array);
}

VOID
RegistryCloseKey(
    IN  HANDLE  Key
    )
{
    ZwClose(Key);
}
