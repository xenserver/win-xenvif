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

#ifndef _XENBUS_GNTTAB_INTERFACE_H
#define _XENBUS_GNTTAB_INTERFACE_H

typedef enum _XENBUS_GNTTAB_ENTRY_TYPE {
    GNTTAB_ENTRY_TYPE_INVALID = 0,
    GNTTAB_ENTRY_FULL_PAGE
} XENBUS_GNTTAB_ENTRY_TYPE, *PXENBUS_GNTTAB_ENTRY_TYPE;

typedef struct _XENBUS_GNTTAB_DESCRIPTOR    XENBUS_GNTTAB_DESCRIPTOR, *PXENBUS_GNTTAB_DESCRIPTOR;

#define DEFINE_GNTTAB_OPERATIONS                                    \
        GNTTAB_OPERATION(VOID,                                      \
                         Acquire,                                   \
                         (                                          \
                         IN  PXENBUS_GNTTAB_CONTEXT     Context     \
                         )                                          \
                         )                                          \
        GNTTAB_OPERATION(VOID,                                      \
                         Release,                                   \
                         (                                          \
                         IN  PXENBUS_GNTTAB_CONTEXT     Context     \
                         )                                          \
                         )                                          \
        GNTTAB_OPERATION(PXENBUS_GNTTAB_DESCRIPTOR,                 \
                         Get,                                       \
                         (                                          \
                         IN  PXENBUS_GNTTAB_CONTEXT     Context     \
                         )                                          \
                         )                                          \
        GNTTAB_OPERATION(VOID,                                      \
                         Put,                                       \
                         (                                          \
                         IN  PXENBUS_GNTTAB_CONTEXT     Context,    \
                         IN  PXENBUS_GNTTAB_DESCRIPTOR  Descriptor  \
                         )                                          \
                         )                                          \
        GNTTAB_OPERATION(NTSTATUS,                                  \
                         PermitForeignAccess,                       \
                         (                                          \
                         IN  PXENBUS_GNTTAB_CONTEXT     Context,    \
                         IN  PXENBUS_GNTTAB_DESCRIPTOR  Descriptor, \
                         IN  USHORT                     Domain,     \
                         IN  XENBUS_GNTTAB_ENTRY_TYPE   Type,       \
                         ...                                        \
                         )                                          \
                         )                                          \
        GNTTAB_OPERATION(NTSTATUS,                                  \
                         RevokeForeignAccess,                       \
                         (                                          \
                         IN  PXENBUS_GNTTAB_CONTEXT     Context,    \
                         IN  PXENBUS_GNTTAB_DESCRIPTOR  Descriptor  \
                         )                                          \
                         )                                          \
        GNTTAB_OPERATION(ULONG,                                     \
                         Reference,                                 \
                         (                                          \
                         IN  PXENBUS_GNTTAB_CONTEXT     Context,    \
                         IN  PXENBUS_GNTTAB_DESCRIPTOR  Descriptor  \
                         )                                          \
                         )

typedef struct _XENBUS_GNTTAB_CONTEXT   XENBUS_GNTTAB_CONTEXT, *PXENBUS_GNTTAB_CONTEXT;

#define GNTTAB_OPERATION(_Type, _Name, _Arguments) \
        _Type (*GNTTAB_ ## _Name) _Arguments;

typedef struct _XENBUS_GNTTAB_OPERATIONS {
    DEFINE_GNTTAB_OPERATIONS
} XENBUS_GNTTAB_OPERATIONS, *PXENBUS_GNTTAB_OPERATIONS;

#undef GNTTAB_OPERATION

typedef struct _XENBUS_GNTTAB_INTERFACE  XENBUS_GNTTAB_INTERFACE, *PXENBUS_GNTTAB_INTERFACE;

// {CC32D7DF-88BE-4248-9A53-1F178BE9D60E}
DEFINE_GUID(GUID_GNTTAB_INTERFACE, 
            0xcc32d7df,
            0x88be,
            0x4248,
            0x9a,
            0x53,
            0x1f,
            0x17,
            0x8b,
            0xe9,
            0xd6,
            0xe);

#define GNTTAB_INTERFACE_VERSION    4

#define GNTTAB_OPERATIONS(_Interface) \
        (PXENBUS_GNTTAB_OPERATIONS *)((ULONG_PTR)(_Interface))

#define GNTTAB_CONTEXT(_Interface) \
        (PXENBUS_GNTTAB_CONTEXT *)((ULONG_PTR)(_Interface) + sizeof (PVOID))

#define GNTTAB(_Operation, _Interface, ...) \
        (*GNTTAB_OPERATIONS(_Interface))->GNTTAB_ ## _Operation((*GNTTAB_CONTEXT(_Interface)), __VA_ARGS__)

#endif  // _XENBUS_GNTTAB_INTERFACE_H

