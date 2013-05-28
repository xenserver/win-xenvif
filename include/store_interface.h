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

#ifndef _XENBUS_STORE_INTERFACE_H
#define _XENBUS_STORE_INTERFACE_H

typedef struct _XENBUS_STORE_TRANSACTION    XENBUS_STORE_TRANSACTION, *PXENBUS_STORE_TRANSACTION;
typedef struct _XENBUS_STORE_WATCH          XENBUS_STORE_WATCH, *PXENBUS_STORE_WATCH;

#define DEFINE_STORE_OPERATIONS                                                 \
        STORE_OPERATION(VOID,                                                   \
                        Acquire,                                                \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context                 \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(VOID,                                                   \
                        Release,                                                \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context                 \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(VOID,                                                   \
                        Free,                                                   \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context,                \
                        IN  PCHAR                       Value                   \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(NTSTATUS,                                               \
                        Read,                                                   \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context,                \
                        IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,   \
                        IN  PCHAR                       Prefix OPTIONAL,        \
                        IN  PCHAR                       Node,                   \
                        OUT PCHAR                       *Value                  \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(NTSTATUS,                                               \
                        Write,                                                  \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context,                \
                        IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,   \
                        IN  PCHAR                       Prefix OPTIONAL,        \
                        IN  PCHAR                       Node,                   \
                        IN  PCHAR                       Value                   \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(NTSTATUS,                                               \
                        Printf,                                                 \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context,                \
                        IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,   \
                        IN  PCHAR                       Prefix OPTIONAL,        \
                        IN  PCHAR                       Node,                   \
                        IN  const CHAR                  *Format,                \
                        ...                                                     \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(NTSTATUS,                                               \
                        Remove,                                                 \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context,                \
                        IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,   \
                        IN  PCHAR                       Prefix OPTIONAL,        \
                        IN  PCHAR                       Node                    \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(NTSTATUS,                                               \
                        Directory,                                              \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context,                \
                        IN  PXENBUS_STORE_TRANSACTION   Transaction OPTIONAL,   \
                        IN  PCHAR                       Prefix OPTIONAL,        \
                        IN  PCHAR                       Node,                   \
                        OUT PCHAR                       *Value                  \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(NTSTATUS,                                               \
                        TransactionStart,                                       \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context,                \
                        OUT PXENBUS_STORE_TRANSACTION   *Transaction            \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(NTSTATUS,                                               \
                        TransactionEnd,                                         \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context,                \
                        IN  PXENBUS_STORE_TRANSACTION   Transaction,            \
                        IN  BOOLEAN                     Commit                  \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(NTSTATUS,                                               \
                        Watch,                                                  \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context,                \
                        IN  PCHAR                       Prefix OPTIONAL,        \
                        IN  PCHAR                       Node,                   \
                        IN  PKEVENT                     Event,                  \
                        OUT PXENBUS_STORE_WATCH         *Watch                  \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(NTSTATUS,                                               \
                        Unwatch,                                                \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context,                \
                        IN  PXENBUS_STORE_WATCH         Watch                   \
                        )                                                       \
                        )                                                       \
        STORE_OPERATION(VOID,                                                   \
                        Poll,                                                   \
                        (                                                       \
                        IN  PXENBUS_STORE_CONTEXT       Context                 \
                        )                                                       \
                        )

typedef struct _XENBUS_STORE_CONTEXT    XENBUS_STORE_CONTEXT, *PXENBUS_STORE_CONTEXT;

#define STORE_OPERATION(_Type, _Name, _Arguments) \
        _Type (*STORE_ ## _Name) _Arguments;

typedef struct _XENBUS_STORE_OPERATIONS {
    DEFINE_STORE_OPERATIONS
} XENBUS_STORE_OPERATIONS, *PXENBUS_STORE_OPERATIONS;

#undef STORE_OPERATION

typedef struct _XENBUS_STORE_INTERFACE   XENBUS_STORE_INTERFACE, *PXENBUS_STORE_INTERFACE;

// {916920F1-F9EE-465d-8137-5CC61786B840}
DEFINE_GUID(GUID_STORE_INTERFACE,
            0x916920f1,
            0xf9ee,
            0x465d,
            0x81,
            0x37,
            0x5c,
            0xc6,
            0x17,
            0x86,
            0xb8,
            0x40);

#define STORE_INTERFACE_VERSION 4

#define STORE_OPERATIONS(_Interface) \
        (PXENBUS_STORE_OPERATIONS *)((ULONG_PTR)(_Interface))

#define STORE_CONTEXT(_Interface) \
        (PXENBUS_STORE_CONTEXT *)((ULONG_PTR)(_Interface) + sizeof (PVOID))

#define STORE(_Operation, _Interface, ...) \
        (*STORE_OPERATIONS(_Interface))->STORE_ ## _Operation((*STORE_CONTEXT(_Interface)), __VA_ARGS__)

#endif  // _XENBUS_STORE_INTERFACE_H

