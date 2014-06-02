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

#ifndef _XENBUS_CACHE_INTERFACE_H
#define _XENBUS_CACHE_INTERFACE_H

typedef struct _XENBUS_CACHE    XENBUS_CACHE, *PXENBUS_CACHE;

#define DEFINE_CACHE_OPERATIONS                                             \
        CACHE_OPERATION(VOID,                                               \
                        Acquire,                                            \
                        (                                                   \
                        IN  PXENBUS_CACHE_CONTEXT Context                   \
                        )                                                   \
                        )                                                   \
        CACHE_OPERATION(VOID,                                               \
                        Release,                                            \
                        (                                                   \
                        IN  PXENBUS_CACHE_CONTEXT Context                   \
                        )                                                   \
                        )                                                   \
        CACHE_OPERATION(NTSTATUS,                                           \
                        Create,                                             \
                        (                                                   \
                        IN  PXENBUS_CACHE_CONTEXT Context,                  \
                        IN  const CHAR            *Name,                    \
                        IN  ULONG                 Size,                     \
                        IN  ULONG                 Reservation,              \
                        IN  NTSTATUS              (*Ctor)(PVOID, PVOID),    \
                        IN  VOID                  (*Dtor)(PVOID, PVOID),    \
                        IN  VOID                  (*AcquireLock)(PVOID),    \
                        IN  VOID                  (*ReleaseLock)(PVOID),    \
                        IN  PVOID                 Argument,                 \
                        OUT PXENBUS_CACHE         *Cache                    \
                        )                                                   \
                        )                                                   \
        CACHE_OPERATION(PVOID,                                              \
                        Get,                                                \
                        (                                                   \
                        IN  PXENBUS_CACHE_CONTEXT Context,                  \
                        IN  PXENBUS_CACHE         Cache,                    \
                        IN  BOOLEAN               Locked                    \
                        )                                                   \
                        )                                                   \
        CACHE_OPERATION(VOID,                                               \
                        Put,                                                \
                        (                                                   \
                        IN  PXENBUS_CACHE_CONTEXT Context,                  \
                        IN  PXENBUS_CACHE         Cache,                    \
                        IN  PVOID                 Object,                   \
                        IN  BOOLEAN               Locked                    \
                        )                                                   \
                        )                                                   \
        CACHE_OPERATION(VOID,                                               \
                        Destroy,                                            \
                        (                                                   \
                        IN  PXENBUS_CACHE_CONTEXT Context,                  \
                        IN  PXENBUS_CACHE         Cache                     \
                        )                                                   \
                        )

typedef struct _XENBUS_CACHE_CONTEXT  XENBUS_CACHE_CONTEXT, *PXENBUS_CACHE_CONTEXT;

#define CACHE_OPERATION(_Type, _Name, _Arguments) \
        _Type (*CACHE_ ## _Name) _Arguments;

typedef struct _XENBUS_CACHE_OPERATIONS {
    DEFINE_CACHE_OPERATIONS
} XENBUS_CACHE_OPERATIONS, *PXENBUS_CACHE_OPERATIONS;

#undef CACHE_OPERATION

typedef struct _XENBUS_CACHE_INTERFACE XENBUS_CACHE_INTERFACE, *PXENBUS_CACHE_INTERFACE;

// {9484b4fb-15bc-4317-ab34-73a2826de5d9}
DEFINE_GUID(GUID_CACHE_INTERFACE, 
            0x9484b4fb,
            0x15bc,
            0x4317,
            0xab,
            0x34,
            0x73,
            0xa2,
            0x82,
            0x6d,
            0xe5,
            0xd9);

#define CACHE_INTERFACE_VERSION   1

#define CACHE_OPERATIONS(_Interface) \
        (PXENBUS_CACHE_OPERATIONS *)((ULONG_PTR)(_Interface))

#define CACHE_CONTEXT(_Interface) \
        (PXENBUS_CACHE_CONTEXT *)((ULONG_PTR)(_Interface) + sizeof (PVOID))

#define CACHE(_Operation, _Interface, ...) \
        (*CACHE_OPERATIONS(_Interface))->CACHE_ ## _Operation((*CACHE_CONTEXT(_Interface)), __VA_ARGS__)

#endif  // _XENBUS_CACHE_H
