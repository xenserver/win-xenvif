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

#ifndef _XENBUS_DEBUG_INTERFACE_H
#define _XENBUS_DEBUG_INTERFACE_H

typedef struct _XENBUS_DEBUG_CALLBACK   XENBUS_DEBUG_CALLBACK, *PXENBUS_DEBUG_CALLBACK;

#define DEFINE_DEBUG_OPERATIONS                                                 \
        DEBUG_OPERATION(VOID,                                                   \
                        Acquire,                                                \
                        (                                                       \
                        IN  PXENBUS_DEBUG_CONTEXT  Context                      \
                        )                                                       \
                        )                                                       \
        DEBUG_OPERATION(VOID,                                                   \
                        Release,                                                \
                        (                                                       \
                        IN  PXENBUS_DEBUG_CONTEXT  Context                      \
                        )                                                       \
                        )                                                       \
        DEBUG_OPERATION(NTSTATUS,                                               \
                        Register,                                               \
                        (                                                       \
                        IN  PXENBUS_DEBUG_CONTEXT  Context,                     \
                        IN  const CHAR             *Prefix,                     \
                        IN  VOID                   (*Function)(PVOID, BOOLEAN), \
                        IN  PVOID                  Argument OPTIONAL,           \
                        OUT PXENBUS_DEBUG_CALLBACK *Callback                    \
                        )                                                       \
                        )                                                       \
        DEBUG_OPERATION(VOID,                                                   \
                        Printf,                                                 \
                        (                                                       \
                        IN  PXENBUS_DEBUG_CONTEXT  Context,                     \
                        IN  PXENBUS_DEBUG_CALLBACK Callback,                    \
                        IN  const CHAR             *Format,                     \
                        ...                                                     \
                        )                                                       \
                        )                                                       \
        DEBUG_OPERATION(VOID,                                                   \
                        Deregister,                                             \
                        (                                                       \
                        IN  PXENBUS_DEBUG_CONTEXT  Context,                     \
                        IN  PXENBUS_DEBUG_CALLBACK Callback                     \
                        )                                                       \
                        )

typedef struct _XENBUS_DEBUG_CONTEXT    XENBUS_DEBUG_CONTEXT, *PXENBUS_DEBUG_CONTEXT;

#define DEBUG_OPERATION(_Type, _Name, _Arguments) \
        _Type (*DEBUG_ ## _Name) _Arguments;

typedef struct _XENBUS_DEBUG_OPERATIONS {
    DEFINE_DEBUG_OPERATIONS
} XENBUS_DEBUG_OPERATIONS, *PXENBUS_DEBUG_OPERATIONS;

#undef DEBUG_OPERATION

typedef struct _XENBUS_DEBUG_INTERFACE   XENBUS_DEBUG_INTERFACE, *PXENBUS_DEBUG_INTERFACE;

// {54AAE52C-1838-49d3-AA43-9DDDD891603B}
DEFINE_GUID(GUID_DEBUG_INTERFACE, 
            0x54aae52c,
            0x1838,
            0x49d3,
            0xaa,
            0x43,
            0x9d,
            0xdd,
            0xd8,
            0x91,
            0x60,
            0x3b);

#define DEBUG_INTERFACE_VERSION    4

#define DEBUG_OPERATIONS(_Interface) \
        (PXENBUS_DEBUG_OPERATIONS *)((ULONG_PTR)(_Interface))

#define DEBUG_CONTEXT(_Interface) \
        (PXENBUS_DEBUG_CONTEXT *)((ULONG_PTR)(_Interface) + sizeof (PVOID))

#define DEBUG(_Operation, _Interface, ...) \
        (*DEBUG_OPERATIONS(_Interface))->DEBUG_ ## _Operation((*DEBUG_CONTEXT(_Interface)), __VA_ARGS__)

#endif  // _XENBUS_DEBUG_INTERFACE_H

