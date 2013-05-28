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

#ifndef _XENBUS_SUSPEND_INTERFACE_H
#define _XENBUS_SUSPEND_INTERFACE_H

typedef enum _XENBUS_SUSPEND_CALLBACK_TYPE {
    SUSPEND_CALLBACK_TYPE_INVALID = 0,
    SUSPEND_CALLBACK_EARLY,
    SUSPEND_CALLBACK_LATE
} XENBUS_SUSPEND_CALLBACK_TYPE, *PXENBUS_SUSPEND_CALLBACK_TYPE;

typedef struct _XENBUS_SUSPEND_CALLBACK   XENBUS_SUSPEND_CALLBACK, *PXENBUS_SUSPEND_CALLBACK;

#define DEFINE_SUSPEND_OPERATIONS                                                   \
        SUSPEND_OPERATION(VOID,                                                     \
                          Acquire,                                                  \
                          (                                                         \
                          IN  PXENBUS_SUSPEND_CONTEXT  Context                      \
                          )                                                         \
                          )                                                         \
        SUSPEND_OPERATION(VOID,                                                     \
                          Release,                                                  \
                          (                                                         \
                          IN  PXENBUS_SUSPEND_CONTEXT  Context                      \
                          )                                                         \
                          )                                                         \
        SUSPEND_OPERATION(NTSTATUS,                                                 \
                          Register,                                                 \
                          (                                                         \
                          IN  PXENBUS_SUSPEND_CONTEXT      Context,                 \
                          IN  XENBUS_SUSPEND_CALLBACK_TYPE Type,                    \
                          IN  VOID                         (*Function)(PVOID),      \
                          IN  PVOID                        Argument OPTIONAL,       \
                          OUT PXENBUS_SUSPEND_CALLBACK     *Callback                \
                          )                                                         \
                          )                                                         \
        SUSPEND_OPERATION(VOID,                                                     \
                          Deregister,                                               \
                          (                                                         \
                          IN  PXENBUS_SUSPEND_CONTEXT  Context,                     \
                          IN  PXENBUS_SUSPEND_CALLBACK Callback                     \
                          )                                                         \
                          )                                                         \
        SUSPEND_OPERATION(ULONG,                                                    \
                          Count,                                                    \
                          (                                                         \
                          IN  PXENBUS_SUSPEND_CONTEXT  Context                      \
                          )                                                         \
                          )

typedef struct _XENBUS_SUSPEND_CONTEXT  XENBUS_SUSPEND_CONTEXT, *PXENBUS_SUSPEND_CONTEXT;

#define SUSPEND_OPERATION(_Type, _Name, _Arguments) \
        _Type (*SUSPEND_ ## _Name) _Arguments;

typedef struct _XENBUS_SUSPEND_OPERATIONS {
    DEFINE_SUSPEND_OPERATIONS
} XENBUS_SUSPEND_OPERATIONS, *PXENBUS_SUSPEND_OPERATIONS;

#undef SUSPEND_OPERATION

typedef struct _XENBUS_SUSPEND_INTERFACE XENBUS_SUSPEND_INTERFACE, *PXENBUS_SUSPEND_INTERFACE;

// 104f0a14-e2d5-42b6-b10f-a669ccd410a1

DEFINE_GUID(GUID_SUSPEND_INTERFACE, 
            0x104f0a14,
            0xe2d5,
            0x42b6,
            0xb1,
            0x0f,
            0xa6,
            0x69,
            0xcc,
            0xd4,
            0x10,
            0xa1);

#define SUSPEND_INTERFACE_VERSION   2

#define SUSPEND_OPERATIONS(_Interface) \
        (PXENBUS_SUSPEND_OPERATIONS *)((ULONG_PTR)(_Interface))

#define SUSPEND_CONTEXT(_Interface) \
        (PXENBUS_SUSPEND_CONTEXT *)((ULONG_PTR)(_Interface) + sizeof (PVOID))

#define SUSPEND(_Operation, _Interface, ...) \
        (*SUSPEND_OPERATIONS(_Interface))->SUSPEND_ ## _Operation((*SUSPEND_CONTEXT(_Interface)), __VA_ARGS__)

#endif  // _XENBUS_SUSPEND_INTERFACE_H

