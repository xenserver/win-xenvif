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

#ifndef _XENBUS_EVTCHN_INTERFACE_H
#define _XENBUS_EVTCHN_INTERFACE_H

typedef enum _XENBUS_EVTCHN_TYPE {
    EVTCHN_TYPE_INVALID = 0,
    EVTCHN_FIXED,
    EVTCHN_UNBOUND,
    EVTCHN_INTER_DOMAIN,
    EVTCHN_VIRQ
} XENBUS_EVTCHN_TYPE, *PXENBUS_EVTCHN_TYPE;

typedef struct _XENBUS_EVTCHN_DESCRIPTOR    XENBUS_EVTCHN_DESCRIPTOR, *PXENBUS_EVTCHN_DESCRIPTOR;

#define PORT_INVALID  0xFFFFFFFF

#define DEFINE_EVTCHN_OPERATIONS                                                    \
        EVTCHN_OPERATION(VOID,                                                      \
                         Acquire,                                                   \
                         (                                                          \
                         IN PXENBUS_EVTCHN_CONTEXT    Context                       \
                         )                                                          \
                         )                                                          \
        EVTCHN_OPERATION(VOID,                                                      \
                         Release,                                                   \
                         (                                                          \
                         IN PXENBUS_EVTCHN_CONTEXT    Context                       \
                         )                                                          \
                         )                                                          \
        EVTCHN_OPERATION(PXENBUS_EVTCHN_DESCRIPTOR,                                 \
                         Open,                                                      \
                         (                                                          \
                         IN PXENBUS_EVTCHN_CONTEXT  Context,                        \
                         IN XENBUS_EVTCHN_TYPE      Type,                           \
                         IN PKSERVICE_ROUTINE       Function,                       \
                         IN PVOID                   Argument OPTIONAL,              \
                         ...                                                        \
                         )                                                          \
                         )                                                          \
        EVTCHN_OPERATION(BOOLEAN,                                                   \
                         Unmask,                                                    \
                         (                                                          \
                         IN PXENBUS_EVTCHN_CONTEXT    Context,                      \
                         IN PXENBUS_EVTCHN_DESCRIPTOR Descriptor,                   \
                         IN BOOLEAN                   Locked                        \
                         )                                                          \
                         )                                                          \
        EVTCHN_OPERATION(NTSTATUS,                                                  \
                         Send,                                                      \
                         (                                                          \
                         IN PXENBUS_EVTCHN_CONTEXT    Context,                      \
                         IN PXENBUS_EVTCHN_DESCRIPTOR Descriptor                    \
                         )                                                          \
                         )                                                          \
        EVTCHN_OPERATION(BOOLEAN,                                                   \
                         Trigger,                                                   \
                         (                                                          \
                         IN PXENBUS_EVTCHN_CONTEXT    Context,                      \
                         IN PXENBUS_EVTCHN_DESCRIPTOR Descriptor                    \
                         )                                                          \
                         )                                                          \
        EVTCHN_OPERATION(VOID,                                                      \
                         Close,                                                     \
                         (                                                          \
                         IN PXENBUS_EVTCHN_CONTEXT    Context,                      \
                         IN PXENBUS_EVTCHN_DESCRIPTOR Descriptor                    \
                         )                                                          \
                         )                                                          \
        EVTCHN_OPERATION(ULONG,                                                     \
                         Port,                                                      \
                         (                                                          \
                         IN PXENBUS_EVTCHN_CONTEXT    Context,                      \
                         IN PXENBUS_EVTCHN_DESCRIPTOR Descriptor                    \
                         )                                                          \
                         )

typedef struct _XENBUS_EVTCHN_CONTEXT   XENBUS_EVTCHN_CONTEXT, *PXENBUS_EVTCHN_CONTEXT;

#define EVTCHN_OPERATION(_Type, _Name, _Arguments) \
        _Type (*EVTCHN_ ## _Name) _Arguments;

typedef struct _XENBUS_EVTCHN_OPERATIONS {
    DEFINE_EVTCHN_OPERATIONS
} XENBUS_EVTCHN_OPERATIONS, *PXENBUS_EVTCHN_OPERATIONS;

#undef EVTCHN_OPERATION

typedef struct _XENBUS_EVTCHN_INTERFACE  XENBUS_EVTCHN_INTERFACE, *PXENBUS_EVTCHN_INTERFACE;

// {F87E8751-D6FB-44e8-85E3-DAC19FFA17A6}
DEFINE_GUID(GUID_EVTCHN_INTERFACE, 
            0xf87e8751,
            0xd6fb,
            0x44e8,
            0x85,
            0xe3,
            0xda,
            0xc1,
            0x9f,
            0xfa,
            0x17,
            0xa6);

#define EVTCHN_INTERFACE_VERSION    4

#define EVTCHN_OPERATIONS(_Interface) \
        (PXENBUS_EVTCHN_OPERATIONS *)((ULONG_PTR)(_Interface))

#define EVTCHN_CONTEXT(_Interface) \
        (PXENBUS_EVTCHN_CONTEXT *)((ULONG_PTR)(_Interface) + sizeof (PVOID))

#define EVTCHN(_Operation, _Interface, ...) \
        (*EVTCHN_OPERATIONS(_Interface))->EVTCHN_ ## _Operation((*EVTCHN_CONTEXT(_Interface)), __VA_ARGS__)

#endif  // _XENBUS_EVTCHN_INTERFACE_H

