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

#ifndef _XENFILT_EMULATED_INTERFACE_H
#define _XENFILT_EMULATED_INTERFACE_H

#define DEFINE_EMULATED_OPERATIONS                                      \
        EMULATED_OPERATION(VOID,                                        \
                           Acquire,                                     \
                           (                                            \
                           IN  PXENFILT_EMULATED_CONTEXT Context        \
                           )                                            \
                           )                                            \
        EMULATED_OPERATION(VOID,                                        \
                           Release,                                     \
                           (                                            \
                           IN  PXENFILT_EMULATED_CONTEXT Context        \
                           )                                            \
                           )                                            \
        EMULATED_OPERATION(BOOLEAN,                                     \
                           IsDevicePresent,                             \
                           (                                            \
                           IN  PXENFILT_EMULATED_CONTEXT Context,       \
                           IN  PCHAR                     DeviceID,      \
                           IN  PCHAR                     InstanceID     \
                           )                                            \
                           )                                            \
        EMULATED_OPERATION(BOOLEAN,                                     \
                           IsDiskPresent,                               \
                           (                                            \
                           IN  PXENFILT_EMULATED_CONTEXT Context,       \
                           IN  ULONG                     Controller,    \
                           IN  ULONG                     Target,        \
                           IN  ULONG                     Lun            \
                           )                                            \
                           )

typedef struct _XENFILT_EMULATED_CONTEXT    XENFILT_EMULATED_CONTEXT, *PXENFILT_EMULATED_CONTEXT;

#define EMULATED_OPERATION(_Type, _Name, _Arguments) \
        _Type (*EMULATED_ ## _Name) _Arguments;

typedef struct _XENFILT_EMULATED_OPERATIONS {
    DEFINE_EMULATED_OPERATIONS
} XENFILT_EMULATED_OPERATIONS, *PXENFILT_EMULATED_OPERATIONS;

#undef EMULATED_OPERATION

typedef struct _XENFILT_EMULATED_INTERFACE   XENFILT_EMULATED_INTERFACE, *PXENFILT_EMULATED_INTERFACE;

// {062AAC96-2BF8-4A69-AD6B-154CF051E977}
DEFINE_GUID(GUID_EMULATED_INTERFACE, 
            0x62aac96,
            0x2bf8,
            0x4a69,
            0xad,
            0x6b,
            0x15,
            0x4c,
            0xf0,
            0x51,
            0xe9,
            0x77);

#define EMULATED_INTERFACE_VERSION    4

#define EMULATED_OPERATIONS(_Interface) \
        (PXENFILT_EMULATED_OPERATIONS *)((ULONG_PTR)(_Interface))

#define EMULATED_CONTEXT(_Interface) \
        (PXENFILT_EMULATED_CONTEXT *)((ULONG_PTR)(_Interface) + sizeof (PVOID))

#define EMULATED(_Operation, _Interface, ...) \
        (*EMULATED_OPERATIONS(_Interface))->EMULATED_ ## _Operation((*EMULATED_CONTEXT(_Interface)), __VA_ARGS__)

#endif  // _XENFILT_EMULATED_INTERFACE_H

