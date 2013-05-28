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

#ifndef _XENVIF_NOTIFIER_H
#define _XENVIF_NOTIFIER_H

#include <ntddk.h>
#include <store_interface.h>

#include "frontend.h"

typedef struct _XENVIF_NOTIFIER XENVIF_NOTIFIER, *PXENVIF_NOTIFIER;

extern NTSTATUS
NotifierInitialize(
    IN  PXENVIF_FRONTEND    Frontend,
    OUT PXENVIF_NOTIFIER    *Notifier
    );

extern NTSTATUS
NotifierConnect(
    IN  PXENVIF_NOTIFIER    Notifier
    );

extern NTSTATUS
NotifierStoreWrite(
    IN  PXENVIF_NOTIFIER            Notifier,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    );

extern NTSTATUS
NotifierEnable(
    IN  PXENVIF_NOTIFIER    Notifier
    );

extern VOID
NotifierDisable(
    IN  PXENVIF_NOTIFIER    Notifier
    );

extern VOID
NotifierDisconnect(
    IN  PXENVIF_NOTIFIER    Notifier
    );

extern VOID
NotifierTeardown(
    IN  PXENVIF_NOTIFIER    Notifier
    );

extern VOID
NotifierSend(
    IN  PXENVIF_NOTIFIER    Notifier
    );

extern VOID
NotifierTrigger(
    IN  PXENVIF_NOTIFIER    Notifier
    );

#endif  // _XENVIF_NOTIFIER_H
