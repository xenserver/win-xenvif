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

#ifndef _XENVIF_FRONTEND_H
#define _XENVIF_FRONTEND_H

#include <ntddk.h>
#include <evtchn_interface.h>
#include <debug_interface.h>
#include <store_interface.h>
#include <gnttab_interface.h>
#include <vif_interface.h>

#include "pdo.h"
#include "ethernet.h"

typedef struct _XENVIF_FRONTEND XENVIF_FRONTEND, *PXENVIF_FRONTEND;

typedef enum _XENVIF_FRONTEND_STATE {
    FRONTEND_STATE_INVALID,
    FRONTEND_CLOSED,
    FRONTEND_PREPARED,
    FRONTEND_CONNECTED,
    FRONTEND_ENABLED
} XENVIF_FRONTEND_STATE, *PXENVIF_FRONTEND_STATE;

extern NTSTATUS
FrontendInitialize(
    IN  PXENVIF_PDO         Pdo,
    OUT PXENVIF_FRONTEND    *Frontend
    );

extern VOID
FrontendTeardown(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern VOID
FrontendRemoveFailed(
    IN PXENVIF_FRONTEND Frontend
    );

extern NTSTATUS
FrontendSetState(
    IN  PXENVIF_FRONTEND        Frontend,
    IN  XENVIF_FRONTEND_STATE   State
    );

extern NTSTATUS
FrontendResume(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern VOID
FrontendSuspend(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PETHERNET_ADDRESS
FrontendGetPermanentMacAddress(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PETHERNET_ADDRESS
FrontendGetCurrentMacAddress(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PCHAR
FrontendGetPrefix(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PCHAR
FrontendGetPath(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PCHAR
FrontendGetBackendPath(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern USHORT
FrontendGetBackendDomain(
    IN  PXENVIF_FRONTEND    Frontend
    );

#include "notifier.h"

extern PXENVIF_NOTIFIER
FrontendGetNotifier(
    IN  PXENVIF_FRONTEND    Frontend
    );

#include "mac.h"

extern PXENVIF_MAC
FrontendGetMac(
    IN  PXENVIF_FRONTEND    Frontend
    );

#include "receiver.h"

extern PXENVIF_RECEIVER
FrontendGetReceiver(
    IN  PXENVIF_FRONTEND    Frontend
    );

#include "transmitter.h"

extern PXENVIF_TRANSMITTER
FrontendGetTransmitter(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PXENBUS_EVTCHN_INTERFACE
FrontendGetEvtchnInterface(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PXENBUS_DEBUG_INTERFACE
FrontendGetDebugInterface(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PXENBUS_SUSPEND_INTERFACE
FrontendGetSuspendInterface(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PXENBUS_STORE_INTERFACE
FrontendGetStoreInterface(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PXENBUS_GNTTAB_INTERFACE
FrontendGetGnttabInterface(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PXENVIF_VIF_INTERFACE
FrontendGetVifInterface(
    IN  PXENVIF_FRONTEND    Frontend
    );

extern PCHAR
FrontendGetAddress(
    IN  PXENVIF_FRONTEND    Frontend
    );

#endif  // _XENVIF_FRONTEND_H
