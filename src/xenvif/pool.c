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
#include <ntstrsafe.h>
#include <util.h>

#include "pool.h"
#include "dbg_print.h"
#include "assert.h"

#define POOL_POOL   'OBJE'

typedef struct _OBJECT_HEADER {
    ULONG       Magic;

#define OBJECT_HEADER_MAGIC 0x02121996

    LIST_ENTRY  ListEntry;
} OBJECT_HEADER, *POBJECT_HEADER;

#define MAXIMUM_SLOTS   6

typedef struct _POOL_MAGAZINE {
    PVOID   Slot[MAXIMUM_SLOTS];
} POOL_MAGAZINE, *PPOOL_MAGAZINE;

struct _XENVIF_POOL {
    const CHAR      *Name;
    ULONG           Size;
    NTSTATUS        (*Ctor)(PVOID, PVOID);
    VOID            (*Dtor)(PVOID, PVOID);
    VOID            (*AcquireLock)(PVOID);
    VOID            (*ReleaseLock)(PVOID);
    PVOID           Argument;
    KTIMER          Timer;
    KDPC            Dpc;
    LIST_ENTRY      GetList;
    PLIST_ENTRY     PutList;
    POOL_MAGAZINE   Magazine[MAXIMUM_PROCESSORS];
    LONG            Allocated;
    LONG            MaximumAllocated;
    LONG            Count;
    LONG            MinimumCount;
};

static FORCEINLINE PVOID
__PoolAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, POOL_POOL);
}

static FORCEINLINE VOID
__PoolFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, POOL_POOL);
}

static FORCEINLINE VOID
__PoolSwizzle(
    IN  PXENVIF_POOL    Pool
    )
{
    PLIST_ENTRY         ListEntry;

    ListEntry = InterlockedExchangePointer(&Pool->PutList, NULL);

    while (ListEntry != NULL) {
        PLIST_ENTRY Next;

        Next = ListEntry->Flink;
        ListEntry->Flink = NULL;
        ASSERT3P(ListEntry->Blink, ==, NULL);

        InsertTailList(&Pool->GetList, ListEntry);

        ListEntry = Next;
    }
}

static FORCEINLINE PVOID
__PoolGetShared(
    IN  PXENVIF_POOL    Pool,
    IN  BOOLEAN         Locked
    )
{
    LONG                Count;
    POBJECT_HEADER      Header;
    PVOID               Object;
    LONG                Allocated;
    NTSTATUS            status;

    Count = InterlockedDecrement(&Pool->Count);

    if (Count >= 0) {
        PLIST_ENTRY     ListEntry;

        if (!Locked)
            Pool->AcquireLock(Pool->Argument);

        if (Count < Pool->MinimumCount)
            Pool->MinimumCount = Count;

        if (IsListEmpty(&Pool->GetList))
            __PoolSwizzle(Pool);

        ListEntry = RemoveHeadList(&Pool->GetList);
        ASSERT(ListEntry != &Pool->GetList);

        if (!Locked)
            Pool->ReleaseLock(Pool->Argument);

        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Header = CONTAINING_RECORD(ListEntry, OBJECT_HEADER, ListEntry);
        ASSERT3U(Header->Magic, ==, OBJECT_HEADER_MAGIC);

        Object = Header + 1;
        goto done;
    }

    (VOID) InterlockedIncrement(&Pool->Count);

    Header = __PoolAllocate(sizeof (OBJECT_HEADER) + Pool->Size);

    status = STATUS_NO_MEMORY;
    if (Header == NULL)
        goto fail1;

    Header->Magic = OBJECT_HEADER_MAGIC;

    Object = Header + 1;

    status = Pool->Ctor(Pool->Argument, Object);
    if (!NT_SUCCESS(status))
        goto fail2;

    Allocated = InterlockedIncrement(&Pool->Allocated);

    if (Allocated > Pool->MaximumAllocated) {
        if (!Locked)
            Pool->AcquireLock(Pool->Argument);

        if (Allocated > Pool->MaximumAllocated)
            Pool->MaximumAllocated = Allocated;

        if (!Locked)
            Pool->ReleaseLock(Pool->Argument);
    }

done:
    return Object;

fail2:
    Error("fail2\n");

    Header->Magic = 0;

    ASSERT(IsZeroMemory(Header, sizeof (OBJECT_HEADER)));
    __PoolFree(Header);

fail1:
    Error("fail1 (%08x)\n", status);

    return NULL;    
}

static FORCEINLINE VOID
__PoolPutShared(
    IN  PXENVIF_POOL    Pool,
    IN  PVOID           Object,
    IN  BOOLEAN         Locked
    )
{
    POBJECT_HEADER      Header;
    PLIST_ENTRY         Old;
    PLIST_ENTRY         New;

    ASSERT(Object != NULL);

    Header = Object;
    --Header;
    ASSERT3U(Header->Magic, ==, OBJECT_HEADER_MAGIC);

    ASSERT(IsZeroMemory(&Header->ListEntry, sizeof (LIST_ENTRY)));

    if (!Locked) {
        New = &Header->ListEntry;

        do {
            Old = Pool->PutList;
            New->Flink = Old;
        } while (InterlockedCompareExchangePointer(&Pool->PutList, New, Old) != Old);
    } else {
        InsertTailList(&Pool->GetList, &Header->ListEntry);
    }

    KeMemoryBarrier();

    (VOID) InterlockedIncrement(&Pool->Count);
}

static FORCEINLINE PVOID
__PoolGetMagazine(
    IN  PXENVIF_POOL    Pool,
    IN  ULONG           Cpu
    )
{
    PPOOL_MAGAZINE      Magazine;
    ULONG               Index;

    Magazine = &Pool->Magazine[Cpu];

    for (Index = 0; Index < MAXIMUM_SLOTS; Index++) {
        PVOID   Object;

        if (Magazine->Slot[Index] != NULL) {
            Object = Magazine->Slot[Index];
            Magazine->Slot[Index] = NULL;

            return Object;
        }
    }

    return NULL;
}

static FORCEINLINE BOOLEAN
__PoolPutMagazine(
    IN  PXENVIF_POOL    Pool,
    IN  ULONG           Cpu,
    IN  PVOID           Object
    )
{
    PPOOL_MAGAZINE      Magazine;
    ULONG               Index;

    Magazine = &Pool->Magazine[Cpu];

    for (Index = 0; Index < MAXIMUM_SLOTS; Index++) {
        if (Magazine->Slot[Index] == NULL) {
            Magazine->Slot[Index] = Object;
            return TRUE;
        }
    }

    return FALSE;
}

PVOID
PoolGet(
    IN  PXENVIF_POOL    Pool,
    IN  BOOLEAN         Locked
    )
{
    KIRQL               Irql;
    ULONG               Cpu;
    PVOID               Object;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    Cpu = KeGetCurrentProcessorNumber();

    Object = __PoolGetMagazine(Pool, Cpu);
    if (Object == NULL)
        Object = __PoolGetShared(Pool, Locked);

    KeLowerIrql(Irql);

    return Object;
}

VOID
PoolPut(
    IN  PXENVIF_POOL    Pool,
    IN  PVOID           Object,
    IN  BOOLEAN         Locked
    )
{
    KIRQL               Irql;
    ULONG               Cpu;

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    Cpu = KeGetCurrentProcessorNumber();

    if (!__PoolPutMagazine(Pool, Cpu, Object))
        __PoolPutShared(Pool, Object, Locked);

    KeLowerIrql(Irql);
}

VOID
PoolGetStatistics(
    IN  PXENVIF_POOL    Pool,
    OUT PULONG          Allocated,
    OUT PULONG          MaximumAllocated,
    OUT PULONG          Count,
    OUT PULONG          MinimumCount
    )
{
    *Allocated = Pool->Allocated;
    *MaximumAllocated = Pool->MaximumAllocated;

    *Count = Pool->Count;
    *MinimumCount = Pool->MinimumCount;
}

static FORCEINLINE
__PoolFlushMagazines(
    IN  PXENVIF_POOL    Pool
    )
{
    ULONG               Cpu;

    for (Cpu = 0; Cpu < MAXIMUM_PROCESSORS; Cpu++) {
        PVOID   Object;

        while ((Object = __PoolGetMagazine(Pool, Cpu)) != NULL)
            __PoolPutShared(Pool, Object, TRUE);
    }
}

static FORCEINLINE VOID
__PoolTrimShared(
    IN      PXENVIF_POOL    Pool,
    IN OUT  PLIST_ENTRY     List
    )
{
    LONG                    Count;
    LONG                    Excess;

    Count = Pool->Count;

    KeMemoryBarrier();

    Excess = Pool->MinimumCount;

    while (Excess != 0) {
        PLIST_ENTRY     ListEntry;

        Count = InterlockedDecrement(&Pool->Count);
        if (Count < 0) {
            Count = InterlockedIncrement(&Pool->Count);
            break;
        }

        if (IsListEmpty(&Pool->GetList))
            __PoolSwizzle(Pool);

        ListEntry = RemoveHeadList(&Pool->GetList);
        ASSERT(ListEntry != &Pool->GetList);

        InsertTailList(List, ListEntry);

        InterlockedDecrement(&Pool->Allocated);
        --Excess;
    }

    Pool->MinimumCount = Count;
}

static FORCEINLINE VOID
__PoolEmpty(
    IN      PXENVIF_POOL    Pool,
    IN OUT  PLIST_ENTRY     List
    )
{
    while (!IsListEmpty(List)) {
        PLIST_ENTRY     ListEntry;
        POBJECT_HEADER  Header;
        PVOID           Object;

        ListEntry = RemoveHeadList(List);
        RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

        Header = CONTAINING_RECORD(ListEntry, OBJECT_HEADER, ListEntry);
        ASSERT3U(Header->Magic, ==, OBJECT_HEADER_MAGIC);

        Object = Header + 1;

        Pool->Dtor(Pool->Argument, Object);

        Header->Magic = 0;

        ASSERT(IsZeroMemory(Header, sizeof (OBJECT_HEADER)));
        __PoolFree(Header);
    }
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

#define POOL_PERIOD  1000

KDEFERRED_ROUTINE   PoolDpc;

VOID
PoolDpc(
    IN  PKDPC       Dpc,
    IN  PVOID       Context,
    IN  PVOID       Argument1,
    IN  PVOID       Argument2
    )
{
    PXENVIF_POOL    Pool = Context;
    LIST_ENTRY      List;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

    ASSERT(Pool != NULL);

    InitializeListHead(&List);

    Pool->AcquireLock(Pool->Argument);
    __PoolTrimShared(Pool, &List);
    Pool->ReleaseLock(Pool->Argument);

    __PoolEmpty(Pool, &List);
    ASSERT(IsListEmpty(&List));
}

NTSTATUS
PoolInitialize(
    IN  const CHAR      *Name,
    IN  ULONG           Size,
    IN  NTSTATUS        (*Ctor)(PVOID, PVOID),
    IN  VOID            (*Dtor)(PVOID, PVOID),
    IN  VOID            (*AcquireLock)(PVOID),
    IN  VOID            (*ReleaseLock)(PVOID),
    IN  PVOID           Argument,
    OUT PXENVIF_POOL    *Pool
    )
{
    LARGE_INTEGER       Timeout;
    NTSTATUS            status;

    *Pool = __PoolAllocate(sizeof (XENVIF_POOL));

    status = STATUS_NO_MEMORY;
    if (*Pool == NULL)
        goto fail1;

    (*Pool)->Name = Name;
    (*Pool)->Size = Size;
    (*Pool)->Ctor = Ctor;
    (*Pool)->Dtor = Dtor;
    (*Pool)->AcquireLock = AcquireLock;
    (*Pool)->ReleaseLock = ReleaseLock;
    (*Pool)->Argument = Argument;

    InitializeListHead(&(*Pool)->GetList);

    KeInitializeDpc(&(*Pool)->Dpc,
                    PoolDpc,
                    (*Pool));

    Timeout.QuadPart = TIME_RELATIVE(TIME_MS(POOL_PERIOD));

    KeInitializeTimer(&(*Pool)->Timer);
    KeSetTimerEx(&(*Pool)->Timer,
                 Timeout,
                 POOL_PERIOD,
                 &(*Pool)->Dpc);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    return status;    
}

VOID
PoolTeardown(
    IN  PXENVIF_POOL    Pool
    )
{
    LIST_ENTRY          List;

    KeCancelTimer(&Pool->Timer);
    KeFlushQueuedDpcs();

    RtlZeroMemory(&Pool->Timer, sizeof (KTIMER));
    RtlZeroMemory(&Pool->Dpc, sizeof (KDPC));

    InitializeListHead(&List);

    __PoolFlushMagazines(Pool);

    Pool->MinimumCount = Pool->Count;
    __PoolTrimShared(Pool, &List);
    __PoolEmpty(Pool, &List);

    ASSERT3U(Pool->Count, ==, 0);
    ASSERT3U(Pool->Allocated, ==, 0);
    Pool->MaximumAllocated = 0;

    RtlZeroMemory(&Pool->GetList, sizeof (LIST_ENTRY));

    Pool->Argument = NULL;
    Pool->ReleaseLock = NULL;
    Pool->AcquireLock = NULL;
    Pool->Dtor = NULL;
    Pool->Ctor = NULL;
    Pool->Size = 0;
    Pool->Name = NULL;

    ASSERT(IsZeroMemory(Pool, sizeof (XENVIF_POOL)));
    __PoolFree(Pool);
}
