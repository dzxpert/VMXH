/*
 * hv_hook.c - VMX Anti-Anti-Debug Hypervisor
 * Universal EPT/NPT Hook Framework - Core Implementation
 *
 * Dynamic thunk allocation, hook install/remove, decision logic, event logging.
 */

#include "hv_hook.h"
#include "hv_ops.h"
#include "vmx.h"
#include "log.h"
#include <ntstrsafe.h>

/* ========================================================================= */
/*  Globals                                                                  */
/* ========================================================================= */

GENERIC_HOOK_STATE g_GenericHookState = { 0 };

/* ========================================================================= */
/*  Thunk Stub Generation                                                    */
/* ========================================================================= */

static VOID BuildThunkStub(PUCHAR Base, ULONG HookId, ULONG64 DispatcherAddr)
{
    /* mov r10, imm64  (10 bytes: 49 BA + 8-byte immediate) */
    Base[0] = 0x49;
    Base[1] = 0xBA;
    *(PULONG64)(Base + 2) = (ULONG64)HookId;

    /* jmp [rip+0]  (6 bytes: FF 25 00000000) */
    Base[10] = 0xFF;
    Base[11] = 0x25;
    *(PULONG)(Base + 12) = 0;

    /* absolute 8-byte target address */
    *(PULONG64)(Base + 16) = DispatcherAddr;
}

/* ========================================================================= */
/*  Thunk Page Management (dynamic)                                          */
/* ========================================================================= */

static PTHUNK_PAGE AllocateThunkPage(ULONG BaseId)
{
    PTHUNK_PAGE Page;

    Page = (PTHUNK_PAGE)ExAllocatePoolWithTag(NonPagedPool, sizeof(THUNK_PAGE), VMX_TAG);
    if (!Page) return NULL;

    RtlZeroMemory(Page, sizeof(THUNK_PAGE));

    /* NonPagedPool is executable on WDK 7600 target */
    Page->CodeBase = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, VMX_TAG);
    if (!Page->CodeBase) {
        ExFreePoolWithTag(Page, VMX_TAG);
        return NULL;
    }

    RtlZeroMemory(Page->CodeBase, PAGE_SIZE);
    Page->Capacity = THUNKS_PER_PAGE;
    Page->UsedCount = 0;
    Page->BaseId = BaseId;
    Page->Next = NULL;

    return Page;
}

static VOID FreeThunkPage(PTHUNK_PAGE Page)
{
    if (Page) {
        if (Page->CodeBase) {
            ExFreePoolWithTag(Page->CodeBase, VMX_TAG);
        }
        ExFreePoolWithTag(Page, VMX_TAG);
    }
}

/*
 * Allocate a thunk slot. If all existing pages are full, allocate a new page.
 * Returns the thunk code address and writes the HookId into the thunk.
 */
static PVOID AllocateThunk(ULONG HookId)
{
    PTHUNK_PAGE Page;
    PUCHAR      ThunkAddr;

    /* Search existing pages for a free slot */
    Page = g_GenericHookState.ThunkPageHead;
    while (Page) {
        if (Page->UsedCount < Page->Capacity) {
            ThunkAddr = (PUCHAR)Page->CodeBase + (Page->UsedCount * THUNK_STUB_SIZE);
            BuildThunkStub(ThunkAddr, HookId, (ULONG64)AsmGenericHookDispatcher);
            Page->UsedCount++;
            return ThunkAddr;
        }
        Page = Page->Next;
    }

    /* All pages full, allocate a new one */
    Page = AllocateThunkPage(HookId);
    if (!Page) return NULL;

    /* Link to head */
    Page->Next = g_GenericHookState.ThunkPageHead;
    g_GenericHookState.ThunkPageHead = Page;
    g_GenericHookState.ThunkPageCount++;

    ThunkAddr = (PUCHAR)Page->CodeBase;
    BuildThunkStub(ThunkAddr, HookId, (ULONG64)AsmGenericHookDispatcher);
    Page->UsedCount++;

    return ThunkAddr;
}

/* ========================================================================= */
/*  Hook Entry Lookup                                                        */
/* ========================================================================= */

static PGENERIC_HOOK_ENTRY FindHookById(ULONG HookId)
{
    PGENERIC_HOOK_ENTRY Entry = g_GenericHookState.HookListHead;
    while (Entry) {
        if (Entry->Active && Entry->HookId == HookId) {
            return Entry;
        }
        Entry = Entry->Next;
    }
    return NULL;
}

static PGENERIC_HOOK_ENTRY FindHookByAddress(ULONG64 TargetVa)
{
    PGENERIC_HOOK_ENTRY Entry = g_GenericHookState.HookListHead;
    while (Entry) {
        if (Entry->Active && Entry->TargetVirtualAddress == TargetVa) {
            return Entry;
        }
        Entry = Entry->Next;
    }
    return NULL;
}

/* ========================================================================= */
/*  Initialization / Cleanup                                                 */
/* ========================================================================= */

NTSTATUS GenericHookInit(VOID)
{
    RtlZeroMemory(&g_GenericHookState, sizeof(GENERIC_HOOK_STATE));
    KeInitializeSpinLock(&g_GenericHookState.Lock);
    KeInitializeSpinLock(&g_GenericHookState.EventLock);

    g_GenericHookState.HookListHead = NULL;
    g_GenericHookState.ThunkPageHead = NULL;
    g_GenericHookState.NextHookId = 1;  /* IDs start from 1 */
    g_GenericHookState.Initialized = TRUE;

    LOG_INFO("Generic hook framework initialized (dynamic thunks, unlimited hooks)");
    return STATUS_SUCCESS;
}

VOID GenericHookCleanup(VOID)
{
    PGENERIC_HOOK_ENTRY Entry, Next;
    PTHUNK_PAGE Page, NextPage;

    if (!g_GenericHookState.Initialized) return;

    /* Remove all hooks */
    GenericHookRemoveAll();

    /* Free all hook entries */
    Entry = g_GenericHookState.HookListHead;
    while (Entry) {
        Next = Entry->Next;
        ExFreePoolWithTag(Entry, VMX_TAG);
        Entry = Next;
    }

    /* Free all thunk pages */
    Page = g_GenericHookState.ThunkPageHead;
    while (Page) {
        NextPage = Page->Next;
        FreeThunkPage(Page);
        Page = NextPage;
    }

    g_GenericHookState.HookListHead = NULL;
    g_GenericHookState.ThunkPageHead = NULL;
    g_GenericHookState.Initialized = FALSE;

    LOG_INFO("Generic hook framework cleaned up");
}

/* ========================================================================= */
/*  Hook Install                                                             */
/* ========================================================================= */

NTSTATUS GenericHookInstall(
    ULONG64     TargetVa,
    ULONG       ProcessId,
    const WCHAR *FunctionName,
    PHOOK_RULE  Rule,
    PULONG      OutHookId
)
{
    KIRQL               OldIrql;
    PGENERIC_HOOK_ENTRY Hook;
    PVOID               ThunkAddr;
    PVOID               Trampoline = NULL;
    NTSTATUS            Status;
    ULONG               HookId;

    if (!g_GenericHookState.Initialized) return STATUS_UNSUCCESSFUL;

    KeAcquireSpinLock(&g_GenericHookState.Lock, &OldIrql);

    /* Check duplicate */
    if (FindHookByAddress(TargetVa)) {
        KeReleaseSpinLock(&g_GenericHookState.Lock, OldIrql);
        return STATUS_ALREADY_REGISTERED;
    }

    /* Assign ID */
    HookId = g_GenericHookState.NextHookId++;

    /* Allocate thunk */
    ThunkAddr = AllocateThunk(HookId);
    if (!ThunkAddr) {
        KeReleaseSpinLock(&g_GenericHookState.Lock, OldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeReleaseSpinLock(&g_GenericHookState.Lock, OldIrql);

    /* Install EPT/NPT hook: target VA → thunk, get trampoline back */
    Status = HvHookFunction(TargetVa, ThunkAddr, &Trampoline);
    if (!NT_SUCCESS(Status)) {
        LOG_WARN("GenericHookInstall: HvHookFunction failed: 0x%08X", Status);
        return Status;
    }

    /* Allocate hook entry */
    Hook = (PGENERIC_HOOK_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(GENERIC_HOOK_ENTRY), VMX_TAG);
    if (!Hook) {
        HvUnhookFunction(TargetVa);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Hook, sizeof(GENERIC_HOOK_ENTRY));

    Hook->Active = TRUE;
    Hook->HookId = HookId;
    Hook->TargetVirtualAddress = TargetVa;
    Hook->ProcessId = ProcessId;
    Hook->Trampoline = Trampoline;
    Hook->ThunkAddress = ThunkAddr;
    Hook->HitCount = 0;
    RtlCopyMemory(&Hook->Rule, Rule, sizeof(HOOK_RULE));

    if (FunctionName) {
        RtlStringCchCopyW(Hook->FunctionName, HOOK_MAX_NAME_LEN, FunctionName);
    } else {
        Hook->FunctionName[0] = L'\0';
    }

    /* Link to list */
    KeAcquireSpinLock(&g_GenericHookState.Lock, &OldIrql);
    Hook->Next = g_GenericHookState.HookListHead;
    g_GenericHookState.HookListHead = Hook;
    g_GenericHookState.HookCount++;
    KeReleaseSpinLock(&g_GenericHookState.Lock, OldIrql);

    if (OutHookId) *OutHookId = HookId;

    LOG_INFO("Generic hook installed: id=%u, VA=0x%llX, action=%u",
             HookId, TargetVa, Rule->Action);

    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  Hook Remove                                                              */
/* ========================================================================= */

NTSTATUS GenericHookRemove(ULONG HookId)
{
    KIRQL                OldIrql;
    PGENERIC_HOOK_ENTRY  Entry, Prev;

    if (!g_GenericHookState.Initialized) return STATUS_UNSUCCESSFUL;

    KeAcquireSpinLock(&g_GenericHookState.Lock, &OldIrql);

    Prev = NULL;
    Entry = g_GenericHookState.HookListHead;
    while (Entry) {
        if (Entry->HookId == HookId && Entry->Active) {
            /* Unhook via EPT/NPT */
            KeReleaseSpinLock(&g_GenericHookState.Lock, OldIrql);
            HvUnhookFunction(Entry->TargetVirtualAddress);
            KeAcquireSpinLock(&g_GenericHookState.Lock, &OldIrql);

            /* Unlink from list */
            if (Prev) {
                Prev->Next = Entry->Next;
            } else {
                g_GenericHookState.HookListHead = Entry->Next;
            }
            g_GenericHookState.HookCount--;

            KeReleaseSpinLock(&g_GenericHookState.Lock, OldIrql);

            LOG_INFO("Generic hook removed: id=%u, VA=0x%llX", HookId, Entry->TargetVirtualAddress);
            ExFreePoolWithTag(Entry, VMX_TAG);
            return STATUS_SUCCESS;
        }
        Prev = Entry;
        Entry = Entry->Next;
    }

    KeReleaseSpinLock(&g_GenericHookState.Lock, OldIrql);
    return STATUS_NOT_FOUND;
}

VOID GenericHookRemoveAll(VOID)
{
    KIRQL               OldIrql;
    PGENERIC_HOOK_ENTRY Entry, Next;

    if (!g_GenericHookState.Initialized) return;

    KeAcquireSpinLock(&g_GenericHookState.Lock, &OldIrql);

    Entry = g_GenericHookState.HookListHead;
    while (Entry) {
        Next = Entry->Next;
        if (Entry->Active) {
            KeReleaseSpinLock(&g_GenericHookState.Lock, OldIrql);
            HvUnhookFunction(Entry->TargetVirtualAddress);
            KeAcquireSpinLock(&g_GenericHookState.Lock, &OldIrql);
        }
        ExFreePoolWithTag(Entry, VMX_TAG);
        Entry = Next;
    }

    g_GenericHookState.HookListHead = NULL;
    g_GenericHookState.HookCount = 0;

    KeReleaseSpinLock(&g_GenericHookState.Lock, OldIrql);
    LOG_INFO("All generic hooks removed");
}

/* ========================================================================= */
/*  Hook Query                                                               */
/* ========================================================================= */

NTSTATUS GenericHookGetInfo(ULONG HookId, PVMX_HOOK_INFO OutInfo)
{
    PGENERIC_HOOK_ENTRY Entry = FindHookById(HookId);
    if (!Entry) return STATUS_NOT_FOUND;

    OutInfo->HookId = Entry->HookId;
    OutInfo->Active = Entry->Active;
    OutInfo->TargetAddress = Entry->TargetVirtualAddress;
    OutInfo->ProcessId = Entry->ProcessId;
    RtlCopyMemory(&OutInfo->Rule, &Entry->Rule, sizeof(HOOK_RULE));
    OutInfo->HitCount = (ULONG64)Entry->HitCount;
    RtlCopyMemory(OutInfo->FunctionName, Entry->FunctionName, sizeof(Entry->FunctionName));

    return STATUS_SUCCESS;
}

ULONG GenericHookGetCount(VOID)
{
    return g_GenericHookState.HookCount;
}

/* ========================================================================= */
/*  C Decision Function (called from ASM dispatcher)                         */
/* ========================================================================= */

/*
 * GenericHookDecide - Called from AsmGenericHookDispatcher
 *
 * Looks up the hook by ID (R10), checks PID filter, fills HOOK_DECISION.
 * This runs at whatever IRQL the hooked function was called at.
 */
VOID NTAPI GenericHookDecide(
    ULONG64         HookIndex,
    ULONG64         CallerRetAddr,
    PHOOK_DECISION  OutDecision
)
{
    PGENERIC_HOOK_ENTRY Entry;
    ULONG               CurrentPid;

    UNREFERENCED_PARAMETER(CallerRetAddr);

    RtlZeroMemory(OutDecision, sizeof(HOOK_DECISION));

    /* Find hook entry by ID */
    Entry = FindHookById((ULONG)HookIndex);
    if (!Entry || !Entry->Active || !Entry->Trampoline) {
        /* Hook not found - passthrough via trampoline if possible */
        OutDecision->Action = HOOK_ACTION_PASSTHROUGH;
        OutDecision->Trampoline = Entry ? Entry->Trampoline : NULL;
        OutDecision->ShouldLog = FALSE;
        return;
    }

    /* PID filter check */
    if (Entry->Rule.TargetPid != 0) {
        CurrentPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        if (CurrentPid != Entry->Rule.TargetPid) {
            /* Not target process - passthrough */
            OutDecision->Action = HOOK_ACTION_PASSTHROUGH;
            OutDecision->Trampoline = Entry->Trampoline;
            OutDecision->ShouldLog = FALSE;
            return;
        }
    }

    /* Increment hit counter */
    InterlockedIncrement64(&Entry->HitCount);

    /* Fill decision based on rule */
    OutDecision->Action = Entry->Rule.Action;
    OutDecision->BlockReturnValue = Entry->Rule.BlockReturnValue;
    OutDecision->NewReturnValue = Entry->Rule.NewReturnValue;
    OutDecision->Trampoline = Entry->Trampoline;
    OutDecision->ShouldLog = Entry->Rule.LogEnabled ||
                             (Entry->Rule.Action == HOOK_ACTION_LOG_ONLY);
}

/* ========================================================================= */
/*  C Post-Call Function (called from ASM dispatcher after trampoline)       */
/* ========================================================================= */

VOID NTAPI GenericHookPostCall(
    ULONG64     HookIndex,
    ULONG       Action,
    ULONG64     FinalRetVal,
    ULONG64     CallerRetAddr,
    ULONG64     ShouldLog
)
{
    if (ShouldLog) {
        ULONG Pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        HookLogEvent((ULONG)HookIndex, Pid, CallerRetAddr, FinalRetVal, Action);
    }
}

/* ========================================================================= */
/*  Event Log Ring Buffer                                                    */
/* ========================================================================= */

VOID HookLogEvent(ULONG HookId, ULONG Pid, ULONG64 CallerAddr,
                   ULONG64 FinalRetVal, ULONG ActionTaken)
{
    KIRQL       OldIrql;
    LONG        Index;
    PHOOK_EVENT Event;
    LARGE_INTEGER Timestamp;

    KeQuerySystemTime(&Timestamp);

    KeAcquireSpinLock(&g_GenericHookState.EventLock, &OldIrql);

    Index = g_GenericHookState.EventWriteIndex;
    Event = &g_GenericHookState.EventRing[Index];

    Event->HookId = HookId;
    Event->ProcessId = Pid;
    Event->Timestamp = (ULONG64)Timestamp.QuadPart;
    Event->ReturnAddress = CallerAddr;
    Event->FinalRetVal = FinalRetVal;
    Event->ActionTaken = ActionTaken;

    g_GenericHookState.EventWriteIndex = (Index + 1) % HOOK_EVENT_RING_SIZE;

    if (g_GenericHookState.EventCount < HOOK_EVENT_RING_SIZE) {
        g_GenericHookState.EventCount++;
    } else {
        g_GenericHookState.EventReadIndex =
            (g_GenericHookState.EventReadIndex + 1) % HOOK_EVENT_RING_SIZE;
    }

    KeReleaseSpinLock(&g_GenericHookState.EventLock, OldIrql);
}

ULONG HookLogRead(PHOOK_EVENT OutputBuffer, ULONG MaxEntries)
{
    KIRQL   OldIrql;
    ULONG   Copied = 0;

    if (!OutputBuffer || MaxEntries == 0) return 0;

    KeAcquireSpinLock(&g_GenericHookState.EventLock, &OldIrql);

    while (Copied < MaxEntries && g_GenericHookState.EventCount > 0) {
        RtlCopyMemory(&OutputBuffer[Copied],
                       &g_GenericHookState.EventRing[g_GenericHookState.EventReadIndex],
                       sizeof(HOOK_EVENT));

        g_GenericHookState.EventReadIndex =
            (g_GenericHookState.EventReadIndex + 1) % HOOK_EVENT_RING_SIZE;
        g_GenericHookState.EventCount--;
        Copied++;
    }

    KeReleaseSpinLock(&g_GenericHookState.EventLock, OldIrql);
    return Copied;
}
