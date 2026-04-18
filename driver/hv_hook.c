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

/*
 * L-5: for user-mode hook install via KeStackAttachProcess.
 *
 * KeStackAttachProcess / KeUnstackDetachProcess / PsLookupProcessByProcessId
 * live in <ntifs.h>, which we intentionally do NOT include here (to keep
 * this translation unit lean and avoid pulling the full FS-driver surface).
 * We forward-declare the three APIs AND the small KAPC_STATE structure
 * they need.  Keep this in sync with the identical local definition in
 * shadow_ssdt.c so the two views never diverge.
 *
 * Structure layout is stable across every supported Windows version
 * (documented in WDK headers; used by thousands of drivers unchanged
 * since Windows XP).
 */
typedef struct _KAPC_STATE {
    LIST_ENTRY  ApcListHead[2];
    PKPROCESS   Process;
    BOOLEAN     KernelApcInProgress;
    BOOLEAN     KernelApcPending;
    BOOLEAN     UserApcPending;
} KAPC_STATE, *PKAPC_STATE;

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
NTKERNELAPI VOID     KeStackAttachProcess(PEPROCESS Process, PKAPC_STATE ApcState);
NTKERNELAPI VOID     KeUnstackDetachProcess(PKAPC_STATE ApcState);

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
    ULONG       SlotIdx;
    ULONG       w, b;

    /*
     * H-3: search existing pages for any free slot (recycles holes left
     * by previously-freed thunks instead of always growing UsedCount).
     */
    Page = g_GenericHookState.ThunkPageHead;
    while (Page) {
        if (Page->UsedCount < Page->Capacity) {
            /* Find the first clear bit in SlotBitmap. */
            for (w = 0; w < THUNK_BITMAP_WORDS; w++) {
                if (Page->SlotBitmap[w] != ~0ULL) {
                    /* Word has at least one free slot. */
                    for (b = 0; b < 64; b++) {
                        SlotIdx = w * 64 + b;
                        if (SlotIdx >= Page->Capacity) break;
                        if ((Page->SlotBitmap[w] & (1ULL << b)) == 0) {
                            Page->SlotBitmap[w] |= (1ULL << b);
                            Page->UsedCount++;
                            ThunkAddr = (PUCHAR)Page->CodeBase + (SlotIdx * THUNK_STUB_SIZE);
                            BuildThunkStub(ThunkAddr, HookId,
                                           (ULONG64)AsmGenericHookDispatcher);
                            return ThunkAddr;
                        }
                    }
                }
            }
            /* UsedCount lied — repair it. */
            Page->UsedCount = Page->Capacity;
        }
        Page = Page->Next;
    }

    /* All pages full — allocate a new one. */
    Page = AllocateThunkPage(HookId);
    if (!Page) return NULL;

    Page->Next = g_GenericHookState.ThunkPageHead;
    g_GenericHookState.ThunkPageHead = Page;
    g_GenericHookState.ThunkPageCount++;

    /* Slot 0 of the new page. */
    Page->SlotBitmap[0] |= 1ULL;
    Page->UsedCount = 1;
    ThunkAddr = (PUCHAR)Page->CodeBase;
    BuildThunkStub(ThunkAddr, HookId, (ULONG64)AsmGenericHookDispatcher);
    return ThunkAddr;
}

/*
 * H-3 (revised): release a thunk slot previously allocated by AllocateThunk.
 *
 * Timing is subtle.  By the time FreeThunk is called, HvUnhookFunction has
 * already rebuilt the hooked page's EPT/NPT entry to point at the ORIGINAL
 * (unhooked) content and flushed the nested TLB on every CPU via
 * Ept/NptInvalidateAllCpusSync — so no guest VA now dispatches into this
 * thunk anymore.  HOWEVER:
 *
 *   (a) A CPU may currently be executing INSIDE AsmGenericHookDispatcher,
 *       having entered through the thunk microseconds ago.  If we zero
 *       the thunk bytes now, the dispatcher itself is unaffected (it's
 *       in a different page), but a stale RIP return address that some
 *       frame pointer still references would become invalid.  In
 *       practice AsmGenericHookDispatcher doesn't leave anything on the
 *       stack pointing BACK into the thunk (it jumps to trampoline via
 *       an indirect register jump), so zeroing is safe.
 *
 *   (b) A CPU may have ALREADY read the thunk bytes into its icache but
 *       not yet executed them.  After the TLB sync that icache line is
 *       stale but icache coherency on x86 handles that — modifying
 *       writable memory that was executed causes the CPU to self-modify
 *       its own icache for that line (Intel SDM Vol.3 §11.6).  So
 *       rewriting the thunk bytes is safe from the icache perspective.
 *
 *   (c) The slot MIGHT be handed out to a NEW hook install before any
 *       of the above CPUs finish.  BuildThunkStub would then write
 *       different bytes to the same location.  For the still-running
 *       dispatcher this is fine (see (a)); but the slot reuse must not
 *       happen until the TLB sync has completed — and that's already
 *       guaranteed because HvUnhookFunction synchronously calls
 *       Ept/NptInvalidateAllCpusSync BEFORE returning to
 *       GenericHookRemove, which only then calls FreeThunk.
 *
 * Therefore: zero + mark-free immediately is safe.  The only remaining
 * concern is that the slot bitmap update must be atomic w.r.t. concurrent
 * AllocateThunk, which is already enforced by g_GenericHookState.Lock
 * (both hold it).
 *
 * We do NOT free the containing thunk page even when UsedCount drops to
 * zero — recycling the page avoids the cost of reallocation for the next
 * install and makes page lifetime monotonic (simplifying lifetime
 * analysis for any future dispatcher-stack-walk callback).
 */
static VOID FreeThunk(PVOID ThunkAddr)
{
    PTHUNK_PAGE Page;

    if (!ThunkAddr) return;

    Page = g_GenericHookState.ThunkPageHead;
    while (Page) {
        ULONG64 PageBase = (ULONG64)Page->CodeBase;
        ULONG64 Addr     = (ULONG64)ThunkAddr;
        if (Addr >= PageBase && Addr < PageBase + PAGE_SIZE) {
            ULONG SlotIdx = (ULONG)((Addr - PageBase) / THUNK_STUB_SIZE);
            ULONG w = SlotIdx / 64;
            ULONG b = SlotIdx % 64;
            if (w < THUNK_BITMAP_WORDS && (Page->SlotBitmap[w] & (1ULL << b))) {
                /*
                 * Order of operations:
                 *   1. Zero the stub bytes FIRST (so if an AllocateThunk
                 *      race somehow observed the freed-but-not-yet-zeroed
                 *      slot, it would build fresh bytes on top — harmless,
                 *      but clean order simplifies reasoning).
                 *   2. Clear the bitmap bit and decrement UsedCount.
                 *
                 * Both operations happen under the caller-held spin lock
                 * so this is effectively atomic.
                 */
                RtlZeroMemory((PUCHAR)Page->CodeBase + (SlotIdx * THUNK_STUB_SIZE),
                              THUNK_STUB_SIZE);
                Page->SlotBitmap[w] &= ~(1ULL << b);
                if (Page->UsedCount > 0) Page->UsedCount--;
            }
            return;
        }
        Page = Page->Next;
    }
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

    /*
     * L-5 FIX: for user-mode target VAs, MmGetPhysicalAddress (called
     * inside HvHookFunction) only works in the context of the owning
     * process.  If the IOCTL caller is not the target process we must
     * KeStackAttachProcess first, otherwise we would hook the wrong
     * physical page (or get PA=0 and fail).
     *
     * Heuristic for "user-mode VA": address < 0x0000_8000_0000_0000
     * (canonical lower half on x64).  Kernel-mode VAs stay in the upper
     * half and are valid regardless of process context.
     */
    {
        BOOLEAN    IsUserVa     = (TargetVa < 0x0000800000000000ULL);
        BOOLEAN    Attached     = FALSE;
        KAPC_STATE ApcState     = { 0 };
        PEPROCESS  TargetProcess = NULL;

        if (IsUserVa) {
            if (ProcessId == 0) {
                LOG_ERROR("GenericHookInstall: user-mode TargetVa 0x%llX requires ProcessId",
                          TargetVa);
                /* Roll back thunk allocation */
                KeAcquireSpinLock(&g_GenericHookState.Lock, &OldIrql);
                /* (AllocateThunk slot is not freed here by design; see H-3.) */
                KeReleaseSpinLock(&g_GenericHookState.Lock, OldIrql);
                return STATUS_INVALID_PARAMETER;
            }

            Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &TargetProcess);
            if (!NT_SUCCESS(Status)) {
                LOG_ERROR("GenericHookInstall: PsLookupProcessByProcessId(%u) failed: 0x%08X",
                          ProcessId, Status);
                return Status;
            }
            KeStackAttachProcess(TargetProcess, &ApcState);
            Attached = TRUE;
        }

        /* Install EPT/NPT hook: target VA → thunk, get trampoline back */
        Status = HvHookFunction(TargetVa, ThunkAddr, &Trampoline);

        if (Attached) {
            KeUnstackDetachProcess(&ApcState);
            ObDereferenceObject(TargetProcess);
        }
    }
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

            /* H-3: return thunk slot to its page so it can be re-used. */
            FreeThunk(Entry->ThunkAddress);

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
            /* H-3: return thunk slot. */
            FreeThunk(Entry->ThunkAddress);
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
