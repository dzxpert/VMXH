/*
 * npt.c - VMX Anti-Anti-Debug Hypervisor
 * AMD Nested Page Tables: identity mapping, hook engine, NPF handler
 *
 * This is the AMD equivalent of ept.c. The page table structure is
 * identical, but the hooking strategy differs because AMD NPT does
 * NOT support Execute-Only pages.
 *
 * Hook Strategy (AMD NPT):
 *   Since Execute-Only is not available, we use a different approach:
 *   - Normal state: page is No-Access (R=0, W=0, X=0)
 *   - On any access (read/write/execute), NPF fires
 *   - In the NPF handler, check guest RIP:
 *     - If RIP is within the hooked page -> execution -> temporarily set R+W+X
 *       with hook page mapped, enable single-step (TF), after single-step
 *       restore No-Access
 *     - If RIP is outside the hooked page -> read/write -> temporarily set R+W+X
 *       with original page mapped, enable single-step, after step restore No-Access
 *
 *   Alternative simpler approach (used here):
 *   - Hook page is mapped with Read+Execute (no Write)
 *   - Writes trigger NPF -> temporarily give Write access, single-step, restore
 *   - Reads see the hook page (with JMP), but since reads of code pages
 *     are rare in anti-debug scenarios, this is acceptable
 *   - For integrity-checking targets, use the full No-Access approach
 */

#include "npt.h"
#include "svm.h"
#include "log.h"

/* ========================================================================= */
/*  Forward declarations for per-CPU helpers (defined later in this file)     */
/* ========================================================================= */
static NTSTATUS NptEnsurePerCpuPdForRegion(ULONG PdptIndex);
static NTSTATUS NptEnsurePerCpuSplitPage(ULONG splitIdx, ULONG PdptIndex, ULONG PdIndex);

/* ========================================================================= */
/*  Constants (needed before global array declarations)                      */
/* ========================================================================= */

/* Page directory and split page pools (same as EPT) */
#define NPT_MAX_SPLIT_PAGES    128
#define NPT_MAX_PD_PAGES       512

/* ========================================================================= */
/*  Globals                                                                  */
/* ========================================================================= */

NPT_STATE       g_NptState = { 0 };
NPT_HOOK_STATE  g_NptHookState = { 0 };
PNPT_CPU_STATE  g_NptCpuStates = NULL;     /* per-CPU NPT root array */

/*
 * Per-CPU split page tracking (NPT side, mirrors EPT's per-CPU splits).
 */
typedef struct _NPT_PER_CPU_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[EPT_PTE_COUNT];
    ULONG64     PhysicalAddress;
    BOOLEAN     Allocated;
} NPT_PER_CPU_SPLIT, *PNPT_PER_CPU_SPLIT;

static PNPT_PER_CPU_SPLIT *g_NptPerCpuSplitPages = NULL;

typedef struct _NPT_PER_CPU_PD_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Entries[EPT_PDE_COUNT];
} NPT_PER_CPU_PD_PAGE;

static NPT_PER_CPU_PD_PAGE **g_NptPerCpuPdPages = NULL;
static BOOLEAN g_NptPerCpuPdAllocated[NPT_MAX_PD_PAGES] = { 0 };

/*
 * Per-CPU tracking of which physical page was temporarily made permissive
 * by the NPF handler. The #DB handler reads and clears this to know which
 * page to restore, avoiding a multi-core race condition.
 *
 * This is the AMD-side equivalent of g_MtfRelaxedPagePa in ept.c.
 */
static volatile ULONG64 *g_NptDbRelaxedPagePa = NULL;  /* dynamic [g_MaxProcessors] */

/*
 * NptDbTrackRelaxedPage - Record which physical page this CPU just made
 * permissive (called from NptHandlePageFault).
 */
VOID NptDbTrackRelaxedPage(ULONG64 PagePhysicalAddr)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    if (g_NptDbRelaxedPagePa && CpuIndex < g_MaxProcessors) {
        g_NptDbRelaxedPagePa[CpuIndex] = PagePhysicalAddr;
    }
}

/*
 * NptDbGetAndClearRelaxedPage - Get and clear the relaxed page for this CPU.
 * Called from SvmHandleDbException in svm_exit.c.
 * Returns 0 if no page was recorded (shouldn't happen normally).
 */
ULONG64 NptDbGetAndClearRelaxedPage(VOID)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    ULONG64 Pa = 0;
    if (g_NptDbRelaxedPagePa && CpuIndex < g_MaxProcessors) {
        Pa = g_NptDbRelaxedPagePa[CpuIndex];
        g_NptDbRelaxedPagePa[CpuIndex] = 0;
    }
    return Pa;
}

typedef struct _NPT_SPLIT_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[EPT_PTE_COUNT];
    ULONG64     PhysicalAddress;
    ULONG64     BasePhysAddr2MB;
    BOOLEAN     InUse;
} NPT_SPLIT_PAGE, *PNPT_SPLIT_PAGE;

typedef struct _NPT_PD_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Entries[EPT_PDE_COUNT];
} NPT_PD_PAGE;

static NPT_SPLIT_PAGE  *g_NptSplitPages = NULL;
static ULONG             g_NptSplitPageCount = 0;
static NPT_PD_PAGE     *g_NptPdPages = NULL;

/*
 * BUG FIX (Issue #3+5+6): Split page hash table for O(1) lookup (NPT side).
 * Mirrors the EPT split hash table design.
 */
typedef struct _NPT_SPLIT_HASH_ENTRY {
    ULONG64 Base2MB;
    ULONG   SplitIdx;
} NPT_SPLIT_HASH_ENTRY;

static NPT_SPLIT_HASH_ENTRY g_NptSplitHashTable[EPT_SPLIT_HASH_SIZE];

static __forceinline ULONG NptSplitHashFn(ULONG64 Base2MB)
{
    ULONG64 Idx2MB = Base2MB >> 21;
    return (ULONG)((Idx2MB * 2654435761ULL) >> (32 - EPT_SPLIT_HASH_BITS)) & (EPT_SPLIT_HASH_SIZE - 1);
}

static __forceinline ULONG NptSplitHashLookup(ULONG64 Base2MB)
{
    ULONG Slot = NptSplitHashFn(Base2MB);
    ULONG i;
    for (i = 0; i < EPT_SPLIT_HASH_SIZE; i++) {
        ULONG Idx = (Slot + i) & (EPT_SPLIT_HASH_SIZE - 1);
        if (g_NptSplitHashTable[Idx].SplitIdx == EPT_SPLIT_HASH_EMPTY)
            return EPT_SPLIT_HASH_EMPTY;
        if (g_NptSplitHashTable[Idx].Base2MB == Base2MB)
            return g_NptSplitHashTable[Idx].SplitIdx;
    }
    return EPT_SPLIT_HASH_EMPTY;
}

static __forceinline VOID NptSplitHashInsert(ULONG64 Base2MB, ULONG SplitIdx)
{
    ULONG Slot = NptSplitHashFn(Base2MB);
    ULONG i;
    for (i = 0; i < EPT_SPLIT_HASH_SIZE; i++) {
        ULONG Idx = (Slot + i) & (EPT_SPLIT_HASH_SIZE - 1);
        if (g_NptSplitHashTable[Idx].SplitIdx == EPT_SPLIT_HASH_EMPTY) {
            g_NptSplitHashTable[Idx].Base2MB = Base2MB;
            g_NptSplitHashTable[Idx].SplitIdx = SplitIdx;
            return;
        }
    }
}

/*
 * Hook hash table helper functions (NPT side).
 */
static __forceinline ULONG NptHookHashFn(ULONG64 PagePa)
{
    ULONG64 Pfn = PagePa >> 12;
    return (ULONG)((Pfn * 2654435761ULL) >> (32 - EPT_HOOK_HASH_BITS)) & (EPT_HOOK_HASH_SIZE - 1);
}

/*
 * NptHookHashRebuild - Rebuild the NPT hook hash table from scratch.
 * Must be called with g_NptHookState.Lock held.
 */
static VOID NptHookHashRebuild(VOID)
{
    ULONG i;
    for (i = 0; i < EPT_HOOK_HASH_SIZE; i++)
        g_NptHookState.HookHashTable[i] = EPT_HOOK_HASH_EMPTY;
    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        if (g_NptHookState.Hooks[i].Active) {
            ULONG Slot = NptHookHashFn(g_NptHookState.Hooks[i].TargetPhysicalAddr);
            ULONG j;
            for (j = 0; j < EPT_HOOK_HASH_SIZE; j++) {
                ULONG Idx = (Slot + j) & (EPT_HOOK_HASH_SIZE - 1);
                if (g_NptHookState.HookHashTable[Idx] == EPT_HOOK_HASH_EMPTY) {
                    g_NptHookState.HookHashTable[Idx] = i;
                    break;
                }
            }
        }
    }
}

/* ========================================================================= */
/*  Internal Helpers                                                         */
/* ========================================================================= */

static ULONG64 NptVaToPhysical(PVOID Va)
{
    PHYSICAL_ADDRESS Pa = MmGetPhysicalAddress(Va);
    return Pa.QuadPart;
}

/* ========================================================================= */
/*  NPT Identity Map Setup                                                   */
/* ========================================================================= */

NTSTATUS NptInitialize(VOID)
{
    ULONG i, j;
    ULONG64 PhysAddr;
    ULONG64 PdptPa;

    if (g_NptState.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_NptState, sizeof(NPT_STATE));
    RtlZeroMemory(&g_NptHookState, sizeof(NPT_HOOK_STATE));
    KeInitializeSpinLock(&g_NptHookState.Lock);

    /*
     * BUG FIX (Issue #3+5+6): Initialize hash tables for O(1) lookups.
     */
    {
        ULONG htIdx;
        for (htIdx = 0; htIdx < EPT_HOOK_HASH_SIZE; htIdx++)
            g_NptHookState.HookHashTable[htIdx] = EPT_HOOK_HASH_EMPTY;
        for (htIdx = 0; htIdx < EPT_SPLIT_HASH_SIZE; htIdx++)
            g_NptSplitHashTable[htIdx].SplitIdx = EPT_SPLIT_HASH_EMPTY;
    }

    /* Allocate per-CPU tracking array (dynamic based on g_MaxProcessors) */
    if (g_MaxProcessors > 0) {
        g_NptDbRelaxedPagePa = (volatile ULONG64 *)ExAllocatePoolWithTag(
            NonPagedPool, g_MaxProcessors * sizeof(ULONG64), 'tpnM');
        if (!g_NptDbRelaxedPagePa) {
            LOG_ERROR("Failed to allocate NPT per-CPU tracking array");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory((PVOID)g_NptDbRelaxedPagePa, g_MaxProcessors * sizeof(ULONG64));
    }

    /* Allocate Page Directory pages */
    g_NptPdPages = (NPT_PD_PAGE *)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(NPT_PD_PAGE) * NPT_MAX_PD_PAGES, SVM_TAG);
    if (!g_NptPdPages) {
        LOG_ERROR("Failed to allocate NPT page directory pages");
        /*
         * BUG FIX (Review Issue #5): Free per-CPU tracking array on failure.
         * Previously leaked g_NptDbRelaxedPagePa.
         */
        if (g_NptDbRelaxedPagePa) {
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedPagePa, 'tpnM');
            g_NptDbRelaxedPagePa = NULL;
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_NptPdPages, sizeof(NPT_PD_PAGE) * NPT_MAX_PD_PAGES);

    /* Allocate split page pool */
    g_NptSplitPages = (NPT_SPLIT_PAGE *)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(NPT_SPLIT_PAGE) * NPT_MAX_SPLIT_PAGES, SVM_TAG);
    if (!g_NptSplitPages) {
        LOG_ERROR("Failed to allocate NPT split page pool");
        ExFreePoolWithTag(g_NptPdPages, SVM_TAG);
        if (g_NptDbRelaxedPagePa) {
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedPagePa, 'tpnM');
            g_NptDbRelaxedPagePa = NULL;
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_NptSplitPages, sizeof(NPT_SPLIT_PAGE) * NPT_MAX_SPLIT_PAGES);

    /* Build identity-mapped NPT using 2MB large pages */
    for (i = 0; i < NPT_MAX_PD_PAGES && i < EPT_PDPTE_COUNT; i++) {
        ULONG64 PdPa = NptVaToPhysical(&g_NptPdPages[i]);

        g_NptState.Pdpt[i].Value = 0;
        g_NptState.Pdpt[i].Read = 1;
        g_NptState.Pdpt[i].Write = 1;
        g_NptState.Pdpt[i].Execute = 1;
        g_NptState.Pdpt[i].PhysAddr = PdPa >> 12;

        for (j = 0; j < EPT_PDE_COUNT; j++) {
            PhysAddr = ((ULONG64)i * 512 + j) * (2 * 1024 * 1024);

            g_NptPdPages[i].Entries[j].Value = 0;
            g_NptPdPages[i].Entries[j].Read = 1;
            g_NptPdPages[i].Entries[j].Write = 1;
            g_NptPdPages[i].Entries[j].Execute = 1;
            g_NptPdPages[i].Entries[j].LargePage = 1;
            g_NptPdPages[i].Entries[j].PhysAddr = PhysAddr >> 12;
        }
    }

    /* Setup PML4[0] to point to PDPT */
    PdptPa = NptVaToPhysical(g_NptState.Pdpt);
    g_NptState.Pml4[0].Value = 0;
    g_NptState.Pml4[0].Read = 1;
    g_NptState.Pml4[0].Write = 1;
    g_NptState.Pml4[0].Execute = 1;
    g_NptState.Pml4[0].PhysAddr = PdptPa >> 12;

    g_NptState.Pml4Pa = NptVaToPhysical(g_NptState.Pml4);

    g_NptState.Initialized = TRUE;
    g_NptHookState.Initialized = TRUE;

    LOG_INFO("NPT initialized: identity map for 512GB, PML4PA=0x%llX", g_NptState.Pml4Pa);
    return STATUS_SUCCESS;
}

VOID NptCleanup(VOID)
{
    NptUnhookAll();

    if (g_NptSplitPages) {
        ExFreePoolWithTag(g_NptSplitPages, SVM_TAG);
        g_NptSplitPages = NULL;
    }

    /*
     * BUG FIX: Reset split hash table after freeing split pages.
     * If the driver is re-initialized without a full reload, stale hash
     * entries would point to freed memory, causing dangling pointer lookups.
     */
    {
        ULONG htIdx;
        for (htIdx = 0; htIdx < EPT_SPLIT_HASH_SIZE; htIdx++)
            g_NptSplitHashTable[htIdx].SplitIdx = EPT_SPLIT_HASH_EMPTY;
    }
    if (g_NptPdPages) {
        ExFreePoolWithTag(g_NptPdPages, SVM_TAG);
        g_NptPdPages = NULL;
    }

    /* Free per-CPU tracking array */
    if (g_NptDbRelaxedPagePa) {
        ExFreePoolWithTag((PVOID)g_NptDbRelaxedPagePa, 'tpnM');
        g_NptDbRelaxedPagePa = NULL;
    }

    g_NptState.Initialized = FALSE;
    g_NptHookState.Initialized = FALSE;

    LOG_INFO("NPT cleaned up");
}

ULONG64 NptGetRootPageTablePa(VOID)
{
    return g_NptState.Pml4Pa;
}

/* ========================================================================= */
/*  2MB -> 4KB Page Splitting                                                */
/* ========================================================================= */

VOID NptSplitLargePage(ULONG64 PhysicalAddress)
{
    ULONG64     Base2MB;
    ULONG       PdptIndex, PdIndex;
    PEPT_PDE    TargetPde;
    PNPT_SPLIT_PAGE SplitPage = NULL;
    ULONG       i;
    ULONG       splitIdx = (ULONG)-1;

    Base2MB = PhysicalAddress & ~((2ULL * 1024 * 1024) - 1);
    PdptIndex = (ULONG)((Base2MB >> 30) & 0x1FF);
    PdIndex   = (ULONG)((Base2MB >> 21) & 0x1FF);

    if (PdptIndex >= NPT_MAX_PD_PAGES) {
        LOG_ERROR("NPT split: address 0x%llX beyond mapped range", PhysicalAddress);
        return;
    }

    TargetPde = &g_NptPdPages[PdptIndex].Entries[PdIndex];

    if (!TargetPde->LargePage) {
        return;  /* Already split */
    }

    /* Find a free split page */
    for (i = 0; i < NPT_MAX_SPLIT_PAGES; i++) {
        if (!g_NptSplitPages[i].InUse) {
            SplitPage = &g_NptSplitPages[i];
            splitIdx = i;
            break;
        }
    }

    if (!SplitPage) {
        LOG_ERROR("NPT split: no free split pages");
        return;
    }

    /* Initialize 512 PTEs for the 2MB region */
    for (i = 0; i < EPT_PTE_COUNT; i++) {
        ULONG64 PagePa = Base2MB + (ULONG64)i * PAGE_SIZE;

        SplitPage->Pte[i].Value = 0;
        SplitPage->Pte[i].Read = 1;
        SplitPage->Pte[i].Write = 1;
        SplitPage->Pte[i].Execute = 1;
        SplitPage->Pte[i].MemoryType = EPT_MEMORY_TYPE_WB;
        SplitPage->Pte[i].PhysAddr = PagePa >> 12;
    }

    SplitPage->PhysicalAddress = NptVaToPhysical(SplitPage->Pte);
    SplitPage->BasePhysAddr2MB = Base2MB;
    SplitPage->InUse = TRUE;
    g_NptSplitPageCount++;

    /*
     * BUG FIX (Issue #3+5+6): Insert into split page hash table for O(1) lookup.
     */
    NptSplitHashInsert(Base2MB, splitIdx);

    /* Update PDE */
    TargetPde->Value = 0;
    TargetPde->Read = 1;
    TargetPde->Write = 1;
    TargetPde->Execute = 1;
    TargetPde->LargePage = 0;
    TargetPde->PhysAddr = SplitPage->PhysicalAddress >> 12;

    LOG_INFO("NPT: Split 2MB page at 0x%llX into 4KB pages", Base2MB);
}

/* ========================================================================= */
/*  NPT PTE Lookup                                                          */
/* ========================================================================= */

PEPT_PTE NptGetPteForPhysicalAddress(ULONG64 PhysicalAddress)
{
    ULONG64     Base2MB;
    ULONG       PdptIndex, PdIndex, PtIndex;
    PEPT_PDE    Pde;
    ULONG       splitIdx;

    Base2MB = PhysicalAddress & ~((2ULL * 1024 * 1024) - 1);
    PdptIndex = (ULONG)((PhysicalAddress >> 30) & 0x1FF);
    PdIndex   = (ULONG)((PhysicalAddress >> 21) & 0x1FF);
    PtIndex   = (ULONG)((PhysicalAddress >> 12) & 0x1FF);

    if (PdptIndex >= NPT_MAX_PD_PAGES) {
        return NULL;
    }

    Pde = &g_NptPdPages[PdptIndex].Entries[PdIndex];

    if (Pde->LargePage) {
        return NULL;  /* Need to split first */
    }

    /*
     * BUG FIX (Issue #3+5+6): O(1) hash table lookup instead of O(n) scan.
     */
    splitIdx = NptSplitHashLookup(Base2MB);
    if (splitIdx != EPT_SPLIT_HASH_EMPTY && splitIdx < NPT_MAX_SPLIT_PAGES) {
        return &g_NptSplitPages[splitIdx].Pte[PtIndex];
    }

    return NULL;
}

/* ========================================================================= */
/*  NPT Hook Engine                                                          */
/* ========================================================================= */

/*
 * NPT Hook Strategy:
 * Since AMD NPT doesn't support Execute-Only, we use:
 *   - Hook page mapped with R+X (no W): execution sees JMP, reads see hook page
 *   - Writes trigger NPF -> temporarily set R+W+X with original page, single-step
 *   - After single-step completes (via #DB/TF), restore R+X with hook page
 *
 * This is slightly less stealthy than Intel's Execute-Only approach
 * (reads will see the JMP), but works for our anti-anti-debug use case
 * since the target applications primarily execute code, not read it for
 * integrity checks.
 */
NTSTATUS NptHookFunction(ULONG64 TargetVa, PVOID HookFunction, PVOID *OriginalFunction)
{
    KIRQL               OldIrql;
    PEPT_HOOK_ENTRY     Hook = NULL;
    PEPT_HOOK_ENTRY     PageOwner = NULL;
    ULONG64             TargetPa;
    ULONG64             PageBase;
    ULONG               PageOffset;
    PEPT_PTE            Pte;
    PHYSICAL_ADDRESS    PhysAddr;
    ULONG               i;
    PVOID               TargetPageVa;
    PUCHAR              HookPoint;
    PUCHAR              Trampoline;

    if (!g_NptHookState.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    PhysAddr = MmGetPhysicalAddress((PVOID)TargetVa);
    TargetPa = PhysAddr.QuadPart;

    if (TargetPa == 0) {
        LOG_ERROR("NPT Hook: Failed to get PA for VA 0x%llX", TargetVa);
        return STATUS_INVALID_ADDRESS;
    }

    PageBase = TargetPa & ~0xFFFULL;
    PageOffset = (ULONG)(TargetPa & 0xFFF);

    KeAcquireSpinLock(&g_NptHookState.Lock, &OldIrql);

    /* Check for duplicate */
    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        if (g_NptHookState.Hooks[i].Active &&
            g_NptHookState.Hooks[i].TargetVirtualAddr == TargetVa) {
            KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
            return STATUS_ALREADY_REGISTERED;
        }
    }

    /* Check if another hook already exists on the same physical page */
    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        if (g_NptHookState.Hooks[i].Active &&
            g_NptHookState.Hooks[i].TargetPhysicalAddr == PageBase &&
            g_NptHookState.Hooks[i].OwnsPages)
        {
            PageOwner = &g_NptHookState.Hooks[i];
            break;
        }
    }

    /* Find free slot */
    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        if (!g_NptHookState.Hooks[i].Active) {
            Hook = &g_NptHookState.Hooks[i];
            break;
        }
    }

    if (!Hook) {
        KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Split 2MB page */
    NptSplitLargePage(TargetPa);

    /*
     * BUG FIX: After splitting a 2MB page into 4KB pages, other CPUs may
     * still have stale TLB entries pointing to the old 2MB PDE.  If they
     * access memory in this range before seeing the new 4KB PTEs, the CPU
     * will detect an NPT format mismatch and trigger NPF → crash.
     *
     * Fix: Invalidate NPT TLB immediately after page split so all CPUs
     * pick up the new page table structure before any further accesses.
     */
    NptInvalidateAll();

    Pte = NptGetPteForPhysicalAddress(TargetPa);
    if (!Pte) {
        KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
        return STATUS_UNSUCCESSFUL;
    }

    if (PageOwner) {
        /* Shared page path */
        Hook->OriginalPageVa = PageOwner->OriginalPageVa;
        Hook->HookPageVa     = PageOwner->HookPageVa;
        Hook->HookPagePa     = PageOwner->HookPagePa;
        Hook->OwnsPages       = FALSE;
    } else {
        /* First hook on this page */
        Hook->OriginalPageVa = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, SVM_TAG);
        Hook->HookPageVa = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, SVM_TAG);

        if (!Hook->OriginalPageVa || !Hook->HookPageVa) {
            if (Hook->OriginalPageVa) ExFreePoolWithTag(Hook->OriginalPageVa, SVM_TAG);
            if (Hook->HookPageVa)     ExFreePoolWithTag(Hook->HookPageVa, SVM_TAG);
            KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        TargetPageVa = (PVOID)(TargetVa & ~0xFFFULL);
        RtlCopyMemory(Hook->OriginalPageVa, TargetPageVa, PAGE_SIZE);
        RtlCopyMemory(Hook->HookPageVa, TargetPageVa, PAGE_SIZE);

        Hook->HookPagePa = NptVaToPhysical(Hook->HookPageVa);
        Hook->OwnsPages   = TRUE;
    }

    /* Allocate trampoline (always per-hook) */
    Hook->TrampolineVa = ExAllocatePoolWithTag(NonPagedPool, EPT_TRAMPOLINE_SIZE, SVM_TAG);
    if (!Hook->TrampolineVa) {
        if (Hook->OwnsPages) {
            ExFreePoolWithTag(Hook->HookPageVa, SVM_TAG);
            ExFreePoolWithTag(Hook->OriginalPageVa, SVM_TAG);
        }
        KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /*
     * Save original bytes at hook point.
     * We need at least 12 bytes for our JMP (48 B8 [imm64] FF E0).
     * Must NOT cut an instruction in half — that would cause the
     * trampoline to execute a truncated instruction → #UD → BSOD.
     *
     * Use the x64 instruction length decoder to find the minimum
     * number of complete instructions that cover >= 12 bytes.
     */
    {
        ULONG TotalLen = 0;
        PUCHAR Code = (PUCHAR)TargetVa;
        while (TotalLen < 12) {
            ULONG InsnLen = EptGetInstructionLength(Code + TotalLen);
            if (InsnLen == 0) {
                LOG_ERROR("NPT Hook: Cannot decode instruction at VA 0x%llX + 0x%X",
                          TargetVa, TotalLen);
                if (Hook->OwnsPages) {
                    ExFreePoolWithTag(Hook->HookPageVa, SVM_TAG);
                    ExFreePoolWithTag(Hook->OriginalPageVa, SVM_TAG);
                }
                ExFreePoolWithTag(Hook->TrampolineVa, SVM_TAG);
                KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
                return STATUS_UNSUCCESSFUL;
            }
            if (TotalLen + InsnLen > sizeof(((EPT_HOOK_ENTRY*)0)->OriginalBytes)) {
                LOG_ERROR("NPT Hook: OriginalBytes overflow at VA 0x%llX "
                          "(TotalLen=%u + InsnLen=%u > %u)",
                          TargetVa, TotalLen, InsnLen,
                          (ULONG)sizeof(((EPT_HOOK_ENTRY*)0)->OriginalBytes));
                if (Hook->OwnsPages) {
                    ExFreePoolWithTag(Hook->HookPageVa, SVM_TAG);
                    ExFreePoolWithTag(Hook->OriginalPageVa, SVM_TAG);
                }
                ExFreePoolWithTag(Hook->TrampolineVa, SVM_TAG);
                KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
                return STATUS_BUFFER_TOO_SMALL;
            }
            TotalLen += InsnLen;
        }
        Hook->OriginalBytesSize = TotalLen;
    }
    RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, Hook->OriginalBytesSize);

    /*
     * Build hook page: MOV RAX, imm64; JMP RAX (12 bytes).
     * Avoids a RIP-relative data read that would fault on execute-only pages.
     */
    HookPoint = (PUCHAR)Hook->HookPageVa + PageOffset;
    HookPoint[0] = 0x48;                                /* REX.W prefix       */
    HookPoint[1] = 0xB8;                                /* MOV RAX, imm64     */
    *(PULONG64)(HookPoint + 2) = (ULONG64)HookFunction; /* 8-byte immediate   */
    HookPoint[10] = 0xFF;                               /* JMP RAX            */
    HookPoint[11] = 0xE0;

    /*
     * Build trampoline: original bytes + JMP back to (Target + OriginalBytesSize)
     *
     * BUG FIX (Issue #2 mirror to NPT): After copying original bytes to the
     * trampoline, scan each instruction for RIP-relative addressing
     * (ModRM Mod=00 RM=101). If found, fix up the disp32 so it still
     * points to the original target from the trampoline's different VA.
     * If relocation fails (target too far), refuse to hook rather than
     * execute broken instructions.
     */
    Trampoline = (PUCHAR)Hook->TrampolineVa;
    RtlCopyMemory(Trampoline, Hook->OriginalBytes, Hook->OriginalBytesSize);

    /* Relocate RIP-relative instructions in trampoline */
    {
        ULONG TrampolineOffset = 0;
        ULONG64 TrampolineBaseVa = (ULONG64)Hook->TrampolineVa;
        while (TrampolineOffset < Hook->OriginalBytesSize) {
            ULONG InsnLen = EptGetInstructionLength(Trampoline + TrampolineOffset);
            if (InsnLen == 0) break;  /* Already validated above, shouldn't happen */

            {
                ULONG DispOffset = 0;
                if (EptIsRipRelativeInstruction(Trampoline + TrampolineOffset, InsnLen, &DispOffset)) {
                    ULONG64 OrigInsnVa = TargetVa + TrampolineOffset;
                    ULONG64 TrampolineInsnVa = TrampolineBaseVa + TrampolineOffset;

                    if (!EptRelocateRipRelativeInstruction(
                            Trampoline + TrampolineOffset,
                            InsnLen, DispOffset,
                            OrigInsnVa, TrampolineInsnVa)) {
                        LOG_ERROR("NPT Hook: RIP-relative relocation failed at VA 0x%llX "
                                  "(trampoline too far from target)", OrigInsnVa);
                        if (Hook->OwnsPages) {
                            ExFreePoolWithTag(Hook->HookPageVa, SVM_TAG);
                            ExFreePoolWithTag(Hook->OriginalPageVa, SVM_TAG);
                        }
                        ExFreePoolWithTag(Hook->TrampolineVa, SVM_TAG);
                        KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
                        return STATUS_UNSUCCESSFUL;
                    }
                    LOG_DEBUG("NPT Hook: Relocated RIP-relative insn at VA 0x%llX +%u (disp offset %u)",
                              TargetVa, TrampolineOffset, DispOffset);
                }
            }
            TrampolineOffset += InsnLen;
        }
    }

    Trampoline[Hook->OriginalBytesSize + 0] = 0xFF;
    Trampoline[Hook->OriginalBytesSize + 1] = 0x25;
    *(PULONG)(Trampoline + Hook->OriginalBytesSize + 2) = 0;
    *(PULONG64)(Trampoline + Hook->OriginalBytesSize + 6) = TargetVa + Hook->OriginalBytesSize;

    /* Fill hook entry */
    Hook->TargetVirtualAddr = TargetVa;
    Hook->TargetPhysicalAddr = PageBase;
    Hook->TargetPageOffset = PageOffset;
    Hook->HookFunction = HookFunction;
    Hook->TargetPte = Pte;
    Hook->Active = TRUE;
    g_NptHookState.HookCount++;

    /*
     * BUG FIX (Issue #3+5+6): Insert into hook hash table for O(1) lookup.
     */
    {
        ULONG hookArrayIdx = (ULONG)(Hook - g_NptHookState.Hooks);
        ULONG htSlot = NptHookHashFn(PageBase);
        ULONG htI;
        for (htI = 0; htI < EPT_HOOK_HASH_SIZE; htI++) {
            ULONG htIdx = (htSlot + htI) & (EPT_HOOK_HASH_SIZE - 1);
            if (g_NptHookState.HookHashTable[htIdx] == EPT_HOOK_HASH_EMPTY) {
                g_NptHookState.HookHashTable[htIdx] = hookArrayIdx;
                break;
            }
        }
    }

    Pte->Read = 1;
    Pte->Write = 0;
    Pte->Execute = 1;
    Pte->PhysAddr = Hook->HookPagePa >> 12;

    /*
     * Per-CPU hook page isolation:
     * Clone the PD and split PT page for this 2MB region to all CPUs,
     * then replicate the same PTE permissions on each CPU's private copy.
     */
    if (g_NptCpuStates && g_NptPerCpuSplitPages && g_NptPerCpuPdPages) {
        ULONG PdptIdx = (ULONG)((PageBase >> 30) & 0x1FF);
        ULONG PdIdx   = (ULONG)((PageBase >> 21) & 0x1FF);
        ULONG splitIdx, cpu;
        NTSTATUS PerCpuStatus;

        PerCpuStatus = NptEnsurePerCpuPdForRegion(PdptIdx);
        if (NT_SUCCESS(PerCpuStatus)) {
            /*
             * BUG FIX (Issue #3+5+6): Use hash lookup for split page index.
             */
            splitIdx = NptSplitHashLookup(PageBase & ~((2ULL * 1024 * 1024) - 1));
            if (splitIdx != EPT_SPLIT_HASH_EMPTY && splitIdx < NPT_MAX_SPLIT_PAGES) {
                PerCpuStatus = NptEnsurePerCpuSplitPage(splitIdx, PdptIdx, PdIdx);
                if (NT_SUCCESS(PerCpuStatus)) {
                    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
                        PEPT_PTE CpuPte = NptGetPerCpuPte(cpu, TargetPa);
                        if (CpuPte) {
                            CpuPte->Read = Pte->Read;
                            CpuPte->Write = Pte->Write;
                            CpuPte->Execute = Pte->Execute;
                            CpuPte->PhysAddr = Pte->PhysAddr;
                        }
                    }
                    LOG_INFO("Per-CPU NPT isolation set up for hook at PA=0x%llX", PageBase);
                }
            }
        }
    }

    if (OriginalFunction) {
        *OriginalFunction = Hook->TrampolineVa;
    }

    KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);

    NptInvalidateAll();

    LOG_INFO("NPT Hook installed: VA=0x%llX -> Hook=0x%p, Trampoline=0x%p%s",
             TargetVa, HookFunction, Hook->TrampolineVa,
             PageOwner ? " (shared page)" : "");

    return STATUS_SUCCESS;
}

NTSTATUS NptUnhookFunction(ULONG64 TargetVa)
{
    KIRQL   OldIrql;
    ULONG   i;

    KeAcquireSpinLock(&g_NptHookState.Lock, &OldIrql);

    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        PEPT_HOOK_ENTRY Hook = &g_NptHookState.Hooks[i];

        if (Hook->Active && Hook->TargetVirtualAddr == TargetVa) {
            ULONG64 PageBase = Hook->TargetPhysicalAddr;
            BOOLEAN OtherHooksOnPage = FALSE;
            ULONG   j;

            /* Restore original bytes on shared HookPage */
            if (Hook->HookPageVa) {
                PUCHAR HookPoint = (PUCHAR)Hook->HookPageVa + Hook->TargetPageOffset;
                RtlCopyMemory(HookPoint, Hook->OriginalBytes, Hook->OriginalBytesSize);
            }

            /* Check if other hooks share this page */
            for (j = 0; j < NPT_MAX_HOOKS; j++) {
                if (j != i &&
                    g_NptHookState.Hooks[j].Active &&
                    g_NptHookState.Hooks[j].TargetPhysicalAddr == PageBase)
                {
                    OtherHooksOnPage = TRUE;
                    break;
                }
            }

            if (!OtherHooksOnPage) {
                /*
                 * BUG FIX (Review Issue #2): Two-pass single-function unhook.
                 *
                 * Same UAF pattern as was fixed in NptUnhookAll:
                 * Pass 1: Restore NPT PTEs to original physical address (RWX).
                 * Then flush TLB before freeing pages, so stale TLB entries on
                 * other CPUs won't reference freed memory.
                 */
                PVOID FreeOriginalPage = Hook->OwnsPages ? Hook->OriginalPageVa : NULL;
                PVOID FreeHookPage     = Hook->OwnsPages ? Hook->HookPageVa : NULL;

                /* Pass 1: Restore NPT mapping */
                if (Hook->TargetPte) {
                    Hook->TargetPte->Read = 1;
                    Hook->TargetPte->Write = 1;
                    Hook->TargetPte->Execute = 1;
                    Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
                }

                /* Also restore all per-CPU PTEs for this page */
                if (g_NptCpuStates && g_NptPerCpuSplitPages) {
                    ULONG cpu;
                    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
                        PEPT_PTE CpuPte = NptGetPerCpuPte(cpu, Hook->TargetPhysicalAddr);
                        if (CpuPte) {
                            CpuPte->Read = 1;
                            CpuPte->Write = 1;
                            CpuPte->Execute = 1;
                            CpuPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
                        }
                    }
                }

                if (Hook->TrampolineVa) ExFreePoolWithTag(Hook->TrampolineVa, SVM_TAG);

                RtlZeroMemory(Hook, sizeof(EPT_HOOK_ENTRY));
                g_NptHookState.HookCount--;
                NptHookHashRebuild();

                KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);

                /* TLB flush BEFORE freeing pages — prevents UAF from stale TLB */
                NptInvalidateAll();

                /* Pass 2: Now safe to free pages */
                if (FreeOriginalPage) ExFreePoolWithTag(FreeOriginalPage, SVM_TAG);
                if (FreeHookPage)     ExFreePoolWithTag(FreeHookPage, SVM_TAG);
            } else {
                if (Hook->OwnsPages) {
                    PEPT_HOOK_ENTRY NewOwner = &g_NptHookState.Hooks[j];
                    NewOwner->OwnsPages = TRUE;
                }

                if (Hook->TrampolineVa) ExFreePoolWithTag(Hook->TrampolineVa, SVM_TAG);

                RtlZeroMemory(Hook, sizeof(EPT_HOOK_ENTRY));
                g_NptHookState.HookCount--;

                /*
                 * BUG FIX (Issue #3+5+6): Rebuild hook hash table after removal.
                 */
                NptHookHashRebuild();

                KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
                NptInvalidateAll();
            }

            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
    return STATUS_NOT_FOUND;
}

VOID NptUnhookAll(VOID)
{
    KIRQL   OldIrql;
    ULONG   i;

    if (!g_NptHookState.Initialized) return;

    KeAcquireSpinLock(&g_NptHookState.Lock, &OldIrql);

    /*
     * BUG FIX (Issue #7+10 mirror to NPT): Two-pass unhook to avoid UAF.
     *
     * Pass 1: Restore all NPT PTEs to original physical addresses (RWX).
     *         Do NOT free any pages yet — other CPUs may still have stale TLB
     *         entries pointing to HookPage/OriginalPage. Freeing here would
     *         create a use-after-free window.
     *
     * Then: Flush TLB on all CPUs to clear stale entries.
     *
     * Pass 2: Now safe to free HookPage/OriginalPage/Trampoline memory
     *         since no CPU can reference them via stale TLB entries.
     */

    /* Pass 1: Restore all PTEs */
    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        PEPT_HOOK_ENTRY Hook = &g_NptHookState.Hooks[i];

        if (Hook->Active) {
            if (Hook->TargetPte) {
                Hook->TargetPte->Read = 1;
                Hook->TargetPte->Write = 1;
                Hook->TargetPte->Execute = 1;
                Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
            }

            /* Also restore all per-CPU PTEs for this page */
            if (g_NptCpuStates && g_NptPerCpuSplitPages) {
                ULONG cpu;
                for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
                    PEPT_PTE CpuPte = NptGetPerCpuPte(cpu, Hook->TargetPhysicalAddr);
                    if (CpuPte) {
                        CpuPte->Read = 1;
                        CpuPte->Write = 1;
                        CpuPte->Execute = 1;
                        CpuPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
                    }
                }
            }
        }
    }

    KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);

    /*
     * Flush NPT TLB on all CPUs BEFORE freeing any pages.
     * This ensures no CPU still has stale TLB entries pointing to
     * pages we're about to free.
     */
    NptInvalidateAll();

    /* Pass 2: Free memory (safe now that TLB is flushed) */
    KeAcquireSpinLock(&g_NptHookState.Lock, &OldIrql);

    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        PEPT_HOOK_ENTRY Hook = &g_NptHookState.Hooks[i];

        if (Hook->Active) {
            /* Only page owners free the shared pages */
            if (Hook->OwnsPages) {
                if (Hook->OriginalPageVa) ExFreePoolWithTag(Hook->OriginalPageVa, SVM_TAG);
                if (Hook->HookPageVa)     ExFreePoolWithTag(Hook->HookPageVa, SVM_TAG);
            }

            /* Trampoline is always per-hook */
            if (Hook->TrampolineVa) ExFreePoolWithTag(Hook->TrampolineVa, SVM_TAG);

            RtlZeroMemory(Hook, sizeof(EPT_HOOK_ENTRY));
        }
    }

    g_NptHookState.HookCount = 0;

    /*
     * BUG FIX (Issue #3+5+6): Clear hook hash table — all hooks removed.
     */
    {
        ULONG htIdx;
        for (htIdx = 0; htIdx < EPT_HOOK_HASH_SIZE; htIdx++)
            g_NptHookState.HookHashTable[htIdx] = EPT_HOOK_HASH_EMPTY;
    }

    KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
}

/* ========================================================================= */
/*  NPT Hook Lookup                                                          */
/* ========================================================================= */

/*
 * BUG FIX (Issue #3+5+6): O(1) hook lookup using hash table (NPT side).
 * Mirrors the EPT optimization in EptFindHookByPhysicalAddress.
 */
PEPT_HOOK_ENTRY NptFindHookByPhysicalAddress(ULONG64 PhysicalAddress)
{
    ULONG64 PagePa = PhysicalAddress & ~0xFFFULL;
    ULONG Slot = NptHookHashFn(PagePa);
    ULONG i;

    for (i = 0; i < EPT_HOOK_HASH_SIZE; i++) {
        ULONG Idx = (Slot + i) & (EPT_HOOK_HASH_SIZE - 1);
        ULONG HookIdx = g_NptHookState.HookHashTable[Idx];

        if (HookIdx == EPT_HOOK_HASH_EMPTY)
            return NULL;

        if (HookIdx < NPT_MAX_HOOKS &&
            g_NptHookState.Hooks[HookIdx].Active &&
            g_NptHookState.Hooks[HookIdx].TargetPhysicalAddr == PagePa) {
            return &g_NptHookState.Hooks[HookIdx];
        }
    }
    return NULL;
}

/* ========================================================================= */
/*  NPT Page Fault (#NPF) Handler                                           */
/* ========================================================================= */

/*
 * Called from SVM exit handler when SVM_EXIT_NPF occurs.
 *
 * exit_info_1: Error code bits (P, W, U, RSV, ID)
 * exit_info_2: Guest physical address that caused the fault
 *
 * NPT Hook handling:
 * Since we map hooked pages as Read+Execute (no Write):
 *   - Write access -> NPF: temporarily give R+W+X with original page,
 *     enable single-step, after step restore R+X with hook page
 *   - Execution is already allowed via hook page
 */
BOOLEAN NptHandlePageFault(PVOID GuestContext)
{
    PSVM_CPU_CONTEXT    CpuCtx;
    PVMCB               Vmcb;
    ULONG64             GuestPhysAddr;
    ULONG64             ExitInfo1;
    PEPT_HOOK_ENTRY     Hook;
    PEPT_PTE            Pte;

    UNREFERENCED_PARAMETER(GuestContext);

    {
        ULONG CpuNum = KeGetCurrentProcessorNumber();
        if (CpuNum >= g_MaxProcessors || !g_SvmState.CpuContexts) {
            return FALSE;
        }
        CpuCtx = &g_SvmState.CpuContexts[CpuNum];
    }
    Vmcb = CpuCtx->VmcbVa;

    ExitInfo1 = Vmcb->Control.ExitInfo1;
    GuestPhysAddr = Vmcb->Control.ExitInfo2;

    Hook = NptFindHookByPhysicalAddress(GuestPhysAddr);

    if (!Hook) {
        /* NPF on non-hooked page - fix by setting R+W+X */
        LOG_WARN("NPF on non-hooked page: GPA=0x%llX, Info1=0x%llX",
                 GuestPhysAddr, ExitInfo1);

        {
            ULONG CpuIdx = KeGetCurrentProcessorNumber();
            Pte = NptGetPerCpuPte(CpuIdx, GuestPhysAddr);
            if (!Pte) Pte = NptGetPteForPhysicalAddress(GuestPhysAddr);
        }
        if (Pte) {
            Pte->Read = 1;
            Pte->Write = 1;
            Pte->Execute = 1;
            NptInvalidateAll();
        }
        return TRUE;
    }

    /*
     * Per-CPU hook page isolation: use this CPU's private PTE if available.
     * This eliminates the multi-core race condition where two CPUs
     * simultaneously toggle the same shared PTE.
     */
    {
        ULONG CpuIdx = KeGetCurrentProcessorNumber();
        Pte = NptGetPerCpuPte(CpuIdx, Hook->TargetPhysicalAddr);
        if (!Pte) Pte = Hook->TargetPte;
    }

    /*
     * BUG FIX (Review Issue #7): Unified fault handling.
     *
     * Both write faults and unexpected read faults on hooked pages need the
     * same treatment: temporarily map original page with R+W+X, enable TF
     * for single-step. After #DB fires, we restore R+X with hook page.
     *
     * Note: With R+X hook mapping, only writes should fault. If we get a
     * read/execute fault here, it indicates an unexpected state (race
     * condition or hardware quirk) — handle it the same way for safety.
     */
    Pte->Read = 1;
    Pte->Write = 1;
    Pte->Execute = 1;
    Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;

    NptInvalidateAll();

    /* Track which page this CPU relaxed (for per-CPU #DB restore) */
    NptDbTrackRelaxedPage(Hook->TargetPhysicalAddr);

    /* Enable single-step via RFLAGS.TF */
    Vmcb->Save.Rflags |= (1ULL << 8);  /* Set TF */

    /* Don't advance RIP - re-execute the faulting instruction */
    return TRUE;
}

/* ========================================================================= */
/*  Per-CPU NPT Management (Hook Page Isolation)                             */
/* ========================================================================= */

NTSTATUS NptInitPerCpu(VOID)
{
    ULONG i;

    if (!g_NptState.Initialized || g_MaxProcessors == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    g_NptCpuStates = (PNPT_CPU_STATE)ExAllocatePoolWithTag(
        NonPagedPool, g_MaxProcessors * sizeof(NPT_CPU_STATE), 'tpNC');
    if (!g_NptCpuStates) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_NptCpuStates, g_MaxProcessors * sizeof(NPT_CPU_STATE));

    g_NptPerCpuSplitPages = (PNPT_PER_CPU_SPLIT *)ExAllocatePoolWithTag(
        NonPagedPool, g_MaxProcessors * sizeof(PNPT_PER_CPU_SPLIT), 'tpNS');
    if (!g_NptPerCpuSplitPages) {
        ExFreePoolWithTag(g_NptCpuStates, 'tpNC');
        g_NptCpuStates = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_NptPerCpuSplitPages, g_MaxProcessors * sizeof(PNPT_PER_CPU_SPLIT));

    g_NptPerCpuPdPages = (NPT_PER_CPU_PD_PAGE **)ExAllocatePoolWithTag(
        NonPagedPool, g_MaxProcessors * sizeof(NPT_PER_CPU_PD_PAGE *), 'tpNP');
    if (!g_NptPerCpuPdPages) {
        ExFreePoolWithTag(g_NptPerCpuSplitPages, 'tpNS');
        g_NptPerCpuSplitPages = NULL;
        ExFreePoolWithTag(g_NptCpuStates, 'tpNC');
        g_NptCpuStates = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_NptPerCpuPdPages, g_MaxProcessors * sizeof(NPT_PER_CPU_PD_PAGE *));

    for (i = 0; i < g_MaxProcessors; i++) {
        ULONG64 PdptPa;

        RtlCopyMemory(g_NptCpuStates[i].Pml4, g_NptState.Pml4, sizeof(g_NptState.Pml4));
        RtlCopyMemory(g_NptCpuStates[i].Pdpt, g_NptState.Pdpt, sizeof(g_NptState.Pdpt));

        PdptPa = NptVaToPhysical(g_NptCpuStates[i].Pdpt);
        g_NptCpuStates[i].Pml4[0].PhysAddr = PdptPa >> 12;

        g_NptCpuStates[i].Pml4Pa = NptVaToPhysical(g_NptCpuStates[i].Pml4);
    }

    RtlZeroMemory(g_NptPerCpuPdAllocated, sizeof(g_NptPerCpuPdAllocated));

    LOG_INFO("Per-CPU NPT initialized for %u CPUs", g_MaxProcessors);
    return STATUS_SUCCESS;
}

VOID NptCleanupPerCpu(VOID)
{
    ULONG cpu;

    if (g_NptPerCpuSplitPages) {
        for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
            if (g_NptPerCpuSplitPages[cpu]) {
                ExFreePoolWithTag(g_NptPerCpuSplitPages[cpu], 'tpNS');
            }
        }
        ExFreePoolWithTag(g_NptPerCpuSplitPages, 'tpNS');
        g_NptPerCpuSplitPages = NULL;
    }

    if (g_NptPerCpuPdPages) {
        for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
            if (g_NptPerCpuPdPages[cpu]) {
                ExFreePoolWithTag(g_NptPerCpuPdPages[cpu], 'tpNP');
            }
        }
        ExFreePoolWithTag(g_NptPerCpuPdPages, 'tpNP');
        g_NptPerCpuPdPages = NULL;
    }

    if (g_NptCpuStates) {
        ExFreePoolWithTag(g_NptCpuStates, 'tpNC');
        g_NptCpuStates = NULL;
    }

    LOG_INFO("Per-CPU NPT cleaned up");
}

static NTSTATUS NptEnsurePerCpuPdForRegion(ULONG PdptIndex)
{
    ULONG cpu;

    if (PdptIndex >= NPT_MAX_PD_PAGES) return STATUS_INVALID_PARAMETER;
    if (g_NptPerCpuPdAllocated[PdptIndex]) return STATUS_SUCCESS;

    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (!g_NptPerCpuPdPages[cpu]) {
            g_NptPerCpuPdPages[cpu] = (NPT_PER_CPU_PD_PAGE *)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(NPT_PER_CPU_PD_PAGE) * NPT_MAX_PD_PAGES, 'tpNP');
            if (!g_NptPerCpuPdPages[cpu]) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(g_NptPerCpuPdPages[cpu], g_NptPdPages,
                          sizeof(NPT_PER_CPU_PD_PAGE) * NPT_MAX_PD_PAGES);
        }

        {
            ULONG64 CpuPdPa = NptVaToPhysical(&g_NptPerCpuPdPages[cpu][PdptIndex]);
            g_NptCpuStates[cpu].Pdpt[PdptIndex].PhysAddr = CpuPdPa >> 12;
        }
    }

    g_NptPerCpuPdAllocated[PdptIndex] = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS NptEnsurePerCpuSplitPage(ULONG splitIdx, ULONG PdptIndex, ULONG PdIndex)
{
    ULONG cpu;

    if (splitIdx >= NPT_MAX_SPLIT_PAGES) return STATUS_INVALID_PARAMETER;

    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (!g_NptPerCpuSplitPages[cpu]) {
            g_NptPerCpuSplitPages[cpu] = (PNPT_PER_CPU_SPLIT)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(NPT_PER_CPU_SPLIT) * NPT_MAX_SPLIT_PAGES, 'tpNS');
            if (!g_NptPerCpuSplitPages[cpu]) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(g_NptPerCpuSplitPages[cpu],
                          sizeof(NPT_PER_CPU_SPLIT) * NPT_MAX_SPLIT_PAGES);
        }

        if (!g_NptPerCpuSplitPages[cpu][splitIdx].Allocated) {
            RtlCopyMemory(g_NptPerCpuSplitPages[cpu][splitIdx].Pte,
                          g_NptSplitPages[splitIdx].Pte,
                          sizeof(EPT_PTE) * EPT_PTE_COUNT);
            g_NptPerCpuSplitPages[cpu][splitIdx].PhysicalAddress =
                NptVaToPhysical(g_NptPerCpuSplitPages[cpu][splitIdx].Pte);
            g_NptPerCpuSplitPages[cpu][splitIdx].Allocated = TRUE;
        }

        if (g_NptPerCpuPdPages[cpu]) {
            PEPT_PDE CpuPde = &g_NptPerCpuPdPages[cpu][PdptIndex].Entries[PdIndex];
            CpuPde->Value = 0;
            CpuPde->Read = 1;
            CpuPde->Write = 1;
            CpuPde->Execute = 1;
            CpuPde->LargePage = 0;
            CpuPde->PhysAddr = g_NptPerCpuSplitPages[cpu][splitIdx].PhysicalAddress >> 12;
        }
    }

    return STATUS_SUCCESS;
}

/*
 * BUG FIX (Issue #3+5+6): O(1) hash lookup instead of O(n) linear scan.
 */
PEPT_PTE NptGetPerCpuPte(ULONG CpuIndex, ULONG64 PhysicalAddress)
{
    ULONG64 Base2MB;
    ULONG   PtIndex;
    ULONG   splitIdx;

    if (!g_NptPerCpuSplitPages || CpuIndex >= g_MaxProcessors ||
        !g_NptPerCpuSplitPages[CpuIndex]) {
        return NULL;
    }

    Base2MB = PhysicalAddress & ~((2ULL * 1024 * 1024) - 1);
    PtIndex = (ULONG)((PhysicalAddress >> 12) & 0x1FF);

    splitIdx = NptSplitHashLookup(Base2MB);
    if (splitIdx != EPT_SPLIT_HASH_EMPTY && splitIdx < NPT_MAX_SPLIT_PAGES &&
        g_NptPerCpuSplitPages[CpuIndex][splitIdx].Allocated) {
        return &g_NptPerCpuSplitPages[CpuIndex][splitIdx].Pte[PtIndex];
    }

    return NULL;
}

ULONG64 NptGetPerCpuRootPa(ULONG CpuIndex)
{
    if (g_NptCpuStates && CpuIndex < g_MaxProcessors) {
        return g_NptCpuStates[CpuIndex].Pml4Pa;
    }
    return 0;
}

/* ========================================================================= */
/*  TLB Invalidation                                                         */
/* ========================================================================= */

/*
 * For AMD SVM, TLB invalidation is done by setting TlbCtl in the VMCB.
 * The next VMRUN will flush TLB entries.
 * We set it on all CPUs' VMCBs.
 */
VOID NptInvalidateAll(VOID)
{
    ULONG i;

    /*
     * BUG FIX (Review Issue #6): Guard against NULL dereference.
     * CpuContexts may be NULL if called before SVM init or after cleanup.
     */
    if (!g_SvmState.CpuContexts) return;

    for (i = 0; i < g_SvmState.CpuCount; i++) {
        if (g_SvmState.CpuContexts[i].VmcbVa) {
            g_SvmState.CpuContexts[i].VmcbVa->Control.TlbCtl = TLB_CONTROL_FLUSH_ALL_ASID;
        }
    }
}
