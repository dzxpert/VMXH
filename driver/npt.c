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
static NTSTATUS NptEnsurePerCpuPdForRegion(ULONG FlatPdptIndex);
static NTSTATUS NptEnsurePerCpuSplitPage(ULONG splitIdx, ULONG FlatPdptIndex, ULONG PdIndex);

/* ========================================================================= */
/*  Constants (needed before global array declarations)                      */
/* ========================================================================= */

/* Page directory and split page pools (same as EPT) */
#define NPT_MAX_SPLIT_PAGES    128

/*
 * Default / minimum PD-page count for the NPT identity map.
 *
 * See ept.c for the full rationale (mirror of EPT side).  The embedded
 * g_NptState.Pdpt[] covers the first 512GB of PA space via 2MB large pages.
 * For hosts with physical memory / MMIO > 512GB we allocate additional
 * PDPT pages and hook them onto PML4[1..g_NptPml4Count-1].
 */
#define NPT_DEFAULT_PD_PAGES   EPT_PDPTE_COUNT                        /* 512 → 512GB */
#define NPT_MAX_PD_PAGES_CAP   (EPT_PML4E_COUNT * EPT_PDPTE_COUNT)    /* 256TB */

/* Runtime-resolved identity-map sizing; set once by NptInitialize(). */
static ULONG g_NptPdptTotal  = NPT_DEFAULT_PD_PAGES;
static ULONG g_NptPml4Count  = 1;

/* ========================================================================= */
/*  Globals                                                                  */
/* ========================================================================= */

NPT_STATE       g_NptState = { 0 };
NPT_HOOK_STATE  g_NptHookState = { 0 };
PNPT_CPU_STATE  g_NptCpuStates = NULL;     /* per-CPU NPT root array */

/*
 * Extended PDPT pages for NPT PML4[1..N-1] when identity map > 512GB.
 */
typedef struct _NPT_PDPT_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Entries[EPT_PDPTE_COUNT];
} NPT_PDPT_PAGE;

static NPT_PDPT_PAGE  *g_NptExtPdptPages = NULL;
static NPT_PDPT_PAGE **g_NptCpuExtPdpt   = NULL;

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
static PBOOLEAN g_NptPerCpuPdAllocated = NULL;  /* [g_NptPdptTotal] */

/*
 * Per-CPU tracking of which physical page was temporarily made permissive
 * by the NPF handler. The #DB handler reads and clears this to know which
 * page to restore, avoiding a multi-core race condition.
 *
 * This is the AMD-side equivalent of g_MtfRelaxedPagePa in ept.c.
 *
 * M-4: additionally track the guest RIP at the time of the relaxation so
 * the #DB handler can distinguish "our" single-step #DB (RIP has advanced
 * by a few bytes from the recorded value) from the guest's own #DB (RIP
 * is nowhere near the recorded hook-target instruction).  Misclassifying
 * a guest #DB as ours would swallow the exception and break user
 * debuggers; misclassifying ours as the guest's would leave the page
 * permissive forever (silent hook bypass).
 */
static volatile ULONG64 *g_NptDbRelaxedPagePa  = NULL;  /* dynamic [g_MaxProcessors] — tracker "armed" flag (non-zero = active) */
static volatile ULONG64 *g_NptDbRelaxedRip     = NULL;  /* dynamic [g_MaxProcessors] */
static volatile ULONG64 *g_NptDbRelaxedCr3     = NULL;  /* dynamic [g_MaxProcessors] — M-4: pair Rip with Cr3 to disambiguate cross-process coincidence */

/*
 * M-4 (revised): per-CPU #DB relaxation tracker.
 *
 * When NptHandlePageFault makes a hooked page temporarily permissive to
 * let a guest instruction complete, we set TF=1 so that #DB fires right
 * after that single instruction — the #DB handler then re-tightens the
 * hook and clears TF.  Recording {PagePa, Rip, Cr3} at the moment of
 * relaxation lets the #DB handler verify the event really belongs to
 * that sequence:
 *
 *   - PagePa  — acts as the "armed" flag (0 = no tracker, !=0 = armed).
 *   - Rip     — must still be within a 15-byte (max-insn-length) window
 *               from the recorded value.  Larger drift ⇒ branch /
 *               interrupt / unrelated #DB ⇒ not ours.
 *   - Cr3     — must match the recorded CR3.  A context switch that
 *               happens to land on a nearby RIP in a DIFFERENT address
 *               space must NOT be mistaken for our single-step.
 *
 * Memory ordering (critical for correctness on weakly-ordered paths):
 *
 *   TRACKER SIDE (NptDbTrackRelaxedPage):
 *       write Rip
 *       write Cr3
 *       _WriteBarrier()      ; prevent store-store reorder below
 *       write PagePa         ; arms the tracker; MUST be last
 *
 *   OBSERVER SIDE (NptDbSnapshotRelaxedTracker):
 *       read PagePa          ; if 0, bail out
 *       _ReadBarrier()       ; prevent load-load reorder below
 *       read Cr3
 *       read Rip
 *
 *   With this discipline, whenever the observer sees PagePa != 0, the
 *   Cr3/Rip it reads are guaranteed to be the pair that was written
 *   BEFORE that PagePa (not stale values from a previous arming).
 *
 *   x86 has a strong memory model so _WriteBarrier / _ReadBarrier here
 *   are effectively compiler barriers only — but writing them makes
 *   the intent explicit and guards against cross-platform drift.
 */

VOID NptDbTrackRelaxedPage(ULONG64 PagePhysicalAddr)
{
    ULONG    CpuIndex = KeGetCurrentProcessorNumber();
    ULONG64  GuestRip = 0;
    ULONG64  GuestCr3 = 0;

    if (CpuIndex >= g_MaxProcessors)  return;
    if (!g_NptDbRelaxedPagePa)        return;
    if (!g_NptDbRelaxedRip)           return;
    if (!g_NptDbRelaxedCr3)           return;

    if (g_SvmState.CpuContexts) {
        PVMCB Vmcb = g_SvmState.CpuContexts[CpuIndex].VmcbVa;
        if (Vmcb) {
            GuestRip = Vmcb->Save.Rip;
            GuestCr3 = Vmcb->Save.Cr3;
        }
    }

    /* Write Rip and Cr3 first. */
    g_NptDbRelaxedRip[CpuIndex] = GuestRip;
    g_NptDbRelaxedCr3[CpuIndex] = GuestCr3;

    /*
     * Ensure Rip/Cr3 stores are visible BEFORE we arm the tracker by
     * writing PagePa last.  _WriteBarrier is a compiler barrier which
     * combined with x86's strong ordering is sufficient.
     */
    _WriteBarrier();

    g_NptDbRelaxedPagePa[CpuIndex] = PagePhysicalAddr;
}

/*
 * Atomic snapshot: returns all three recorded values in one go (if any).
 * Does NOT clear the tracker — use NptDbClearRelaxedTracker for that.
 */
typedef struct _NPT_DB_SNAPSHOT {
    ULONG64 PagePa;
    ULONG64 Rip;
    ULONG64 Cr3;
} NPT_DB_SNAPSHOT, *PNPT_DB_SNAPSHOT;

static VOID NptDbSnapshotRelaxedTracker(PNPT_DB_SNAPSHOT Snapshot)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();

    Snapshot->PagePa = 0;
    Snapshot->Rip    = 0;
    Snapshot->Cr3    = 0;

    if (CpuIndex >= g_MaxProcessors)  return;
    if (!g_NptDbRelaxedPagePa)        return;
    if (!g_NptDbRelaxedRip)           return;
    if (!g_NptDbRelaxedCr3)           return;

    Snapshot->PagePa = g_NptDbRelaxedPagePa[CpuIndex];
    _ReadBarrier();
    Snapshot->Cr3    = g_NptDbRelaxedCr3[CpuIndex];
    Snapshot->Rip    = g_NptDbRelaxedRip[CpuIndex];
}

static VOID NptDbClearRelaxedTracker(VOID)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    if (CpuIndex >= g_MaxProcessors) return;
    /* Clear the "armed" flag FIRST — subsequent snapshot reads will bail out. */
    if (g_NptDbRelaxedPagePa)        g_NptDbRelaxedPagePa[CpuIndex] = 0;
    _WriteBarrier();
    if (g_NptDbRelaxedRip)           g_NptDbRelaxedRip[CpuIndex] = 0;
    if (g_NptDbRelaxedCr3)           g_NptDbRelaxedCr3[CpuIndex] = 0;
}

/*
 * NptDbGetAndClearRelaxedPage - legacy API kept for source compatibility.
 * Returns just the PagePa (the caller has already validated via
 * NptDbMatchesOurRelaxation that this #DB is ours).
 */
ULONG64 NptDbGetAndClearRelaxedPage(VOID)
{
    NPT_DB_SNAPSHOT Snap;
    ULONG64 Pa;

    NptDbSnapshotRelaxedTracker(&Snap);
    Pa = Snap.PagePa;
    NptDbClearRelaxedTracker();
    return Pa;
}

/*
 * M-4 (revised): return TRUE iff the current #DB matches the tracker
 * recorded at the last NptDbTrackRelaxedPage call — that is, same CR3
 * AND current RIP is within 15 bytes ahead of the recorded RIP.  This
 * is the authoritative "is this #DB ours?" test.  The legacy name
 * NptDbMatchesRelaxedRip is kept because callers already exist.
 *
 * Does NOT clear the tracker; the caller clears only after also doing
 * the hook-restore work.
 */
BOOLEAN NptDbMatchesRelaxedRip(ULONG64 CurrentRip)
{
    NPT_DB_SNAPSHOT Snap;
    ULONG CpuIndex;

    NptDbSnapshotRelaxedTracker(&Snap);
    if (Snap.PagePa == 0) return FALSE;   /* not armed */

    /* Compare CR3 — rejects cross-process RIP coincidence. */
    if (g_SvmState.CpuContexts) {
        CpuIndex = KeGetCurrentProcessorNumber();
        if (CpuIndex < g_MaxProcessors) {
            PVMCB Vmcb = g_SvmState.CpuContexts[CpuIndex].VmcbVa;
            if (Vmcb) {
                /*
                 * Mask PCID + high bits — same logic as
                 * ProcessFindByCr3 (M-2).
                 */
                ULONG64 CurCr3 = Vmcb->Save.Cr3 & 0x000FFFFFFFFFF000ULL;
                ULONG64 OldCr3 = Snap.Cr3       & 0x000FFFFFFFFFF000ULL;
                if (CurCr3 != OldCr3) return FALSE;
            }
        }
    }

    /* Compare RIP window. */
    if (CurrentRip >= Snap.Rip && (CurrentRip - Snap.Rip) <= 15) {
        return TRUE;
    }
    return FALSE;
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
/*  Flat PDPT-index helpers (for > 512GB identity map support, mirror of EPT)*/
/* ========================================================================= */

static __forceinline ULONG NptPaToFlatPdptIdx(ULONG64 PhysicalAddress)
{
    ULONG64 Flat = PhysicalAddress >> 30;
    if (Flat >= (ULONG64)g_NptPdptTotal) return (ULONG)-1;
    return (ULONG)Flat;
}

static __forceinline VOID NptFlatIdxSplit(ULONG FlatIdx, PULONG Pml4Idx, PULONG PdptIdx)
{
    *Pml4Idx = FlatIdx >> 9;
    *PdptIdx = FlatIdx & 0x1FF;
}

static __forceinline PEPT_PDPTE NptGetSharedPdptePtr(ULONG FlatIdx)
{
    ULONG Pml4Idx, PdptIdx;
    NptFlatIdxSplit(FlatIdx, &Pml4Idx, &PdptIdx);
    if (Pml4Idx == 0) {
        return &g_NptState.Pdpt[PdptIdx];
    }
    if (g_NptExtPdptPages) {
        return &g_NptExtPdptPages[Pml4Idx - 1].Entries[PdptIdx];
    }
    return NULL;
}

static __forceinline PEPT_PDPTE NptGetCpuPdptePtr(ULONG CpuIndex, ULONG FlatIdx)
{
    ULONG Pml4Idx, PdptIdx;
    if (!g_NptCpuStates || CpuIndex >= g_MaxProcessors) return NULL;
    NptFlatIdxSplit(FlatIdx, &Pml4Idx, &PdptIdx);
    if (Pml4Idx == 0) {
        return &g_NptCpuStates[CpuIndex].Pdpt[PdptIdx];
    }
    if (g_NptCpuExtPdpt && g_NptCpuExtPdpt[CpuIndex]) {
        return &g_NptCpuExtPdpt[CpuIndex][Pml4Idx - 1].Entries[PdptIdx];
    }
    return NULL;
}

static ULONG NptComputeRequiredPdPages(VOID)
{
    PPHYSICAL_MEMORY_RANGE Ranges;
    ULONG64 MaxPa = 0;
    ULONG   i;
    ULONG64 Required1GB;

    Ranges = MmGetPhysicalMemoryRanges();
    if (Ranges) {
        for (i = 0; Ranges[i].BaseAddress.QuadPart != 0 || Ranges[i].NumberOfBytes.QuadPart != 0; i++) {
            ULONG64 End = (ULONG64)Ranges[i].BaseAddress.QuadPart +
                          (ULONG64)Ranges[i].NumberOfBytes.QuadPart;
            if (End > MaxPa) MaxPa = End;
        }
        ExFreePool(Ranges);
    }

    MaxPa += (2ULL * 1024 * 1024 * 1024);  /* 2GB headroom for MMIO */
    Required1GB = (MaxPa + ((1ULL << 30) - 1)) >> 30;

    if (Required1GB < NPT_DEFAULT_PD_PAGES) Required1GB = NPT_DEFAULT_PD_PAGES;
    if (Required1GB > NPT_MAX_PD_PAGES_CAP) Required1GB = NPT_MAX_PD_PAGES_CAP;

    /* Round up to whole PDPT page */
    Required1GB = (Required1GB + 511) & ~((ULONG64)511);

    return (ULONG)Required1GB;
}

/* ========================================================================= */
/*  NPT Identity Map Setup                                                   */
/* ========================================================================= */

NTSTATUS NptInitialize(VOID)
{
    ULONG i, j;
    ULONG64 PhysAddr;
    ULONG64 PdptPa;
    ULONG   RequiredPdpt;
    ULONG   Pml4Count;

    if (g_NptState.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_NptState, sizeof(NPT_STATE));
    RtlZeroMemory(&g_NptHookState, sizeof(NPT_HOOK_STATE));
    KeInitializeSpinLock(&g_NptHookState.Lock);

    /* H-2: detect required identity-map size */
    RequiredPdpt = NptComputeRequiredPdPages();
    Pml4Count    = RequiredPdpt / EPT_PDPTE_COUNT;
    if (Pml4Count == 0) Pml4Count = 1;
    if (Pml4Count > EPT_PML4E_COUNT) {
        LOG_ERROR("NPT: required PML4 count %u exceeds hardware max %u",
                  Pml4Count, (ULONG)EPT_PML4E_COUNT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_NptPdptTotal = RequiredPdpt;
    g_NptPml4Count = Pml4Count;

    LOG_INFO("NPT identity map sizing: %u PDPT entries (%llu GB), %u PML4 entries",
             g_NptPdptTotal, (ULONG64)g_NptPdptTotal, g_NptPml4Count);

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

        /* M-4: parallel array for the guest RIP recorded at relaxation time. */
        g_NptDbRelaxedRip = (volatile ULONG64 *)ExAllocatePoolWithTag(
            NonPagedPool, g_MaxProcessors * sizeof(ULONG64), 'tpnR');
        if (!g_NptDbRelaxedRip) {
            LOG_ERROR("Failed to allocate NPT per-CPU RIP tracking array");
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedPagePa, 'tpnM');
            g_NptDbRelaxedPagePa = NULL;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory((PVOID)g_NptDbRelaxedRip, g_MaxProcessors * sizeof(ULONG64));

        /*
         * M-4 (revised): parallel array for the guest CR3 at relaxation.
         * Needed so the #DB handler can distinguish "our" single-step (same
         * process, RIP ≤ 15 bytes ahead) from a coincidental #DB in a
         * different address space that happens to land on the same RIP
         * value.  Without CR3 pairing, a context switch during the
         * single-step window could make a foreign #DB look like ours and
         * swallow it silently.
         */
        g_NptDbRelaxedCr3 = (volatile ULONG64 *)ExAllocatePoolWithTag(
            NonPagedPool, g_MaxProcessors * sizeof(ULONG64), 'tpnC');
        if (!g_NptDbRelaxedCr3) {
            LOG_ERROR("Failed to allocate NPT per-CPU CR3 tracking array");
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedRip, 'tpnR');
            g_NptDbRelaxedRip = NULL;
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedPagePa, 'tpnM');
            g_NptDbRelaxedPagePa = NULL;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory((PVOID)g_NptDbRelaxedCr3, g_MaxProcessors * sizeof(ULONG64));
    }

    /* Allocate Page Directory pages (H-2: sized by g_NptPdptTotal) */
    g_NptPdPages = (NPT_PD_PAGE *)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(NPT_PD_PAGE) * g_NptPdptTotal, SVM_TAG);
    if (!g_NptPdPages) {
        LOG_ERROR("Failed to allocate NPT page directory pages (%u pages)", g_NptPdptTotal);
        if (g_NptDbRelaxedPagePa) {
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedPagePa, 'tpnM');
            g_NptDbRelaxedPagePa = NULL;
        }
        if (g_NptDbRelaxedRip) {
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedRip, 'tpnR');
            g_NptDbRelaxedRip = NULL;
        }
        if (g_NptDbRelaxedCr3) {
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedCr3, 'tpnC');
            g_NptDbRelaxedCr3 = NULL;
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_NptPdPages, sizeof(NPT_PD_PAGE) * g_NptPdptTotal);

    /* H-2: allocate dynamic g_NptPerCpuPdAllocated bitmap */
    g_NptPerCpuPdAllocated = (PBOOLEAN)ExAllocatePoolWithTag(
        NonPagedPool, g_NptPdptTotal * sizeof(BOOLEAN), 'tpnA');
    if (!g_NptPerCpuPdAllocated) {
        LOG_ERROR("Failed to allocate NPT per-CPU PD tracking bitmap");
        ExFreePoolWithTag(g_NptPdPages, SVM_TAG); g_NptPdPages = NULL;
        if (g_NptDbRelaxedPagePa) { ExFreePoolWithTag((PVOID)g_NptDbRelaxedPagePa, 'tpnM'); g_NptDbRelaxedPagePa = NULL; }
        if (g_NptDbRelaxedRip)    { ExFreePoolWithTag((PVOID)g_NptDbRelaxedRip,    'tpnR'); g_NptDbRelaxedRip = NULL; }
        if (g_NptDbRelaxedCr3)    { ExFreePoolWithTag((PVOID)g_NptDbRelaxedCr3,    'tpnC'); g_NptDbRelaxedCr3 = NULL; }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_NptPerCpuPdAllocated, g_NptPdptTotal * sizeof(BOOLEAN));

    /* H-2: allocate extended PDPT pages for PML4[1..] if needed */
    if (g_NptPml4Count > 1) {
        ULONG ExtCount = g_NptPml4Count - 1;
        g_NptExtPdptPages = (NPT_PDPT_PAGE *)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(NPT_PDPT_PAGE) * ExtCount, 'tpnX');
        if (!g_NptExtPdptPages) {
            LOG_ERROR("Failed to allocate %u NPT extended PDPT pages", ExtCount);
            ExFreePoolWithTag(g_NptPerCpuPdAllocated, 'tpnA'); g_NptPerCpuPdAllocated = NULL;
            ExFreePoolWithTag(g_NptPdPages, SVM_TAG); g_NptPdPages = NULL;
            if (g_NptDbRelaxedPagePa) { ExFreePoolWithTag((PVOID)g_NptDbRelaxedPagePa, 'tpnM'); g_NptDbRelaxedPagePa = NULL; }
            if (g_NptDbRelaxedRip)    { ExFreePoolWithTag((PVOID)g_NptDbRelaxedRip,    'tpnR'); g_NptDbRelaxedRip = NULL; }
            if (g_NptDbRelaxedCr3)    { ExFreePoolWithTag((PVOID)g_NptDbRelaxedCr3,    'tpnC'); g_NptDbRelaxedCr3 = NULL; }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(g_NptExtPdptPages, sizeof(NPT_PDPT_PAGE) * ExtCount);
    }

    /* Allocate split page pool */
    g_NptSplitPages = (NPT_SPLIT_PAGE *)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(NPT_SPLIT_PAGE) * NPT_MAX_SPLIT_PAGES, SVM_TAG);
    if (!g_NptSplitPages) {
        LOG_ERROR("Failed to allocate NPT split page pool");
        if (g_NptExtPdptPages) { ExFreePoolWithTag(g_NptExtPdptPages, 'tpnX'); g_NptExtPdptPages = NULL; }
        ExFreePoolWithTag(g_NptPerCpuPdAllocated, 'tpnA'); g_NptPerCpuPdAllocated = NULL;
        ExFreePoolWithTag(g_NptPdPages, SVM_TAG); g_NptPdPages = NULL;
        if (g_NptDbRelaxedPagePa) {
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedPagePa, 'tpnM');
            g_NptDbRelaxedPagePa = NULL;
        }
        if (g_NptDbRelaxedRip) {
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedRip, 'tpnR');
            g_NptDbRelaxedRip = NULL;
        }
        if (g_NptDbRelaxedCr3) {
            ExFreePoolWithTag((PVOID)g_NptDbRelaxedCr3, 'tpnC');
            g_NptDbRelaxedCr3 = NULL;
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_NptSplitPages, sizeof(NPT_SPLIT_PAGE) * NPT_MAX_SPLIT_PAGES);

    /* Build identity-mapped NPT using 2MB large pages (flat index over all PML4s) */
    for (i = 0; i < g_NptPdptTotal; i++) {
        ULONG64    PdPa  = NptVaToPhysical(&g_NptPdPages[i]);
        PEPT_PDPTE Pdpte = NptGetSharedPdptePtr(i);
        if (!Pdpte) continue;

        Pdpte->Value    = 0;
        Pdpte->Read     = 1;
        Pdpte->Write    = 1;
        Pdpte->Execute  = 1;
        Pdpte->PhysAddr = PdPa >> 12;

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

    /* Setup PML4[0..Pml4Count-1] */
    PdptPa = NptVaToPhysical(g_NptState.Pdpt);
    g_NptState.Pml4[0].Value = 0;
    g_NptState.Pml4[0].Read = 1;
    g_NptState.Pml4[0].Write = 1;
    g_NptState.Pml4[0].Execute = 1;
    g_NptState.Pml4[0].PhysAddr = PdptPa >> 12;

    for (i = 1; i < g_NptPml4Count; i++) {
        ULONG64 ExtPa = NptVaToPhysical(&g_NptExtPdptPages[i - 1]);
        g_NptState.Pml4[i].Value    = 0;
        g_NptState.Pml4[i].Read     = 1;
        g_NptState.Pml4[i].Write    = 1;
        g_NptState.Pml4[i].Execute  = 1;
        g_NptState.Pml4[i].PhysAddr = ExtPa >> 12;
    }

    g_NptState.Pml4Pa = NptVaToPhysical(g_NptState.Pml4);

    g_NptState.Initialized = TRUE;
    g_NptHookState.Initialized = TRUE;

    LOG_INFO("NPT initialized: identity map for %llu GB across %u PML4 entries, PML4PA=0x%llX",
             (ULONG64)g_NptPdptTotal, g_NptPml4Count, g_NptState.Pml4Pa);
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

    /* H-2: release extended PDPT pages and dynamic bitmap */
    if (g_NptExtPdptPages) {
        ExFreePoolWithTag(g_NptExtPdptPages, 'tpnX');
        g_NptExtPdptPages = NULL;
    }
    if (g_NptPerCpuPdAllocated) {
        ExFreePoolWithTag(g_NptPerCpuPdAllocated, 'tpnA');
        g_NptPerCpuPdAllocated = NULL;
    }

    /* Free per-CPU tracking array */
    if (g_NptDbRelaxedPagePa) {
        ExFreePoolWithTag((PVOID)g_NptDbRelaxedPagePa, 'tpnM');
        g_NptDbRelaxedPagePa = NULL;
    }
    /* M-4: free the parallel RIP tracking array. */
    if (g_NptDbRelaxedRip) {
        ExFreePoolWithTag((PVOID)g_NptDbRelaxedRip, 'tpnR');
        g_NptDbRelaxedRip = NULL;
    }
    /* M-4 (revised): free the parallel CR3 tracking array. */
    if (g_NptDbRelaxedCr3) {
        ExFreePoolWithTag((PVOID)g_NptDbRelaxedCr3, 'tpnC');
        g_NptDbRelaxedCr3 = NULL;
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
    ULONG       FlatPdptIdx, PdIndex;
    PEPT_PDE    TargetPde;
    PNPT_SPLIT_PAGE SplitPage = NULL;
    ULONG       i;
    ULONG       splitIdx = (ULONG)-1;

    Base2MB     = PhysicalAddress & ~((2ULL * 1024 * 1024) - 1);
    FlatPdptIdx = NptPaToFlatPdptIdx(Base2MB);
    PdIndex     = (ULONG)((Base2MB >> 21) & 0x1FF);

    if (FlatPdptIdx == (ULONG)-1) {
        LOG_ERROR("NPT split: address 0x%llX beyond mapped range (max %llu GB)",
                  PhysicalAddress, (ULONG64)g_NptPdptTotal);
        return;
    }

    TargetPde = &g_NptPdPages[FlatPdptIdx].Entries[PdIndex];

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
    ULONG       FlatPdptIdx, PdIndex, PtIndex;
    PEPT_PDE    Pde;
    ULONG       splitIdx;

    Base2MB     = PhysicalAddress & ~((2ULL * 1024 * 1024) - 1);
    FlatPdptIdx = NptPaToFlatPdptIdx(PhysicalAddress);
    PdIndex     = (ULONG)((PhysicalAddress >> 21) & 0x1FF);
    PtIndex     = (ULONG)((PhysicalAddress >> 12) & 0x1FF);

    if (FlatPdptIdx == (ULONG)-1) {
        return NULL;
    }

    Pde = &g_NptPdPages[FlatPdptIdx].Entries[PdIndex];

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

    /*
     * L-4 FIX: JMP patch requires 12 bytes; reject hook points too close
     * to the page end.  See ept.c for rationale (same logic).
     */
    if (PageOffset + 12 > PAGE_SIZE) {
        LOG_ERROR("NPT Hook: TargetVa 0x%llX too close to page end "
                  "(offset=0x%X, need 12 bytes)", TargetVa, PageOffset);
        return STATUS_INVALID_PARAMETER;
    }

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
        /* H-2: flat PDPT index supports > 512GB */
        ULONG PdptIdx = NptPaToFlatPdptIdx(PageBase);
        ULONG PdIdx   = (ULONG)((PageBase >> 21) & 0x1FF);
        ULONG splitIdx, cpu;
        NTSTATUS PerCpuStatus;

        if (PdptIdx == (ULONG)-1) {
            LOG_ERROR("NPT hook: page base 0x%llX beyond identity map", PageBase);
        } else {
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
    }

    if (OriginalFunction) {
        *OriginalFunction = Hook->TrampolineVa;
    }

    KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);

    NptInvalidateAll();

    /*
     * C-3: NPT hooks need #DB to drive their single-step restore cycle.
     * Make sure #DB intercept is enabled across all CPUs.  The change
     * takes effect on each CPU's next VMRUN.  #BP intercept is managed
     * independently by anti-anti-debug.
     */
    SvmSetExceptionInterceptDb(TRUE);

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

                /*
                 * H-5 FIX: synchronous IPI-based flush on all CPUs before
                 * freeing pages — prevents UAF from stale TLB on
                 * HLT-ing CPUs.
                 */
                NptInvalidateAllCpusSync();

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

            /*
             * C-3: if we just removed the last hook, disable #DB intercept.
             * HookCount is read without the spin lock here — this is fine
             * because SvmSetExceptionInterceptDb is idempotent (guards via
             * its own lock) and the worst case on a race is a momentary
             * redundant enable/disable.
             */
            if (g_NptHookState.HookCount == 0) {
                SvmSetExceptionInterceptDb(FALSE);
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
     * H-5 FIX: synchronously flush NPT TLB on ALL CPUs via IPI before
     * freeing pages.  NptInvalidateAll() only queues a flush for the
     * next VMRUN; if any CPU is in HLT / C-state it won't VMRUN and we
     * can UAF on freed pages through its stale TLB.
     */
    NptInvalidateAllCpusSync();

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

    /* C-3: no hooks left → disable #DB intercept (AAD's #BP untouched). */
    SvmSetExceptionInterceptDb(FALSE);
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
        /*
         * H-2: if GPA is beyond the identity map, resuming would loop forever.
         * Signal SVM shutdown so the host returns control safely.
         */
        if (NptPaToFlatPdptIdx(GuestPhysAddr) == (ULONG)-1) {
            LOG_ERROR("NPF beyond identity map: GPA=0x%llX (map covers %llu GB) - shutting down SVM",
                      GuestPhysAddr, (ULONG64)g_NptPdptTotal);
            return FALSE;
        }

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

    /* H-2: allocate per-CPU extended PDPT pages for PML4[1..] if needed */
    if (g_NptPml4Count > 1) {
        ULONG ExtCount = g_NptPml4Count - 1;
        g_NptCpuExtPdpt = (NPT_PDPT_PAGE **)ExAllocatePoolWithTag(
            NonPagedPool, g_MaxProcessors * sizeof(NPT_PDPT_PAGE *), 'tpNX');
        if (!g_NptCpuExtPdpt) {
            ExFreePoolWithTag(g_NptPerCpuPdPages, 'tpNP'); g_NptPerCpuPdPages = NULL;
            ExFreePoolWithTag(g_NptPerCpuSplitPages, 'tpNS'); g_NptPerCpuSplitPages = NULL;
            ExFreePoolWithTag(g_NptCpuStates, 'tpNC'); g_NptCpuStates = NULL;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(g_NptCpuExtPdpt, g_MaxProcessors * sizeof(NPT_PDPT_PAGE *));

        for (i = 0; i < g_MaxProcessors; i++) {
            g_NptCpuExtPdpt[i] = (NPT_PDPT_PAGE *)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(NPT_PDPT_PAGE) * ExtCount, 'tpNX');
            if (!g_NptCpuExtPdpt[i]) {
                ULONG k;
                for (k = 0; k < i; k++) {
                    if (g_NptCpuExtPdpt[k]) ExFreePoolWithTag(g_NptCpuExtPdpt[k], 'tpNX');
                }
                ExFreePoolWithTag(g_NptCpuExtPdpt, 'tpNX'); g_NptCpuExtPdpt = NULL;
                ExFreePoolWithTag(g_NptPerCpuPdPages, 'tpNP'); g_NptPerCpuPdPages = NULL;
                ExFreePoolWithTag(g_NptPerCpuSplitPages, 'tpNS'); g_NptPerCpuSplitPages = NULL;
                ExFreePoolWithTag(g_NptCpuStates, 'tpNC'); g_NptCpuStates = NULL;
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(g_NptCpuExtPdpt[i], g_NptExtPdptPages,
                          sizeof(NPT_PDPT_PAGE) * ExtCount);
        }
    }

    for (i = 0; i < g_MaxProcessors; i++) {
        ULONG64 PdptPa;
        ULONG   pml4;

        RtlCopyMemory(g_NptCpuStates[i].Pml4, g_NptState.Pml4, sizeof(g_NptState.Pml4));
        RtlCopyMemory(g_NptCpuStates[i].Pdpt, g_NptState.Pdpt, sizeof(g_NptState.Pdpt));

        PdptPa = NptVaToPhysical(g_NptCpuStates[i].Pdpt);
        g_NptCpuStates[i].Pml4[0].PhysAddr = PdptPa >> 12;

        /* H-2: update PML4[1..] to this CPU's extended PDPT pages */
        for (pml4 = 1; pml4 < g_NptPml4Count; pml4++) {
            ULONG64 ExtPa = NptVaToPhysical(&g_NptCpuExtPdpt[i][pml4 - 1]);
            g_NptCpuStates[i].Pml4[pml4].PhysAddr = ExtPa >> 12;
        }

        g_NptCpuStates[i].Pml4Pa = NptVaToPhysical(g_NptCpuStates[i].Pml4);
    }

    /* H-2: g_NptPerCpuPdAllocated is dynamic; already zeroed in NptInitialize */

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

    /* H-2: release per-CPU extended PDPT pages */
    if (g_NptCpuExtPdpt) {
        for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
            if (g_NptCpuExtPdpt[cpu]) {
                ExFreePoolWithTag(g_NptCpuExtPdpt[cpu], 'tpNX');
            }
        }
        ExFreePoolWithTag(g_NptCpuExtPdpt, 'tpNX');
        g_NptCpuExtPdpt = NULL;
    }

    if (g_NptCpuStates) {
        ExFreePoolWithTag(g_NptCpuStates, 'tpNC');
        g_NptCpuStates = NULL;
    }

    LOG_INFO("Per-CPU NPT cleaned up");
}

static NTSTATUS NptEnsurePerCpuPdForRegion(ULONG FlatPdptIndex)
{
    ULONG cpu;

    if (FlatPdptIndex >= g_NptPdptTotal) return STATUS_INVALID_PARAMETER;
    if (g_NptPerCpuPdAllocated[FlatPdptIndex]) return STATUS_SUCCESS;

    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (!g_NptPerCpuPdPages[cpu]) {
            g_NptPerCpuPdPages[cpu] = (NPT_PER_CPU_PD_PAGE *)ExAllocatePoolWithTag(
                NonPagedPool, sizeof(NPT_PER_CPU_PD_PAGE) * g_NptPdptTotal, 'tpNP');
            if (!g_NptPerCpuPdPages[cpu]) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlCopyMemory(g_NptPerCpuPdPages[cpu], g_NptPdPages,
                          sizeof(NPT_PER_CPU_PD_PAGE) * g_NptPdptTotal);
        }

        {
            ULONG64    CpuPdPa = NptVaToPhysical(&g_NptPerCpuPdPages[cpu][FlatPdptIndex]);
            PEPT_PDPTE CpuPdpte = NptGetCpuPdptePtr(cpu, FlatPdptIndex);
            if (!CpuPdpte) return STATUS_UNSUCCESSFUL;
            CpuPdpte->PhysAddr = CpuPdPa >> 12;
        }
    }

    g_NptPerCpuPdAllocated[FlatPdptIndex] = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS NptEnsurePerCpuSplitPage(ULONG splitIdx, ULONG FlatPdptIndex, ULONG PdIndex)
{
    ULONG cpu;

    if (splitIdx >= NPT_MAX_SPLIT_PAGES) return STATUS_INVALID_PARAMETER;
    if (FlatPdptIndex >= g_NptPdptTotal) return STATUS_INVALID_PARAMETER;

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
            PEPT_PDE CpuPde = &g_NptPerCpuPdPages[cpu][FlatPdptIndex].Entries[PdIndex];
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

/*
 * H-5 (revised) FIX: synchronous TLB flush across all CPUs (NPT side).
 *
 * SVM has no root-mode instruction that can flush the nested-TLB
 * wholesale (INVLPGA flushes a single page only).  The only way to drop
 * the nested TLB is to set VMCB.Control.TlbCtl = FLUSH_ALL_ASID and let
 * the next VMRUN apply it as part of the guest-context switch.
 *
 * Strategy:
 *   1. Set TlbCtl on every CPU's VMCB (NptInvalidateAll).
 *   2. Kick every CPU with an IPI and force one VMEXIT→VMRUN cycle each
 *      by executing CPUID (always intercepted by our VMCB setup), so the
 *      pending TlbCtl actually takes effect before we return.
 *
 * Edge cases:
 *   - !g_SvmState.Initialized: SVM is off on all CPUs already; there is
 *     no nested TLB to flush.  Skip the IPI entirely — a host-mode CPUID
 *     would be a harmless no-op, but we also want to avoid the
 *     KeIpiGenericCall overhead during teardown.
 *   - Mid-teardown (some CPUs have VMXOFF'd but not all): for still-guest
 *     CPUs the CPUID forces a VMEXIT and the TlbCtl flush; for host-mode
 *     CPUs CPUID is a no-op and that's fine (no guest TLB to clear).
 *     KeIpiGenericCall still returns only after every CPU has run the
 *     callback, so we have a hard barrier.
 *
 * IRQL: must be called at IRQL ≤ APC_LEVEL (KeIpiGenericCall).
 */
static ULONG_PTR NptInveptIpiCallback(ULONG_PTR Context)
{
    INT CpuInfo[4];
    UNREFERENCED_PARAMETER(Context);
    /*
     * CPUID is intercepted by our VMCB (see SvmSetupVmcb —
     * SVM_INTERCEPT_CPUID is always set).  If this CPU is in guest mode
     * the execution will VMEXIT → VMRUN, applying the TlbCtl we queued.
     * If this CPU is in host mode (SVM off here) CPUID just runs
     * natively, which is fine: no guest TLB on this CPU to worry about.
     */
    __cpuid(CpuInfo, 0);
    return 0;
}

VOID NptInvalidateAllCpusSync(VOID)
{
    /*
     * Set TlbCtl = FLUSH_ALL_ASID on every active VMCB.  Handles NULL
     * CpuContexts gracefully.
     */
    NptInvalidateAll();

    /*
     * If SVM is fully off there is no nested TLB anywhere — skip the IPI.
     * This also avoids the KeIpiGenericCall cost on the unload hot path.
     */
    if (!g_SvmState.Initialized) return;

    /*
     * IPI all CPUs.  Every CPU that is still in guest mode takes a
     * forced VMEXIT → VMRUN cycle via the intercepted CPUID, which
     * applies the queued TlbCtl.  KeIpiGenericCall is a synchronous
     * barrier: when it returns, every CPU has run the callback and the
     * nested TLB is known clean.
     */
    KeIpiGenericCall(NptInveptIpiCallback, 0);
}
