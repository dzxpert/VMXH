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
/*  Globals                                                                  */
/* ========================================================================= */

NPT_STATE       g_NptState = { 0 };
NPT_HOOK_STATE  g_NptHookState = { 0 };

/* Page directory and split page pools (same as EPT) */
#define NPT_MAX_SPLIT_PAGES    32
#define NPT_MAX_PD_PAGES       512

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

    /* Allocate Page Directory pages */
    g_NptPdPages = (NPT_PD_PAGE *)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(NPT_PD_PAGE) * NPT_MAX_PD_PAGES, SVM_TAG);
    if (!g_NptPdPages) {
        LOG_ERROR("Failed to allocate NPT page directory pages");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_NptPdPages, sizeof(NPT_PD_PAGE) * NPT_MAX_PD_PAGES);

    /* Allocate split page pool */
    g_NptSplitPages = (NPT_SPLIT_PAGE *)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(NPT_SPLIT_PAGE) * NPT_MAX_SPLIT_PAGES, SVM_TAG);
    if (!g_NptSplitPages) {
        LOG_ERROR("Failed to allocate NPT split page pool");
        ExFreePoolWithTag(g_NptPdPages, SVM_TAG);
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
    if (g_NptPdPages) {
        ExFreePoolWithTag(g_NptPdPages, SVM_TAG);
        g_NptPdPages = NULL;
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

    Base2MB = PhysicalAddress & ~((2 * 1024 * 1024) - 1);
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
    ULONG       i;

    Base2MB = PhysicalAddress & ~((2 * 1024 * 1024) - 1);
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

    for (i = 0; i < NPT_MAX_SPLIT_PAGES; i++) {
        if (g_NptSplitPages[i].InUse && g_NptSplitPages[i].BasePhysAddr2MB == Base2MB) {
            return &g_NptSplitPages[i].Pte[PtIndex];
        }
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

    Pte = NptGetPteForPhysicalAddress(TargetPa);
    if (!Pte) {
        KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
        return STATUS_UNSUCCESSFUL;
    }

    /* Allocate pages */
    Hook->OriginalPageVa = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, SVM_TAG);
    Hook->HookPageVa = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, SVM_TAG);
    Hook->TrampolineVa = ExAllocatePoolWithTag(NonPagedPool, 64, SVM_TAG);

    if (!Hook->OriginalPageVa || !Hook->HookPageVa || !Hook->TrampolineVa) {
        if (Hook->OriginalPageVa) ExFreePoolWithTag(Hook->OriginalPageVa, SVM_TAG);
        if (Hook->HookPageVa)     ExFreePoolWithTag(Hook->HookPageVa, SVM_TAG);
        if (Hook->TrampolineVa)   ExFreePoolWithTag(Hook->TrampolineVa, SVM_TAG);
        KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Copy pages */
    TargetPageVa = (PVOID)(TargetVa & ~0xFFFULL);
    RtlCopyMemory(Hook->OriginalPageVa, TargetPageVa, PAGE_SIZE);
    RtlCopyMemory(Hook->HookPageVa, TargetPageVa, PAGE_SIZE);

    /* Save original bytes */
    Hook->OriginalBytesSize = 14;
    RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, Hook->OriginalBytesSize);

    /* Build hook page: 14-byte absolute JMP */
    HookPoint = (PUCHAR)Hook->HookPageVa + PageOffset;
    HookPoint[0] = 0xFF;
    HookPoint[1] = 0x25;
    *(PULONG)(HookPoint + 2) = 0;
    *(PULONG64)(HookPoint + 6) = (ULONG64)HookFunction;

    /* Build trampoline */
    Trampoline = (PUCHAR)Hook->TrampolineVa;
    RtlCopyMemory(Trampoline, Hook->OriginalBytes, Hook->OriginalBytesSize);
    Trampoline[Hook->OriginalBytesSize + 0] = 0xFF;
    Trampoline[Hook->OriginalBytesSize + 1] = 0x25;
    *(PULONG)(Trampoline + Hook->OriginalBytesSize + 2) = 0;
    *(PULONG64)(Trampoline + Hook->OriginalBytesSize + 6) = TargetVa + Hook->OriginalBytesSize;

    /* Fill hook entry */
    Hook->TargetVirtualAddr = TargetVa;
    Hook->TargetPhysicalAddr = PageBase;
    Hook->TargetPageOffset = PageOffset;
    Hook->HookPagePa = NptVaToPhysical(Hook->HookPageVa);
    Hook->HookFunction = HookFunction;
    Hook->TargetPte = Pte;
    Hook->Active = TRUE;
    g_NptHookState.HookCount++;

    /*
     * Set NPT PTE:
     * AMD NPT doesn't support Execute-Only, so we use Read+Execute (no Write).
     * Map to the hook page so execution hits our JMP.
     * Writes will trigger NPF where we temporarily show original page.
     */
    Pte->Read = 1;
    Pte->Write = 0;
    Pte->Execute = 1;
    Pte->PhysAddr = Hook->HookPagePa >> 12;

    if (OriginalFunction) {
        *OriginalFunction = Hook->TrampolineVa;
    }

    KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);

    NptInvalidateAll();

    LOG_INFO("NPT Hook installed: VA=0x%llX -> Hook=0x%p, Trampoline=0x%p",
             TargetVa, HookFunction, Hook->TrampolineVa);

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
            if (Hook->TargetPte) {
                Hook->TargetPte->Read = 1;
                Hook->TargetPte->Write = 1;
                Hook->TargetPte->Execute = 1;
                Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
            }

            if (Hook->OriginalPageVa) ExFreePoolWithTag(Hook->OriginalPageVa, SVM_TAG);
            if (Hook->HookPageVa)     ExFreePoolWithTag(Hook->HookPageVa, SVM_TAG);
            if (Hook->TrampolineVa)   ExFreePoolWithTag(Hook->TrampolineVa, SVM_TAG);

            RtlZeroMemory(Hook, sizeof(EPT_HOOK_ENTRY));
            g_NptHookState.HookCount--;

            KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
            NptInvalidateAll();
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

    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        PEPT_HOOK_ENTRY Hook = &g_NptHookState.Hooks[i];

        if (Hook->Active) {
            if (Hook->TargetPte) {
                Hook->TargetPte->Read = 1;
                Hook->TargetPte->Write = 1;
                Hook->TargetPte->Execute = 1;
                Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
            }

            if (Hook->OriginalPageVa) ExFreePoolWithTag(Hook->OriginalPageVa, SVM_TAG);
            if (Hook->HookPageVa)     ExFreePoolWithTag(Hook->HookPageVa, SVM_TAG);
            if (Hook->TrampolineVa)   ExFreePoolWithTag(Hook->TrampolineVa, SVM_TAG);

            RtlZeroMemory(Hook, sizeof(EPT_HOOK_ENTRY));
        }
    }

    g_NptHookState.HookCount = 0;
    KeReleaseSpinLock(&g_NptHookState.Lock, OldIrql);
}

/* ========================================================================= */
/*  NPT Hook Lookup                                                          */
/* ========================================================================= */

PEPT_HOOK_ENTRY NptFindHookByPhysicalAddress(ULONG64 PhysicalAddress)
{
    ULONG i;
    ULONG64 PagePa = PhysicalAddress & ~0xFFFULL;

    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        if (g_NptHookState.Hooks[i].Active &&
            g_NptHookState.Hooks[i].TargetPhysicalAddr == PagePa) {
            return &g_NptHookState.Hooks[i];
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
    BOOLEAN             IsWrite;
    PEPT_PTE            Pte;

    UNREFERENCED_PARAMETER(GuestContext);

    CpuCtx = &g_SvmState.CpuContexts[KeGetCurrentProcessorNumber()];
    Vmcb = CpuCtx->VmcbVa;

    ExitInfo1 = Vmcb->Control.ExitInfo1;
    GuestPhysAddr = Vmcb->Control.ExitInfo2;

    IsWrite = (ExitInfo1 & SVM_NPF_W) != 0;

    Hook = NptFindHookByPhysicalAddress(GuestPhysAddr);

    if (!Hook) {
        /* NPF on non-hooked page - fix by setting R+W+X */
        LOG_WARN("NPF on non-hooked page: GPA=0x%llX, Info1=0x%llX",
                 GuestPhysAddr, ExitInfo1);

        Pte = NptGetPteForPhysicalAddress(GuestPhysAddr);
        if (Pte) {
            Pte->Read = 1;
            Pte->Write = 1;
            Pte->Execute = 1;
            NptInvalidateAll();
        }
        return TRUE;
    }

    if (IsWrite) {
        /*
         * Write to hooked page:
         * Temporarily map original page with R+W+X, enable TF for single-step.
         * After the write completes and #DB fires, we restore R+X with hook page.
         */
        Hook->TargetPte->Read = 1;
        Hook->TargetPte->Write = 1;
        Hook->TargetPte->Execute = 1;
        Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;

        NptInvalidateAll();

        /* Enable single-step via RFLAGS.TF */
        Vmcb->Save.Rflags |= (1ULL << 8);  /* Set TF */

    } else {
        /*
         * Read or execute access that shouldn't fault with our R+X mapping.
         * If we get here, it might be a race condition or unexpected state.
         * Temporarily grant full access and single-step.
         */
        Hook->TargetPte->Read = 1;
        Hook->TargetPte->Write = 1;
        Hook->TargetPte->Execute = 1;
        Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;

        NptInvalidateAll();

        Vmcb->Save.Rflags |= (1ULL << 8);  /* Set TF */
    }

    /* Don't advance RIP - re-execute the faulting instruction */
    return TRUE;
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

    for (i = 0; i < g_SvmState.CpuCount; i++) {
        if (g_SvmState.CpuContexts[i].VmcbVa) {
            g_SvmState.CpuContexts[i].VmcbVa->Control.TlbCtl = TLB_CONTROL_FLUSH_ALL_ASID;
        }
    }
}
