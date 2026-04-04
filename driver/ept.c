/*
 * ept.c - VMX Anti-Anti-Debug Hypervisor
 * Extended Page Tables: identity mapping, hook engine, violation handler
 */

#include "ept.h"
#include "vmx.h"
#include "log.h"

/* ========================================================================= */
/*  Globals                                                                  */
/* ========================================================================= */

EPT_STATE       g_EptState = { 0 };
EPT_HOOK_STATE  g_EptHookState = { 0 };

/*
 * Global flag: Guest code sets this after modifying EPT PTEs.
 * Each CPU checks it at every VM-Exit and executes INVEPT if non-zero.
 *
 * We use a generation counter instead of a simple flag: the Guest
 * increments it, and each CPU tracks the last generation it has seen.
 * This way every CPU eventually executes INVEPT, not just the first
 * one to notice the change.
 */
volatile LONG   g_EptInveptGeneration = 0;
static LONG     g_EptInveptCpuGen[64] = { 0 };  /* per-CPU last-seen generation */

/*
 * Dynamically allocated page directory and page table pages.
 * For a full identity map we use 2MB large pages by default,
 * and split to 4KB only when we need fine-grained EPT hooks.
 */

/* Pool of split page tables (for 2MB -> 4KB splitting) */
#define MAX_SPLIT_PAGES     128

typedef struct _EPT_SPLIT_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[EPT_PTE_COUNT];
    ULONG64     PhysicalAddress;    /* PA of this PTE array */
    ULONG64     BasePhysAddr2MB;    /* The 2MB region this covers */
    BOOLEAN     InUse;
} EPT_SPLIT_PAGE, *PEPT_SPLIT_PAGE;

static EPT_SPLIT_PAGE  *g_SplitPages = NULL;
static ULONG            g_SplitPageCount = 0;

/* Page directory pages - we need one PD per PDPT entry (512 entries) */
/* For simplicity, we pre-allocate for the first 512GB of physical memory */
/* Each PD covers 1GB and has 512 entries of 2MB each */
#define MAX_PD_PAGES    512

typedef struct _EPT_PD_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Entries[EPT_PDE_COUNT];
} EPT_PD_PAGE;

static EPT_PD_PAGE  *g_PdPages = NULL;

/* ========================================================================= */
/*  Internal Helpers                                                         */
/* ========================================================================= */

static ULONG64 VaToPhysical(PVOID Va)
{
    PHYSICAL_ADDRESS Pa = MmGetPhysicalAddress(Va);
    return Pa.QuadPart;
}

/* ========================================================================= */
/*  EPT Identity Map Setup                                                   */
/* ========================================================================= */

NTSTATUS EptInitialize(VOID)
{
    ULONG i, j;
    ULONG64 PhysAddr;
    ULONG64 PdptPa;

    if (g_EptState.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_EptState, sizeof(EPT_STATE));
    RtlZeroMemory(&g_EptHookState, sizeof(EPT_HOOK_STATE));
    KeInitializeSpinLock(&g_EptHookState.Lock);

    /*
     * Detect Execute-Only EPT support (IA32_VMX_EPT_VPID_CAP bit 0).
     * Many nested hypervisors (VMware, Hyper-V) do NOT expose this bit,
     * which means R=0,W=0,X=1 causes EPT Misconfiguration instead of
     * working as an execute-only page.  When unsupported, we fall back
     * to R=1,W=0,X=1 (read+execute) for hook pages.
     */
    {
        ULONG64 EptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
        g_EptHookState.ExecuteOnlySupported = (EptVpidCap & 1) != 0;

        LOG_INFO("EPT Execute-Only pages: %s",
                 g_EptHookState.ExecuteOnlySupported ? "supported" : "NOT supported (fallback to R+X)");
    }

    /*
     * Allocate Page Directory pages.
     * We map the first 512GB using 2MB large pages (512 PDs * 512 entries * 2MB = 512GB).
     */
    g_PdPages = (EPT_PD_PAGE *)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(EPT_PD_PAGE) * MAX_PD_PAGES,
        VMX_TAG
    );
    if (!g_PdPages) {
        LOG_ERROR("Failed to allocate EPT page directory pages");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_PdPages, sizeof(EPT_PD_PAGE) * MAX_PD_PAGES);

    /* Allocate split page pool */
    g_SplitPages = (EPT_SPLIT_PAGE *)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(EPT_SPLIT_PAGE) * MAX_SPLIT_PAGES,
        VMX_TAG
    );
    if (!g_SplitPages) {
        LOG_ERROR("Failed to allocate EPT split page pool");
        ExFreePoolWithTag(g_PdPages, VMX_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_SplitPages, sizeof(EPT_SPLIT_PAGE) * MAX_SPLIT_PAGES);

    /*
     * Build identity-mapped EPT using 2MB large pages.
     *
     * PML4 -> PDPT -> PD (2MB entries)
     *
     * We map the first 512GB of physical address space.
     */

    /* Setup PDPT entries - each points to a PD page */
    for (i = 0; i < MAX_PD_PAGES && i < EPT_PDPTE_COUNT; i++) {
        ULONG64 PdPa = VaToPhysical(&g_PdPages[i]);

        g_EptState.Pdpt[i].Value = 0;
        g_EptState.Pdpt[i].Read = 1;
        g_EptState.Pdpt[i].Write = 1;
        g_EptState.Pdpt[i].Execute = 1;
        g_EptState.Pdpt[i].PhysAddr = PdPa >> 12;

        /* Setup PD entries - each is a 2MB large page */
        for (j = 0; j < EPT_PDE_COUNT; j++) {
            PhysAddr = ((ULONG64)i * 512 + j) * (2 * 1024 * 1024); /* 2MB per entry */

            g_PdPages[i].Entries[j].Value = 0;
            g_PdPages[i].Entries[j].Read = 1;
            g_PdPages[i].Entries[j].Write = 1;
            g_PdPages[i].Entries[j].Execute = 1;
            g_PdPages[i].Entries[j].LargePage = 1;  /* 2MB page */
            g_PdPages[i].Entries[j].PhysAddr = PhysAddr >> 12;
        }
    }

    /* Setup PML4[0] to point to our PDPT */
    PdptPa = VaToPhysical(g_EptState.Pdpt);
    g_EptState.Pml4[0].Value = 0;
    g_EptState.Pml4[0].Read = 1;
    g_EptState.Pml4[0].Write = 1;
    g_EptState.Pml4[0].Execute = 1;
    g_EptState.Pml4[0].PhysAddr = PdptPa >> 12;

    /* Store PML4 physical address */
    g_EptState.Pml4Pa = VaToPhysical(g_EptState.Pml4);

    /* Build EPTP */
    g_EptState.Eptp.Value = 0;
    g_EptState.Eptp.MemoryType = EPT_MEMORY_TYPE_WB;
    g_EptState.Eptp.PageWalkLength = EPT_PAGE_WALK_LENGTH_4;
    g_EptState.Eptp.DirtyAccess = 0; /* Can enable if supported */
    g_EptState.Eptp.Pml4PhysAddr = g_EptState.Pml4Pa >> 12;

    g_EptState.Initialized = TRUE;
    g_EptHookState.Initialized = TRUE;

    LOG_INFO("EPT initialized: identity map for 512GB, EPTP=0x%llX", g_EptState.Eptp.Value);
    return STATUS_SUCCESS;
}

VOID EptCleanup(VOID)
{
    /* Unhook everything first */
    EptUnhookAll();

    if (g_SplitPages) {
        ExFreePoolWithTag(g_SplitPages, VMX_TAG);
        g_SplitPages = NULL;
    }
    if (g_PdPages) {
        ExFreePoolWithTag(g_PdPages, VMX_TAG);
        g_PdPages = NULL;
    }

    g_EptState.Initialized = FALSE;
    g_EptHookState.Initialized = FALSE;

    LOG_INFO("EPT cleaned up");
}

/*
 * Set up EPT for a specific CPU's VMCS
 */
NTSTATUS EptSetupIdentityMap(struct _VMX_CPU_CONTEXT *CpuCtx, struct _VMX_STATE *State)
{
    UNREFERENCED_PARAMETER(CpuCtx);
    UNREFERENCED_PARAMETER(State);

    if (!g_EptState.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    /* Write EPTP into VMCS */
    VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptState.Eptp.Value);

    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  2MB -> 4KB Page Splitting                                                */
/* ========================================================================= */

/*
 * Split a 2MB large page into 512 4KB pages.
 * Required for fine-grained EPT permission control (hooks).
 */
VOID EptSplitLargePage(ULONG64 PhysicalAddress)
{
    ULONG64     Base2MB;
    ULONG       PdptIndex, PdIndex;
    PEPT_PDE    TargetPde;
    PEPT_SPLIT_PAGE SplitPage = NULL;
    ULONG       i;

    /* Align to 2MB boundary */
    Base2MB = PhysicalAddress & ~((2 * 1024 * 1024) - 1);

    /* Calculate indices */
    PdptIndex = (ULONG)((Base2MB >> 30) & 0x1FF);   /* 1GB per PDPT entry */
    PdIndex   = (ULONG)((Base2MB >> 21) & 0x1FF);   /* 2MB per PD entry */

    if (PdptIndex >= MAX_PD_PAGES) {
        LOG_ERROR("EPT split: address 0x%llX is beyond mapped range", PhysicalAddress);
        return;
    }

    TargetPde = &g_PdPages[PdptIndex].Entries[PdIndex];

    /* Check if already split */
    if (!TargetPde->LargePage) {
        LOG_DEBUG("EPT: 2MB page at 0x%llX already split", Base2MB);
        return;
    }

    /* Find a free split page */
    for (i = 0; i < MAX_SPLIT_PAGES; i++) {
        if (!g_SplitPages[i].InUse) {
            SplitPage = &g_SplitPages[i];
            break;
        }
    }

    if (!SplitPage) {
        LOG_ERROR("EPT split: no free split pages available");
        return;
    }

    /* Initialize 512 PTEs mapping the same 2MB region as 4KB pages */
    for (i = 0; i < EPT_PTE_COUNT; i++) {
        ULONG64 PagePa = Base2MB + (ULONG64)i * PAGE_SIZE;

        SplitPage->Pte[i].Value = 0;
        SplitPage->Pte[i].Read = 1;
        SplitPage->Pte[i].Write = 1;
        SplitPage->Pte[i].Execute = 1;
        SplitPage->Pte[i].MemoryType = EPT_MEMORY_TYPE_WB;
        SplitPage->Pte[i].PhysAddr = PagePa >> 12;
    }

    SplitPage->PhysicalAddress = VaToPhysical(SplitPage->Pte);
    SplitPage->BasePhysAddr2MB = Base2MB;
    SplitPage->InUse = TRUE;
    g_SplitPageCount++;

    /* Update PDE: change from 2MB large page to pointer to PT */
    TargetPde->Value = 0;
    TargetPde->Read = 1;
    TargetPde->Write = 1;
    TargetPde->Execute = 1;
    TargetPde->LargePage = 0;   /* No longer a large page */
    TargetPde->PhysAddr = SplitPage->PhysicalAddress >> 12;

    LOG_INFO("EPT: Split 2MB page at 0x%llX into 4KB pages", Base2MB);
}

/* ========================================================================= */
/*  EPT PTE Lookup                                                           */
/* ========================================================================= */

PEPT_PTE EptGetPteForPhysicalAddress(ULONG64 PhysicalAddress)
{
    ULONG64     Base2MB;
    ULONG       PdptIndex, PdIndex, PtIndex;
    PEPT_PDE    Pde;
    ULONG       i;

    Base2MB = PhysicalAddress & ~((2 * 1024 * 1024) - 1);
    PdptIndex = (ULONG)((PhysicalAddress >> 30) & 0x1FF);
    PdIndex   = (ULONG)((PhysicalAddress >> 21) & 0x1FF);
    PtIndex   = (ULONG)((PhysicalAddress >> 12) & 0x1FF);

    if (PdptIndex >= MAX_PD_PAGES) {
        return NULL;
    }

    Pde = &g_PdPages[PdptIndex].Entries[PdIndex];

    /* If it's still a 2MB page, we need to split first */
    if (Pde->LargePage) {
        return NULL;  /* Caller should split first */
    }

    /* Find the split page for this 2MB region */
    for (i = 0; i < MAX_SPLIT_PAGES; i++) {
        if (g_SplitPages[i].InUse && g_SplitPages[i].BasePhysAddr2MB == Base2MB) {
            return &g_SplitPages[i].Pte[PtIndex];
        }
    }

    return NULL;
}

/* ========================================================================= */
/*  EPT Hook Engine                                                          */
/* ========================================================================= */

/*
 * Install an EPT hook on a function.
 *
 * This works by:
 * 1. Splitting the 2MB page containing the target into 4KB pages
 * 2. Creating a "hook page" - copy of original page with a JMP at the hook point
 * 3. Setting the EPT PTE to Execute-Only pointing to hook page
 * 4. Reads/writes see original page, execution sees hook page
 *
 * TargetVa:          Virtual address of the function to hook (kernel VA)
 * HookFunction:      Our replacement function
 * OriginalFunction:  [out] Pointer to trampoline for calling original
 */
NTSTATUS EptHookFunction(ULONG64 TargetVa, PVOID HookFunction, PVOID *OriginalFunction)
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

    if (!g_EptHookState.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    /* Translate target VA to PA */
    PhysAddr = MmGetPhysicalAddress((PVOID)TargetVa);
    TargetPa = PhysAddr.QuadPart;

    if (TargetPa == 0) {
        LOG_ERROR("EPT Hook: Failed to get PA for VA 0x%llX", TargetVa);
        return STATUS_INVALID_ADDRESS;
    }

    PageBase = TargetPa & PAGE_MASK_4KB;
    PageOffset = (ULONG)(TargetPa & 0xFFF);

    KeAcquireSpinLock(&g_EptHookState.Lock, &OldIrql);

    /* Check for duplicate hook */
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active &&
            g_EptHookState.Hooks[i].TargetVirtualAddr == TargetVa) {
            KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
            LOG_WARN("EPT Hook: Already hooked at VA 0x%llX", TargetVa);
            return STATUS_ALREADY_REGISTERED;
        }
    }

    /*
     * Check if another hook already exists on the same physical page.
     * If so, we share its HookPage and OriginalPage instead of allocating new ones.
     */
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active &&
            g_EptHookState.Hooks[i].TargetPhysicalAddr == PageBase &&
            g_EptHookState.Hooks[i].OwnsPages)
        {
            PageOwner = &g_EptHookState.Hooks[i];
            break;
        }
    }

    /* Find free hook slot */
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (!g_EptHookState.Hooks[i].Active) {
            Hook = &g_EptHookState.Hooks[i];
            break;
        }
    }

    if (!Hook) {
        KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
        LOG_ERROR("EPT Hook: No free hook slots");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Split the 2MB page to 4KB if needed */
    EptSplitLargePage(TargetPa);

    /* Get the PTE for this specific 4KB page */
    Pte = EptGetPteForPhysicalAddress(TargetPa);
    if (!Pte) {
        KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
        LOG_ERROR("EPT Hook: Failed to get PTE for PA 0x%llX", TargetPa);
        return STATUS_UNSUCCESSFUL;
    }

    if (PageOwner) {
        /*
         * Shared page path: another hook already owns the pages for this
         * physical page. Reuse its HookPage/OriginalPage and just add
         * our JMP patch at our offset.
         */
        Hook->OriginalPageVa = PageOwner->OriginalPageVa;
        Hook->HookPageVa     = PageOwner->HookPageVa;
        Hook->HookPagePa     = PageOwner->HookPagePa;
        Hook->OwnsPages       = FALSE;
    } else {
        /*
         * First hook on this page: allocate fresh copies.
         */
        Hook->OriginalPageVa = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, VMX_TAG);
        if (!Hook->OriginalPageVa) {
            KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Hook->HookPageVa = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, VMX_TAG);
        if (!Hook->HookPageVa) {
            ExFreePoolWithTag(Hook->OriginalPageVa, VMX_TAG);
            KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /*
         * Copy the original page content.
         * Both OriginalPage (for EPT R/W violations) and HookPage (base for patches)
         * start as copies of the original code page.
         */
        TargetPageVa = (PVOID)(TargetVa & PAGE_MASK_4KB);
        RtlCopyMemory(Hook->OriginalPageVa, TargetPageVa, PAGE_SIZE);
        RtlCopyMemory(Hook->HookPageVa, TargetPageVa, PAGE_SIZE);

        Hook->HookPagePa = VaToPhysical(Hook->HookPageVa);
        Hook->OwnsPages   = TRUE;
    }

    /* Allocate trampoline (always per-hook, not shared) */
    Hook->TrampolineVa = ExAllocatePoolWithTag(NonPagedPool, 64, VMX_TAG);
    if (!Hook->TrampolineVa) {
        if (Hook->OwnsPages) {
            ExFreePoolWithTag(Hook->HookPageVa, VMX_TAG);
            ExFreePoolWithTag(Hook->OriginalPageVa, VMX_TAG);
        }
        KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Save original bytes at hook point */
    Hook->OriginalBytesSize = 14;  /* Size of an absolute JMP (FF 25 00000000 + 8-byte addr) */
    RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, Hook->OriginalBytesSize);

    /*
     * Patch the shared HookPage at our offset with a JMP to our hook function.
     * Using: 48 B8 [imm64] + FF E0  (MOV RAX, imm64; JMP RAX)
     * This is a 12-byte absolute JMP that encodes the target as an immediate,
     * avoiding any data read from the page.  The old FF 25 encoding performed
     * a RIP-relative memory read of the 8-byte target address, which caused an
     * EPT violation on execute-only pages (R=0,W=0,X=1) and resulted in an
     * infinite EPT-violation loop where the hook never fired.
     *
     * Clobbering RAX is safe: we are at function entry, RAX is volatile, and
     * the hook dispatcher does not depend on RAX's incoming value.
     *
     * Because the HookPage is shared, each hook on the same page accumulates
     * its JMP patch at a different offset — they don't overwrite each other.
     */
    HookPoint = (PUCHAR)Hook->HookPageVa + PageOffset;
    HookPoint[0] = 0x48;                                /* REX.W prefix       */
    HookPoint[1] = 0xB8;                                /* MOV RAX, imm64     */
    *(PULONG64)(HookPoint + 2) = (ULONG64)HookFunction; /* 8-byte immediate   */
    HookPoint[10] = 0xFF;                               /* JMP RAX            */
    HookPoint[11] = 0xE0;

    /*
     * Build trampoline: original bytes + JMP back to (Target + OriginalBytesSize)
     */
    Trampoline = (PUCHAR)Hook->TrampolineVa;
    RtlCopyMemory(Trampoline, Hook->OriginalBytes, Hook->OriginalBytesSize);
    Trampoline[Hook->OriginalBytesSize + 0] = 0xFF;
    Trampoline[Hook->OriginalBytesSize + 1] = 0x25;
    *(PULONG)(Trampoline + Hook->OriginalBytesSize + 2) = 0;
    *(PULONG64)(Trampoline + Hook->OriginalBytesSize + 6) = TargetVa + Hook->OriginalBytesSize;

    /* Fill in hook entry */
    Hook->TargetVirtualAddr = TargetVa;
    Hook->TargetPhysicalAddr = PageBase;
    Hook->TargetPageOffset = PageOffset;
    Hook->HookFunction = HookFunction;
    Hook->TargetPte = Pte;
    Hook->Active = TRUE;
    g_EptHookState.HookCount++;

    /*
     * Set EPT PTE pointing to the (shared) hook page.
     *
     * If Execute-Only is supported: R=0, W=0, X=1 (hook page)
     *   - Reads/writes cause EPT violation -> we show original page
     *   - Execution goes to hook page -> our JMP gets executed
     *   - Most stealthy: integrity scans read original code
     *
     * If Execute-Only is NOT supported: R=0, W=0, X=0 (hook page)
     *   - ALL accesses cause EPT violation
     *   - In the handler, check Guest RIP to distinguish:
     *     * RIP is within this page -> execution -> temporarily R+W+X with hook page + MTF
     *     * RIP is elsewhere -> read/write -> temporarily R+W+X with original page + MTF
     *   - PatchGuard reads see original (unpatched) code
     */
    Pte->Read = 0;
    Pte->Write = 0;
    Pte->PhysAddr = Hook->HookPagePa >> 12;

    if (g_EptHookState.ExecuteOnlySupported) {
        Pte->Execute = 1;
    } else {
        Pte->Execute = 0;
    }

    /* Return trampoline as the "original function" */
    if (OriginalFunction) {
        *OriginalFunction = Hook->TrampolineVa;
    }

    KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);

    /* Invalidate EPT TLB via VMCALL (we're in Guest/non-root mode) */
    EptInvalidateFromGuest();

    LOG_INFO("EPT Hook installed: VA=0x%llX -> Hook=0x%p, Trampoline=0x%p%s",
             TargetVa, HookFunction, Hook->TrampolineVa,
             PageOwner ? " (shared page)" : "");

    return STATUS_SUCCESS;
}

NTSTATUS EptUnhookFunction(ULONG64 TargetVa)
{
    KIRQL   OldIrql;
    ULONG   i;

    KeAcquireSpinLock(&g_EptHookState.Lock, &OldIrql);

    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        PEPT_HOOK_ENTRY Hook = &g_EptHookState.Hooks[i];

        if (Hook->Active && Hook->TargetVirtualAddr == TargetVa) {
            ULONG64 PageBase = Hook->TargetPhysicalAddr;
            BOOLEAN OtherHooksOnPage = FALSE;
            ULONG   j;

            /*
             * Restore original bytes on the shared HookPage so this
             * function's JMP patch is removed while other patches survive.
             */
            if (Hook->HookPageVa) {
                PUCHAR HookPoint = (PUCHAR)Hook->HookPageVa + Hook->TargetPageOffset;
                RtlCopyMemory(HookPoint, Hook->OriginalBytes, Hook->OriginalBytesSize);
            }

            /* Check if other active hooks share this page */
            for (j = 0; j < MAX_EPT_HOOKS; j++) {
                if (j != i &&
                    g_EptHookState.Hooks[j].Active &&
                    g_EptHookState.Hooks[j].TargetPhysicalAddr == PageBase)
                {
                    OtherHooksOnPage = TRUE;
                    break;
                }
            }

            if (!OtherHooksOnPage) {
                /* Last hook on this page — restore EPT mapping and free pages */
                if (Hook->TargetPte) {
                    Hook->TargetPte->Read = 1;
                    Hook->TargetPte->Write = 1;
                    Hook->TargetPte->Execute = 1;
                    Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
                }

                if (Hook->OwnsPages) {
                    if (Hook->OriginalPageVa) ExFreePoolWithTag(Hook->OriginalPageVa, VMX_TAG);
                    if (Hook->HookPageVa)     ExFreePoolWithTag(Hook->HookPageVa, VMX_TAG);
                }
            } else if (Hook->OwnsPages) {
                /*
                 * This hook owns the pages but other hooks still need them.
                 * Transfer ownership to another hook on the same page.
                 */
                PEPT_HOOK_ENTRY NewOwner = &g_EptHookState.Hooks[j];
                NewOwner->OwnsPages = TRUE;
                /* NewOwner already points to the same pages */
            }

            /* Trampoline is always per-hook */
            if (Hook->TrampolineVa) ExFreePoolWithTag(Hook->TrampolineVa, VMX_TAG);

            RtlZeroMemory(Hook, sizeof(EPT_HOOK_ENTRY));
            g_EptHookState.HookCount--;

            KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);

            EptInvalidateFromGuest();

            LOG_INFO("EPT Hook removed: VA=0x%llX", TargetVa);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
    return STATUS_NOT_FOUND;
}

VOID EptUnhookAll(VOID)
{
    KIRQL   OldIrql;
    ULONG   i;

    if (!g_EptHookState.Initialized) {
        return;
    }

    KeAcquireSpinLock(&g_EptHookState.Lock, &OldIrql);

    /*
     * First pass: restore all EPT PTEs and free page-owner resources.
     * We restore PTE for each unique physical page only once.
     */
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        PEPT_HOOK_ENTRY Hook = &g_EptHookState.Hooks[i];

        if (Hook->Active) {
            /* Restore EPT mapping (safe to do multiple times for same PTE) */
            if (Hook->TargetPte) {
                Hook->TargetPte->Read = 1;
                Hook->TargetPte->Write = 1;
                Hook->TargetPte->Execute = 1;
                Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
            }

            /* Only page owners free the shared pages */
            if (Hook->OwnsPages) {
                if (Hook->OriginalPageVa) ExFreePoolWithTag(Hook->OriginalPageVa, VMX_TAG);
                if (Hook->HookPageVa)     ExFreePoolWithTag(Hook->HookPageVa, VMX_TAG);
            }

            /* Trampoline is always per-hook */
            if (Hook->TrampolineVa) ExFreePoolWithTag(Hook->TrampolineVa, VMX_TAG);

            RtlZeroMemory(Hook, sizeof(EPT_HOOK_ENTRY));
        }
    }

    g_EptHookState.HookCount = 0;

    KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);

    LOG_INFO("All EPT hooks removed");
}

/* ========================================================================= */
/*  EPT Hook Lookup                                                          */
/* ========================================================================= */

PEPT_HOOK_ENTRY EptFindHookByPhysicalAddress(ULONG64 PhysicalAddress)
{
    ULONG i;
    ULONG64 PagePa = PhysicalAddress & PAGE_MASK_4KB;

    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active &&
            g_EptHookState.Hooks[i].TargetPhysicalAddr == PagePa) {
            return &g_EptHookState.Hooks[i];
        }
    }

    return NULL;
}

/* ========================================================================= */
/*  EPT Violation Handler                                                    */
/* ========================================================================= */

/*
 * Called from VM-Exit dispatcher when an EPT violation occurs.
 *
 * Strategy depends on Execute-Only support:
 *
 * (A) Execute-Only supported (R=0,W=0,X=1 hook page):
 *   - READ/WRITE violation: switch to original page (RW, no X), enable MTF
 *   - EXEC violation: switch back to hook page (X-only)
 *
 * (B) Execute-Only NOT supported (R=0,W=0,X=0 hook page):
 *   - ALL accesses fault; handler checks Guest RIP:
 *     * RIP within hooked page -> execution -> show hook page (RWX) + MTF
 *     * RIP elsewhere -> data access -> show original page (RWX) + MTF
 *   - PatchGuard reads always see original (unpatched) code
 */
BOOLEAN HandleEptViolation(PVOID GuestContext)
{
    ULONG64 GuestPhysAddr;
    ULONG64 ExitQualification;
    PEPT_HOOK_ENTRY Hook;
    BOOLEAN IsRead, IsWrite, IsExec;
    PEPT_PTE Pte;
    ULONG64 ProcBased;

    UNREFERENCED_PARAMETER(GuestContext);

    GuestPhysAddr = VmxRead(VMCS_GUEST_PHYSICAL_ADDRESS);
    ExitQualification = VmxRead(VMCS_EXIT_QUALIFICATION);

    IsRead  = (ExitQualification & EPT_VIOLATION_READ) != 0;
    IsWrite = (ExitQualification & EPT_VIOLATION_WRITE) != 0;
    IsExec  = (ExitQualification & EPT_VIOLATION_EXEC) != 0;

    /* Find the hook for this physical address */
    Hook = EptFindHookByPhysicalAddress(GuestPhysAddr);

    if (!Hook) {
        /*
         * EPT violation on a non-hooked page.
         * This shouldn't happen with our identity map.
         * Log and try to fix by setting RWX.
         */
        LOG_WARN("EPT violation on non-hooked page: GPA=0x%llX, Qual=0x%llX",
                 GuestPhysAddr, ExitQualification);

        Pte = EptGetPteForPhysicalAddress(GuestPhysAddr);
        if (Pte) {
            Pte->Read = 1;
            Pte->Write = 1;
            Pte->Execute = 1;
            EptInvalidateAllContexts();
        }

        return TRUE;
    }

    if (g_EptHookState.ExecuteOnlySupported) {
        /*
         * Mode A: Execute-Only (R=0,W=0,X=1)
         * EPT hardware distinguishes exec from data access.
         */
        if (IsRead || IsWrite) {
            /* Data access: show original page */
            Hook->TargetPte->Read = 1;
            Hook->TargetPte->Write = 1;
            Hook->TargetPte->Execute = 0;
            Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;

            EptInvalidateAllContexts();

            ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

        } else if (IsExec) {
            /* Exec after MTF restored RW mode: switch back to X-only hook page */
            Hook->TargetPte->Read = 0;
            Hook->TargetPte->Write = 0;
            Hook->TargetPte->Execute = 1;
            Hook->TargetPte->PhysAddr = Hook->HookPagePa >> 12;

            EptInvalidateAllContexts();
        }
    } else {
        /*
         * Mode B: No Execute-Only (R=0,W=0,X=0)
         * ALL accesses fault.  Check Guest RIP to determine intent:
         *   - RIP physical page == hooked page -> instruction fetch
         *     -> show hook page (R+W+X) so JMP patch executes
         *   - RIP elsewhere -> data read/write (e.g. PatchGuard scan)
         *     -> show original page (R+W+X) so scanner sees clean code
         * Then MTF to restore R=0,W=0,X=0 after one instruction.
         */
        {
            PHYSICAL_ADDRESS RipPa;
            ULONG64 GuestRipPagePa;
            ULONG64 GuestRip = VmxRead(VMCS_GUEST_RIP);

            /*
             * MmGetPhysicalAddress is safe at any IRQL for nonpaged kernel
             * addresses.  Guest RIP should always be in kernel .text (nonpaged).
             * If the translation fails (returns 0), assume data access to be safe.
             */
            RipPa = MmGetPhysicalAddress((PVOID)GuestRip);
            GuestRipPagePa = RipPa.QuadPart & PAGE_MASK_4KB;

            Hook->TargetPte->Read = 1;
            Hook->TargetPte->Write = 1;
            Hook->TargetPte->Execute = 1;

            if (GuestRipPagePa == Hook->TargetPhysicalAddr) {
                /* Execution: use hook page (with JMP patch) */
                Hook->TargetPte->PhysAddr = Hook->HookPagePa >> 12;
            } else {
                /* Data access: use original page (clean code) */
                Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
            }

            EptInvalidateAllContexts();

            ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
        }
    }

    /* Don't advance RIP - re-execute the faulting instruction */
    return TRUE;
}

/* ========================================================================= */
/*  INVEPT Wrappers                                                          */
/* ========================================================================= */

/*
 * EptInvalidateAllContexts - Execute INVEPT (all contexts).
 * Must ONLY be called from VMX root mode (VM-Exit handlers).
 */
VOID EptInvalidateAllContexts(VOID)
{
    INVEPT_DESCRIPTOR Desc = { 0 };
    AsmVmxInvept(INVEPT_ALL_CONTEXTS, &Desc);
}

VOID EptInvalidateSingleContext(ULONG64 Eptp)
{
    INVEPT_DESCRIPTOR Desc = { 0 };
    Desc.EptPointer = Eptp;
    AsmVmxInvept(INVEPT_SINGLE_CONTEXT, &Desc);
}

/*
 * EptInvalidateFromGuest - Request EPT TLB flush from Guest (VMX non-root).
 *
 * Bumps a generation counter. Each CPU compares its last-seen generation
 * at every VM-Exit and executes INVEPT if behind.  This ensures all CPUs
 * eventually flush, without relying on VMCALL (which VMware nested
 * virtualization intercepts).
 */
VOID EptInvalidateFromGuest(VOID)
{
    InterlockedIncrement(&g_EptInveptGeneration);
}

/*
 * EptCheckPendingInvept - Check and execute pending INVEPT.
 *
 * Called at the top of every VM-Exit handler (VMX root mode).
 * Compares the current CPU's last-seen generation with the global
 * generation counter.  If behind, executes INVEPT and updates.
 */
VOID EptCheckPendingInvept(VOID)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    LONG  CurrentGen = g_EptInveptGeneration;

    if (CpuIndex < 64 && g_EptInveptCpuGen[CpuIndex] != CurrentGen) {
        g_EptInveptCpuGen[CpuIndex] = CurrentGen;
        EptInvalidateAllContexts();
    }
}
