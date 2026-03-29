/*
 * npt.h - VMX Anti-Anti-Debug Hypervisor
 * AMD Nested Page Tables (NPT) - AMD's equivalent of Intel EPT
 *
 * NPT uses the same 4-level page table format as regular x86-64 paging:
 *   PML4 -> PDPT -> PD -> PT
 * The page table entry format is slightly different from EPT but
 * the overall structure is identical.
 *
 * Key differences from Intel EPT:
 *   - NPT does NOT support Execute-Only pages
 *   - NPT root address goes in VMCB.nested_cr3 (not a VMCS field)
 *   - TLB flush via ASID switch (not INVEPT)
 *   - NPT violation = SVM_EXIT_NPF (0x400)
 */

#ifndef _NPT_H_
#define _NPT_H_

#include <ntddk.h>
#include "ept.h"    /* Reuse EPT page table structure definitions */

/* ========================================================================= */
/*  NPT Constants                                                            */
/* ========================================================================= */

/*
 * NPT reuses the EPT structure types (EPT_PML4E, EPT_PDPTE, EPT_PDE, EPT_PTE)
 * since the page table entry format is compatible.
 * The same identity-mapping and page-splitting logic applies.
 */

#define NPT_MAX_HOOKS       MAX_EPT_HOOKS   /* Same hook limit */

/* ========================================================================= */
/*  NPT State                                                                */
/* ========================================================================= */

/*
 * NPT state is stored separately from EPT state since both may be
 * compiled in but only one is active at runtime.
 * However, the structures are identical (reusing EPT types).
 */
typedef struct _NPT_STATE {
    /* PML4 table (top level) */
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[EPT_PML4E_COUNT];

    /* Pre-allocated PDPT for first 512GB */
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[EPT_PDPTE_COUNT];

    /* Physical address of PML4 (written to VMCB.nested_cr3) */
    ULONG64 Pml4Pa;

    BOOLEAN Initialized;
} NPT_STATE, *PNPT_STATE;

/* ========================================================================= */
/*  NPT Hook State (same structure as EPT hooks)                             */
/* ========================================================================= */

typedef struct _NPT_HOOK_STATE {
    EPT_HOOK_ENTRY  Hooks[NPT_MAX_HOOKS];
    ULONG           HookCount;
    KSPIN_LOCK      Lock;
    BOOLEAN         Initialized;
} NPT_HOOK_STATE, *PNPT_HOOK_STATE;

/* ========================================================================= */
/*  Function Declarations                                                    */
/* ========================================================================= */

/* NPT initialization and cleanup */
NTSTATUS    NptInitialize(VOID);
VOID        NptCleanup(VOID);

/* Get the root page table physical address (for VMCB.nested_cr3) */
ULONG64     NptGetRootPageTablePa(VOID);

/* NPT Hook operations (API matches EPT for abstraction) */
NTSTATUS    NptHookFunction(ULONG64 TargetVa, PVOID HookFunction, PVOID *OriginalFunction);
NTSTATUS    NptUnhookFunction(ULONG64 TargetVa);
VOID        NptUnhookAll(VOID);

/* NPT Violation handler (called from SVM exit handler) */
BOOLEAN     NptHandlePageFault(PVOID GuestContext);

/* NPT page table manipulation */
PEPT_PTE    NptGetPteForPhysicalAddress(ULONG64 PhysicalAddress);
VOID        NptSplitLargePage(ULONG64 PhysicalAddress);

/* TLB invalidation (via ASID flush) */
VOID        NptInvalidateAll(VOID);

/* Find hook by physical address */
PEPT_HOOK_ENTRY NptFindHookByPhysicalAddress(ULONG64 PhysicalAddress);

/* Global state */
extern NPT_STATE        g_NptState;
extern NPT_HOOK_STATE   g_NptHookState;

#endif /* _NPT_H_ */
