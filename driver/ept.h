/*
 * ept.h - VMX Anti-Anti-Debug Hypervisor
 * Extended Page Tables (EPT) management and hook engine
 */

#ifndef _VMX_EPT_H_
#define _VMX_EPT_H_

#include <ntddk.h>

/* Forward declaration */
struct _VMX_CPU_CONTEXT;
struct _VMX_STATE;

/* ========================================================================= */
/*  EPT Constants                                                            */
/* ========================================================================= */

#define EPT_PAGE_WALK_LENGTH_4      3   /* 4-level page walk (value = levels-1) */
#define EPT_MEMORY_TYPE_UC          0   /* Uncacheable */
#define EPT_MEMORY_TYPE_WC          1   /* Write Combining */
#define EPT_MEMORY_TYPE_WT          4   /* Write Through */
#define EPT_MEMORY_TYPE_WP          5   /* Write Protected */
#define EPT_MEMORY_TYPE_WB          6   /* Write Back */

#define EPT_PML4E_COUNT             512
#define EPT_PDPTE_COUNT             512
#define EPT_PDE_COUNT               512
#define EPT_PTE_COUNT               512

/* EPT access rights */
#define EPT_READ                    (1 << 0)
#define EPT_WRITE                   (1 << 1)
#define EPT_EXECUTE                 (1 << 2)
#define EPT_READ_WRITE              (EPT_READ | EPT_WRITE)
#define EPT_READ_WRITE_EXECUTE      (EPT_READ | EPT_WRITE | EPT_EXECUTE)
#define EPT_EXECUTE_ONLY            (EPT_EXECUTE)

/* Maximum number of EPT hooks (SSDT ~500 + Shadow SSDT ~500 + custom) */
#define MAX_EPT_HOOKS               1024

/* ========================================================================= */
/*  EPT Structures                                                           */
/* ========================================================================= */

/*
 * EPT PML4 Entry (Page Map Level 4)
 */
typedef union _EPT_PML4E {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;              /* bit 0 */
        ULONG64 Write : 1;             /* bit 1 */
        ULONG64 Execute : 1;           /* bit 2 */
        ULONG64 Reserved1 : 5;         /* bits 7:3 */
        ULONG64 Accessed : 1;          /* bit 8 */
        ULONG64 Ignored1 : 1;          /* bit 9 */
        ULONG64 UserModeExecute : 1;   /* bit 10 */
        ULONG64 Ignored2 : 1;          /* bit 11 */
        ULONG64 PhysAddr : 40;         /* bits 51:12 */
        ULONG64 Ignored3 : 12;         /* bits 63:52 */
    };
} EPT_PML4E, *PEPT_PML4E;

/*
 * EPT Page Directory Pointer Table Entry
 */
typedef union _EPT_PDPTE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 Reserved1 : 4;
        ULONG64 LargePage : 1;         /* 1GB page if set */
        ULONG64 Accessed : 1;
        ULONG64 Ignored1 : 1;
        ULONG64 UserModeExecute : 1;
        ULONG64 Ignored2 : 1;
        ULONG64 PhysAddr : 40;
        ULONG64 Ignored3 : 12;
    };
} EPT_PDPTE, *PEPT_PDPTE;

/*
 * EPT Page Directory Entry
 */
typedef union _EPT_PDE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 Reserved1 : 4;
        ULONG64 LargePage : 1;         /* 2MB page if set */
        ULONG64 Accessed : 1;
        ULONG64 Ignored1 : 1;
        ULONG64 UserModeExecute : 1;
        ULONG64 Ignored2 : 1;
        ULONG64 PhysAddr : 40;
        ULONG64 Ignored3 : 12;
    };
} EPT_PDE, *PEPT_PDE;

/*
 * EPT Page Table Entry (4KB pages)
 */
typedef union _EPT_PTE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 MemoryType : 3;        /* bits 5:3 */
        ULONG64 IgnorePat : 1;         /* bit 6 */
        ULONG64 Ignored1 : 1;          /* bit 7 */
        ULONG64 Accessed : 1;          /* bit 8 */
        ULONG64 Dirty : 1;             /* bit 9 */
        ULONG64 UserModeExecute : 1;   /* bit 10 */
        ULONG64 Ignored2 : 1;          /* bit 11 */
        ULONG64 PhysAddr : 40;         /* bits 51:12 */
        ULONG64 Ignored3 : 11;         /* bits 62:52 */
        ULONG64 SuppressVe : 1;        /* bit 63 */
    };
} EPT_PTE, *PEPT_PTE;

/*
 * EPT Pointer (EPTP) - stored in VMCS
 */
typedef union _EPT_POINTER {
    ULONG64 Value;
    struct {
        ULONG64 MemoryType : 3;        /* bits 2:0 - should be WB (6) */
        ULONG64 PageWalkLength : 3;    /* bits 5:3 - should be 3 (4-level) */
        ULONG64 DirtyAccess : 1;       /* bit 6 - enable dirty/access flags */
        ULONG64 Reserved1 : 5;         /* bits 11:7 */
        ULONG64 Pml4PhysAddr : 40;     /* bits 51:12 - physical address of PML4 */
        ULONG64 Reserved2 : 12;        /* bits 63:52 */
    };
} EPT_POINTER, *PEPT_POINTER;

/*
 * EPT page table structure (all levels)
 */
typedef struct _EPT_STATE {
    /* PML4 table (top level) */
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[EPT_PML4E_COUNT];

    /* Pre-allocated PDPT for first 512GB (common case) */
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[EPT_PDPTE_COUNT];

    /* EPT Pointer value */
    EPT_POINTER Eptp;

    /* Physical address of PML4 */
    ULONG64 Pml4Pa;

    BOOLEAN Initialized;
} EPT_STATE, *PEPT_STATE;

/*
 * EPT Hook entry
 * Represents a single function hook via EPT page splitting
 */
typedef struct _EPT_HOOK_ENTRY {
    BOOLEAN     Active;

    /* Target information */
    ULONG64     TargetVirtualAddr;      /* VA of the function to hook */
    ULONG64     TargetPhysicalAddr;     /* PA of the target page (4KB aligned) */
    ULONG64     TargetPageOffset;       /* Offset within the page */

    /* Pages (may be shared with other hooks on the same physical page) */
    PVOID       OriginalPageVa;         /* Copy of original page content */
    PVOID       HookPageVa;             /* Modified page with JMP instruction(s) */
    ULONG64     HookPagePa;            /* PA of the hook page */
    BOOLEAN     OwnsPages;              /* TRUE if this entry allocated the pages */

    /* Trampoline for calling original function */
    PVOID       TrampolineVa;           /* Saved original bytes + JMP back */
    ULONG       OriginalBytesSize;      /* Size of original bytes saved */
    UCHAR       OriginalBytes[16];      /* Backup of original instruction bytes */

    /* Hook handler */
    PVOID       HookFunction;           /* Our replacement function */

    /* EPT PTE that maps this page */
    PEPT_PTE    TargetPte;              /* Pointer to the EPT PTE for this GPA */

} EPT_HOOK_ENTRY, *PEPT_HOOK_ENTRY;

/*
 * EPT Hook Manager
 */
typedef struct _EPT_HOOK_STATE {
    EPT_HOOK_ENTRY  Hooks[MAX_EPT_HOOKS];
    ULONG           HookCount;
    KSPIN_LOCK      Lock;
    BOOLEAN         Initialized;

    /*
     * TRUE if the CPU supports Execute-Only EPT pages (R=0,W=0,X=1).
     * Detected from IA32_VMX_EPT_VPID_CAP bit 0 during EptInitialize().
     * When FALSE, hooks fall back to R=1,W=0,X=1 (read+execute),
     * which is less stealthy but functional on all EPT-capable CPUs
     * including nested virtualization (VMware, Hyper-V, etc.).
     */
    BOOLEAN         ExecuteOnlySupported;
} EPT_HOOK_STATE, *PEPT_HOOK_STATE;

/*
 * EPT invalidation generation counter: Guest increments this after
 * modifying EPT PTEs.  Each CPU checks at every VM-Exit and executes
 * INVEPT if its local generation is behind.
 */
extern volatile LONG g_EptInveptGeneration;

/* ========================================================================= */
/*  Function Declarations                                                    */
/* ========================================================================= */

/* EPT initialization and cleanup */
NTSTATUS    EptInitialize(VOID);
VOID        EptCleanup(VOID);

/* Per-CPU EPT setup (called from VMCS setup) */
NTSTATUS    EptSetupIdentityMap(struct _VMX_CPU_CONTEXT *CpuCtx, struct _VMX_STATE *State);

/* EPT Hook operations */
NTSTATUS    EptHookFunction(ULONG64 TargetVa, PVOID HookFunction, PVOID *OriginalFunction);
NTSTATUS    EptUnhookFunction(ULONG64 TargetVa);
VOID        EptUnhookAll(VOID);

/* EPT Violation handler (called from VM-Exit dispatcher) */
BOOLEAN     HandleEptViolation(PVOID GuestContext);

/* EPT page table manipulation */
PEPT_PTE    EptGetPteForPhysicalAddress(ULONG64 PhysicalAddress);
VOID        EptSplitLargePage(ULONG64 PhysicalAddress);

/* INVEPT helpers */
VOID        EptInvalidateAllContexts(VOID);     /* VMX root only */
VOID        EptInvalidateSingleContext(ULONG64 Eptp); /* VMX root only */
VOID        EptInvalidateFromGuest(VOID);        /* Safe from Guest (non-root) */
VOID        EptCheckPendingInvept(VOID);          /* Called from VM-Exit handler */

/* Find hook by physical address */
PEPT_HOOK_ENTRY EptFindHookByPhysicalAddress(ULONG64 PhysicalAddress);

/* Global EPT state */
extern EPT_STATE        g_EptState;
extern EPT_HOOK_STATE   g_EptHookState;

#endif /* _VMX_EPT_H_ */
