[简体中文](per_cpu_pt_hook_isolation_CN.md) | English

# Per-CPU Page Table Hook Page Isolation — Implementation Details

> **Note (Updated April 2026)**: Hardcoded values such as `[MAX_PD_PAGES]` / `MAX_PD_PAGES (512)` in this document have been changed to runtime variables `g_EptPdptTotal / g_NptPdptTotal`. The Per-CPU PD arrays are dynamically allocated according to `g_EptPdptTotal`. Additionally, the extended PDPT pages of PML4[1..] also have independent per-CPU copies (`g_EptCpuExtPdpt / g_NptCpuExtPdpt`). For details, see H-2 in [BAREMETAL_REVIEW_FIXES.md](./BAREMETAL_REVIEW_FIXES.md).
>
> Also, the UAF (Use-After-Free) risk has been concurrently fixed: `EptInvalidateAllCpusSync / NptInvalidateAllCpusSync` uses IPIs to force all CPUs (including those in HLT/C-state) to perform INVEPT / TLB flushes before pages are freed (H-5).

## 1. Design Goals

On multi-core systems, a race condition exists in the three-stage process (**Violation → Single-step → Restoration**) of EPT/NPT hooks:

```
CPU 0: EPT Violation → Relax PTE (R+W) → Enable MTF
CPU 1: EPT Violation → Relax PTE (R+W) → Enable MTF    ← Same PTE!
CPU 0: MTF Triggered → Restore PTE (X-Only)             ← Restores the PTE currently in use by CPU 1!
CPU 1: Still executing the instruction after relaxation → PTE has been restored by CPU 0 → EPT Violation again → Infinite loop/Hang
```

**Solution**: Each CPU has its own copy of the PT (Page Table level) for the hooked 2MB region. PTE permission switches only affect the address translation of the current CPU, without interfering with other CPUs.

**Key Constraint**: Isolation is only performed at the PT level (rather than the entire page table tree), because hooking only involves flipping 4KB PTE permissions and does not require isolating PML4 and PDPT contents. However, in order for the PD entries to point to different PT pages, PD pages also require per-CPU copies.

---

## 2. Overall Architecture

```
        ┌──────────────────────────────────────────────┐
        │  Shared Template (EPT_STATE / NPT_STATE)     │
        │  PML4 → PDPT → PD Pages → Split PT Pages     │
        │  (Shared by all CPUs for non-hooked regions) │
        └──────────────────────────────────────────────┘

Per-CPU Layer (Only for hooked regions):

  CPU 0:  PML4[0] → PDPT[0]                             CPU 1:  PML4[1] → PDPT[1]
            │                                                      │
            ├─ PDPT[x] → Shared PD (Unhooked GB regions)           ├─ PDPT[x] → Shared PD
            │                                                      │
            └─ PDPT[y] → per-CPU PD[0][y]                         └─ PDPT[y] → per-CPU PD[1][y]
                           │                                                     │
                           ├─ PD[z] → per-CPU PT[0]                             ├─ PD[z] → per-CPU PT[1]
                           │   (Hooked 2MB region)                               │   (Hooked 2MB region)
                           │                                                     │
                           └─ PD[Other] → Shared PT                              └─ PD[Other] → Shared PT
```

**Layered Isolation**:
- **PML4 + PDPT**: Independent per-CPU copies (cloned from the template during initialization) to allow PDPT entries to point to different PDs.
- **PD pages**: **Cloned on demand** — per-CPU copies are created only for GB regions containing hooks.
- **PT (split) pages**: **Cloned on demand** — per-CPU copies are created only for 2MB regions containing hooks.
- **Non-hooked regions**: All CPUs still share the same PD/PT pages (by pointing PDPT entries to the shared PD).

---

## 3. Data Structures

### 3.1 Intel EPT Side (`ept.h`)

```c
// Per-CPU EPT root structure (ept.h:178-183)
typedef struct _EPT_CPU_STATE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[EPT_PML4E_COUNT];  // Independent PML4
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[EPT_PDPTE_COUNT];  // Independent PDPT
    EPT_POINTER Eptp;     // The EPTP value for this CPU (written to VMCS)
    ULONG64     Pml4Pa;   // Physical address of PML4
} EPT_CPU_STATE, *PEPT_CPU_STATE;

// Global array: g_EptCpuStates[g_MaxProcessors]
extern PEPT_CPU_STATE g_EptCpuStates;
```

```c
// Per-CPU split PT page copy (ept.c:26-30, 44-48)
typedef struct _EPT_PER_CPU_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[EPT_PTE_COUNT];  // 512 4KB PTEs
    ULONG64     PhysicalAddress;    // Physical address of this page table page
    BOOLEAN     Allocated;          // Whether it is allocated
} EPT_PER_CPU_SPLIT, *PEPT_PER_CPU_SPLIT;

// Per-CPU PD page copy (ept.c:59-61)
typedef struct _EPT_PER_CPU_PD_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Entries[EPT_PDE_COUNT];  // 512 2MB PDEs
} EPT_PER_CPU_PD_PAGE;
```

Global Variables:
```c
PEPT_CPU_STATE              g_EptCpuStates     = NULL;  // [g_MaxProcessors] per-CPU EPT root
static PEPT_PER_CPU_SPLIT  *g_PerCpuSplitPages = NULL;  // [g_MaxProcessors] → [MAX_SPLIT_PAGES]
static EPT_PER_CPU_PD_PAGE**g_PerCpuPdPages    = NULL;  // [g_MaxProcessors] → [MAX_PD_PAGES]
static BOOLEAN              g_PerCpuPdAllocated[MAX_PD_PAGES] = {0}; // Which PDPT entries have been isolated
```

### 3.2 AMD NPT Side (`npt.h`)

```c
// Per-CPU NPT root structure (npt.h:64-68)
typedef struct _NPT_CPU_STATE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[EPT_PML4E_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[EPT_PDPTE_COUNT];
    ULONG64     Pml4Pa;   // Written to VMCB.nested_cr3
} NPT_CPU_STATE, *PNPT_CPU_STATE;

extern PNPT_CPU_STATE g_NptCpuStates;
```

The `NPT_PER_CPU_SPLIT` and `NPT_PER_CPU_PD_PAGE` structures on the NPT side mirror those on the EPT side.

---

## 4. Initialization Flow

### 4.1 Call Chain

```
DriverEntry
  └─ VmxInitialize / SvmInitialize
       ├─ EptInitialize / NptInitialize        ← Create shared template page tables
       ├─ EptInitPerCpu / NptInitPerCpu        ← Create per-CPU PML4+PDPT
       └─ For each CPU:
            └─ EptSetupIdentityMap / SvmInitVmcb
                 └─ Write per-CPU EPTP / nested_cr3 to VMCS / VMCB
```

### 4.2 `EptInitPerCpu()` (ept.c:1466-1546)

```c
NTSTATUS EptInitPerCpu(VOID)
{
    // 1. Allocate g_EptCpuStates[g_MaxProcessors]  (tag 'tpEC')
    // 2. Allocate g_PerCpuSplitPages[g_MaxProcessors] pointer array (tag 'tpES')
    // 3. Allocate g_PerCpuPdPages[g_MaxProcessors] pointer array (tag 'tpEP')
    //    (Only pointer arrays are allocated here; PD pages and split pages are allocated on demand)
    
    // 4. For each CPU:
    for (i = 0; i < g_MaxProcessors; i++) {
        // Clone PML4 and PDPT from the shared template
        RtlCopyMemory(g_EptCpuStates[i].Pml4, g_EptState.Pml4, ...);
        RtlCopyMemory(g_EptCpuStates[i].Pdpt, g_EptState.Pdpt, ...);
        
        // Key: PML4[0] points to its own PDPT
        PdptPa = VaToPhysical(g_EptCpuStates[i].Pdpt);
        g_EptCpuStates[i].Pml4[0].PhysAddr = PdptPa >> 12;
        
        // Build per-CPU EPTP
        g_EptCpuStates[i].Eptp.MemoryType = EPT_MEMORY_TYPE_WB;
        g_EptCpuStates[i].Eptp.PageWalkLength = EPT_PAGE_WALK_LENGTH_4;
        g_EptCpuStates[i].Eptp.Pml4PhysAddr = Pml4Pa >> 12;
    }
}
```

> **Note**: At this point, the PDPT entries of all CPUs still point to the **shared** PD pages (the same as the template). Per-CPU PD and PT pages are only created on demand when hooks are installed.

### 4.3 Writing EPTP / nested_cr3

**Intel Side** — `EptSetupIdentityMap` (ept.c:660-680):
```c
NTSTATUS EptSetupIdentityMap(VMX_CPU_CONTEXT *CpuCtx, VMX_STATE *State)
{
    CpuNum = CpuCtx->ProcessorNumber;
    // Prioritize using per-CPU EPTP, fallback to shared
    if (g_EptCpuStates && CpuNum < g_MaxProcessors) {
        VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptCpuStates[CpuNum].Eptp.Value);
    } else {
        VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptState.Eptp.Value);
    }
}
```

**AMD Side** — `SvmInitVmcb` (svm_init.c:425-434):
```c
NptRootPa = NptGetPerCpuRootPa(CpuNum);
if (NptRootPa == 0) {
    NptRootPa = NptGetRootPageTablePa();  // fallback to shared
}
Vmcb->Control.NestedCr3 = NptRootPa;
```

---

## 5. Per-CPU Configuration During Hook Installation

### 5.1 Per-CPU Block in `EptHookFunction` (ept.c:1074-1112)

After configuring the shared PTE permissions, perform the following operations:

```c
if (g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages) {
    ULONG PdptIdx = (PageBase >> 30) & 0x1FF;   // GB region index
    ULONG PdIdx   = (PageBase >> 21) & 0x1FF;   // 2MB region index
    
    // Step 1: Ensure the PD page for this GB region is isolated per-CPU
    EptEnsurePerCpuPdForRegion(PdptIdx);
    
    // Step 2: Find the corresponding split page index
    for (splitIdx = 0; splitIdx < MAX_SPLIT_PAGES; splitIdx++) {
        if (g_SplitPages[splitIdx].InUse &&
            g_SplitPages[splitIdx].BasePhysAddr2MB == (PageBase & ~(2MB - 1))) {
            break;
        }
    }
    
    // Step 3: Ensure the split page is isolated per-CPU
    EptEnsurePerCpuSplitPage(splitIdx, PdptIdx, PdIdx);
    
    // Step 4: Copy hook PTE permissions to the private copies of all CPUs
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        PEPT_PTE CpuPte = EptGetPerCpuPte(cpu, TargetPa);
        if (CpuPte) {
            CpuPte->Read    = Pte->Read;
            CpuPte->Write   = Pte->Write;
            CpuPte->Execute = Pte->Execute;
            CpuPte->PhysAddr = Pte->PhysAddr;
        }
    }
}
```

### 5.2 On-Demand PD Cloning — `EptEnsurePerCpuPdForRegion` (ept.c:1592-1629)

```c
static NTSTATUS EptEnsurePerCpuPdForRegion(ULONG PdptIndex)
{
    if (g_PerCpuPdAllocated[PdptIndex]) return STATUS_SUCCESS;  // Already isolated
    
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (!g_PerCpuPdPages[cpu]) {
            // First time: Allocate the full MAX_PD_PAGES PD pages
            g_PerCpuPdPages[cpu] = ExAllocatePoolWithTag(NonPagedPool,
                sizeof(EPT_PER_CPU_PD_PAGE) * MAX_PD_PAGES, 'tpEP');
            // Clone from shared PD pages
            RtlCopyMemory(g_PerCpuPdPages[cpu], g_PdPages,
                          sizeof(EPT_PER_CPU_PD_PAGE) * MAX_PD_PAGES);
        }
        // The PDPT[PdptIndex] of this CPU points to its own PD page
        CpuPdPa = VaToPhysical(&g_PerCpuPdPages[cpu][PdptIndex]);
        g_EptCpuStates[cpu].Pdpt[PdptIndex].PhysAddr = CpuPdPa >> 12;
    }
    g_PerCpuPdAllocated[PdptIndex] = TRUE;
}
```

### 5.3 On-Demand PT Cloning — `EptEnsurePerCpuSplitPage` (ept.c:1641-1686)

```c
static NTSTATUS EptEnsurePerCpuSplitPage(ULONG splitIdx, ULONG PdptIndex, ULONG PdIndex)
{
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (!g_PerCpuSplitPages[cpu]) {
            // First time: Allocate MAX_SPLIT_PAGES per-CPU split pages
            g_PerCpuSplitPages[cpu] = ExAllocatePoolWithTag(NonPagedPool,
                sizeof(EPT_PER_CPU_SPLIT) * MAX_SPLIT_PAGES, 'tpES');
            RtlZeroMemory(...);
        }
        
        if (!g_PerCpuSplitPages[cpu][splitIdx].Allocated) {
            // Clone 512 PTEs from the shared split page
            RtlCopyMemory(g_PerCpuSplitPages[cpu][splitIdx].Pte,
                          g_SplitPages[splitIdx].Pte,
                          sizeof(EPT_PTE) * EPT_PTE_COUNT);
            g_PerCpuSplitPages[cpu][splitIdx].PhysicalAddress =
                VaToPhysical(g_PerCpuSplitPages[cpu][splitIdx].Pte);
            g_PerCpuSplitPages[cpu][splitIdx].Allocated = TRUE;
        }
        
        // Update this CPU's PD entry to point to its own PT page
        CpuPde = &g_PerCpuPdPages[cpu][PdptIndex].Entries[PdIndex];
        CpuPde->Read = 1; CpuPde->Write = 1; CpuPde->Execute = 1;
        CpuPde->LargePage = 0;
        CpuPde->PhysAddr = g_PerCpuSplitPages[cpu][splitIdx].PhysicalAddress >> 12;
    }
}
```

---

## 6. Runtime: EPT Violation / NPF Handling

### 6.1 Intel — `HandleEptViolation` (ept.c:1321-1459)

```c
BOOLEAN HandleEptViolation(PVOID GuestContext)
{
    CpuIndex = KeGetCurrentProcessorNumber();
    Hook = EptFindHookByPhysicalAddress(GuestPhysAddr);
    
    // ★ Core: Use per-CPU PTE
    Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
    if (!Pte) Pte = Hook->TargetPte;  // fallback to shared
    
    // Subsequent modifications to Pte->Read/Write/Execute only affect the translation of the current CPU
    if (ExecuteOnlySupported) {
        // Mode A: R=0,W=0,X=1 → Temporarily switch to the original page during data access
        Pte->Read = 1; Pte->Write = 1; Pte->Execute = 0;
        Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
    } else {
        // Mode B: R=0,W=0,X=0 → Determine execution vs. data access based on RIP
        // ... similar logic ...
    }
    
    EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);  // Track which page was relaxed by the current CPU
    // Enable MTF
}
```

### 6.2 Intel — `HandleMtf` (vmx_exit.c:518-579)

```c
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    CpuIndex = KeGetCurrentProcessorNumber();
    
    // Disable MTF
    ProcBased &= ~PROC_BASED_MONITOR_TRAP_FLAG;
    
    // Get the page relaxed by the current CPU
    RelaxedPa = EptMtfGetAndClearRelaxedPage();
    
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (Hook->Active && Hook->TargetPhysicalAddr == RelaxedPa) {
            // ★ Restore using per-CPU PTE
            PEPT_PTE Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
            if (!Pte) Pte = Hook->TargetPte;  // fallback
            
            if (Pte->Read || Pte->Write) {
                // Restore to the hooked state
                Pte->Read = 0; Pte->Write = 0;
                Pte->PhysAddr = Hook->HookPagePa >> 12;
                Pte->Execute = ExecuteOnlySupported ? 1 : 0;
            }
        }
    }
    EptInvalidateAllContexts();
}
```

### 6.3 AMD — `NptHandlePageFault` (npt.c:782-880)

```c
BOOLEAN NptHandlePageFault(PVOID GuestContext)
{
    CpuIdx = KeGetCurrentProcessorNumber();
    Hook = NptFindHookByPhysicalAddress(GuestPhysAddr);
    
    // ★ Use per-CPU PTE
    Pte = NptGetPerCpuPte(CpuIdx, Hook->TargetPhysicalAddr);
    if (!Pte) Pte = Hook->TargetPte;
    
    // Write access: Temporarily set R+W+X + original page, and enable TF single-stepping
    Pte->Read = 1; Pte->Write = 1; Pte->Execute = 1;
    Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
    
    NptDbTrackRelaxedPage(Hook->TargetPhysicalAddr);
    Vmcb->Save.Rflags |= (1ULL << 8);  // Set TF
}
```

### 6.4 AMD — `SvmHandleDbException` (svm_exit.c:403-478)

```c
static BOOLEAN SvmHandleDbException(PGUEST_CONTEXT Ctx)
{
    CpuNum = KeGetCurrentProcessorNumber();
    RelaxedPa = NptDbGetAndClearRelaxedPage();
    
    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        if (Hook->Active && Hook->TargetPhysicalAddr == RelaxedPa) {
            // ★ Restore using per-CPU PTE
            PEPT_PTE Pte = NptGetPerCpuPte(CpuNum, Hook->TargetPhysicalAddr);
            if (!Pte) Pte = Hook->TargetPte;
            
            if (Pte->Read && Pte->Write && Pte->Execute) {
                // Restore to the hooked state: R+X with hook page
                Pte->Read = 1; Pte->Write = 0; Pte->Execute = 1;
                Pte->PhysAddr = Hook->HookPagePa >> 12;
            }
        }
    }
    Vmcb->Save.Rflags &= ~(1ULL << 8);  // Clear TF
    NptInvalidateAll();
}
```

---

## 7. PTE Lookup — `EptGetPerCpuPte` / `NptGetPerCpuPte`

```c
// ept.c:1692-1715
PEPT_PTE EptGetPerCpuPte(ULONG CpuIndex, ULONG64 PhysicalAddress)
{
    if (!g_PerCpuSplitPages || CpuIndex >= g_MaxProcessors ||
        !g_PerCpuSplitPages[CpuIndex]) {
        return NULL;  // per-CPU is uninitialized or not allocated for this CPU
    }
    
    Base2MB = PhysicalAddress & ~(2MB - 1);
    PtIndex = (PhysicalAddress >> 12) & 0x1FF;   // Offset within the 4KB page table
    
    // Iterate through split pages to find the matching 2MB region
    for (i = 0; i < MAX_SPLIT_PAGES; i++) {
        if (g_PerCpuSplitPages[CpuIndex][i].Allocated &&
            g_SplitPages[i].InUse &&
            g_SplitPages[i].BasePhysAddr2MB == Base2MB) {
            return &g_PerCpuSplitPages[CpuIndex][i].Pte[PtIndex];
        }
    }
    return NULL;  // No per-CPU split page for this address → Use the shared PTE
}
```

---

## 8. Per-CPU Cleanup During Hook Removal

### 8.1 `EptUnhookFunction` (ept.c:1166-1187)

When the last hook on the page is removed:

```c
if (!OtherHooksOnPage) {
    // Restore shared PTE
    Hook->TargetPte->Read = 1; ...
    
    // ★ Concurrently restore all per-CPU PTEs
    if (g_EptCpuStates && g_PerCpuSplitPages) {
        for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
            PEPT_PTE CpuPte = EptGetPerCpuPte(cpu, Hook->TargetPhysicalAddr);
            if (CpuPte) {
                CpuPte->Read = 1; CpuPte->Write = 1;
                CpuPte->Execute = 1;
                CpuPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
            }
        }
    }
}
```

### 8.2 `EptUnhookAll` (ept.c:1237-1270) / `NptUnhookAll` (npt.c:699-746)

During bulk removal, perform the same per-CPU PTE restoration for each active hook.

---

## 9. Cleanup Flow

### 9.1 `EptCleanupPerCpu` (ept.c:1551-1581)

```c
VOID EptCleanupPerCpu(VOID)
{
    // Free the per-CPU split page array
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (g_PerCpuSplitPages[cpu]) ExFreePoolWithTag(..., 'tpES');
    }
    ExFreePoolWithTag(g_PerCpuSplitPages, 'tpES');
    
    // Free the per-CPU PD page array
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (g_PerCpuPdPages[cpu]) ExFreePoolWithTag(..., 'tpEP');
    }
    ExFreePoolWithTag(g_PerCpuPdPages, 'tpEP');
    
    // Free the per-CPU EPT root array
    ExFreePoolWithTag(g_EptCpuStates, 'tpEC');
}
```

### 9.2 Call Chain

```
VmxTerminate / SvmTerminate
  ├─ EptCleanupPerCpu / NptCleanupPerCpu   ← First free per-CPU
  └─ EptCleanup / NptCleanup               ← Then free shared
```

---

## 10. Memory Allocation Summary

| Tag (Pool Tag) | Purpose | Allocation Timing | Size |
|---|---|---|---|
| `'tpEC'` | `g_EptCpuStates` — per-CPU EPT root (PML4+PDPT+EPTP) | `EptInitPerCpu` | `g_MaxProcessors × sizeof(EPT_CPU_STATE)` |
| `'tpES'` | `g_PerCpuSplitPages` — per-CPU split PT pointer array + actual PT pages | Pointer: `EptInitPerCpu`; Actual: `EptEnsurePerCpuSplitPage` | Pointer: `g_MaxProcessors × 8`; Actual: `MAX_SPLIT_PAGES × sizeof(EPT_PER_CPU_SPLIT)` per CPU |
| `'tpEP'` | `g_PerCpuPdPages` — per-CPU PD pages | Pointer: `EptInitPerCpu`; Actual: `EptEnsurePerCpuPdForRegion` | Pointer: `g_MaxProcessors × 8`; Actual: `MAX_PD_PAGES × sizeof(EPT_PER_CPU_PD_PAGE)` per CPU |
| `'tpNC'` | `g_NptCpuStates` — per-CPU NPT root | `NptInitPerCpu` | `g_MaxProcessors × sizeof(NPT_CPU_STATE)` |
| `'tpNS'` | `g_NptPerCpuSplitPages` — per-CPU NPT split PT | Same as EPT | Same as EPT |
| `'tpNP'` | `g_NptPerCpuPdPages` — per-CPU NPT PD pages | Same as EPT | Same as EPT |

> **On-Demand Allocation**: The "actual" allocation of `'tpES'`/`'tpEP'` only occurs when the first hook is installed in the corresponding region. No memory is allocated if no hooks are installed.

---

## 11. Fault-Tolerant Design

1. **Initialization failure is non-fatal**: When `EptInitPerCpu`/`NptInitPerCpu` returns failure, it only logs a `LOG_WARN` and continues. Hooks are still usable but fallback to the shared PTE (no isolation).

2. **Fallback to shared PTE**: All code paths utilizing per-CPU PTEs have a fallback mechanism:
   ```c
   Pte = EptGetPerCpuPte(CpuIndex, PA);
   if (!Pte) Pte = Hook->TargetPte;   // ← fallback
   ```

3. **NULL checks**: All per-CPU code paths verify that `g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages` are non-NULL.

---

## 12. List of Affected Files

| File | Modifications |
|---|---|
| `ept.h` | Added `EPT_CPU_STATE` structure; declared `EptInitPerCpu`, `EptCleanupPerCpu`, `EptGetPerCpuPte`, `EptGetPerCpuEptp`; `extern g_EptCpuStates` |
| `ept.c` | Added globals: `g_EptCpuStates`, `g_PerCpuSplitPages`, `g_PerCpuPdPages`, `g_PerCpuPdAllocated`, and per-CPU struct definitions; added functions: `EptInitPerCpu`, `EptCleanupPerCpu`, `EptEnsurePerCpuPdForRegion`, `EptEnsurePerCpuSplitPage`, `EptGetPerCpuPte`, `EptGetPerCpuEptp`; modified: `HandleEptViolation` (per-CPU PTE), `EptHookFunction` (per-CPU configuration), `EptUnhookFunction` (per-CPU restoration), `EptUnhookAll` (per-CPU restoration), `EptSetupIdentityMap` (per-CPU EPTP) |
| `npt.h` | Added `NPT_CPU_STATE` structure; declared `NptInitPerCpu`, `NptCleanupPerCpu`, `NptGetPerCpuPte`, `NptGetPerCpuRootPa`; `extern g_NptCpuStates` |
| `npt.c` | Mirrored all per-CPU changes from `ept.c`; modified: `NptHandlePageFault`, `NptHookFunction`, `NptUnhookFunction`, `NptUnhookAll` |
| `vmx_exit.c` | Modified `HandleMtf`: uses `EptGetPerCpuPte` to restore per-CPU PTEs |
| `svm_exit.c` | Modified `SvmHandleDbException`: uses `NptGetPerCpuPte` to restore per-CPU PTEs |
| `vmx_init.c` | `VmxInitialize` calls `EptInitPerCpu`; `VmxTerminate` calls `EptCleanupPerCpu` |
| `svm_init.c` | `SvmInitialize` calls `NptInitPerCpu`; `SvmTerminate` calls `NptCleanupPerCpu`; `SvmInitVmcb` uses `NptGetPerCpuRootPa` |

---

## 13. Known Limitations & TODOs

1. **Unhook does not free per-CPU PD/PT physical pages**: `EptUnhookFunction`/`NptUnhookFunction` restores per-CPU PTE permissions, but the memory for per-CPU PD pages and split pages is not freed back to the pool. They are only freed during `EptCleanupPerCpu` (driver unload). This is not an issue for scenarios with a small number of hooks.

2. **Full cloning of PD pages**: When `EptEnsurePerCpuPdForRegion` allocates a PD for a CPU for the first time, it clones all `MAX_PD_PAGES` (512) PD pages at once (≈2MB per CPU). This can be optimized to only clone the specific PD page that is required.

3. **Linear scan in `EptGetPerCpuPte`**: Uses `for (i = 0; i < MAX_SPLIT_PAGES; ...)` to iterate and find the matching split page. This has no performance impact for a small number of hooks (<10), but if there are many split pages (approaching 128), a hash table lookup could be considered.

4. **INVEPT/TLB flush granularity**: Currently uses `EptInvalidateAllContexts()` (all-context INVEPT) and `NptInvalidateAll()` (full ASID flush). This can be optimized to single-context INVEPT + per-CPU EPTP to reduce TLB jitter.
