[简体中文](EPT_Analysis_CN.md) | English

# EPT (Extended Page Tables) In-Depth Analysis

> **Note (Updated 2026-04)**: Multiple references to the "512GB identity map" / `MAX_PD_PAGES=512` / `for (i = 0; i < MAX_PD_PAGES; i++)` in this document have been upgraded to **dynamic sizing**. At runtime:
> - `g_EptPdptTotal` is the number of PDPT entries dynamically calculated at startup by `EptComputeRequiredPdPages()` based on the return value of `MmGetPhysicalMemoryRanges()` (plus a 2GB MMIO margin).
> - `g_EptPml4Count` can be > 1. Additional PDPT pages are stored in `g_EptExtPdptPages` and accessed via flat indexing using `EptPaToFlatPdptIdx()` + `EptGetSharedPdptePtr()`.
> - `HandleEptViolation` directly triggers a fatal-shutdown of VMX for GPAs exceeding the mapped range to avoid infinite loops.
>
> The NPT side (`g_NptPdptTotal` / `g_NptPml4Count`) has been optimized with a mirrored implementation.
>
> For details, see H-2 in [BAREMETAL_REVIEW_FIXES.md](./BAREMETAL_REVIEW_FIXES.md).

## 1. What is EPT?

EPT is an **Intel VT-x virtualization-specific hardware feature** that is activated by the CPU only when running in VMX non-root (Guest) mode. The corresponding technology on AMD is called **NPT (Nested Page Tables)**, which functions on the same principles.

### Address Translation Without Virtualization

```
Normal Environment (No Hypervisor):

  Program Virtual Address (VA)  ──→  CR3 Page Table  ──→  Physical Address (PA)  ──→  Memory
                                     (1 page table walk)
```

There is only one layer of translation: VA → PA, managed by the page table pointed to by CR3.

### Address Translation With Virtualization

```
Virtualization Environment (EPT Enabled):

  Guest VA  ──→  Guest CR3 Page Table  ──→  Guest PA (GPA)
                                                │
                                                ▼
                                          EPT Page Table (EPTP)  ──→  Host PA (HPA)  ──→  Memory
                                         (2nd page table walk)
```

Two layers of translation:
1. **Guest CR3 Page Table**: VA → GPA (managed by the Guest OS, which assumes GPA is the actual physical address).
2. **EPT Page Table**: GPA → HPA (managed by the Hypervisor, completely transparent to the Guest).

### Key Points

| Question | Answer |
|------|------|
| Does EPT exist on bare metal? | **No**, EPT is not used by the CPU unless VMX mode is entered. |
| Who enables EPT? | The Hypervisor enables it by setting the `Enable EPT` bit in the Secondary Processor-Based VM-Execution Controls of the VMCS. |
| Is the Guest aware of EPT? | **No**, the Guest believes its GPA is the actual physical address. |
| Is EPT Intel-exclusive? | Intel calls it **EPT**, while AMD calls it **NPT (Nested Page Tables)**. Their principles are identical. |

### Performance Overhead

When EPT is enabled, **each level of the Guest CR3 page table walk** must be translated via EPT:

```
During a 4-level Guest VA → PA page table walk:
  Read PML4E → EPT Translation (4 levels)    = 4 memory accesses
  Read PDPTE → EPT Translation (4 levels)    = 4 memory accesses
  Read PDE   → EPT Translation (4 levels)    = 4 memory accesses
  Read PTE   → EPT Translation (4 levels)    = 4 memory accesses
  Final Data → EPT Translation (4 levels)    = 4 memory accesses
                                              ─────────────
  Worst-case scenario: 4 × 5 = 20 memory accesses (vs. 4 on bare metal)
```

This is why CPUs feature a **TLB cache**—once a GVA → HPA mapping is cached, subsequent accesses bypass the dual-layer page table walk. The `INVEPT` instruction is used to invalidate this EPT TLB cache.

---

## 2. EPT 4-Level Page Table Structure (Project Implementation)

### Data Structure Overview

```
4-Level EPT Page Table (Identity maps 512GB physical address space):

PML4[0] ──> PDPT[512] ──> PD[512][512] ──> 2MB Large Pages
                                |
                         EptSplitLargePage()
                                |
                                v
                          PT[512] ──> 4KB Pages (used for hooks)
```

### Mapping to Code Data Structures

```c
// ept.h - 4-Level EPT Entry Definitions

EPT_PML4E  (ept.h:78)    // Level 1: PML4 Entry (512 entries)
EPT_PDPTE  (ept.h:97)    // Level 2: PDPT Entry (512 entries)
EPT_PDE    (ept.h:117)   // Level 3: PD Entry   (512 entries/PD, 512 PDs total)
EPT_PTE    (ept.h:137)   // Level 4: PT Entry   (512 entries, exists only after splitting)

// ept.c - Global State
EPT_STATE     g_EptState          // Shared template (PML4 + PDPT + EPTP)
EPT_PD_PAGE  *g_PdPages          // Array of PD pages [512]
EPT_SPLIT_PAGE *g_SplitPages     // Split page pool [128]
EPT_CPU_STATE *g_EptCpuStates    // Per-CPU EPT Root (independent per CPU)
```

### Bit Layout of Entries (All Levels)

```
Common fields for EPT PML4E / PDPTE / PDE / PTE:
 ┌───────────────────────────────────────────────────────────────────┐
 │ 63  62:52  51:12        11  10  9  8  7     6:3     2  1  0     │
 │  │   Ign   │ PhysAddr   │Ign│UX│Ign│A│L/Ign│MemType│ X│ W│ R   │
 └───────────────────────────────────────────────────────────────────┘
  R (bit 0):  Read  Read allowed
  W (bit 1):  Write Write allowed
  X (bit 2):  Execute Execute allowed
  A (bit 8):  Accessed (Set by CPU automatically)
  L (bit 7):  LargePage (PDE: 2MB large page / PDPTE: 1GB large page)
  PhysAddr (bits 51:12): Physical address of the next level table / final physical page >> 12
```

---

## 3. EPT Address Translation: GPA → HPA (Hardware Auto-Walk)

### Overall Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Data Structures in Code                       │
│                                                                     │
│  EPT_STATE.g_EptState:                                              │
│  ┌──────────┐                                                       │
│  │ PML4[512]│ ──→ Only PML4[0] is valid                             │
│  │   [0]    │ ──→ Points to PDPT physical address                   │
│  │ [1..511] │     (Unused, R=0 W=0 X=0)                             │
│  └────┬─────┘                                                       │
│       ▼                                                             │
│  ┌──────────────────────┐                                           │
│  │ PDPT[512]            │  ← g_EptState.Pdpt[]                      │
│  │  [0] → PA of PD#0    │                                           │
│  │  [1] → PA of PD#1    │                                           │
│  │  ...                  │  Each PD covers 1GB                      │
│  │ [511] → PA of PD#511 │  Total coverage: 512 GB                   │
│  └──────┬───────────────┘                                           │
│         │ (Each entry points to a PD page)                         │
│         ▼                                                           │
│  ┌─────────────────────────────────────┐                             │
│  │ g_PdPages[i].Entries[512]  (PD)     │  ← EPT_PDE                 │
│  │                                     │                             │
│  │ Default: LargePage=1 (2MB large page)│  ← Identity map             │
│  │   PDE[j] = R=1,W=1,X=1,L=1,         │                             │
│  │            PhysAddr = (i*512+j)*2MB │                             │
│  │                                     │                             │
│  │ Hooked: LargePage=0                 │  ← Split                    │
│  │   PDE[j] → PA of PT page            │                             │
│  └──────────────┬──────────────────────┘                             │
│                 │ (Points to PT after split)                         │
│                 ▼                                                    │
│  ┌─────────────────────────────────────┐                             │
│  │ g_SplitPages[idx].Pte[512]   (PT)   │  ← EPT_PTE                 │
│  │                                     │                             │
│  │ PTE[k]: 4KB Granularity             │                             │
│  │   Normal: R=1,W=1,X=1,              │                             │
│  │           PhysAddr = Original PA    │                             │
│  │   Hooked: R=0,W=0,X=0 (or 1),       │                             │
│  │           PhysAddr = HookPage PA    │                             │
│  └─────────────────────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────┘
```

### GPA Bitfield Breakdown

```
GPA (Guest Physical Address) 48-bit:

  47      39 38      30 29      21 20      12 11          0
 ┌─────────┬──────────┬──────────┬──────────┬─────────────┐
 │ PML4 idx│ PDPT idx │  PD idx  │  PT idx  │ Page Offset │
 │  9 bits │  9 bits  │  9 bits  │  9 bits  │  12 bits    │
 └─────────┴──────────┴──────────┴──────────┴─────────────┘
    ①          ②           ③          ④          ⑤
```

### Translation Process Details

Suppose the Guest attempts to access **GPA = `0x00000000'FFFFF800`**. The CPU executes the following steps:

#### Step 1: Read EPTP (from VMCS)

```
EPTP (VMCS field 0x201a) = g_EptState.Eptp.Value
  ├─ MemoryType = WB (6)
  ├─ PageWalkLength = 3 (representing 4 levels)
  └─ Pml4PhysAddr  = g_EptState.Pml4Pa >> 12  (Physical address of the PML4 table)
```

Corresponding code (`ept.c:1012`):
```c
g_EptState.Eptp.Value = 0;
g_EptState.Eptp.MemoryType = EPT_MEMORY_TYPE_WB;          // 6
g_EptState.Eptp.PageWalkLength = EPT_PAGE_WALK_LENGTH_4;   // 3 (representing 4 levels)
g_EptState.Eptp.Pml4PhysAddr = g_EptState.Pml4Pa >> 12;
```

#### Step 2: Level 1 — PML4 Walk (bits 47:39)

```
PML4 index = GPA[47:39] = 0x000  → PML4[0]

Read PML4[0]:
  Value = g_EptState.Pml4[0]
  R=1, W=1, X=1
  PhysAddr = VaToPhysical(g_EptState.Pdpt) >> 12   ← Physical address of PDPT
```

**Result**: Obtains the physical base address of the PDPT.

Corresponding code (`ept.c:1001`):
```c
PdptPa = VaToPhysical(g_EptState.Pdpt);
g_EptState.Pml4[0].Value = 0;
g_EptState.Pml4[0].Read = 1;
g_EptState.Pml4[0].Write = 1;
g_EptState.Pml4[0].Execute = 1;
g_EptState.Pml4[0].PhysAddr = PdptPa >> 12;
```

#### Step 3: Level 2 — PDPT Walk (bits 38:30)

```
PDPT index = GPA[38:30]

Read PDPT[i] = g_EptState.Pdpt[i]:
  R=1, W=1, X=1
  LargePage = 0      (not a 1GB large page)
  PhysAddr = VaToPhysical(&g_PdPages[i]) >> 12   ← Physical address of PD#i
```

**Result**: Obtains the physical base address of the PD page. Each PD covers a 1GB address space.

Corresponding code (`ept.c:979`):
```c
for (i = 0; i < MAX_PD_PAGES && i < EPT_PDPTE_COUNT; i++) {
    ULONG64 PdPa = VaToPhysical(&g_PdPages[i]);
    g_EptState.Pdpt[i].Value = 0;
    g_EptState.Pdpt[i].Read = 1;
    g_EptState.Pdpt[i].Write = 1;
    g_EptState.Pdpt[i].Execute = 1;
    g_EptState.Pdpt[i].PhysAddr = PdPa >> 12;
    // ...
}
```

#### Step 4: Level 3 — PD Walk (bits 29:21) — **Key Decision Point**

```
PD index = GPA[29:21]

Read PD[pdptIdx][pdIdx] = g_PdPages[pdptIdx].Entries[pdIdx]:

  ════════════════════════════════════════════
  Scenario A: Unsplit (Default State, LargePage = 1)
  ════════════════════════════════════════════
    R=1, W=1, X=1, LargePage=1
    PhysAddr = (pdptIdx*512 + pdIdx) * 2MB >> 12

    → Resolves directly to HPA! (2MB large page, GPA == HPA, identity mapped)
    → HPA = PhysAddr << 12 | GPA[20:0]
    → Translation complete! (Level 4 bypassed)

  ════════════════════════════════════════════
  Scenario B: Split (After Hooking, LargePage = 0)
  ════════════════════════════════════════════
    R=1, W=1, X=1, LargePage=0
    PhysAddr = g_SplitPages[N].PhysicalAddress >> 12  ← Physical address of PT table

    Must proceed to Level 4...
```

Corresponding code — Initialize as 2MB large pages (`ept.c:989`):
```c
for (j = 0; j < EPT_PDE_COUNT; j++) {
    PhysAddr = ((ULONG64)i * 512 + j) * (2 * 1024 * 1024);  // 2MB per entry
    g_PdPages[i].Entries[j].Value = 0;
    g_PdPages[i].Entries[j].Read = 1;
    g_PdPages[i].Entries[j].Write = 1;
    g_PdPages[i].Entries[j].Execute = 1;
    g_PdPages[i].Entries[j].LargePage = 1;   // 2MB page
    g_PdPages[i].Entries[j].PhysAddr = PhysAddr >> 12;
}
```

#### Step 5: Level 4 — PT Walk (Only after split, bits 20:12)

```
PT index = GPA[20:12]

Read PT[ptIdx] = g_SplitPages[N].Pte[ptIdx]:

  ═══════════════════════════════════════
  Scenario B-1: The 4KB page is NOT hooked
  ═══════════════════════════════════════
    R=1, W=1, X=1
    PhysAddr = Base2MB + ptIdx * 4KB >> 12
    → HPA == GPA  (Identity mapped)

  ═══════════════════════════════════════
  Scenario B-2: The 4KB page IS hooked!
  ═══════════════════════════════════════
    R=0, W=0, X=1 (or X=0, depending on ExecuteOnlySupported)
    PhysAddr = Hook->HookPagePa >> 12   ← ★ Points to the hook page!
    
    → HPA = HookPagePa + Offset   (Not the original physical address!)
    → This is the core of EPT Hook: "Read/Write sees the original page, Execute sees the hooked page"
    → If permissions are insufficient → Triggers EPT Violation VM-Exit → HandleEptViolation()
```

### Full Walkthrough Summary

```
Guest Initiates Memory Access (GPA)
        │
        ▼
┌───────────────────────────────────────────────┐
│ Step 1: CPU reads EPTP from VMCS              │
│         → Obtains PML4 physical base address  │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 2: PML4[GPA[47:39]]                      │
│         → Obtains PDPT physical base address  │
│         (Only PML4[0] is valid in this project)│
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 3: PDPT[GPA[38:30]]                      │
│         → LargePage?                          │
│           Yes(1GB) → Translation Done         │
│           No   → Obtains PD physical base addr│
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 4: PD[GPA[29:21]]                        │
│         → LargePage?(2MB)                     │
│           Yes → Done (Identity map, HPA==GPA) │
│           No  → Obtains PT physical base addr │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 5: PT[GPA[20:12]]                        │
│         → 4KB Page, final HPA                 │
│         → Permission Check (R/W/X)            │
│         Insufficient permissions?             │
│           Yes → EPT Violation VM-Exit!        │
│           No  → Access HPA                    │
└───────────────────────────────────────────────┘
```

---

## 4. EptSplitLargePage — 2MB → 4KB Splitting Process

Taking a hook on a 2MB page containing the GPA `0xFFFF1234` as an example:

### Before Splitting

```
PD[x][y] = {R=1, W=1, X=1, L=1, PA=Base2MB>>12}   ← 2MB large page
Coverage: Base2MB ~ Base2MB + 2MB (512 x 4KB pages)
```

### Splitting Process (`ept.c:1100`)

```
EptSplitLargePage(PhysicalAddress):
  ① Align to 2MB boundary:
     Base2MB = PA & ~(2MB - 1)

  ② Calculate indices:
     PdptIndex = (Base2MB >> 30) & 0x1FF    // 1GB per PDPT entry
     PdIndex   = (Base2MB >> 21) & 0x1FF    // 2MB per PD entry

  ③ Allocate g_SplitPages[N] (a new PT page with 512 PTEs)

  ④ Initialize 512 PTEs as identity mapped:
     for i in 0..511:
       PT[i] = {R=1, W=1, X=1, MemoryType=WB, PA=(Base2MB+i*4KB)>>12}

  ⑤ Modify the original PDE:
     PD[x][y] = {R=1, W=1, X=1, L=0, PA=SplitPage.PhysAddr>>12}
                                       ^^^
                                       No longer a large page; points to PT instead
 
  ⑥ Insert into the hash table for O(1) lookups:
     EptSplitHashInsert(Base2MB, splitIdx)
```

### After Splitting

```
PD[x][y] → PT[512]:
  GPA Base2MB + 0*4KB  → PT[0]   → HPA Base2MB + 0*4KB     (Identity map)
  GPA Base2MB + 1*4KB  → PT[1]   → HPA Base2MB + 1*4KB     (Identity map)
  ...
  GPA Base2MB + N*4KB  → PT[N]   → Can be individually permission-configured / redirected to HookPage!
  ...
  GPA Base2MB + 511*4KB → PT[511] → HPA Base2MB + 511*4KB  (Identity map)
```

**Why splitting is required**: 4KB granularity is necessary to apply different permissions and redirect individual pages to distinct physical frames.

---

## 5. EPT Hook Permission Switching Mechanism

### Execute-Only Mode (R=0, W=0, X=1)

```
                    ┌─────────────────────────────┐
                    │  Hook Page (contains JMP)   │
                    │  Permissions: X-only        │
                    │  PhysAddr = HookPagePa      │
    ┌──────────┐    └────────────┬────────────────┘
    │ EPT PTE  │────────────────►│
    │          │                 │
    └──────────┘    ┌────────────┴────────────────┐
                    │  Original Page (clean code) │
                    │  Permissions: R+W (temp)    │
                    │  PhysAddr = TargetPhysAddr  │
                    └─────────────────────────────┘

Execution Flow:
  1. Guest execution hits Hook address → X=1 allowed → Executes JMP on HookPage.
  2. Guest reads Hook address (e.g., PatchGuard scan) → R=0 → EPT Violation!
     → HandleEptViolation: Temporarily switch to original page (R=1, W=1, X=0).
     → Enable MTF (Monitor Trap Flag, single-step execution).
     → Guest reads clean original code (PatchGuard detects no modification).
  3. MTF triggers → Reverts to Hook page (R=0, W=0, X=1).
```

### Non-Execute-Only Mode (R=0, W=0, X=0)

```
All accesses trigger an EPT Violation. Intent is determined via Guest RIP:

  Is RIP inside the Hook page? → Execution request → Temporarily apply R+W+X to Hook page.
  Is RIP elsewhere?            → Data read/write → Temporarily apply R+W+X to original page.
  → Revert to R=0, W=0, X=0 after MTF step.
```

---

## 6. Comparison with x86-64 CR3 Page Tables

| Feature | x86-64 CR3 Page Tables (VA→PA) | EPT Page Tables (GPA→HPA) |
|------|--------------------------|---------------------|
| **Purpose** | Virtual address translation within the Guest OS | Physical address translation of the Guest managed by the Hypervisor |
| **Trigger** | On memory accesses by the Guest | On every Guest physical memory access (CPU auto-walk) |
| **Root Pointer Location** | CR3 register | EPTP field in the VMCS |
| **Permission Bits** | U/S, R/W, NX (2 bits + 1 bit) | R/W/X (3 independent control bits) |
| **Exception Type** | Page Fault (#PF, Vector 14) | EPT Violation / Misconfiguration (VM-Exit) |
| **Manager** | OS Kernel | Hypervisor (VMX root) |
| **Visible to Guest?** | Yes (Guest's own page tables) | No (Completely transparent to Guest) |
| **Large Page Support** | 2MB / 1GB | 2MB / 1GB (Identical) |
| **TLB Invalidation** | MOV CR3 / INVLPG | INVEPT |
| **Code Implementation** | Managed by Windows Kernel | `g_EptState` → PML4 → PDPT → PD → PT |

---

## 7. Per-CPU EPT Isolation

### Why Per-CPU is Necessary

```
Scenario: CPU0 and CPU1 trigger EPT Violations simultaneously

  CPU0: Modifies shared PTE → R=1, W=1, X=0 (Exposes original page)
  CPU1: Modifies shared PTE → R=0, W=0, X=1 (Restores hook page)
  
  → Before CPU0's MTF is triggered, the PTE is modified back by CPU1!
  → Race Condition!
```

### Per-CPU Solution

```
Each CPU has its own independent:
  PML4[cpu] → PDPT[cpu] → PD[cpu] → PT[cpu]

  CPU0 modifies PT[0][idx] → Affects CPU0 only.
  CPU1 modifies PT[1][idx] → Affects CPU1 only.
  
  → Eliminates multi-core race conditions entirely!
```

Corresponding Data Structures:
```c
EPT_CPU_STATE  *g_EptCpuStates        // Per-CPU PML4 + PDPT + EPTP
EPT_PER_CPU_PD_PAGE **g_PerCpuPdPages // Per-CPU PD pages
PEPT_PER_CPU_SPLIT  *g_PerCpuSplitPages // Per-CPU PT pages (Split pages)
```

---

## 8. AMD NPT (Nested Page Tables) Analysis

### 8.1 NPT Overview

NPT is the **second-level address translation** mechanism in **AMD SVM (Secure Virtual Machine)** virtualization technology, serving as the equivalent to Intel's EPT. The core goal is identical: translating Guest Physical Addresses (GPA) to Host Physical Addresses (HPA) transparently to the Guest.

```
Intel: Guest VA → [Guest CR3] → GPA → [EPT]  → HPA
AMD:   Guest VA → [Guest CR3] → GPA → [NPT]  ── HPA
                                       ^^^^^^^^^^
                                       Completely equivalent functionality
```

### 8.2 Similarities Between NPT and EPT

| Feature | Description |
|--------|------|
| **Page Table Levels** | Both are 4-level: PML4 → PDPT → PD → PT |
| **Entry Format** | In this project, NPT directly reuses the EPT structure definitions (`EPT_PML4E`, `EPT_PDPTE`, `EPT_PDE`, `EPT_PTE`). |
| **GPA Breakdown** | Identical: GPA[47:39]=PML4, [38:30]=PDPT, [29:21]=PD, [20:12]=PT, [11:0]=Offset. |
| **Large Page Support** | Both support 2MB (PDE.LargePage=1) and 1GB (PDPTE.LargePage=1) pages. |
| **Identity Map** | In this project, both EPT and NPT identity map the 512GB physical space. |
| **Hooking Principle** | Both split 2MB → 4KB pages to modify individual PTE permissions and redirect physical addresses. |
| **Per-CPU Isolation** | Both require Per-CPU page tables to prevent multi-core race conditions. |
| **TLB Translation Cost** | Both incur a worst-case penalty of 20 memory accesses (4 levels × 5 walks). |
| **Hash Tables** | Both utilize O(1) hash tables to accelerate hook and split page lookups. |
| **Trampoline Construction** | NPT reuses the EPT instruction length decoder (`EptGetInstructionLength`) and RIP-relative relocation logic. |

Code Evidence — NPT reuses EPT type definitions (`npt.h:21`):
```c
#include "ept.h"    /* Reuse EPT page table structure definitions */
```

### 8.3 Key Differences Between NPT and EPT

#### Comparison Table

| Feature | Intel EPT | AMD NPT |
|------|-----------|---------|
| **Virtualization Tech** | VT-x (VMX) | AMD-V (SVM) |
| **Root Pointer Location** | EPTP field in VMCS | `nested_cr3` field in VMCB |
| **Root Pointer Format** | `EPT_POINTER` union (includes MemoryType, PageWalkLength) | Raw physical address (direct PML4 PA) |
| **Execute-Only** | **Supported** (R=0, W=0, X=1) — requires `IA32_VMX_EPT_VPID_CAP` bit 0 | **Not Supported** — AMD architecture prohibits the R=0, X=1 combination |
| **Violation Event** | EPT Violation (VM-Exit) | #NPF = SVM_EXIT_NPF (0x400) (#VMEXIT) |
| **TLB Invalidation** | `INVEPT` instruction (Single-Context / All-Contexts) | `TlbCtl` field in VMCB (invalidated on next VMRUN) |
| **Single-Step Recovery** | MTF (Monitor Trap Flag, VMCS control bit) | RFLAGS.TF (#DB Exception) |
| **Memory Type** | Global MemoryType in EPTP + page-specific MemoryType[5:3] in PTE | Uses standard PAT mechanism |

#### Detailed Differences

##### Difference 1: Execute-Only — The Core Variance

```
Intel EPT (Supports Execute-Only):
  ┌──────────────────────────────────────────────────────┐
  │ Hooked state: PTE = { R=0, W=0, X=1, PA=HookPage }  │
  │                                                      │
  │  Guest Executes Code → X=1 Allowed → Runs HookPage  │
  │  Guest Reads Code    → R=0 Denied  → EPT Violation! │
  │    → Handler switches to original page              │
  │    → PatchGuard sees clean, unmodified code          │
  │                                                      │
  │  ★ Read and Execute can map to different physical   │
  │    pages! Provides maximum stealth.                  │
  └──────────────────────────────────────────────────────┘

AMD NPT (Does NOT Support Execute-Only):
  ┌──────────────────────────────────────────────────────┐
  │ Hooked state: PTE = { R=1, W=0, X=1, PA=HookPage }  │
  │                                                      │
  │  Guest Executes Code → X=1 Allowed → Runs HookPage  │
  │  Guest Reads Code    → R=1 Allowed → Reads HookPage!│
  │    → PatchGuard will see the JMP patch!              │
  │  Guest Writes Code   → W=0 Denied  → #NPF!          │
  │    → Handler temporarily switches to original page   │
  │                                                      │
  │  ★ Read and Execute map to the same page. Stealth    │
  │    is slightly compromised.                          │
  └──────────────────────────────────────────────────────┘
```

Corresponding Code Comparison:
```c
// Intel EPT Hook Permission Settings (ept.c:1544)
Pte->Read = 0;      // Read → EPT Violation
Pte->Write = 0;     // Write → EPT Violation
if (g_EptHookState.ExecuteOnlySupported)
    Pte->Execute = 1;   // Execution goes directly to HookPage ★
else
    Pte->Execute = 0;   // Fallback when unsupported

// AMD NPT Hook Permission Settings (npt.c:747)
Pte->Read = 1;      // Read allowed (Execute-Only cannot be set)
Pte->Write = 0;     // Write → #NPF
Pte->Execute = 1;   // Execution goes directly to HookPage
```

##### Difference 2: Root Pointer Configuration

```
Intel EPT:
  VMCS.EPTP = {
    MemoryType    : 3 bits (WB=6)
    PageWalkLength: 3 bits (4 levels=3)
    DirtyAccess   : 1 bit
    Pml4PhysAddr  : 40 bits (PML4 Physical Address >> 12)
  }
  → Written to VMCS via VmxWrite(VMCS_CTRL_EPT_POINTER, ...)

AMD NPT:
  VMCB.nested_cr3 = g_NptState.Pml4Pa  (Raw physical address, no control bits)
  → Written directly to the VMCB Control Area
```

Corresponding Code:
```c
// Intel: Structure the EPTP (ept.c:1013)
g_EptState.Eptp.MemoryType = EPT_MEMORY_TYPE_WB;
g_EptState.Eptp.PageWalkLength = EPT_PAGE_WALK_LENGTH_4;
g_EptState.Eptp.Pml4PhysAddr = g_EptState.Pml4Pa >> 12;

// AMD: Directly return PML4 Physical Address (npt.c:358)
ULONG64 NptGetRootPageTablePa(VOID) {
    return g_NptState.Pml4Pa;  // Written directly to VMCB.nested_cr3
}
```

##### Difference 3: TLB Invalidation Mechanism

```
Intel EPT:
  Execute INVEPT instruction in VMX root mode:
    AsmVmxInvept(INVEPT_ALL_CONTEXTS, &Desc);       // Flushes all EPTP contexts
    AsmVmxInvept(INVEPT_SINGLE_CONTEXT, &Desc);     // Flushes current EPTP context only
  → Takes effect immediately

AMD NPT:
  Configure the VMCB.TlbCtl field:
    Vmcb->Control.TlbCtl = TLB_CONTROL_FLUSH_ALL_ASID;
  → Invalidation is deferred until the next VMRUN (more efficient)
```

Corresponding Code:
```c
// Intel (ept.c:2335)
VOID EptInvalidateAllContexts(VOID) {
    INVEPT_DESCRIPTOR Desc = { 0 };
    AsmVmxInvept(INVEPT_ALL_CONTEXTS, &Desc);   // Executes instruction immediately
}

// AMD (npt.c:1333)
VOID NptInvalidateAll(VOID) {
    for (i = 0; i < g_SvmState.CpuCount; i++) {
        // Mark VMCB for all CPUs; invalidation occurs on next VMRUN
        g_SvmState.CpuContexts[i].VmcbVa->Control.TlbCtl =
            TLB_CONTROL_FLUSH_ALL_ASID;
    }
}
```

##### Difference 4: Single-Step Recovery (Reverting after temporary permission relaxation)

```
Intel EPT:                                AMD NPT:
  ┌──────────────┐                          ┌──────────────┐
  │ EPT Violation│                          │   #NPF       │
  │ (VM-Exit)    │                          │ (SVM #VMEXIT)│
  └──────┬───────┘                          └──────┬───────┘
         ▼                                         ▼
  Relax PTE permissions                     Relax PTE permissions
  Enable MTF bit                            Set RFLAGS.TF
  (VMCS Control Bit)                        (Guest RFLAGS)
  vmresume                                  vmrun
         │                                         │
         ▼
  Guest executes 1 instruction              Guest executes 1 instruction
         │                                         │
         ▼                                         ▼
  MTF VM-Exit                               #DB Exception #VMEXIT
  (Exit Reason 37)                          (SVM_EXIT_DB)
  Revert PTE to Hooked state                Revert PTE to Hooked state
  Clear MTF bit                             Clear RFLAGS.TF
```

Corresponding Code:
```c
// Intel: Enable MTF (ept.c:1974)
ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

// AMD: Enable TF (npt.c:1127)
Vmcb->Save.Rflags |= (1ULL << 8);  // Set Trap Flag
```

### 8.4 NPT Page Table Walk Process

The NPT GPA → HPA walk is structurally identical to EPT. The only differences lie in the root entry point and the generated exception type:

```
Guest Initiates Memory Access (GPA)
        │
        ▼
┌───────────────────────────────────────────────┐
│ Step 1: CPU reads root address from           │  ← Difference: VMCB nested_cr3, not EPTP
│         VMCB.nested_cr3 → PML4 base address   │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 2: PML4[GPA[47:39]]                      │
│         → Obtains PDPT physical base address  │  (Identical to EPT)
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 3: PDPT[GPA[38:30]]                      │
│         → Obtains PD physical base address    │  (Identical to EPT)
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 4: PD[GPA[29:21]]                        │
│         → LargePage? Yes → Walk Done          │  (Identical to EPT)
│           No → Obtains PT physical base address│
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 5: PT[GPA[20:12]]                        │
│         → 4KB page, final HPA                 │
│         → Permission Check (R/W/X)            │
│         Insufficient permissions?             │
│           Yes → #NPF (SVM_EXIT_NPF)!          │  ← Difference: #NPF, not EPT Violation
│           No  → Access HPA                    │
└───────────────────────────────────────────────┘
```

### 8.5 NPT Hooking Flowchart

Since AMD does not support Execute-Only permissions, the hooking strategy is adjusted:

```
                       ┌──────────────────────────────────┐
                       │  Initial State: Hook Installed    │
                       │  PTE = { R=1, W=0, X=1 }         │
                       │  PhysAddr → HookPage             │
                       └──────────┬───────────────────────┘
                                  │
                ┌─────────────────┼─────────────────┐
                ▼                 ▼                 ▼
         Guest Executes     Guest Reads       Guest Writes
         X=1 → Allowed      R=1 → Allowed     W=0 → #NPF!
                │                 │                 │
                ▼                 ▼                 ▼
         Runs JMP patch     Reads JMP patch   NptHandlePageFault():
         on HookPage        on HookPage        1. Switch to original page (RWX)
         → Jumps to our     (compromised       2. RFLAGS.TF = 1
           hook function     stealth)          3. Re-execute write instruction
                                                        │
                                                        ▼
                                                 Guest executes 1 instruction
                                                 (Write succeeds on original frame)
                                                        │
                                                        ▼
                                                 #DB Exception → SVM #VMEXIT
                                                 SvmHandleDbException():
                                                   1. Clear RFLAGS.TF
                                                   2. Revert PTE to:
                                                      { R=1, W=0, X=1 }
                                                      PhysAddr → HookPage
```

### 8.6 Code Symmetry of EPT and NPT in this Project

This project implements both Intel EPT and AMD NPT, maintaining perfect API symmetry:

| Functionality | Intel EPT (`ept.c`) | AMD NPT (`npt.c`) |
|------|---------------------|--------------------|
| Initialization | `EptInitialize()` | `NptInitialize()` |
| Cleanup | `EptCleanup()` | `NptCleanup()` |
| Install Hook | `EptHookFunction()` | `NptHookFunction()` |
| Remove Hook | `EptUnhookFunction()` | `NptUnhookFunction()` |
| Remove All Hooks | `EptUnhookAll()` | `NptUnhookAll()` |
| Violation Handling | `HandleEptViolation()` | `NptHandlePageFault()` |
| Split Large Page | `EptSplitLargePage()` | `NptSplitLargePage()` |
| PTE Lookup | `EptGetPteForPhysicalAddress()` | `NptGetPteForPhysicalAddress()` |
| Hook Lookup | `EptFindHookByPhysicalAddress()` | `NptFindHookByPhysicalAddress()` |
| TLB Invalidation | `EptInvalidateAllContexts()` | `NptInvalidateAll()` |
| Per-CPU Initialization | `EptInitPerCpu()` | `NptInitPerCpu()` |
| Per-CPU PTE Lookup | `EptGetPerCpuPte()` | `NptGetPerCpuPte()` |
| Single-Step Tracking | `EptMtfTrackRelaxedPage()` | `NptDbTrackRelaxedPage()` |
| Single-Step Restoration | `EptMtfGetAndClearRelaxedPage()` | `NptDbGetAndClearRelaxedPage()` |

### 8.7 Summary: EPT vs NPT Key Differences Quick Reference

```
┌───────────────────────────────────────────────────────────────┐
│                     EPT vs NPT Key Differences                │
├───────────────────┬──────────────────┬────────────────────────┤
│                   │  Intel EPT       │  AMD NPT               │
├───────────────────┼──────────────────┼────────────────────────┤
│ Virtualization    │  VT-x / VMX      │  AMD-V / SVM           │
│ Root Pointer      │  VMCS EPTP       │  VMCB nested_cr3       │
│ Execute-Only      │  ✅ Supported    │  ❌ Not Supported      │
│ Hook Stealth      │  High (Read≠Exec)│  Medium (Read=Exec)    │
│ Violation Event   │  EPT Violation   │  #NPF (Nested PF)      │
│ TLB Invalidation  │  INVEPT Instr    │  VMCB.TlbCtl Field     │
│ Single-Step Mech  │  MTF (VMCS Ctrl) │  RFLAGS.TF (#DB)       │
│ Page Table Struct │  4-level, Custom │  4-level, Standard x86 │
│ Struct Type Reuse │  EPT_PML4E, etc. │  Reuses EPT_PML4E, etc.│
│ Identity Map Range│  512 GB          │  512 GB                │
│ Large Page Split  │  2MB → 4KB       │  2MB → 4KB             │
│ Per-CPU Isolation │  ✅ Supported    │  ✅ Supported          │
│ Hash Acceleration │  ✅ O(1)         │  ✅ O(1)               │
└───────────────────┴──────────────────┴────────────────────────┘

Core Conclusions:
  Page Table Structure & Walk Logic → Identical
  Hook Splitting & Management        → Identical
  Key Variations Exist Only In       → Execute-Only / Root Pointer / TLB Invalidation / Single-Step Recovery
```
