[简体中文](per_cpu_pte_hook_execution_flow_CN.md) | English

# Per-CPU PTE Scheme: Comprehensive Analysis of Hook and Non-Hook Execution Flows

## 1. Core Principle: EPT Permission Separation

The core of this scheme is leveraging the **permission bits of EPT (Extended Page Tables)** to redirect/separate physical address accesses based on whether they are for Execution (Execute) or Read (Read) operations:

- **Original Page** (`OriginalPage`): A copy of the unmodified original code page.
- **Hook Page** (`HookPage`): A copy of the modified code page containing the JMP trampoline.

Every memory access by the CPU goes through EPT translation. The R/W/X permission bits on the EPT PTE determine which type of access is allowed and which type will trigger an **EPT Violation**.

---

## 2. Two Modes

### Mode A: Execute-Only Supported (R=0, W=0, X=1)

This is the most ideal mode, typically supported by modern physical CPUs.

### Mode B: Execute-Only NOT Supported (R=0, W=0, X=0)

Nested virtualization environments (such as VMware/Hyper-V) usually do not expose the Execute-Only bit.

The detection logic is executed during initialization (`ept.c`):

```c
{
    ULONG64 EptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
    g_EptHookState.ExecuteOnlySupported = (EptVpidCap & 1) != 0;

    LOG_INFO("EPT Execute-Only pages: %s",
             g_EptHookState.ExecuteOnlySupported ? "supported" : "NOT supported (fallback to R+X)");
}
```

---

## 3. Detailed Execution Flow

### ▶ Phase 1: Hook Installation (`EptHookFunction`)

```
EptHookFunction(TargetVa, HookFunction, &OriginalFunction)
```

**Steps:**

1. **Translate Target VA → PA** to determine the target 4KB physical page (`PageBase`).
2. **Split 2MB → 4KB**: Call `EptSplitLargePage` to split the 2MB large page containing the target address into 512 4KB PTEs.
3. **Allocate two page copies**:
   - `OriginalPageVa`: An exact full copy of the original code (shown to reads/writes).
   - `HookPageVa`: A modified copy with `MOV RAX, <HookFunction>; JMP RAX` written at the target function entry point.
4. **Construct Trampoline**: Save original instructions + JMP back to the target function (`OriginalBytes + JMP TargetVa+size`).
5. **Configure EPT PTE permissions** pointing to the Hook Page (`ept.c`):

```c
Pte->Read = 0;
Pte->Write = 0;
Pte->PhysAddr = Hook->HookPagePa >> 12;

if (g_EptHookState.ExecuteOnlySupported) {
    Pte->Execute = 1;
} else {
    Pte->Execute = 0;
}
```

6. **Per-CPU Isolation**: Clone the PD and PT pages to each CPU's private copy, and copy the same permission configuration to the private PTEs of all CPUs (`ept.c`):

```c
if (g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages) {
    // ... Ensure per-CPU PD and PT pages exist ...
    // Copy hook PTE permissions to all CPUs
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        PEPT_PTE CpuPte = EptGetPerCpuPte(cpu, TargetPa);
        if (CpuPte) {
            CpuPte->Read = Pte->Read;
            CpuPte->Write = Pte->Write;
            CpuPte->Execute = Pte->Execute;
            CpuPte->PhysAddr = Pte->PhysAddr;
        }
    }
}
```

**EPT PTE States After Hook Installation:**

| Mode | R | W | X | PhysAddr Points To |
|------|---|---|---|---------------------|
| Mode A (Execute-Only) | 0 | 0 | 1 | HookPage |
| Mode B (No Execute-Only) | 0 | 0 | 0 | HookPage |

---

### ▶ Phase 2: Various Accesses in Steady State

#### Scenario 1: Code Execution (Guest Executes TargetVa)

**Mode A (Execute-Only Supported):**

```
Guest executes at TargetVa
    → CPU performs EPT translation
    → PTE: R=0, W=0, X=1, PhysAddr = HookPage
    → Execution allowed (X=1), CPU fetches instructions directly from HookPage
    → Execution reaches the JMP trampoline at the Hook entry point
    → MOV RAX, <HookFunction>; JMP RAX
    → Jumps to our Hook function
    ✅ No VM-Exit, zero overhead!
```

**Mode B (No Execute-Only):**

```
Guest executes at TargetVa
    → CPU performs EPT translation
    → PTE: R=0, W=0, X=0
    → EPT Violation! (instruction fetch with no execute permission)
    → VM-Exit, enters HandleEptViolation()
```

Inside the Handler (`ept.c` `HandleEptViolation`):

```c
{
    // Get the physical page of the Guest RIP
    RipPa = MmGetPhysicalAddress((PVOID)GuestRip);
    GuestRipPagePa = RipPa.QuadPart & PAGE_MASK_4KB;

    // Temporarily grant RWX
    Pte->Read = 1;
    Pte->Write = 1;
    Pte->Execute = 1;

    if (GuestRipPagePa == Hook->TargetPhysicalAddr) {
        /* Execution: RIP is inside the hooked page → use HookPage */
        Pte->PhysAddr = Hook->HookPagePa >> 12;
    } else {
        /* Data access: RIP is elsewhere → use OriginalPage */
        Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
    }

    // Enable MTF single-stepping, restore after executing one instruction
    EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);
    ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
}
```

**Key Check**: Compare the physical page containing Guest RIP with the target physical page:
- RIP is on the hooked page → Instruction fetch → Point to HookPage (containing the JMP trampoline).
- RIP is not on the hooked page → Data read/write → Point to OriginalPage (unmodified code).

---

#### Scenario 2: Data Read (e.g. PatchGuard scanning code integrity)

**Mode A (Execute-Only):**

```
PatchGuard reads contents at TargetVa
    → CPU performs EPT translation
    → PTE: R=0, W=0, X=1, PhysAddr = HookPage
    → Read denied (R=0)! EPT Violation
    → VM-Exit, enters HandleEptViolation()
```

Handling within the Handler (`ept.c` `HandleEptViolation`):

```c
if (IsRead || IsWrite) {
    /* Data access: expose original page (only on current CPU) */
    Pte->Read = 1;
    Pte->Write = 1;
    Pte->Execute = 0;
    Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;  // ← Original physical page!

    EptInvalidateAllContexts();

    /* Record which page was relaxed by the current CPU */
    EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);

    // Enable MTF, restore after executing one instruction
    ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
}
```

Note the transient state transitioned to: **R=1, W=1, X=0, PhysAddr = Original Physical Page**

This means:
- ✅ The read returns the **original unmodified code** (PatchGuard sees clean, original code).
- ✅ Execution is forbidden (X=0) to prevent accidental execution in this state.

**Mode B (No Execute-Only):** Similar to Mode A, but evaluates `GuestRipPagePa != Hook->TargetPhysicalAddr` to determine that it is a data read, then redirects to the original page.

---

#### Scenario 3: Restoration After MTF Trigger (`HandleMtf`)

After granting temporary permissions and allowing the Guest to execute a single instruction, the MTF (Monitor Trap Flag) triggers a VM-Exit before the next instruction. At this point, the original hook state is restored (`vmx_exit.c` `HandleMtf`):

```c
for (i = 0; i < MAX_EPT_HOOKS; i++) {
    if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
        if (RelaxedPa != 0 &&
            g_EptHookState.Hooks[i].TargetPhysicalAddr != RelaxedPa) {
            continue;  // Only restore the page relaxed by the current CPU
        }

        {
            PEPT_PTE Pte = EptGetPerCpuPte(CpuIndex, ...);
            if (!Pte) Pte = g_EptHookState.Hooks[i].TargetPte;

            if (Pte->Read || Pte->Write) {
                Pte->Read = 0;
                Pte->Write = 0;
                Pte->PhysAddr = g_EptHookState.Hooks[i].HookPagePa >> 12;

                if (g_EptHookState.ExecuteOnlySupported) {
                    Pte->Execute = 1;  // Restore X-only
                } else {
                    Pte->Execute = 0;  // Restore all-forbidden
                }
            }
        }
    }
}
```

This restores the EPT PTE to its initial hook state (Mode A: `R=0, W=0, X=1`; Mode B: `R=0, W=0, X=0`) to continue guarding.

---

## 4. How Per-CPU Isolation Resolves Multi-Core Contention

### The Problem: Shared PTE Race Condition

Without per-CPU PTE isolation, the following race condition occurs:

```
Timeline:
  CPU 0: EPT Violation → PTE changed to R=1, W=1, X=0 → Waiting for MTF
  CPU 1: EPT Violation → Same PTE changed to R=1, W=1, X=0 → Waiting for MTF
  CPU 0: MTF triggers → Restores PTE to R=0, W=0, X=1
  CPU 1: Has not finished executing, but the PTE has been changed back by CPU 0! → Triggers EPT Violation again → Infinite Loop
```

### The Solution: Page Table Hierarchy of the Per-CPU Scheme

```
     Shared Template                CPU 0 Private            CPU 1 Private
      ┌─────────┐                ┌─────────┐              ┌─────────┐
      │ PML4    │                │ PML4[0] │              │ PML4[0] │
      │(Templt) │                │→CPU0 PDPT│             │→CPU1 PDPT│
      └─────────┘                └─────────┘              └─────────┘
                                      ↓                        ↓
                                ┌──────────┐             ┌──────────┐
                                │ PDPT[x]  │             │ PDPT[x]  │
                                │→CPU0 PD  │             │→CPU1 PD  │
                                └──────────┘             └──────────┘
                                      ↓                        ↓
               Non-Hook Regions → Shared PD Page (Same Physical Address)
               Hooked Regions   → Individual Private PD Pages
                                      ↓                        ↓
                                ┌──────────┐             ┌──────────┐
                                │ PD[y]    │             │ PD[y]    │
                                │→CPU0 PT  │             │→CPU1 PT  │
                                └──────────┘             └──────────┘
                                      ↓                        ↓
                                ┌──────────┐             ┌──────────┐
                                │ PT[z]    │             │ PT[z]    │
                                │R=0,W=0   │             │R=1,W=1   │  ← Independent!
                                │X=1,Hook  │             │X=0,Orig  │
                                └──────────┘             └──────────┘
```

### Per-CPU EPTP in VMCS

Each CPU's VMCS is configured with its respective EPTP (`vmx_init.c` → `EptSetupIdentityMap`):

```c
if (g_EptCpuStates && CpuNum < g_MaxProcessors) {
    VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptCpuStates[CpuNum].Eptp.Value);
} else {
    VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptState.Eptp.Value);
}
```

### Accessing Per-CPU PTEs in the EPT Violation Handler

In the EPT Violation Handler, we prioritize using the per-CPU PTE (`ept.c` `HandleEptViolation`):

```c
Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
if (!Pte) {
    /* Fallback to shared PTE */
    Pte = Hook->TargetPte;
}
```

Consequently, **CPU 0 modifying its own PTE does not affect CPU 1's PTE**, completely eliminating the race condition.

---

## 5. Comprehensive State Machine Summary

```
┌─────────────────────────────────────────────────────────┐
│              Steady State (After Hook Installed)        │
│  Mode A: R=0, W=0, X=1, PhysAddr = HookPage              │
│  Mode B: R=0, W=0, X=0, PhysAddr = HookPage              │
└───────────────┬──────────────────────┬──────────────────┘
                │                      │
       [Execution Access]       [Read/Write Access]
                │                      │
                ▼                      ▼
   ┌────────────────────┐  ┌──────────────────────────┐
   │ Mode A: Direct     │  │ EPT Violation             │
   │ execute code on    │  │ → Switch to OriginalPage  │
   │ HookPage           │  │ → R=1,W=1,X=0             │
   │ → JMP HookFunc     │  │ → Enable MTF              │
   │ (Zero VM-Exit!)    │  │ → Guest reads original    │
   │                    │  │   code                   │
   │ Mode B:            │  └──────────┬───────────────┘
   │ EPT Violation      │             │
   │ → RIP inside page  │     [MTF: Next Instruction]
   │ → Switch HookPage  │             │
   │ → R=1,W=1,X=1      │             ▼
   │ → Enable MTF       │  ┌──────────────────────────┐
   │ → Execute JMP      │  │ HandleMtf:               │
   └──────────┬─────────┘  │ Restore Steady State     │
              │            │ Mode A: R=0,W=0,X=1,Hook │
         [MTF: Mode B]     │ Mode B: R=0,W=0,X=0,Hook │
              │            └──────────────────────────┘
              ▼
   ┌────────────────────┐
   │ HandleMtf:         │
   │ Restore Steady State│
   └────────────────────┘
```

---

## 6. Key Design Assurances

| Assurance | Implementation Method |
|-----------|-----------------------|
| **Execution routes to Hook** | EPT PTE's PhysAddr points to HookPage (containing the JMP trampoline). |
| **Read routes to Original** | EPT Violation → Temporarily switches PhysAddr to OriginalPage. |
| **Restore after one instruction** | MTF (Monitor Trap Flag) single-steps and immediately restores the hook state. |
| **Multi-core Conflict Free** | Per-CPU independent PML4→PDPT→PD→PT hierarchies; modifications apply only to private PTEs. |
| **PatchGuard sees clean code** | Read operations always return the unmodified content of the OriginalPage. |
| **Fallback Security** | If per-CPU initialization fails or is absent, falls back to the shared PTE (maintains functionality but carries race condition risks). |

---

## 7. Key Source Files Involved

| File | Functionality |
|------|---------------|
| `driver/ept.c` | Core EPT engine: page table construction, 2MB → 4KB splitting, hook installation, EPT Violation handling, and per-CPU PTE management. |
| `driver/ept.h` | EPT data structure definitions: `EPT_CPU_STATE`, `EPT_HOOK_ENTRY`, and function declarations. |
| `driver/vmx_exit.c` | VMX Exit Handler: `HandleEptViolation` dispatching and `HandleMtf` hook state restoration. |
| `driver/vmx_init.c` | VMX Initialization: configures VMCS and writes per-CPU EPTP. |
| `driver/npt.c` | Corresponding AMD NPT implementation (mirrored version for the SVM architecture). |
| `driver/npt.h` | NPT data structure definitions: `NPT_CPU_STATE` and function declarations. |
| `driver/svm_exit.c` | SVM Exit Handler: corresponding AMD #NPF handling and #DB restoration. |
| `driver/svm_init.c` | SVM Initialization: configures VMCB and writes per-CPU nested_cr3. |
