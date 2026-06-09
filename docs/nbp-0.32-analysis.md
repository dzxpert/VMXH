[简体中文](nbp-0.32-analysis_CN.md) | English

# New Blue Pill (NBP) v0.32 Source Code Deep Analysis Report

> Analysis Target: `D:\VMX\nbp-0.32-public`
> Comparison Project: VMXHypervisorToolbox
> Analysis Date: 2026-04-14

---

## I. Project Overview

New Blue Pill v0.32 is Joanna Rutkowska's classic Type-II (Blue Pill) hypervisor proof-of-concept. Its core capability is to subvert a running OS into a virtual machine Guest **without rebooting**, achieving runtime OS subversion (Runtime OS Subversion).

| Attribute | Description |
|------|------|
| Architecture | Intel VMX + AMD SVM dual-platform |
| Mode | Blue Pill (runtime hypervisor injection) |
| Language | C + x64 MASM |
| Highlights | Multi-CPU atomic subversion + IPI coordination + rollback mechanism |
| Anti-Detection | BLUE_CHICKEN mechanism (automatically unloads upon detection of probing) |
| Limitations | No EPT/NPT, no Hook framework, no anti-anti-debugging |

---

## II. Project Structure

```
nbp-0.32-public/
├── common/                    # Architecture-independent common code
│   ├── common.c             # Memory management (identity page table, Spare Page mapping)
│   ├── common.h             # Global structures, CPU structures, configuration macros
│   ├── common-asm.asm       # CmSubvert entry point, register saving/restoration
│   ├── cpuid.asm            # CPUID instruction wrapper
│   ├── interrupts.h         # Interrupt/exception frame structure
│   ├── msr.asm              # MSR read/write wrapper
│   ├── regs.asm             # CPU register accessors (CR0/CR3/CR4/DR/segment registers)
│   ├── traps.c              # Trap registration/lookup/dispatch management
│   └── traps.h              # Trap structures and callback definitions
├── vmx/                      # Intel VMX implementation
│   ├── vmx.c                # VMX initialization, VMCS configuration, VM-Exit dispatching
│   ├── vmx.h                # VMX structures
│   ├── vmcs.h               # VMCS field encoding (complete)
│   ├── vmx-asm.asm          # VMXON/VMLAUNCH/VMRESUME/VMREAD/VMWRITE
│   └── vmxtraps.c           # CPUID/MSR/CR interception handlers
├── svm/                      # AMD SVM implementation
│   ├── svm.c                # SVM initialization, VMCB configuration
│   ├── svm.h                # SVM structures
│   ├── vmcb.h               # VMCB field encoding
│   ├── svm-asm.asm          # VMRUN/VMLOAD/VMSAVE
│   └── svmtraps.c           # SVM Trap handlers
├── hvm.c                     # Hypervisor abstraction layer (HVM_DEPENDENT dispatching)
├── hvm.h                     # HVM structures (CPU, function pointer table)
└── newbp.c                   # Driver entry (DriverEntry / DriverUnload)
```

---

## III. Architectural Abstraction Pattern

NBP uses the `HVM_DEPENDENT` function pointer table to achieve abstraction across both Intel and AMD platforms:

```c
typedef struct {
  BOOLEAN  (*ArchIsImplemented)(VOID);
  NTSTATUS (*ArchInitialize)(PCPU Cpu, PVOID GuestRip, PVOID GuestRsp);
  VOID     (*ArchDispatchEvent)(PCPU Cpu, PGUEST_REGS GuestRegs);
  VOID     (*ArchRegisterTraps)(PCPU Cpu);
  NTSTATUS (*ArchShutdown)(PCPU Cpu, PGUEST_REGS GuestRegs, BOOLEAN bSetupTimeBomb);
} HVM_DEPENDENT;
```

At runtime, `Hvm` points to `&Vmx` or `&Svm`, and all upper-layer code calls via `Hvm->ArchXxx()`.

**Comparison with VMXHypervisorToolbox**: The `HV_OPS` structure in our `hv_ops.h` follows the exact same design philosophy (function pointer vtable pattern), but our interface is richer (including operations such as ReadGuestRip, InjectException, HookFunction, etc.).

---

## IV. Detailed Initialization Flow

### 4.1 Driver Loading (`newbp.c: DriverEntry`)

```
DriverEntry
  → MmInitManager()              // Initialize memory manager
  → MmInitIdentityPageTable()    // Construct identity page table (VA=PA)
  → MmMapGuestKernelPages()      // Map kernel pages to Guest address space
  → HvmInit()                    // Select VMX or SVM backend
  → HvmSwallowBluepill()         // Execute multi-CPU subversion
```

### 4.2 Multi-CPU Subversion (`hvm.c: HvmSwallowBluepill`)

Key Design: **CPU-by-CPU sequential virtualization + atomic rollback on failure**

```c
for (uCpu = 0; uCpu < KeNumberProcessors; uCpu++) {
    status = CmDeliverToProcessor(uCpu, CmSubvert);  // IPI Delivery
    if (FAILED(status)) {
        // Rollback: teardown virtualized CPUs one by one
        for (j = 0; j < uCpu; j++)
            CmDeliverToProcessor(j, CmSlipIntoMatrix);  // Execute VMXOFF
        return STATUS_FAILURE;
    }
}
```

**⭐ Takeaway / Value**: Our `VmxInitialize` also uses CPU-by-CPU sequential VMLAUNCH via DPC + rollback on failure, sharing the same design. However, NBP uses IPI (`CmDeliverToProcessor`) instead of DPC. IPI is more direct and has lower latency.

### 4.3 Single-CPU Virtualization (`hvm.c: HvmSubvertCpu`)

```
CmSubvert (ASM)
  → Save all general-purpose registers to stack
  → Call HvmSubvertCpu(RSP)
      → Place CPU structure at the end of Host stack
      → HvmSetupGdt() / HvmSetupIdt()  // Custom GDT/IDT
      → Hvm->ArchRegisterTraps()        // Register Trap handlers
      → Hvm->ArchInitialize()           // VMXON + VMCS configuration + VMLAUNCH
```

**⭐ Key Technique: CPU structure placed at the end of the Host stack**

```c
PCPU Cpu = (PCPU)((PCHAR)HostStackBase + HOST_STACK_SIZE - 8 - sizeof(CPU));
```

Host RSP points to the CPU structure → The VM-Exit handler can access PCPU directly via `[RSP]` without looking it up via global variables or KeGetCurrentProcessorNumber().

**Comparison**: We look it up via `g_VmxState.CpuContexts[KeGetCurrentProcessorNumber()]`, which requires one extra array index access. NBP's approach is more efficient but more fragile (since it relies on stack layout).

---

## V. VMCS Configuration Comparison

### 5.1 Pin-Based Controls

| Control Bit | NBP | VMXHypervisorToolbox | Description |
|------|-----|---------------------|------|
| EXTERNAL_INT_EXIT | ✅ Requested | ❌ Not requested | NBP intercepts all external interrupts |
| NMI_EXIT | ❌ Not requested | ✅ Requested | We intercept NMIs |

**⭐ Analysis**: NBP intercepts external interrupts but does not intercept NMIs, while we do the opposite. NBP's approach means it must re-inject all external interrupts in the VM-Exit handler (which incurs high overhead), but it gains complete control over interrupts.

### 5.2 Processor-Based Controls

| Control Bit | NBP | VMXHypervisorToolbox |
|------|-----|---------------------|
| MSR_BITMAP | ✅ | ✅ |
| IO_BITMAP | ✅ | ✅ |
| HLT_EXIT | ✅ | ❌ (Not requested) |
| RDTSC_EXIT | ✅ | ❌ |
| MOV_DR_EXIT | ✅ | ✅ |
| CR3_LOAD_EXIT | ❌ | ✅ |
| UNCOND_IO_EXIT | ✅ | ❌ |
| INVLPG_EXIT | ✅ | ❌ (Not requested) |
| SECONDARY_CONTROLS | ❌ | ✅ |

**⭐ Key Differences**:
- NBP intercepts RDTSC (for time virtualization in anti-detection), while we do not.
- NBP has no Secondary Controls (**no EPT/VPID support**).
- We enable EPT + VPID + RDTSCP + INVPCID + XSAVES.

### 5.3 Exit/Entry Controls

NBP only requests `VM_EXIT_IA32E_MODE` and `VM_ENTRY_IA32E_MODE` (64-bit mode). We additionally save/load IA32_EFER.

---

## VI. VM-Exit Handling Comparison

### 6.1 NBP's Trap Registration System

NBP's unique design: **Runtime-registered Trap Callback Chain**

```c
typedef struct _NBP_TRAP {
    ULONG TrapType;            // TRAP_GENERAL / TRAP_MSR / TRAP_IO
    ULONG ExitCode;            // VM-Exit reason
    NBP_TRAP_CALLBACK Callback; // Handler function pointer
    struct _NBP_TRAP *Next;     // Linked list
} NBP_TRAP;
```

When a VM-Exit occurs:
```
VmxHandleInterception()
  → TrFindRegisteredTrap(exitReason)  // Search linked list for handler
  → TrExecuteGeneralTrapHandler()     // Execute callback
```

**Comparison**: We dispatch directly using a massive `switch (ExitReason)`. NBP's linked list approach is more flexible (allowing dynamic registration/unregistration at runtime) but incurs linked list traversal overhead. For the performance-sensitive VM-Exit hot path, our switch is faster.

### 6.2 CPUID Handling

```c
// NBP: vmxtraps.c
static BOOLEAN VmxDispatchCpuid(PCPU Cpu, PGUEST_REGS GuestRegs, ...)
{
    // Backdoor detection
    if (GuestRegs->rax == 0xbabecafe) {
        GuestRegs->rax = 0x69696969;  // Return backdoor signature
        return TRUE;
    }
    // Directly execute real CPUID
    GetCpuIdInfo(GuestRegs->rax, &cpuRegs);
    GuestRegs->rax = cpuRegs.eax;
    // ... Copy results
}
```

**Comparison**: NBP's CPUID handling is extremely simple—just direct execution + backdoor check. Our `AadHandleCpuid` performs extensive masking/spoofing (hiding VMX bits, faking hypervisor leaves, hiding CPUID footprints).

**⭐ Takeaway**: NBP's `0xbabecafe` backdoor pattern can be considered for inclusion to quickly confirm if the hypervisor is active during debugging.

### 6.3 MSR Handling

NBP intercepts specific MSRs and reads/writes from/to the VMCS Guest fields:

```c
case MSR_IA32_SYSENTER_CS:
    VmxRead(GUEST_SYSENTER_CS, &msrValue);  // Read from VMCS
    break;
case MSR_IA32_EFER:
    msrValue = Cpu->Vmx.GuestEFER;  // Read from cache
    break;
default:
    msrValue = MsrRead(msr);  // Execute directly
```

**Comparison**: Our `HandleRdmsrImpl` does much more work—invalid MSR pre-probing, safe-net #GP injection, and spoofing of IA32_DEBUGCTL for anti-anti-debugging. NBP's MSR handling is simpler but less robust than ours.

### 6.4 CR Access Handling

NBP's highlight: **Switching to the identity page table when Guest disables paging in CR0**

```c
case 0:  // MOV-to-CR0
    if (!(value & CR0_PG))           // Guest disabling paging?
        RegSetCr3(IdentityPageTablePA);  // Switch to identity page table
    VmxWrite(GUEST_CR0, value);
    break;
```

**⭐ Takeaway / Value**: Our CR handling does not account for scenarios where the Guest disables paging. Although 64-bit Windows does not disable paging, this is a good defensive programming habit.

### 6.5 Interrupt/NMI/Exception Handling

**NBP completely lacks**:
- ❌ No NMI handling (does not intercept NMI_EXIT)
- ❌ No IDT-Vectoring event re-injection
- ❌ No exception re-injection (#PF/#GP, etc.)
- ✅ External interrupts intercepted via PIN_BASED_EXT_INTR_MASK

**⭐ Critical Discovery**: NBP **lacks IDT-Vectoring re-injection**, meaning if a VM-Exit occurs during IDT event delivery, the Guest will lose that event. This is a known defect in NBP. We recently fixed the exact same issue.

---

## VII. Memory Management

### 7.1 Identity Page Table

NBP builds a VA=PA identity-mapped page table during initialization, which is used for:
- Allowing the Hypervisor to safely access memory even if the Guest disables paging.
- Protecting intermediate states during Guest page table walks.

**Comparison**: We achieve similar functionality using EPT identity mapping, but since NBP lacks EPT, it must handle this via manual page table switching.

### 7.2 Spare Page Mapping

NBP contains a `HvmMapGuestVAToSparePage` function that maps Guest physical pages to Host VAs by manually traversing the 4-level page table:

```
Guest VA → CR3 → PML4 → PDP → PD → PT → Guest PA → Spare Page VA
```

**Comparison**: Our `hv_mem.c` does the same thing (CR3 Walk + MmMapIoSpace), but our implementation is more complete (supporting 2MB/1GB large pages, PSE, and error handling).

### 7.3 Host Stack

| | NBP | VMXHypervisorToolbox |
|---|---|---|
| Size | 16 pages (64KB) | 4 pages (16KB) |
| CPU Struct Location | End of stack | Separate global array |
| Access Method | Direct offset from `[RSP]` | `g_VmxState.CpuContexts[CpuIndex]` |

**⭐ Takeaway**: NBP's 64KB Host stack is more conservative and safer. Our 16KB stack might run a risk of stack overflow under deep call chains (e.g., EPT violation handler → Hook engine → log write). We should consider increasing ours to 32KB.

---

## VIII. Anti-Detection Mechanisms

### 8.1 BLUE_CHICKEN

NBP's unique anti-detection strategy: **Auto-unload when detected**

```c
if (BLUE_CHICKEN_CHECK) {
    CmMakeCpuLeaveVirtualMode();  // Immediate VMXOFF + restore Guest
}
```

Logic: If someone detects the hypervisor via the CPUID backdoor (`0xbabecafe`), it actively exits virtualization. This is more aggressive than hiding—it completely removes the evidence.

### 8.2 RDTSC Interception

NBP intercepts the RDTSC instruction (`CPU_BASED_RDTSC_EXITING`), enabling it to spoof timestamps to counter time-difference-based detection.

**⭐ Takeaway / Value**: We currently do not intercept RDTSC; instead, we use the TSC_OFFSETTING hardware mechanism (which is more efficient). However, if finer RDTSC control is needed (such as spoofing RDTSC for anti-debugging), we could consider switching to RDTSC_EXIT in specific scenarios.

---

## IX. VM Unloading (Guest Liberation)

### 9.1 Dynamic Trampoline Generation

One of NBP's most ingenious techniques: **Runtime generation of assembly Trampoline code**

```c
VmxGenerateTrampolineToGuest(PCPU Cpu, PVOID TrampolineBase)
{
    PUCHAR pCode = (PUCHAR)TrampolineBase;
    
    // Dynamically generate machine code:
    // 1. Restore all Guest registers
    // 2. Restore CR0/CR3/CR4
    // 3. Restore GDT/IDT
    // 4. Restore FS_BASE/GS_BASE
    // 5. Construct IRETQ stack frame (SS:RSP:RFLAGS:CS:RIP)
    // 6. VMXOFF
    // 7. IRETQ → Return to Guest
}
```

**Comparison**: Our `VmxShutdown` (vmx_asm.asm) is static assembly code. It performs VMXOFF + RET after reading Guest state via VMCS vmread. NBP's dynamic trampoline is more flexible (supporting recovery of arbitrary Guest state), but our static method is simpler and more reliable.

**⭐ Takeaway**: NBP uses `IRETQ` to restore the Guest (which restores CS:RIP + SS:RSP + RFLAGS all at once), whereas we use a `popfq` + `ret` combination. IRETQ is the more standard way.

---

## X. Summary of Key Borrowable Techniques

### ⭐⭐⭐ High Priority

| # | Technique | NBP Implementation | Current Status | Recommendation |
|---|---|---|---|---|
| 1 | **CPUID Backdoor** | `CPUID(0xbabecafe)` → `0x69696969` | None | Add debug backdoor for easy verification of hypervisor presence |
| 2 | **Host Stack Size** | 16 pages (64KB) | 4 pages (16KB) | Consider increasing to 32KB to prevent stack overflow in deep call chains |
| 3 | **IRETQ Restoration** | Use IRETQ to restore CS:RIP+SS:RSP+RFLAGS all at once after VMXOFF | popfq + ret | Consider switching to IRETQ, which is more standard |

### ⭐⭐ Medium Priority

| # | Technique | NBP Implementation | Current Status | Recommendation |
|---|---|---|---|---|
| 4 | **Trap Registration System** | Linked list + callbacks | switch dispatch | The current switch approach has better performance, but this can be kept in mind for future dynamic hook scenarios |
| 5 | **EFER Cache** | Cache GuestEFER + sync VM_ENTRY_IA32E_MODE | Partially implemented | Ensure EFER handling is fully complete |
| 6 | **CR0 Paging Check** | Switch to identity page table when paging is disabled | Unhandled | Add defensively (won't trigger under 64-bit Windows) |

### ⭐ Low Priority / Reference

| # | Technique | Description |
|---|---|---|
| 7 | BLUE_CHICKEN Anti-Detection | Automatically unload when probed—extreme but effective |
| 8 | RDTSC Interception | Used for time spoofing in anti-detection; our TSC_OFFSETTING is more efficient |
| 9 | Identity Page Table | We have EPT so this is not needed, but the concept is useful for EPT-less scenarios |
| 10 | IPI instead of DPC | IPI has lower latency than DPC, but DPC is safer (can wait for completion) |

---

## XI. Limitations of NBP (Areas Where We Have Surpassed It)

| Area | NBP | VMXHypervisorToolbox |
|------|-----|---------------------|
| EPT/NPT | ❌ None | ✅ Complete EPT + NPT + Hook framework |
| IDT-Vectoring Re-injection | ❌ None (loses Guest exceptions) | ✅ Implemented |
| NMI Handling | ❌ Not intercepted | ✅ Intercepted + re-injected |
| Anti-Anti-Debugging | ❌ None | ✅ 10+ independent techniques |
| SSDT/Shadow SSDT | ❌ None | ✅ Discovery + Hooking + Monitoring |
| Process Memory R/W | ❌ Basic Spare Page | ✅ Complete CR3 Walk + direct physical memory access |
| MSR Safety | ❌ Direct execution may #GP | ✅ Pre-probing + safety net |
| Logging System | ❌ DbgPrint only | ✅ Lock-free Ring Buffer + Flush Thread |
| VPID | ❌ None | ✅ Per-CPU VPID |
| XSAVES | ❌ None | ✅ Supported |

---

## XII. Conclusion

NBP v0.32 is an elegant, compact Blue Pill proof-of-concept with a small codebase (~5000 lines). Its architectural abstraction pattern (HVM_DEPENDENT) is highly consistent with our hv_ops design, validating our architectural direction.

**Most Valuable Takeaway Points**:
1. **CPUID Backdoor** — A simple and practical debugging tool.
2. **Larger Host Stack** — Prevents stack overflow in deep call chains.
3. **IRETQ Restoration** — A more standard approach for restoring Guest state.

**Areas Where We Have Surpassed NBP**: EPT/NPT Hook framework, complete anti-anti-debugging engine, SSDT monitoring, IDT-Vectoring re-injection, safe MSR handling, and process memory read/write engine. NBP is excellent for educational purposes and proof-of-concepts but is not suitable for production use.
