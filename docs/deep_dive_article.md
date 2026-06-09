[简体中文](deep_dive_article_CN.md) | English

# VMX Hypervisor Toolbox Deep Technical Analysis

> **A comprehensive technical article for security researchers and kernel developers**
>
> This article starts from the principles of x86-64 hardware virtualization and goes deep, layer by layer, into the implementation details of a complete Type-2 (Blue Pill) Hypervisor — VMX Hypervisor Toolbox. It covers source-code-level technical details of all core subsystems, including Intel VT-x / AMD SVM dual-platform architecture, EPT/NPT page-splitting Hook, PatchGuard bypass mechanism, Hyper-V nested virtualization optimizations, anti-anti-debugging engine, Hypervisor-level memory read/write engine, and SSDT/Shadow SSDT monitoring framework.

---

## Table of Contents

- [Chapter 1: x86-64 Hardware-Assisted Virtualization Principles](#chapter-1-x86-64-hardware-assisted-virtualization-principles)
- [Chapter 2: Intel VT-x vs AMD SVM Architecture Comparison](#chapter-2-intel-vt-x-vs-amd-svm-architecture-comparison)
- [Chapter 3: PatchGuard (KPP) Principles and Bypass Mechanism](#chapter-3-patchguard-kpp-principles-and-bypass-mechanism)
- [Chapter 4: Windows Hyper-V and Nested Virtualization](#chapter-4-windows-hyper-v-and-nested-virtualization)
- [Chapter 5: Blue Pill Late-Launch Virtualization](#chapter-5-blue-pill-late-launch-virtualization)
- [Chapter 6: VMX Initialization Full Flow](#chapter-6-vmx-initialization-full-flow)
- [Chapter 7: Generic EPT/NPT Hook Framework](#chapter-7-generic-eptnpt-hook-framework)
- [Chapter 8: Anti-Anti-Debugging Engine](#chapter-8-anti-anti-debugging-engine)
- [Chapter 9: Hypervisor Memory Read/Write Engine](#chapter-9-hypervisor-memory-readwrite-engine)
- [Chapter 10: SSDT & Shadow SSDT Monitoring and Hook Framework](#chapter-10-ssdt--shadow-ssdt-monitoring-and-hook-framework)
- [Chapter 11: Driver-User Mode Communication Architecture](#chapter-11-driver-user-mode-communication-architecture)
- [Appendix](#appendix)

---

## Chapter 1: x86-64 Hardware-Assisted Virtualization Principles

> 📊 Architecture Diagram References: `vmx_nested_virtualization.drawio`, `vmx_init_flow.drawio`

### 1.1 The Evolution from Software Virtualization to Hardware Virtualization

Prior to hardware virtualization, the x86 architecture suffered from "virtualization holes" — 17 sensitive instructions behaved differently in Ring 0 and Ring 3, but did not trigger a trap (exception). For example, the `POPF` instruction modifies the IF (interrupt flag) when executed in Ring 0, but is silently ignored in Ring 3. The traditional Trap-and-Emulate model relies on the assumption that "all privileged instructions trigger a trap", which could not be directly satisfied on original x86 architectures.

Early virtualization solutions, such as those by VMware, adopted **Binary Translation (BT)** technology — dynamically scanning guest code prior to execution and replacing sensitive instructions with equivalent, safe instruction sequences. This approach incurred significant performance overhead (approximately 10-30%) and was extremely complex to implement.

Between 2005 and 2006, Intel and AMD respectively introduced hardware virtualization extensions:

| Feature | Intel | AMD |
|------|-------|-----|
| Brand Name | VT-x (Vanderpool) | AMD-V (Pacifica) |
| Instruction Set | VMX (Virtual Machine Extensions) | SVM (Secure Virtual Machine) |
| Initial CPU | Pentium 4 672/662 (2005) | Athlon 64 X2 (2006) |
| Control Structure | VMCS (4KB) | VMCB (4KB) |
| Second-Level Address Translation | EPT (Nehalem, 2008) | NPT (Barcelona, 2007) |

The core concept of hardware virtualization is: **introducing an execution mode with higher privilege than Ring 0 at the hardware level (Ring -1)**, allowing the Hypervisor to run in this mode, while the Guest OS runs in a restricted Ring 0 controlled by the Hypervisor.

### 1.2 VMX Root / Non-Root Dual-Mode Architecture

Intel VT-x divides the CPU execution states into two fundamentally different modes:

```
┌─────────────────────────────────────────────┐
│            VMX Root Mode (Ring -1)           │
│  ┌───────────────────────────────────────┐   │
│  │  Hypervisor / VMM                     │   │
│  │  - Complete hardware control          │   │
│  │  - Intercepts any guest sensitive ops │   │
│  │  - Manages VMCS / EPT                 │   │
│  └───────────────────────────────────────┘   │
├─────────────────────────────────────────────┤
│          VMX Non-Root Mode (Guest)           │
│  ┌─────────────────────┐ ┌────────────────┐ │
│  │ Ring 0: Guest Kernel │ │ Ring 3: App    │ │
│  │ (Believes it has    │ │ (Normal user   │ │
│  │  highest privilege, │ │  mode)         │ │
│  │  but is actually    │ │                │ │
│  │  monitored by VMM)  │ │                │ │
│  └─────────────────────┘ └────────────────┘ │
└─────────────────────────────────────────────┘
```

Key features:

- **VMX Root Mode**: The mode in which the Hypervisor runs. It has complete control over hardware and decides which Guest operations trigger a VM-Exit through VMCS configuration.
- **VMX Non-Root Mode**: The mode in which the Guest OS runs. Semantically, it is almost identical to normal Ring 0, but the Hypervisor can selectively intercept any sensitive operations.
- **Mode Transitions**: VM-Entry transitions from Root to Non-Root; VM-Exit transitions from Non-Root back to Root.

AMD SVM uses different terminology but is conceptually equivalent: Host Mode corresponds to VMX Root, and Guest Mode corresponds to VMX Non-Root.

### 1.3 The Complete Lifecycle of VM-Entry and VM-Exit

A complete virtualization cycle is as follows:

```
          ┌──── VM-Entry ────┐
          │  (VMLAUNCH/      │
          │   VMRESUME)      │
          ▼                  │
    ┌───────────┐      ┌───────────┐
    │ Non-Root  │─────→│   Root    │
    │ (Guest)   │      │ (Host)    │
    │           │      │           │
    │ Executes  │ VM-Exit│ Analyzes  │
    │ Guest     │──────→│ exit      │
    │ code...   │      │ reason,   │
    │           │      │ handles it│
    └───────────┘      │ & resumes │
                       └───────────┘
```

**VM-Entry Process** (takes approximately several hundred clock cycles):
1. Validate the legality of all Guest State fields in the VMCS.
2. Load Guest's CR0/CR3/CR4, segment registers, and MSRs.
3. Load Guest's RIP/RSP/RFLAGS.
4. Switch to Non-Root Mode and begin executing Guest code.

**VM-Exit Trigger Conditions** (dependent on VMCS configuration):
- Execution of privileged instructions: CPUID, RDMSR/WRMSR, MOV-to-CR, HLT...
- External interrupts (if `External-interrupt exiting` is configured)
- Exceptions (if corresponding bits in the Exception Bitmap are set)
- EPT Violations (second-level page table permission violations)
- Monitor Trap Flag (single-step debugging flag)

**VM-Exit Handling Process**:
1. The CPU automatically saves the Guest state to the VMCS Guest-State area.
2. Load Host state (VMCS Host-State area → CPU registers).
3. Write the exit reason to the VMCS Exit-Information field.
4. Jump to Host RIP (VM-Exit Handler entry point).

### 1.4 VMCS Control Structure Deep Analysis

VMCS (Virtual Machine Control Structure) is the core data structure of Intel VT-x — a 4KB-aligned memory page containing all information necessary to control virtualization behaviors. Internally, it is divided into **6 major areas**:

```
┌──────────────────────────────────────────┐
│  VMCS (4KB Page)                         │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │ 1. Guest-State Area               │  │
│  │   CR0/CR3/CR4, Segment registers,  │  │
│  │   RIP/RSP, RFLAGS, GDT/IDT, MSRs   │  │
│  ├────────────────────────────────────┤  │
│  │ 2. Host-State Area                │  │
│  │   CR0/CR3/CR4, Segment selectors, │  │
│  │   RIP/RSP, GDT/IDT Base, MSRs      │  │
│  ├────────────────────────────────────┤  │
│  │ 3. VM-Execution Control Fields    │  │
│  │   Pin-Based / Proc-Based Controls │  │
│  │   Exception Bitmap, EPT Pointer,  │  │
│  │   MSR Bitmap, CR Masks/Shadows    │  │
│  ├────────────────────────────────────┤  │
│  │ 4. VM-Exit Control Fields         │  │
│  │   Exit Controls, MSR Store/Load   │  │
│  ├────────────────────────────────────┤  │
│  │ 5. VM-Entry Control Fields        │  │
│  │   Entry Controls, Event Injection │  │
│  ├────────────────────────────────────┤  │
│  │ 6. VM-Exit Information (Read-Only) │  │
│  │   Exit Reason, Qualification,     │  │
│  │   Interruption Info, Guest PA     │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

**VMCS Field Encoding Format**:

Each VMCS field is identified by a 32-bit encoding with the following format:

```
Bits [14:13] = Field width: 00=16-bit, 01=64-bit, 10=32-bit, 11=natural-width
Bits [11:10] = Field type:  00=control, 01=read-only, 10=Guest, 11=Host
Bits [9:1]   = Field index
Bit  [0]     = High-half access flag (64-bit fields only)
```

**AdjustControls Formula** — Intel SDM Vol. 3C §31.5.1:

When configuring VMCS control fields, CPU constraints of Allowed-0 and Allowed-1 must be met. The implementation in this project is as follows:

```c
static ULONG VmxAdjustControls(ULONG RequestedControls, ULONG64 Capability)
{
    ULONG Low  = (ULONG)(Capability & 0xFFFFFFFF);   /* Allowed 0-settings (must-be-1) */
    ULONG High = (ULONG)(Capability >> 32);           /* Allowed 1-settings (can-be-1) */

    RequestedControls |= Low;   /* Enforce must-be-1 bits */
    RequestedControls &= High;  /* Enforce must-be-0 bits */

    return RequestedControls;
}
```

Formula essence: `Result = (Requested | Must1) & Can1`. This ensures that every bit in the result satisfies:
- If a bit must be 1 (corresponding bit in Low = 1), then the result bit = 1.
- If a bit must be 0 (corresponding bit in High = 0), then the result bit = 0.
- Other bits are configured according to the requested value.

### 1.5 EPT Second-Level Address Translation

Extended Page Tables (EPT) is Intel's second-level address translation mechanism, providing a two-layer address conversion: **GVA → GPA → HPA**:

```
Guest Virtual Address (GVA)
    │
    ▼  [Guest Page Table Walk, controlled by CR3]
Guest Physical Address (GPA)
    │
    ▼  [EPT Page Table Walk, controlled by EPTP]
Host Physical Address (HPA)
    │
    ▼  [Actual Memory Access]
```

EPT adopts the same 4-level page table structure as traditional x86-64 paging:

```
EPTP (EPT Pointer, stored in VMCS)
  │
  ▼
PML4 (512 entries, each entry covers 512GB)
  │
  ▼
PDPT (512 entries, each entry covers 1GB)
  │
  ▼
PD (512 entries, each entry covers 2MB)     ← Large Page can be used at this level
  │
  ▼
PT (512 entries, each entry covers 4KB)
```

Each EPT Page Table Entry (PTE) contains the following key fields:

| Bit | Name | Description |
|----|------|------|
| 0 | Read | Read access permitted |
| 1 | Write | Write access permitted |
| 2 | Execute | Execute access permitted |
| 7 | LargePage | Marked as large page (2MB/1GB) |
| [51:12] | PhysAddr | Next level page table / physical page frame address |
| [5:3] | MemoryType | Memory type (WB/UC/WT, etc.) |

**Core Advantage of EPT**: The Hypervisor can precisely control the R/W/X permissions of each 4KB physical page without the Guest OS being aware — which is the technical foundation for transparent hooking.

**TLB Caching**: EPT translation results are cached in the TLB. After modifying EPT entries, the `INVEPT` instruction must be executed to invalidate the cache. VPID (Virtual Processor Identifier) allows assigning different TLB tags to different Guests, avoiding full TLB flushes during VM-Entry/VM-Exit.

---

## Chapter 2: Intel VT-x vs AMD SVM Architecture Comparison

> 📊 Architecture Diagram Reference: `svm_vs_vmx_architecture.drawio`

### 2.1 VMCS vs VMCB — Fundamental Control Structure Differences

Although Intel's VMCS and AMD's VMCB are both 4KB control structures, they differ fundamentally in how they are accessed:

| Feature | Intel VMCS | AMD VMCB |
|------|-----------|----------|
| **Access Method** | Indirect access via VMREAD/VMWRITE instructions | Direct memory read/write (struct member offsets) |
| **Internal Layout** | CPU-internal format, opaque to software | Publicly defined C structure |
| **Active State** | Only one VMCS can be active per CPU at a time | VMCB address passed as a parameter to VMRUN |
| **Switching Method** | VMCLEAR + VMPTRLD | Simply replace the VMCB address in RAX |
| **Size** | 4KB (reported by IA32_VMX_BASIC) | 4KB (fixed) |

**Structural Layout of VMCB** (taken from `svm.h`):

```c
typedef struct _VMCB {
    struct {                        /* Control Area (offset 0x000-0x3FF) */
        ULONG   InterceptCr;       /* +0x000: CR read/write intercepts */
        ULONG   InterceptDr;       /* +0x004: DR read/write intercepts */
        ULONG   InterceptExceptions; /* +0x008: Exception intercept bitmap */
        ULONG64 Intercept;         /* +0x00C: Instruction intercept bitmap (64-bit) */
        ULONG64 IopmBasePa;        /* +0x040: I/O permission map PA */
        ULONG64 MsrpmBasePa;       /* +0x048: MSR permission map PA */
        ULONG64 TscOffset;         /* +0x050: TSC offset */
        ULONG   Asid;              /* +0x058: Address space ID */
        ULONG   TlbCtl;            /* +0x05C: TLB control */
        ULONG64 IntCtl;            /* +0x060: Interrupt control */
        ULONG64 ExitCode;          /* +0x070: #VMEXIT exit code */
        ULONG64 ExitInfo1;         /* +0x078: Exit info 1 */
        ULONG64 ExitInfo2;         /* +0x080: Exit info 2 */
        ULONG64 ExitIntInfo;       /* +0x088: Exit interrupt info */
        ULONG64 NestedCtl;         /* +0x090: Nested paging control */
        ULONG64 NestedCr3;         /* +0x0B0: Nested page table root (NCR3) */
        ULONG64 NextRip;           /* +0x0C8: NRIP Save */
        ULONG64 EventInj;          /* +0x0A8: Event injection */
        // ... more control fields
    } Control;

    struct {                        /* State Save Area (offset 0x400-0xFFF) */
        USHORT  EsSel, CsSel, SsSel, DsSel, FsSel, GsSel;
        // Segment bases, limits, attributes
        ULONG64 Cr0, Cr2, Cr3, Cr4;
        ULONG64 Dr6, Dr7;
        ULONG64 Rflags, Rip, Rsp, Rax;
        ULONG64 Star, Lstar, Cstar, Sfmask;
        ULONG64 KernelGsBase;
        ULONG64 SysenterCs, SysenterEsp, SysenterEip;
        // ... more Guest state
    } Save;
} VMCB;
```

Contrast this with the indirect access of Intel VMCS:

```c
/* Intel: Must use VMREAD/VMWRITE instructions */
ULONG64 guestRip = VmxRead(VMCS_GUEST_RIP);     /* __vmx_vmread() */
VmxWrite(VMCS_GUEST_RIP, newRip);                /* __vmx_vmwrite() */

/* AMD: Direct structure member access */
ULONG64 guestRip = Vmcb->Save.Rip;
Vmcb->Save.Rip = newRip;
```

### 2.2 VMLAUNCH/VMRESUME vs VMRUN — Different Paths to Enter the Guest

**Intel Guest Entry Flow**:
```
VMXON → VMCLEAR → VMPTRLD → (Configure VMCS) → VMLAUNCH
                                              │
                                        After VM-Exit
                                                │
                                             VMRESUME → (Another VM-Exit) → VMRESUME → ...
```

Intel distinguishes the first entry (VMLAUNCH) from subsequent resumes (VMRESUME). Once VMLAUNCH succeeds, the VMCS is marked as "launched", and only VMRESUME can be used thereafter.

**AMD Guest Entry Flow**:
```
Set EFER.SVME → Configure VMCB → VMLOAD → VMRUN → (#VMEXIT) → VMSAVE → VMRUN → ...
                                  ▲               │
                                  └───────────────┘
```

AMD's model is simpler: it only has a single `VMRUN` instruction, making no distinction between first/subsequent entries. However, you must manually execute `VMLOAD` (to load hidden Host state) and `VMSAVE` (to save hidden Guest state).

In this project's assembly implementation (`svm_asm.asm`):

```asm
AsmSvmVmrun PROC
    push    rbp
    mov     rbp, rsp
    ; ... save callee-saved registers ...
    mov     rax, rcx            ; RAX = VMCB physical address
    mov     r15, rdx            ; R15 = GUEST_CONTEXT pointer

    ; Restore Guest GP registers from GUEST_CONTEXT
    mov     rcx, [r15+08h]      ; RCX
    mov     rdx, [r15+10h]      ; RDX
    ; ... restore R8-R14 ...

    vmload                      ; Load hidden state from VMCB
    vmrun                       ; Enter Guest (VMCB PA in RAX)
    vmsave                      ; Save hidden state after Guest exit

    ; Save Guest GP registers back to GUEST_CONTEXT
    mov     [r15+08h], rcx
    mov     [r15+10h], rdx
    ; ...
    pop     rbp
    ret
AsmSvmVmrun ENDP
```

### 2.3 EPT vs NPT — Second-Level Page Table Implementation Differences

Intel EPT and AMD NPT are functionally equivalent (both provide GPA → HPA translation), but they differ slightly in implementation details:

| Feature | Intel EPT | AMD NPT |
|------|-----------|---------|
| **Page Table Format** | Similar to x86-64, but with independent permission bits | Reuses x86-64 PTE format |
| **Permission Bits** | Opaque R/W/X three bits | Reuses P/R/W bits + NX bit |
| **Execute-Only** | Supported (R=0, W=0, X=1) | **Not Supported** |
| **TLB Invalidation** | INVEPT instruction | Standard TLB flush + ASID |
| **ASID/VPID** | VPID (16-bit) | ASID (32-bit) |
| **Violation Info** | Detailed R/W/X flags in Exit Qualification | P/W/U/ID flags in ExitInfo1 |

### 2.4 MTF vs RFLAGS.TF — Single-Step Debugging Mechanism

Intel VT-x provides a dedicated **Monitor Trap Flag (MTF)**: after setting the MTF bit in the VMCS Primary Processor-Based Controls, executing exactly one Guest instruction triggers a VM-Exit (Exit Reason = MTF).

AMD SVM lacks an MTF equivalent. This project uses **Guest RFLAGS.TF (Trap Flag)** as an alternative: setting the TF bit triggers a #DB exception after executing one instruction, which is intercepted by the Hypervisor.

```c
/* Intel: Use MTF */
static VOID VmxOpsEnableSingleStep(VOID)
{
    ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
    ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
}

/* AMD: Use RFLAGS.TF + #DB exception interception */
/* In NptHandlePageFault: */
Vmcb->Save.Rflags |= (1ULL << 8);    /* Set TF bit */
/* In SvmHandleDbException restore: */
Vmcb->Save.Rflags &= ~(1ULL << 8);   /* Clear TF bit */
```

### 2.5 Execute-Only Support Difference and Its Impact on Hook Stealth

This is the **most practically significant difference** between the two platforms.

**Intel EPT** supports Execute-Only pages (R=0, W=0, X=1). This means:
- Memory pages can be **executed** but cannot be **read or written**.
- Integrity check tools like PatchGuard read code pages and see the **original, unmodified content**.
- The hooked version of the page is only used when the CPU executes instructions.

**AMD NPT** does not support Execute-Only. The closest alternative is R+X (R=1, W=0, X=1):
- Code pages can be **executed and read**.
- When PatchGuard reads the code pages, it sees the **modified, hooked page content**.
- This reduces stealth, though a dynamically switching page scheme using MTF/TF single-stepping can restore original pages upon read access.

### 2.6 hv_ops Abstraction Layer — How to Support Dual Platforms with One Codebase

This project implements a perfect abstraction of Intel/AMD via an **HV_OPS virtual function table (vtable)**:

```c
typedef struct _HV_OPS {
    const char  *Name;                     /* "Intel VMX" or "AMD SVM" */
    CPU_VENDOR  Vendor;

    /* Lifecycle Management */
    BOOLEAN     (*IsSupported)(VOID);
    NTSTATUS    (*Initialize)(VOID);
    VOID        (*Terminate)(VOID);

    /* Guest State Read/Write */
    ULONG64     (*ReadGuestRip)(VOID);
    VOID        (*WriteGuestRip)(ULONG64 Value);
    ULONG64     (*ReadGuestCr3)(VOID);
    // ... more Guest state access functions

    /* EPT/NPT Operations */
    NTSTATUS    (*HookFunction)(ULONG64 TargetVa, PVOID HookFunc, PVOID *OrigFunc);
    NTSTATUS    (*UnhookFunction)(ULONG64 TargetVa);
    VOID        (*UnhookAll)(VOID);

    /* Single-Step Control */
    VOID        (*EnableSingleStep)(VOID);
    VOID        (*DisableSingleStep)(VOID);

    // ... totaling 30+ function pointers
} HV_OPS;
```

The global pointer `g_HvOps` is set in `DriverEntry` based on the CPU vendor detection results:

```c
/* CPU Detection → Select Backend */
g_CpuVendor = HvDetectCpuVendor();
if (g_CpuVendor == CPU_VENDOR_INTEL && HvCheckVmxSupport()) {
    g_HvOps = &g_VmxOps;    /* Intel VMX Backend */
} else if (g_CpuVendor == CPU_VENDOR_AMD && HvCheckSvmSupport()) {
    g_HvOps = &g_SvmOps;    /* AMD SVM Backend */
}
```

All other modules access functionality via convenience macros and never directly depend on a specific platform:

```c
#define HvReadGuestRip()       g_HvOps->ReadGuestRip()
#define HvReadGuestCr3()       g_HvOps->ReadGuestCr3()
#define HvHookFunction(t,h,o)  g_HvOps->HookFunction(t,h,o)
#define HvAdvanceGuestRip()    g_HvOps->AdvanceGuestRip()
```


## Chapter 3: PatchGuard (KPP) Principles and Bypass Mechanism

> 📊 Architecture Diagram Reference: `vmx_hook_framework.drawio`

### 3.1 PatchGuard Working Principle

Kernel Patch Protection (KPP, commercially known as PatchGuard) is a kernel integrity protection mechanism introduced in Windows x64. Its core responsibility is: **periodically validate critical kernel data structures, and trigger a BSOD (Bug Check 0x109: CRITICAL_STRUCTURE_CORRUPTION) if tampering is detected**.

The objects protected by PatchGuard include but are not limited to:
- **SSDT** (KiServiceTable): System Service Descriptor Table
- **IDT** (Interrupt Descriptor Table): Interrupt Descriptor Table
- **GDT** (Global Descriptor Table): Global Descriptor Table
- **Critical Kernel Functions**: Code segments of `ntoskrnl.exe`
- **MSR**: `IA32_LSTAR` (SYSCALL entry point), etc.
- **Critical Data Structures**: Validation of `EPROCESS`/`ETHREAD` structures.

PatchGuard operates by:
1. Calculating **hash/checksum values** for the aforementioned structures during system initialization.
2. Triggering validation checks using a **randomized timer** (with intervals ranging from seconds to minutes).
3. **Reading** these memory regions during validation and comparing them with the stored checksums.
4. Calling `KeBugCheckEx(0x109, ...)` if any discrepancies are detected.

### 3.2 Why Traditional Hooks are Detected by PatchGuard

Traditional inline hook methods modify the first few bytes of the target function directly:

```
Original Function:           After Hooking:
NtCreateFile:                NtCreateFile:
  mov r11, rsp                 jmp MyHook        ← PatchGuard reads this
  sub rsp, 10h                 nop
  push rbp                     nop
  ...                          ...
```

Since PatchGuard's validation logic runs in **Ring 0** (kernel mode) and directly reads code page memory using `memcmp` or similar methods for comparison, it will inevitably detect changes because traditional hooks alter the actual physical memory content.

### 3.3 EPT/NPT Page Splitting — Separation of Read and Execute Permissions

The core breakthrough of this project lies in utilizing the **permission separation features** of EPT/NPT to return different contents for read and execute accesses to the same address space.

Principle diagram:

```
Guest VA: NtCreateFile (0xfffff800`12345678)
                │
                ▼
          GPA: 0x1A2B3000 (via Guest Page Tables)
                │
         ┌──────┴──────┐
         │ EPT PTE Look │
         │  R=0 W=0 X=1 │  ← Execute-Only
         └──────┬──────┘
                │
    ┌───────────┼───────────┐
    │           │           │
    ▼           ▼           ▼
  Read        Write      Execute
  Access      Access     Access
    │           │           │
    ▼           ▼           ▼
  EPT Violation EPT Violation Normal Execution
  (VM-Exit)    (VM-Exit)    ↓
    │           │       Hooked Page
    ▼           ▼    (with JMP instruction)
  Temporarily  Temporarily
  switch to    switch to
  original     original
  page (R=1,   page (R=1,
  W=1) + MTF   W=1) + MTF
  single-step  single-step
    │           │
    ▼           ▼
  After MTF    After MTF
  Exit,        Exit,
  restore      restore
  X-only       X-only
```

### 3.4 The Brilliance of Execute-Only

After setting `Read=0, Write=0, Execute=1` in the Intel EPT:

- **Execution** (IF/IP instruction fetch): Does not trigger an EPT Violation, and directly executes the hooked page (which contains the JMP to our function).
- **Reading** (data accesses like MOV/CMP): Triggers an EPT Violation. The Hypervisor intervenes and temporarily displays the **original page**.

This means that PatchGuard's `memcmp` checks **always read the unmodified original code**, while the CPU **always executes the hooked code**.

The project's implementation (`ept.c` -> `HandleEptViolation`):

```c
if (IsRead || IsWrite) {
    /* Read/Write access → Show original page */
    Hook->TargetPte->Read = 1;
    Hook->TargetPte->Write = 1;
    Hook->TargetPte->Execute = 0;
    Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;  /* Original physical page */

    EptInvalidateAllContexts();

    /* Enable MTF: VM-Exit after executing one instruction to restore Execute-Only */
    ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
}
```

### 3.5 NPT Compromise Solution: Read+Execute Strategy and Stealth Analysis

Since AMD NPT does not support Execute-Only pages, this project adopts a **R+X (Read=1, Write=0, Execute=1)** strategy on the AMD platform:

- Both **execution and reads** access the hooked page directly.
- Only **writes** trigger an NPT Fault.
- PatchGuard reads see the **hooked page containing the JMP instruction**.

Compromise scheme: Use NPT Fault + RFLAGS.TF single-stepping to dynamically switch pages when a read operation is detected. However, because NPT does not distinguish between read and execute (both require R=1), it cannot achieve the same precise read/execute separation as Intel.

**Stealth Comparison**:

| Scenario | Intel EPT | AMD NPT |
|------|-----------|---------|
| PatchGuard Code Validation | ✅ Fully Hidden | ⚠️ Requires extra handling |
| memcmp Integrity Check | ✅ Read returns original | ❌ Read returns Hooked |
| Code Signature Verification | ✅ Fully Passes | ⚠️ Relies on write-protect trigger |
| Debugger Code Inspection | ✅ Hidden | ⚠️ Visible |

### 3.6 Why Ring -1 Modifications are Completely Invisible to Ring 0 PatchGuard

Final Key Insight:

1. **PatchGuard runs in Ring 0** (Guest's kernel mode), so it can only use memory accesses from the Guest's perspective.
2. **EPT/NPT is hardware-level address translation**, entirely controlled by the Hypervisor (Ring -1).
3. Any memory access instructions from the Guest **must** pass through EPT/NPT translation.
4. PatchGuard **cannot perceive** the existence of EPT/NPT, let alone bypass it.
5. Even if PatchGuard uses `CR3` to directly walk page tables, the translated address is still a **GPA**, which ultimately must be translated by EPT.

This represents an **insurmountable privilege layer gap**: Ring 0 code runs entirely inside a 'sandbox' controlled by Ring -1. Ring -1 has **complete perception and control** over Ring 0, whereas Ring 0 **cannot perceive** Ring -1 (unless permitted by Ring -1).

---

## Chapter 4: Windows Hyper-V and Nested Virtualization

> 📊 Architecture Diagram Reference: `vmx_nested_virtualization.drawio`

### 4.1 Hyper-V Architecture

Microsoft Hyper-V is a **Type-1 Hypervisor** that runs directly on the hardware. Even though Windows appears to be the Host OS, once Hyper-V is enabled, Windows itself runs as a Guest (the Root Partition):

```
┌──────────────────────────────────────────────────────┐
│                    Hardware (CPU/Memory)             │
├──────────────────────────────────────────────────────┤
│              Hyper-V Hypervisor (L0)                  │
│                     Ring -1                           │
├──────────────┬───────────────────────────────────────┤
│ Root Partition│        Child Partitions               │
│ (Windows Host)│   (VMs: Linux, Windows Guest...)      │
│   Ring 0/3    │         Ring 0/3                     │
└──────────────┴───────────────────────────────────────┘
```

### 4.2 Three-Layer L0/L1/L2 Model of Nested Virtualization

When our Type-2 Hypervisor (VMX Toolbox) runs on Windows managed by Hyper-V, a three-layer nested structure is formed:

```
L0: Hyper-V        (Controls hardware, actual VMX Root)
 └─ L1: VMX Toolbox (Our Hypervisor, running inside Hyper-V Guest)
     └─ L2: Windows Kernel + Apps (Guest virtualized by VMX Toolbox)
```

**Core Challenge of Nested Virtualization**: When L1 executes VMX instructions such as `VMLAUNCH`/`VMRESUME`, these instructions themselves trigger a VM-Exit to L0. L0 needs to:
1. Emulate L1's operations on the VMCS.
2. Manage state transitions between L1 and L2.
3. Merge the two EPT layers (L1's EPT-12 + L0's EPT-01 → the actual EPT-02).

### 4.3 VMCS Shadowing — How L0 Virtualizes L1's VMREAD/VMWRITE

In traditional schemes, every VMREAD/VMWRITE executed by L1 triggers a VM-Exit to L0 for emulation. For frequent VMCS accesses (dozens of reads and writes per VM-Exit), this incurs massive performance overhead.

**VMCS Shadowing** (Haswell+) allows L0 to provide a "Shadow VMCS" for L1. VMREAD/VMWRITE from L1 no longer trigger VM-Exits, but instead directly manipulate the memory of the Shadow VMCS. L0 uses a bitmap to control which fields of VMREAD/VMWRITE are allowed to execute directly and which still require Exits.

### 4.4 Enlightened VMCS — VP Assist Page + Clean Fields Bitmask Optimization

Microsoft provides a more aggressive optimization: **Enlightened VMCS**. This is a Hyper-V specific protocol (not in the Intel SDM), defined in the Hypervisor Top-Level Functional Specification (TLFS).

**Core Idea**: Completely abandon VMREAD/VMWRITE instructions and map VMCS fields as members of a **C structure**, which L1 reads and writes directly.

Enable flow:

```c
/* 1. Write the physical address of the VP Assist Page to the Hyper-V MSR */
__writemsr(HV_X64_MSR_VP_ASSIST_PAGE,
           CpuCtx->VpAssistPagePa | HV_VP_ASSIST_PAGE_ENABLE);

/* 2. Enable Enlightened VMCS in the VP Assist Page */
VpAssist->EnlightenedVmcsEnabled = 1;
VpAssist->CurrentEnlightenedVmcs = CpuCtx->EvmcsPa;

/* 3. Initialize eVMCS version and clear Clean Fields */
Evmcs->VersionNumber = 1;
Evmcs->CleanFields = HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
```

**Clean Fields Bitmask Optimization**:

Each VMCS field belongs to a 'Clean Field group' (totaling 16 groups). When L1 writes to a field, the corresponding Clean Bit is **cleared**. During VMRESUME, L0 only checks field groups whose Clean Bits are cleared, **skipping unmodified field groups**.

```c
/* Write to eVMCS field and automatically clear the corresponding Clean Bit */
FORCEINLINE VOID EvmcsWrite(PHV_VMX_ENLIGHTENED_VMCS Evmcs, ULONG Field, ULONG64 Value)
{
    USHORT Offset = EvmcsFieldOffset(Field);
    PUCHAR Base = (PUCHAR)Evmcs;

    /* Write according to field width */
    switch ((Field >> 13) & 0x3) {
    case 0: *(PUSHORT)(Base + Offset) = (USHORT)Value; break;
    case 1: *(PULONG64)(Base + Offset) = Value; break;
    case 2: *(PULONG)(Base + Offset) = (ULONG)Value; break;
    case 3: *(PULONG64)(Base + Offset) = Value; break;
    }

    /* Mark corresponding group as dirty */
    USHORT CleanBit = EvmcsFieldCleanBit(Field);
    if (CleanBit != HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE) {
        Evmcs->CleanFields &= ~(ULONG)CleanBit;
    }
}
```

After VMRESUME succeeds, reset all Clean Bits:

```c
if (g_IsNestedMode && CpuCtx->EvmcsVa) {
    PHV_VMX_ENLIGHTENED_VMCS Evmcs = (PHV_VMX_ENLIGHTENED_VMCS)CpuCtx->EvmcsVa;
    Evmcs->CleanFields = HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;  /* 0xFFFF */
}
```

### 4.5 Enlightened VMCB — AMD's Nested Optimization

AMD's nested optimization is similar but simpler. There is an Enlightened VMCB overlay area at VMCB offset 0x3E0 containing:

```c
typedef struct _SVM_ENLIGHTENED_VMCB {
    ULONG       Version;                    /* +0x3E0: Version number (1) */
    ULONG       NptTlbControl;              /* +0x3E4: NPT TLB Control */
    ULONG       MsrBitmapEnable;            /* +0x3E8: MSR Bitmap Enable */
    ULONG       Reserved1;
    ULONG       VpId;                       /* +0x3F0: VP Identifier */
    ULONG       Reserved2;
    ULONG64     VmId;                       /* +0x3F8: VM Identifier */
    ULONG64     PartitionAssistPagePa;      /* +0x400: Partition Assist PA */
} SVM_ENLIGHTENED_VMCB;
```

### 4.6 Nested EPT Merging

When L2 accesses memory, address translation must pass through two EPT layers:

```
L2 GVA → [L2 Page Table] → L2 GPA → [L1's EPT-12] → L1 GPA → [L0's EPT-01] → HPA
```

If this two-layer translation is walked twice every time, performance is extremely poor. L0 typically **merges** the two EPT layers into a single EPT-02 (L2 GPA → HPA) and caches the merged results. When either EPT layer changes, the merged cache must be invalidated and rebuilt.

### 4.7 Nested VM-Exit Routing

VM-Exits triggered during L2 execution must be routed to either L0 or L1:

- **L0 Handling**: Hardware interrupts, EPT-02 Violations (caused by L0's own EPT).
- **Forwarded to L1**: Intercept conditions configured by L1 match (CPUID, MSR accesses, etc.).

L0 makes this decision by inspecting control fields in L1's VMCS (or eVMCS).

### 4.8 Detection Flow: CPUID Leaf 0x40000000 → Hyper-V Identification

This project uses a three-step detection flow (`hv_detect.c`):

```c
BOOLEAN HvDetectNestedMode(VOID)
{
    int CpuInfo[4];

    /* Step 1: Check Hypervisor Present Bit */
    __cpuid(CpuInfo, 1);
    if (!(CpuInfo[2] & (1 << 31)))       /* ECX[31] = 0 → Bare metal */
        return FALSE;

    /* Step 2: Identify Microsoft Hyper-V */
    __cpuid(CpuInfo, 0x40000000);
    if (CpuInfo[1] != 0x7263694D ||       /* "Micr" */
        CpuInfo[2] != 0x666F736F ||       /* "osof" */
        CpuInfo[3] != 0x76482074)         /* "t Hv" */
        return FALSE;

    /* Step 3: Probe Nested Virtualization Enlightenments */
    if (g_HypervisorMaxLeaf >= 0x4000000A) {
        __cpuid(CpuInfo, 0x4000000A);
        /* EAX[0] = Enlightened VMCS support */
        /* EAX[1] = Direct virtual flush support */
    }

    g_IsNestedMode = TRUE;
    return TRUE;
}
```

---

## Chapter 5: Blue Pill Late-Launch Virtualization

> 📊 Architecture Diagram Reference: `late_launch_virtualization.drawio`

### 5.1 Fundamental Differences between Type-2 (Blue Pill) and Type-1 Hypervisors

| Feature | Type-1 (Bare-metal Hypervisor) | Type-2 (Blue Pill) |
|------|-------------------------|-------------------|
| **Representative Examples** | Hyper-V, VMware ESXi | This project, HyperPlatform |
| **Launch Time** | Earliest stage of system boot | Loaded after OS is fully running |
| **OS Role** | The OS runs as a Guest | OS is unaware it has become a Guest |
| **Memory Layout** | Pre-allocated by Hypervisor | Must be compatible with existing layout |
| **Driver Dependencies** | None | Loaded as a kernel driver |

The name "Blue Pill" comes from the movie *The Matrix* — the blue pill keeps you in the virtual world without your knowledge. Similarly, a Blue Pill Hypervisor "quietly" places the entire running OS into a virtual machine, and the OS is completely unaware that its world has changed.

### 5.2 The Essence of Identity Mapping: GPA == HPA

This is the most critical design aspect of Blue Pill — **EPT/NPT Identity Mapping**: mapping Guest Physical Addresses directly to the identical Host Physical Addresses.

```
GPA 0x00000000 → HPA 0x00000000
GPA 0x00001000 → HPA 0x00001000
GPA 0x00002000 → HPA 0x00002000
...
GPA 0x7FFFFFFFFF → HPA 0x7FFFFFFFFF   (512GB range)
```

Project implementation (`ept.c`):

```c
/* Establish identity mapping using 2MB large pages covering 512GB physical address space */
for (i = 0; i < MAX_PD_PAGES; i++) {          /* 512 PDPT entries */
    for (j = 0; j < EPT_PDE_COUNT; j++) {      /* 512 PDEs each */
        PhysAddr = ((ULONG64)i * 512 + j) * (2 * 1024 * 1024);  /* 2MB steps */

        g_PdPages[i].Entries[j].Read = 1;
        g_PdPages[i].Entries[j].Write = 1;
        g_PdPages[i].Entries[j].Execute = 1;
        g_PdPages[i].Entries[j].LargePage = 1;    /* 2MB large page */
        g_PdPages[i].Entries[j].PhysAddr = PhysAddr >> 12;
    }
}
```

**Why Identity Mapping is Crucial**:

Since GPA == HPA, all existing memory mappings of the operating system remain **completely unchanged** before and after enabling virtualization. The OS does not need to remap pages, modify page tables, or notify any drivers — everything continues to run as before.

### 5.3 Initiation Timeline T0→T3

```
T0: DriverEntry() Executes
    - Detect CPU type (Intel/AMD)
    - Detect Hyper-V nested mode
    - Select g_HvOps backend

T1: VmxInitialize() / SvmInitialize()
    - Allocate per-CPU memory structures
    - Establish EPT/NPT identity mapping
    - Initialize Hook framework

T2: Per-CPU DPC (VmxInitDpcRoutine)
    - Executes on each logical CPU
    - CR4.VMXE = 1 / EFER.SVME = 1
    - VMXON / (SVM: write VM_HSAVE_PA MSR)
    - Configure VMCS/VMCB: Guest State = Current CPU State
    - Guest RIP = Next instruction after VMLAUNCH in VmxInitDpcRoutine

T3: VMLAUNCH / VMRUN Succeeds
    ★ At this moment, the CPU enters Non-Root Mode from Root Mode
    ★ However, the address of the next executed instruction remains identical
    ★ All memory mappings remain unchanged (Identity Mapping)
    ★ All register states remain unchanged
    → The Windows kernel continues executing normally, completely unaware
```

### 5.4 Why Windows and Guest Software Have Zero Awareness

**6-Dimensional Unawareness Analysis**:

1. **Memory Address Invariance**: Identity mapping ensures identical results for all virtual/physical address translations.
2. **Uninterrupted Instruction Flow**: Guest RIP is set to the instruction immediately following VMLAUNCH.
3. **Register Preservation**: All general-purpose registers, segment registers, and CR registers retain identical values before and after virtualization.
4. **CR4.VMXE Hiding**: The VMXE bit is hidden using the CR4 Guest-Host Mask and Read Shadow.
5. **Temporal Continuity**: The TSC (Time Stamp Counter) increments continuously without jumps.
6. **Interrupt Normalcy**: NMIs and external interrupts are correctly forwarded to the Guest.

```c
/* CR4 Shadow hides the VMXE bit */
VmxWrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMXE);        /* Monitor VMXE bit only */
VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, Cr4 & ~CR4_VMXE);    /* Guest sees CR4 without VMXE on read */
```

### 5.5 Fundamental Differences from Traditional VMs

Traditional virtual machines (VMware Workstation, VirtualBox) create a **completely new virtual hardware environment** in which the Guest OS boots from scratch. In contrast, Blue Pill:

- Does not create new virtual hardware.
- Does not boot a new OS instance.
- Simply inserts a Hypervisor layer "beneath" the existing running environment.
- Analogy: Quietly placing a transparent stand beneath a running fish tank.

### 5.6 EPT/NPT Performance Overhead Analysis

The 2MB large page strategy of the identity mapping significantly reduces EPT/NPT overhead:

- **2MB Large Pages**: Requires only 3 levels of page table walks (PML4 → PDPT → PD), eliminating the 4th level PT.
- **TLB Caching**: 2MB pages result in fewer TLB entries but larger coverage.
- **VPID/ASID**: Avoids TLB flushes during VM-Entry/Exit.

Only when a hook is required is a 2MB large page split into 512 4KB small pages — limiting the overhead to the specific 2MB region containing the hooked function.

Actual performance impact:
- **No Hook Scenario**: < 1% CPU overhead (only EPT translation + necessary VM-Exits).
- **Hook Scenario**: 2-5% CPU overhead (EPT Violation handling + MTF single-stepping).
- **Memory Overhead**: ~1MB (EPT page tables) + ~12KB per hook (original page + hook page + metadata).


## Chapter 6: VMX Initialization Full Flow

> 📊 Architecture Diagram Reference: `vmx_init_flow.drawio`

### 6.1 DriverEntry → CPU Detection → Backend Selection

The first step of driver loading is detecting the CPU vendor and selecting the corresponding virtualization backend. Detection is performed via the vendor string returned by `CPUID Leaf 0`:

```c
CPU_VENDOR HvDetectCpuVendor(VOID)
{
    int CpuInfo[4] = { 0 };
    __cpuid(CpuInfo, 0);

    /* Intel: EBX:EDX:ECX = "GenuineIntel" */
    if (CpuInfo[1] == 0x756E6547 &&    /* "Genu" */
        CpuInfo[3] == 0x49656E69 &&    /* "ineI" */
        CpuInfo[2] == 0x6C65746E)      /* "ntel" */
        return CPU_VENDOR_INTEL;

    /* AMD: EBX:EDX:ECX = "AuthenticAMD" */
    if (CpuInfo[1] == 0x68747541 &&    /* "Auth" */
        CpuInfo[3] == 0x69746E65 &&    /* "enti" */
        CpuInfo[2] == 0x444D4163)      /* "cAMD" */
        return CPU_VENDOR_AMD;

    return CPU_VENDOR_UNKNOWN;
}
```

Note that the string returned by CPUID is in **EBX:EDX:ECX** order (not EBX:ECX:EDX), which is a common pitfall for beginners.

### 6.2 Capability Probing: MSR Read Chain

Capability detection for Intel VMX is performed by reading a series of MSRs (`VmxCheckCapabilities`):

```
IA32_VMX_BASIC (0x480)
    ├─ Bits [30:0]:  VMCS Revision ID
    ├─ Bit  [55]:    True Controls support flag
    │   └─ If = 1, read True versions of MSRs:
    │       ├─ IA32_VMX_TRUE_PINBASED_CTLS  (0x48D)
    │       ├─ IA32_VMX_TRUE_PROCBASED_CTLS (0x48E)
    │       ├─ IA32_VMX_TRUE_EXIT_CTLS      (0x48F)
    │       └─ IA32_VMX_TRUE_ENTRY_CTLS     (0x490)
    └─ Otherwise use standard versions:
        ├─ IA32_VMX_PINBASED_CTLS  (0x481)
        ├─ IA32_VMX_PROCBASED_CTLS (0x482)
        ├─ IA32_VMX_EXIT_CTLS      (0x483)
        └─ IA32_VMX_ENTRY_CTLS     (0x484)

IA32_VMX_PROCBASED_CTLS (0x482)
    └─ If Secondary Controls are available:
        └─ IA32_VMX_PROCBASED_CTLS2 (0x48B)
            ├─ Bit 1: Enable EPT
            ├─ Bit 3: Enable RDTSCP
            └─ Bit 5: Enable VPID

IA32_VMX_EPT_VPID_CAP (0x48C)
    ├─ Bit 0: Execute-Only EPT support
    ├─ Bit 6: 4-level EPT support
    ├─ Bit 14: WB memory type EPT support
    ├─ Bit 16: 2MB large page EPT support
    └─ Bit 20: INVEPT instruction support
```

Key Code:

```c
State->VmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
State->VmcsRevisionId = (ULONG)(State->VmxBasic & 0x7FFFFFFF);
State->TrueControlsSupported = (State->VmxBasic >> 55) & 1;

/* Validate required features: EPT is mandatory */
ULONG SecondaryAdj = VmxAdjustControls(
    PROC_BASED2_ENABLE_EPT | PROC_BASED2_ENABLE_RDTSCP | PROC_BASED2_ENABLE_VPID,
    State->ProcBased2Cap
);
if (!(SecondaryAdj & PROC_BASED2_ENABLE_EPT)) {
    LOG_ERROR("EPT not supported - cannot continue");
    return FALSE;
}
```

### 6.3 Per-CPU Memory Allocation

Each logical CPU requires its own set of memory structures:

```
Per-CPU Memory (VMX_CPU_CONTEXT):
┌──────────────────────────────────────────┐
│ VMXON Region    (4KB, page-aligned, phys contiguous)  │ ← Must write VMCS Revision ID
│ VMCS Region     (4KB, page-aligned, phys contiguous)  │ ← Same as above
│ MSR Bitmap      (4KB, page-aligned, phys contiguous)  │ ← Controls which MSRs trigger Exits
│ Host Stack      (16KB, NonPagedPool)                  │ ← Stack for VM-Exit Handler
├──────────── Extra Allocations for Nested Mode ────────┤
│ VP Assist Page  (4KB, page-aligned, phys contiguous)  │ ← Enlightened VMCS control page
│ eVMCS Page      (4KB, page-aligned, phys contiguous)  │ ← Enlightened VMCS data page
└──────────────────────────────────────────┘
```

The first 4 bytes of VMXON Region and VMCS Region must write the VMCS Revision ID:

```c
CpuCtx->VmxonRegionVa = VmxAllocateAlignedMemory(PAGE_SIZE_4KB, &CpuCtx->VmxonRegionPa);
*(PULONG)CpuCtx->VmxonRegionVa = VmcsRevision;    /* First 4 bytes = Revision ID */

CpuCtx->VmcsRegionVa = VmxAllocateAlignedMemory(PAGE_SIZE_4KB, &CpuCtx->VmcsRegionPa);
*(PULONG)CpuCtx->VmcsRegionVa = VmcsRevision;
```

### 6.4 VMCS Five-Stage Configuration

`VmxSetupVmcs()` configures approximately 100 fields of the VMCS across 5 stages:

**Stage 1: VM-Execution Controls**

```c
/* Pin-Based Controls: NMI Exit */
PinBased = VmxAdjustControls(PIN_BASED_NMI_EXIT, PinBasedCap);

/* Primary Processor-Based Controls */
ProcBased = VmxAdjustControls(
    PROC_BASED_USE_MSR_BITMAPS |        /* Use MSR Bitmaps instead of intercepting all */
    PROC_BASED_SECONDARY_CONTROLS |     /* Enable Secondary Controls */
    PROC_BASED_CR3_LOAD_EXIT |          /* Intercept CR3 writes (process switch detection) */
    PROC_BASED_MOV_DR_EXIT |            /* Intercept DR register accesses */
    PROC_BASED_RDTSC_EXIT,              /* Intercept RDTSC instruction */
    ProcBasedCap);

/* Secondary Controls */
ProcBased2 = VmxAdjustControls(
    PROC_BASED2_ENABLE_EPT |            /* Enable EPT */
    PROC_BASED2_ENABLE_RDTSCP |         /* Allow Guest to use RDTSCP */
    PROC_BASED2_ENABLE_VPID |           /* Enable VPID (TLB tagging) */
    PROC_BASED2_ENABLE_INVPCID,         /* Allow INVPCID instruction */
    ProcBased2Cap);

/* Exception Bitmap: Only intercept #DB(1) and #BP(3) */
VmxWrite(VMCS_CTRL_EXCEPTION_BITMAP,
         EXCEPTION_BITMAP_DB | EXCEPTION_BITMAP_BP);
```

**Stage 2: VM-Exit Controls**

```c
ExitCtls = VmxAdjustControls(
    VMEXIT_HOST_ADDR_SPACE_SIZE |       /* Host is 64-bit */
    VMEXIT_SAVE_IA32_EFER |             /* Save EFER on exit */
    VMEXIT_LOAD_IA32_EFER |             /* Load Host EFER on exit */
    VMEXIT_ACK_INT_ON_EXIT,             /* Acknowledge external interrupt automatically */
    ExitCap);
```

**Stage 3: VM-Entry Controls**

```c
EntryCtls = VmxAdjustControls(
    VMENTRY_IA32E_MODE_GUEST |          /* Guest runs in 64-bit mode */
    VMENTRY_LOAD_IA32_EFER,             /* Load Guest EFER on entry */
    EntryCap);
```

**Stage 4: Guest State**

Copy the complete state of the current CPU to the VMCS Guest-State area:

```c
/* Segment registers: Require parsing Base/Limit/AccessRights from GDT */
VmxWrite(VMCS_GUEST_CS_SEL, Cs);
VmxWrite(VMCS_GUEST_CS_BASE, VmxGetSegmentBase(GdtBase, Cs));
VmxWrite(VMCS_GUEST_CS_LIMIT, VmxGetSegmentLimit(GdtBase, Cs));
VmxWrite(VMCS_GUEST_CS_ACCESS_RIGHTS, VmxGetSegmentAccessRights(GdtBase, Cs));
/* FS/GS Base are read from MSRs instead of GDT */
VmxWrite(VMCS_GUEST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
VmxWrite(VMCS_GUEST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));

/* Control Registers */
VmxWrite(VMCS_GUEST_CR0, __readcr0());
VmxWrite(VMCS_GUEST_CR3, __readcr3());
VmxWrite(VMCS_GUEST_CR4, __readcr4());

/* VMCS Link Pointer: 0xFFFFFFFF_FFFFFFFF (no Shadow VMCS) */
VmxWrite(VMCS_GUEST_VMCS_LINK_PTR, 0xFFFFFFFFFFFFFFFF);
```

**Stage 5: Host State**

```c
/* Host RIP: Jump address on VM-Exit = Assembly entry point */
VmxWrite(VMCS_HOST_RIP, (ULONG64)AsmVmxExitHandler);

/* Host RSP: Use the top of the pre-allocated 16KB stack */
VmxWrite(VMCS_HOST_RSP,
         (ULONG64)CpuCtx->HostStackBase + CpuCtx->HostStackSize - 8);

/* Host Segment Selectors: RPL must be 0 */
VmxWrite(VMCS_HOST_CS_SEL, Cs & 0xFFF8);
```

### 6.5 CR4 Shadow Hiding Techniques

Enabling VMX requires setting the `CR4.VMXE` bit, but this exposes the presence of the Hypervisor. We hide it using the CR4 Guest-Host Mask and Read Shadow:

```c
/* Guest-Host Mask: We are only interested in the VMXE bit */
VmxWrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMXE);

/* Read Shadow: Return CR4 value without VMXE */
VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, Cr4 & ~CR4_VMXE);
```

When the Guest executes `MOV RAX, CR4`, for bits marked in the Mask (VMXE), the CPU returns the value from the Shadow (0) instead of the actual value (1). The Guest never sees VMXE being set.

### 6.6 VMLAUNCH and AsmVmxExitHandler Assembly Entry

Once VMLAUNCH succeeds, the CPU enters Non-Root Mode and resumes execution from Guest RIP. When a VM-Exit occurs, the CPU jumps to Host RIP — which is `AsmVmxExitHandler`:

```asm
AsmVmxExitHandler PROC
    ; On VM-Exit, the CPU has automatically:
    ;   - Saved Guest state to VMCS
    ;   - Loaded Host segment registers, CR, RSP, RIP
    ; But GP registers still hold Guest values! They must be saved manually.

    sub     rsp, 128                ; GUEST_CONTEXT size (16 64-bit registers)

    ; Save all Guest GP registers
    mov     [rsp+000h], rax         ; Rax
    mov     [rsp+008h], rcx         ; Rcx
    mov     [rsp+010h], rdx         ; Rdx
    mov     [rsp+018h], rbx         ; Rbx
    ; (RSP is read from VMCS, not saved here)
    mov     [rsp+028h], rbp         ; Rbp
    mov     [rsp+030h], rsi         ; Rsi
    mov     [rsp+038h], rdi         ; Rdi
    mov     [rsp+040h], r8
    ; ... r9 to r15 ...

    ; Call the C language VM-Exit dispatcher function
    mov     rcx, rsp                ; First parameter = GUEST_CONTEXT pointer
    sub     rsp, 28h                ; Shadow space + alignment
    call    VmxExitHandler          ; Return value: AL = TRUE (continue) / FALSE (shutdown)
    add     rsp, 28h

    test    al, al
    jz      VmxShutdown             ; AL == 0 → Turn off VMX

    ; Restore Guest GP registers
    mov     rax, [rsp+000h]
    mov     rcx, [rsp+008h]
    ; ... restore all ...
    add     rsp, 128

    vmresume                        ; Resume Guest execution
    ; If VMRESUME fails, execution will not reach the next line
    jmp     VmxResumeFailed

VmxShutdown:
    ; Restore all registers
    ; ... restore code ...
    add     rsp, 128
    vmxoff                          ; Turn off VMX operation
    ret
AsmVmxExitHandler ENDP
```

### 6.7 VM-Exit Dispatcher Complete Mapping

The switch statement in `VmxExitHandler` covers **17+ exit reasons**:

```c
BOOLEAN VmxExitHandler(PGUEST_CONTEXT GuestContext)
{
    ULONG ExitReason = (ULONG)VmxRead(VMCS_EXIT_REASON);
    InterlockedIncrement64(&g_VmxState.CpuContexts[CpuIndex].ExitCount);

    /* Check VM-Entry failure (bit 31) */
    if (ExitReason & 0x80000000) {
        LOG_ERROR("VM-Entry failure! Reason: %u", ExitReason & 0xFFFF);
        return FALSE;
    }

    switch (ExitReason & 0xFFFF) {
    case EXIT_REASON_CPUID:         return HandleCpuid(Ctx);        /* → AadHandleCpuid */
    case EXIT_REASON_RDMSR:         return HandleRdmsr(Ctx);        /* → HandleRdmsrImpl */
    case EXIT_REASON_WRMSR:         return HandleWrmsr(Ctx);        /* → HandleWrmsrImpl */
    case EXIT_REASON_CR_ACCESS:     return HandleCrAccess(Ctx);     /* CR0/3/4 reads/writes */
    case EXIT_REASON_DR_ACCESS:     return HandleDrAccess(Ctx);     /* → AadHandleDrAccess */
    case EXIT_REASON_EXCEPTION_NMI: return HandleException(Ctx);    /* #DB/#BP/NMI */
    case EXIT_REASON_RDTSC:         return HandleRdtsc(Ctx);        /* → AadHandleRdtsc */
    case EXIT_REASON_RDTSCP:        return HandleRdtscp(Ctx);       /* RDTSC + TSC_AUX */
    case EXIT_REASON_EPT_VIOLATION: return HandleEptViol(Ctx);      /* → HandleEptViolation */
    case EXIT_REASON_EPT_MISCONFIG: return HandleEptMisconfig(Ctx); /* Fatal error */
    case EXIT_REASON_MTF:           return HandleMtf(Ctx);          /* Single-step done */
    case EXIT_REASON_VMCALL:        return HandleVmcall(Ctx);       /* Hypercall */
    case EXIT_REASON_XSETBV:        return HandleXsetbv(Ctx);       /* XCR0 write */
    case EXIT_REASON_INVD:          return HandleInvd(Ctx);         /* → WBINVD */
    case EXIT_REASON_INVLPG:        return HandleInvlpg(Ctx);       /* TLB invalidate */
    case EXIT_REASON_WBINVD:        return HandleWbinvd(Ctx);       /* Cache writeback */
    case EXIT_REASON_TRIPLE_FAULT:  return HandleTripleFault(Ctx);  /* Fatal */
    case EXIT_REASON_HLT:           VmxAdvanceGuestRip(); break;
    case EXIT_REASON_EXTERNAL_INT:  break;                          /* ACK_INT handling */
    case EXIT_REASON_INT_WINDOW:    /* Clear interrupt window bit */ break;
    default:                        VmxAdvanceGuestRip(); break;
    }
    return TRUE;
}
```

---

## Chapter 7: Generic EPT/NPT Hook Framework

> 📊 Architecture Diagram Reference: `vmx_hook_framework.drawio`

### 7.1 Architecture Overview: Thunk Stub → AsmGenericHookDispatcher → C Decision

This project implements a platform-independent generic Hook framework. Its core data flow is as follows:

```
Hooked Function (executed by Guest)
    │
    ▼ [EPT/NPT: Execute-Only → Hooked Page]
Thunk Stub (24 bytes)
    │ mov r10, HookId      ← Identifies which Hook is triggered
    │ jmp AsmGenericHookDispatcher
    ▼
AsmGenericHookDispatcher (Assembly)
    ├─ Phase 1: Save parameters (RCX/RDX/R8/R9/stack parameters)
    ├─ Phase 2: call GenericHookDecide() → HOOK_DECISION
    │   ├─ PASSTHROUGH: call Trampoline, returns original result
    │   ├─ LOG_ONLY:    call Trampoline, records log
    │   ├─ BLOCK:       does not call, returns BlockReturnValue
    │   └─ MODIFY_RETVAL: call Trampoline, replaces return value
    ├─ Phase 3: call GenericHookPostCall() (logging)
    └─ Return to original caller
```

### 7.2 Dynamic Thunk Allocation (170 per page, growing on demand)

A Thunk Stub is a 24-byte machine code snippet responsible for passing the Hook ID to the dispatcher:

```
┌─── Thunk Stub (24 bytes) ───┐
│ 49 BA [8-byte HookId]       │  mov r10, <hook_id>    (10 bytes)
│ FF 25 00000000              │  jmp [rip+0]           (6 bytes)
│ [8-byte Dispatcher address] │  (absolute address)    (8 bytes)
└─────────────────────────────┘
```

R10 is a volatile register in the Windows x64 calling convention (not used for parameter passing), so it can be safely used without affecting the hooked function's arguments (RCX, RDX, R8, R9).

Thunks are dynamically allocated in units of 4KB pages:

```c
#define THUNK_STUB_SIZE     24
#define THUNKS_PER_PAGE     (0x1000 / THUNK_STUB_SIZE)   /* 170 per 4KB page */

typedef struct _THUNK_PAGE {
    struct _THUNK_PAGE *Next;       /* Linked list */
    PVOID               CodeBase;   /* 4KB executable page */
    ULONG               Capacity;   /* 170 */
    ULONG               UsedCount;
    ULONG               BaseId;
} THUNK_PAGE;
```

When all existing Thunk pages are full, a new page is automatically allocated and appended to the list.

### 7.3 Hook Installation Flow: VA→PA→Page Splitting→Permission Config→INVEPT

Complete Hook installation process:

```
GenericHookInstall(TargetVa, ProcessId, FunctionName, Rule)
    │
    ├─1. Allocate HookId (global incrementing counter)
    │
    ├─2. AllocateThunk(HookId)
    │       → Write in Thunk page: mov r10, HookId; jmp AsmGenericHookDispatcher
    │
    ├─3. HvHookFunction(TargetVa, ThunkAddr, &Trampoline)
    │   │
    │   ├─ MmGetPhysicalAddress(TargetVa) → Get Physical Address (PA)
    │   │
    │   ├─ EptSplitLargePage(PA)
    │   │   → Split 2MB large page into 512 4KB pages
    │   │   → Find free EPT_SPLIT_PAGE structure
    │   │   → Initialize 512 PTEs (identity mapping)
    │   │   → Modify PDE: LargePage=0, pointing to the new PT page
    │   │
    │   ├─ Allocate 3 auxiliary pages:
    │   │   ├─ OriginalPage (4KB): Full copy of the target page
    │   │   ├─ HookPage (4KB): Target page copy + JMP patch
    │   │   └─ Trampoline (64B): Original first 14 bytes + JMP back address
    │   │
    │   ├─ Write a 14-byte absolute JMP at target offset in HookPage:
    │   │   FF 25 00000000 [8-byte: ThunkAddr]
    │   │
    │   ├─ Modify EPT PTE:
    │   │   Read=0, Write=0, Execute=1    ← Execute-Only!
    │   │   PhysAddr = physical address of HookPage
    │   │
    │   └─ INVEPT (flush EPT TLB)
    │
    └─4. Create GENERIC_HOOK_ENTRY and insert into global list
```

### 7.4 4 Hook Actions

| Action | Value | Behavior | Typical Usage |
|------|---|------|---------|
| `PASSTHROUGH` | 0 | Calls the original function, returns the original result, only counts | Performance statistics |
| `LOG_ONLY` | 1 | Calls the original function, logs call details and return value | Behavior auditing |
| `BLOCK` | 2 | Does not call the original function, directly returns `BlockReturnValue` | Disabling features |
| `MODIFY_RETVAL` | 3 | Calls the original function, but replaces the return value with `NewReturnValue` | Result tampering |

### 7.5 ASM Dispatcher Three Phases

`AsmGenericHookDispatcher` assembly implementation:

```asm
; ===== Phase 1: Save State =====
push    rbp
mov     rbp, rsp
sub     rsp, 0C0h              ; 192 bytes local space

; Save original arguments (arguments of the hooked function are still in registers)
mov     [rbp-08h], rcx         ; Argument 1
mov     [rbp-10h], rdx         ; Argument 2
mov     [rbp-18h], r8          ; Argument 3
mov     [rbp-20h], r9          ; Argument 4
mov     [rbp-28h], r10         ; HookId (from Thunk)

; Save caller return address and stack parameters 5-8
mov     rax, [rbp+08h]
mov     [rbp-30h], rax         ; Return address

; ===== Phase 2: Decide + Call =====
mov     rcx, r10               ; HookId
mov     rdx, [rbp-30h]         ; Caller return address
lea     r8, [rbp-90h]          ; &Decision structure
call    GenericHookDecide       ; C function fills Decision

; Check Action
cmp     eax, 2                 ; BLOCK?
je      _do_block

; Restore parameters and call the original function via Trampoline
mov     rcx, [rbp-08h]
mov     rdx, [rbp-10h]
mov     r8,  [rbp-18h]
mov     r9,  [rbp-20h]
mov     rax, [rbp-90h+18h]    ; Decision.Trampoline
call    rax                    ; Call original function
; RAX = original return value

cmp     ecx, 3                 ; MODIFY_RETVAL?
jne     _post_call
mov     rax, [rbp-90h+10h]    ; Replace with NewReturnValue

; ===== Phase 3: Log =====
_post_call:
mov     rcx, [rbp-28h]        ; HookId
mov     edx, [rbp-98h]        ; Action
mov     r8, [rbp-0A0h]        ; FinalRetVal
mov     r9, [rbp-30h]         ; CallerRetAddr
call    GenericHookPostCall

; Return
mov     rax, [rbp-0A0h]       ; Final return value
mov     rsp, rbp
pop     rbp
ret
```

### 7.6 Event Ring Buffer and Logging System

Hook events are logged using a 512-entry ring buffer:

```c
typedef struct _HOOK_EVENT {
    ULONG       HookId;
    ULONG       ProcessId;
    ULONG64     Timestamp;
    ULONG64     ReturnAddress;      /* Caller return address */
    ULONG64     FinalRetVal;        /* Final return value */
    ULONG       ActionTaken;        /* Action actually executed */
} HOOK_EVENT;

#define HOOK_EVENT_RING_SIZE    512

/* Writing side */
Index = g_GenericHookState.EventWriteIndex;
Event = &g_GenericHookState.EventRing[Index];
/* ... fill event fields ... */
g_GenericHookState.EventWriteIndex = (Index + 1) % HOOK_EVENT_RING_SIZE;

/* Reading side (via IOCTL_VMX_GET_HOOK_EVENTS) */
while (Copied < MaxEntries && EventCount > 0) {
    RtlCopyMemory(&OutputBuffer[Copied],
                   &EventRing[EventReadIndex], sizeof(HOOK_EVENT));
    EventReadIndex = (EventReadIndex + 1) % HOOK_EVENT_RING_SIZE;
    EventCount--;
    Copied++;
}
```

A policy of **overwriting the oldest entries** is adopted when the buffer is full, and read/write operations are protected by a SpinLock.

---

## Chapter 8: Anti-Anti-Debugging Engine — Dual-Layer Interception of 10 Techniques

> 📊 Architecture Diagram Reference: `anti_anti_debug_engine.drawio`

### 8.1 Dual-Layer Architecture Overview

The anti-anti-debugging engine adopts a dual-layer architecture consisting of a **VM-Exit Handler Layer + EPT Hook Layer**:

```
┌──────────────────────────────────────────────────────────┐
│                 VM-Exit Handler Layer (Ring -1)          │
│                                                          │
│  Intercept CPU instruction-level operations:             │
│  ① CPUID (Hide Hypervisor presence)                     │
│  ② MOV DR (Hide hardware breakpoints)                    │
│  ③ RDTSC/RDTSCP (Compensate debug pause time)           │
│  ④ Exceptions #DB/#BP (Normalize to SEH)                 │
│  ⑤ RDMSR/WRMSR (Debug-related MSR interception)          │
├──────────────────────────────────────────────────────────┤
│                  EPT Hook Layer (Ring -1)                │
│                                                          │
│  Hook kernel APIs:                                       │
│  ⑥ NtQueryInformationProcess (ProcessDebugPort, etc.)    │
│  ⑦ NtQuerySystemInformation (KernelDebuggerInfo)        │
│  ⑧ NtSetInformationThread (ThreadHideFromDebugger)      │
│  ⑨ NtClose (Invalid handle exception suppression)        │
│  ⑩ PEB modifications (BeingDebugged/NtGlobalFlag/Heap)   │
└──────────────────────────────────────────────────────────┘
```

### 8.2 In-Depth Analysis of 5 VM-Exit Layer Techniques

**① CPUID Hiding (`AadHandleCpuid`)**

Some protectors detect virtualization environments by checking `CPUID Leaf 1, ECX[31]` (Hypervisor Present bit):

```c
if (!g_IsNestedMode && IsFeatureEnabled(GuestCr3, AAD_HIDE_CPUID)) {
    switch (Leaf) {
    case 1:
        CpuInfo[2] &= ~(1 << 31);    /* Clear Hypervisor Present bit */
        break;
    case 0x40000000 ... 0x40000006:
        /* Zero out all Hypervisor-specific leaves */
        CpuInfo[0] = CpuInfo[1] = CpuInfo[2] = CpuInfo[3] = 0;
        break;
    }
}
```

**Key Detail**: In nested mode (running under Hyper-V), CPUID hiding is automatically disabled to avoid interfering with Hyper-V's own CPUID leaves.

**② DR Register Spoofing (`AadHandleDrAccess`)**

Hardware breakpoints are stored in DR0-DR3. Anti-debugging detection reads DR registers to check if breakpoints are set:

```c
if (IsFeatureEnabled(GuestCr3, AAD_HIDE_HWBP)) {
    if (Direction == DR_ACCESS_DIRECTION_READ) {
        switch (DrNumber) {
        case 0: case 1: case 2: case 3:
            FakeValue = 0;                  /* Hardware breakpoint address → return 0 */
            break;
        case 6:
            FakeValue = DR6_DEFAULT_VALUE;  /* Debug status → return default value */
            break;
        case 7:
            FakeValue = DR7_DEFAULT_VALUE;  /* Debug control → return no breakpoints */
            break;
        }
        *RegPtr = FakeValue;
    } else {
        /* Write to DR: Allow actual writes (breakpoints still trigger) */
        /* Hide on read only */
        switch (DrNumber) {
            case 0: __writedr(0, Value); break;
            /* ... */
        }
    }
}
```

**Core Design**: Writes to DR are executed normally (so hardware breakpoints remain active), but reads return fake values. This allows the debugger to set breakpoints successfully while making them invisible to the application's integrity self-checks.

**③ RDTSC Time Compensation (`AadHandleRdtsc`)**

A common anti-debugging pattern reads the TSC before and after a block of code; if the difference is too large, it assumes a debugger is attached.

```c
if (IsFeatureEnabled(GuestCr3, AAD_HIDE_TIMING)) {
    PHV_CPU_CONTEXT HvCtx = g_HvOps->GetCurrentCpuContext();
    if (HvCtx) {
        LONG64 Offset = HvCtx->TscOffset;
        RealTsc -= (ULONG64)Offset;    /* Subtract accumulated pause time */
    }
}
GuestContext->Rax = (RealTsc & 0xFFFFFFFF);     /* EDX:EAX = TSC */
GuestContext->Rdx = (RealTsc >> 32);
```

**TSC Offset Accumulation Mechanism**:

```c
/* Debug pause starts */
VOID AadNotifyDebugPause(ULONG CpuIndex) {
    HvCtx->LastDebugPauseTsc = __rdtsc();
    HvCtx->InDebugPause = TRUE;
}

/* Debug resume */
VOID AadNotifyDebugResume(ULONG CpuIndex) {
    ULONG64 PauseDuration = __rdtsc() - HvCtx->LastDebugPauseTsc;
    HvCtx->TscOffset += (LONG64)PauseDuration;   /* Accumulate into offset */
    HvCtx->InDebugPause = FALSE;
}
```

**④ Exception Normalization (`AadHandleException`)**

`INT 2D` and `INT 3` behave differently under debugging vs. non-debugging environments. We inject these exceptions back into the Guest untouched, letting the application's SEH/VEH handle them normally:

```c
/* Construct injection info */
InjectInfo = INTERRUPT_INFO_VALID;
InjectInfo |= (Vector & INTERRUPT_INFO_VECTOR_MASK);
InjectInfo |= (IntType << INTERRUPT_INFO_TYPE_SHIFT);
if (HasErrorCode) {
    InjectInfo |= INTERRUPT_INFO_DELIVER_ERR_CODE;
    HvSetEntryExceptionErrorCode((ULONG)ErrorCode);
}
HvSetEntryInterruptionInfo(InjectInfo);
```

**⑤ MSR Interception**

Intercept debug-related MSRs (e.g., `IA32_DEBUGCTL`) using the MSR Bitmap and MSRPM, returning normal values in target processes.

### 8.3 EPT Hook Layer 4+2 Techniques

**⑥ NtQueryInformationProcess Hook**

The hooked version calls the original function and then tampers with the returned results:

```c
static NTSTATUS NTAPI HookNtQueryInformationProcess(...)
{
    /* Call original function first */
    Status = g_AadState.OrigNtQueryInformationProcess(
        ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);

    /* Check if it is the target process */
    CurrentCr3 = __readcr3();
    Target = ProcessFindByCr3(CurrentCr3);
    if (!Target || !(Target->Flags & AAD_HIDE_DEBUGGER))
        return Status;

    /* Tamper with debug-related info classes */
    switch (ProcessInformationClass) {
    case ProcessDebugPort:          /* 0x07: Debug Port */
        *(PULONG_PTR)ProcessInformation = 0;        /* Pretend no debugger is present */
        break;
    case ProcessDebugObjectHandle:  /* 0x1E: Debug Object Handle */
        *(PHANDLE)ProcessInformation = NULL;
        Status = STATUS_PORT_NOT_SET;               /* Return "not set" */
        break;
    case ProcessDebugFlags:         /* 0x1F: Debug Flags */
        *(PULONG)ProcessInformation = 1;            /* 1 = No debugging */
        break;
    }
    return Status;
}
```

**⑦ NtQuerySystemInformation Hook**

Intercept `SystemKernelDebuggerInformation`:

```c
if (SystemInformationClass == SystemKernelDebuggerInformation) {
    Info->KernelDebuggerEnabled = FALSE;      /* Kernel debugger not enabled */
    Info->KernelDebuggerNotPresent = TRUE;    /* Kernel debugger not present */
}
```

**⑧ NtSetInformationThread Hook**

Block `ThreadHideFromDebugger` (a common anti-debugging "poisoning" technique):

```c
if (ThreadInformationClass == 0x11 &&       /* ThreadHideFromDebugger */
    IsFeatureEnabled(CurrentCr3, AAD_HIDE_THREADINFO)) {
    return STATUS_SUCCESS;                  /* Pretend to succeed but do nothing */
}
```

**⑨ NtClose Hook**

Passing an invalid handle to `CloseHandle` triggers an exception in a debugging environment. We suppress this exception:

```c
if (IsFeatureEnabled(CurrentCr3, AAD_HIDE_NTCLOSE)) {
    __try {
        Status = g_AadState.OrigNtClose(Handle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();    /* Swallow the exception */
    }
    return Status;
}
```

### 8.4 PEB Fields Modification

The PEB (Process Environment Block) contains two commonly checked debug fields:
- `BeingDebugged` (offset +0x002): Non-zero if being debugged.
- `NtGlobalFlag` (offset +0x0BC): The combination of `FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS` indicates a debugged heap.

We modify these fields directly using the memory engine (implemented in the Heap Flags and Parent PID techniques).

### 8.5 Per-Process Bitmask Flags and CR3 Fast Matching

Each protected process has a separate bitmask flags `Flags`, composed of combinations of `AAD_HIDE_*` constants:

```c
#define AAD_HIDE_DEBUGGER       (1 << 0)    /* PEB + NtQueryInformationProcess */
#define AAD_HIDE_HWBP           (1 << 1)    /* DR0-DR7 */
#define AAD_HIDE_TIMING         (1 << 2)    /* RDTSC compensation */
#define AAD_HIDE_CPUID          (1 << 3)    /* CPUID hiding */
#define AAD_HIDE_SYSINFO        (1 << 4)    /* NtQuerySystemInformation */
#define AAD_HIDE_EXCEPTIONS     (1 << 5)    /* Exception normalization */
#define AAD_HIDE_NTCLOSE        (1 << 6)    /* NtClose exception suppression */
#define AAD_HIDE_THREADINFO     (1 << 7)    /* ThreadHideFromDebugger */
#define AAD_HIDE_HEAP           (1 << 8)    /* Heap flags hiding */
#define AAD_HIDE_PARENT         (1 << 9)    /* Parent process spoofing */
#define AAD_HIDE_ALL            (0xFFFFFFFF)
```

In VM-Exit Handlers, we determine if the current process is targeted using **CR3 Fast Matching**:

```c
ULONG64 GuestCr3 = HvReadGuestCr3();
Target = ProcessFindByCr3(GuestCr3);
if (Target && (Target->Flags & AAD_HIDE_HWBP)) {
    /* Hardware breakpoint hiding is enabled for this process */
}
```

CR3 matching is faster than PID matching because the CR3 value can be read directly from the VMCS/VMCB without calling any Windows APIs.

### 8.6 Compatibility Handling in Nested Mode

In Hyper-V nested virtualization mode, **CPUID hiding is automatically disabled**:

```c
/* Skip CPUID hiding in nested mode to avoid interfering with Hyper-V's 0x40000000+ leaves */
if (!g_IsNestedMode && IsFeatureEnabled(GuestCr3, AAD_HIDE_CPUID)) {
    /* Only modify CPUID outputs when not in nested mode */
}
```

This is because Hyper-V uses the `0x40000000` series CPUID leaves to communicate with the Guest OS (Enlightenments, clock synchronization, etc.). Clearing these leaves would cause the Guest OS to lose communication capabilities with Hyper-V.


## Chapter 9: Hypervisor Memory Read/Write Engine

> 📊 Architecture Diagram Reference: `hypervisor_memory_engine.drawio`

### 9.1 Why it Can Bypass All Anti-Cheat Drivers

Traditional process memory reading and writing (`ReadProcessMemory`, `NtReadVirtualMemory`, `MmCopyVirtualMemory`) pass through the Windows kernel's security check chain:

```
User-mode calls ReadProcessMemory()
    → ntdll!NtReadVirtualMemory
        → nt!NtReadVirtualMemory  ← ObRegisterCallbacks can intercept
            → MmCopyVirtualMemory ← Anti-cheat drivers can Hook
                → Target process page table walk
                    → Physical memory read
```

Anti-cheat drivers (e.g., EAC, BattlEye) typically deploy defenses at the following levels:
- `ObRegisterCallbacks`: Intercepts `PROCESS_VM_READ` handle permissions.
- SSDT Hook / Inline Hook: Intercepts `NtReadVirtualMemory`.
- `MmCopyVirtualMemory` Inline Hook.

**The read/write path of the Hypervisor memory engine does not pass through any of these checks**:

```
VMXToolbox.exe → IOCTL_VMX_READ_MEMORY → Driver Kernel
    → VMCALL → Hypervisor (Ring -1)
        → Manually walk target process CR3 page table (physical memory level)
            → Directly read physical address via identity mapping
                → Return result
```

In this path:
1. **No Windows APIs are used** — anti-cheat API Hooks are rendered useless.
2. **Object Manager is bypassed** — `ObRegisterCallbacks` is bypassed.
3. **Guest page tables are bypassed** — Guest PTE permissions are bypassed.
4. **Execution occurs in Ring -1** — Ring 0 drivers cannot detect or intercept it.

### 9.2 Guest 4-Level Page Table Walk (CR3→PML4→PDPT→PD→PT→PA)

`HvGuestVaToPa()` manually walks the 4-level page tables of the target process to translate a virtual address into a physical address:

```c
ULONG64 HvGuestVaToPa(ULONG64 GuestCr3, ULONG64 VirtualAddress)
{
    ULONG64 Pml4Base, Pml4e, Pdpte, Pde, Pte;
    ULONG64 Pml4eAddr, PdpteAddr, PdeAddr, PteAddr;

    /* Index calculation formulas (x86-64 4-level paging) */
    /* PML4  Index = VA[47:39] (9 bits) */
    /* PDPT  Index = VA[38:30] (9 bits) */
    /* PD    Index = VA[29:21] (9 bits) */
    /* PT    Index = VA[20:12] (9 bits) */
    /* Offset      = VA[11:0]  (12 bits) */

    /* CR3 → PML4 Base Address (low 12 bits are PCID/flags) */
    Pml4Base = GuestCr3 & 0x000FFFFFFFFFF000ULL;

    /* Level 4: PML4 */
    Pml4eAddr = Pml4Base + ((VirtualAddress >> 39) & 0x1FF) * 8;
    if (!SafeReadPhysU64(Pml4eAddr, &Pml4e) || !(Pml4e & PAGE_PRESENT))
        return 0;

    /* Level 3: PDPT */
    PdpteAddr = (Pml4e & PAGE_ADDR_MASK_4K) + ((VirtualAddress >> 30) & 0x1FF) * 8;
    if (!SafeReadPhysU64(PdpteAddr, &Pdpte) || !(Pdpte & PAGE_PRESENT))
        return 0;
    if (Pdpte & PAGE_LARGE)    /* 1GB large page */
        return (Pdpte & PAGE_ADDR_MASK_1G) | (VirtualAddress & 0x3FFFFFFF);

    /* Level 2: PD */
    PdeAddr = (Pdpte & PAGE_ADDR_MASK_4K) + ((VirtualAddress >> 21) & 0x1FF) * 8;
    if (!SafeReadPhysU64(PdeAddr, &Pde) || !(Pde & PAGE_PRESENT))
        return 0;
    if (Pde & PAGE_LARGE)      /* 2MB large page */
        return (Pde & PAGE_ADDR_MASK_2M) | (VirtualAddress & 0x1FFFFF);

    /* Level 1: PT */
    PteAddr = (Pde & PAGE_ADDR_MASK_4K) + ((VirtualAddress >> 12) & 0x1FF) * 8;
    if (!SafeReadPhysU64(PteAddr, &Pte) || !(Pte & PAGE_PRESENT))
        return 0;

    return (Pte & PAGE_ADDR_MASK_4K) | (VirtualAddress & 0xFFF);
}
```

`SafeReadPhysU64()` utilizes identity mapping to dereference the physical address directly as a pointer:

```c
static BOOLEAN SafeReadPhysU64(ULONG64 PhysAddr, PULONG64 Value)
{
    if (PhysAddr == 0 || PhysAddr >= (512ULL * 1024 * 1024 * 1024))
        return FALSE;    /* Exceeds the 512GB identity mapping range */

    PULONG64 Ptr = (PULONG64)PhysAddr;    /* PA == VA (identity mapping) */
    __try {
        *Value = *Ptr;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}
```

### 9.3 Direct Physical Memory Access (Identity Map: PA==VA)

Due to EPT/NPT identity mapping, physical addresses can be **used directly as virtual addresses**. This eliminates the use of system APIs like `MmMapIoSpace`, bypassing the Guest OS entirely.

```c
/* Access memory directly via physical address */
PhysPtr = (PVOID)PhysAddr;    /* Identity mapping: PA == VA */
if (IsRead) {
    RtlCopyMemory(Buffer + BytesDone, PhysPtr, ChunkSize);
} else {
    RtlCopyMemory(PhysPtr, Buffer + BytesDone, ChunkSize);
}
```

### 9.4 Comparison: IOCTL Path vs. VMCALL Path

This project provides two memory access paths:

| Feature | IOCTL Path | VMCALL Path |
|------|-----------|-------------|
| **Entry Point** | `DeviceIoControl` → IRP | `VMCALL` instruction → VM-Exit |
| **Execution Context** | Ring 0 (inside driver) | Ring -1 (inside Hypervisor) |
| **Performance** | Slightly faster (no VM-Exit overhead) | Slightly slower (VM-Exit + VM-Entry) |
| **Stealth** | Requires opening device handle | No API call footprints |
| **Parameter Passing** | `SystemBuffer` | RAX=Magic, RDX=ParamsVA |

Parameters for the VMCALL path are passed via the `VMCALL_MEM_PARAMS` structure:

```c
BOOLEAN HvHandleMemoryVmcall(PVOID GuestContext, ULONG SubCommand)
{
    ULONG64 ParamsVa = Ctx->Rdx;            /* RDX = Virtual address of parameter block */
    ULONG64 CallerCr3 = HvReadGuestCr3();   /* Caller (driver) CR3 */

    /* Translate parameter address: Caller VA → PA */
    ULONG64 ParamsPa = HvGuestVaToPa(CallerCr3, ParamsVa);
    PVMCALL_MEM_PARAMS Params = (PVMCALL_MEM_PARAMS)ParamsPa;  /* Identity mapping */

    /* Perform cross-process copy: Requires two CR3s */
    /* Source: TargetCr3 + TargetVa → SrcPA */
    /* Dest:   CallerCr3 + BufferVa → DstPA */
    /* Copy PA-to-PA directly */
    RtlCopyMemory((PVOID)DstPa, (PVOID)SrcPa, Chunk);
}
```

### 9.5 Automatic Handling of Page Boundaries and Safety Restrictions

`HvCopyGuestMemory()` automatically handles reads/writes that cross 4KB page boundaries:

```c
while (BytesDone < Size) {
    PhysAddr = HvGuestVaToPa(GuestCr3, GuestVa + BytesDone);

    /* Remaining bytes within the current page */
    PageOffset = (ULONG)(PhysAddr & 0xFFF);
    ChunkSize = 0x1000 - PageOffset;
    if (ChunkSize > (Size - BytesDone))
        ChunkSize = Size - BytesDone;

    /* Copy this chunk */
    RtlCopyMemory(..., ChunkSize);
    BytesDone += ChunkSize;
    /* Next iteration translates the next VA → which may map to a completely different physical page */
}
```

Safety Restrictions:
- Maximum single request size: **64KB** (`VMX_MEM_MAX_SIZE`).
- Physical addresses must be within the **512GB** identity mapping range.
- All physical memory accesses are protected using `__try/__except`.
- Translation failures (page not mapped/Paged Out) return `STATUS_INVALID_ADDRESS`.

---

## Chapter 10: SSDT & Shadow SSDT Monitoring and Hook Framework

> 📊 Architecture Diagram Reference: `ssdt_shadow_ssdt_framework.drawio`

### 10.1 SSDT Two-Tier Discovery Strategy

**Tier 1: Disk Mapping (SEC_IMAGE)**

The most reliable method for SSDT discovery — reading from the disk file to avoid memory data that may have been modified by other drivers:

```c
static NTSTATUS SsdtDiscoverAndResolveFromDisk(VOID)
{
    /* 1. Retrieve ntoskrnl.exe disk path and load address */
    SsdtGetNtoskrnlBase();

    /* 2. Map it into kernel address space as SEC_IMAGE */
    /*    ZwCreateSection(SEC_IMAGE) → ZwMapViewOfSection */
    SsdtMapNtoskrnlFromDisk();

    /* 3. Walk the PE export table to find KeServiceDescriptorTable */
    /*    Compare export names → retrieve RVA */

    /* 4. Read KiServiceTable entries from the mapped file image */
    for (i = 0; i < ServiceCount; i++) {
        LONG entry = KiServiceTable[i];
        ResolvedAddresses[i] = LiveTableVa + (entry >> 4);
    }
}
```

**Tier 2: Memory Read (Fallback Scheme)**

If disk mapping fails, fallback to reading from PatchGuard-protected memory:

```c
static NTSTATUS SsdtDiscoverAndResolveFromMemory(VOID)
{
    PVOID KeServiceDescTable = MmGetSystemRoutineAddress(
        L"KeServiceDescriptorTable");
    PKSERVICE_TABLE_DESCRIPTOR Desc = (PKSERVICE_TABLE_DESCRIPTOR)KeServiceDescTable;

    for (i = 0; i < Desc->Limit; i++) {
        LONG entry = Desc->Base[i];
        ResolvedAddresses[i] = (ULONG64)Desc->Base + (entry >> 4);
    }
}
```

### 10.2 KSERVICE_TABLE_DESCRIPTOR Structure and Address Resolution

```c
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PLONG       Base;       /* +0x00: KiServiceTable (array of LONG offsets) */
    PULONG      Count;      /* +0x08: Unused (always NULL on x64) */
    ULONG64     Limit;      /* +0x10: Total number of services */
    PUCHAR      Number;     /* +0x18: Parameter byte count table (KiArgumentTable) */
} KSERVICE_TABLE_DESCRIPTOR;
```

**x64 SSDT Address Resolution Formula**:

```
LONG RawEntry = KiServiceTable[Index]
FunctionVA = (ULONG64)KiServiceTable + (LONG64)(RawEntry >> 4)
ArgCount   = RawEntry & 0x0F
```

The low 4 bits encode the argument count (in units of `ULONG64`), while the high 28 bits represent a **signed relative offset** (shifted right by 4 bits to expand the addressing range).

### 10.3 Shadow SSDT Discovery

Shadow SSDT (`KeServiceDescriptorTableShadow`) contains win32k system calls (`NtUser*` / `NtGdi*`). The discovery process is more complex because it is **not exported publicly**, and win32k is mapped **per-session**.

**Phase 1: KTHREAD.ServiceTable Offset Scanning**

The KTHREAD structure contains a `ServiceTable` pointer pointing to the service table used by the thread. For non-GUI processes (e.g., the System process), it points to `KeServiceDescriptorTable`; for GUI processes, it points to `KeServiceDescriptorTableShadow`.

```c
NTSTATUS KthreadResolveServiceTableOffset(VOID)
{
    /* 1. Retrieve the known address of KeServiceDescriptorTable */
    PVOID KnownSdt = MmGetSystemRoutineAddress(L"KeServiceDescriptorTable");

    /* 2. Retrieve threads of the System process (PID=4) */
    /* 3. Scan KTHREAD structure (first 0x400 bytes) */
    for (offset = 0; offset < 0x400; offset += 8) {
        ULONG64 value = *(PULONG64)((PUCHAR)Thread + offset);
        if (value == (ULONG64)KnownSdt) {
            /* Match found! This is the ServiceTable offset */
            g_ShadowSsdtState.KthreadOffsets.ServiceTableOffset = offset;
            break;
        }
    }
    /* 4. Validate using a second System thread */
}
```

**Phase 2: Locating the Shadow Table**

```c
/* Iterate through threads of all GUI processes */
for (each thread in GUI processes) {
    ULONG64 ThreadSdt = *(PULONG64)(Thread + ServiceTableOffset);
    if (ThreadSdt != KnownSdt && ThreadSdt > 0xFFFF800000000000) {
        /* Different from normal SSDT and located in kernel address space → candidate Shadow Table */

        /* Triple Validation */
        PKSERVICE_TABLE_DESCRIPTOR Shadow = (PKSERVICE_TABLE_DESCRIPTOR)ThreadSdt;
        if (Shadow[0].Base == NormalSsdt[0].Base &&      /* ntoskrnl section matches */
            Shadow[0].Limit == NormalSsdt[0].Limit &&
            Shadow[1].Limit > 0 && Shadow[1].Limit < 2048) {  /* win32k section limit is reasonable */
            /* Shadow SSDT Found! */
            g_ShadowSsdtState.W32pServiceTableVa = (ULONG64)Shadow[1].Base;
        }
    }
}
```

### 10.4 Windows 10+ Module Splitting

Starting with Windows 10, `win32k.sys` has been split into three modules:

| Module | Responsibility |
|------|------|
| `win32kbase.sys` | Basic GDI/User implementations |
| `win32kfull.sys` | Full GDI/User features |
| `win32k.sys` | Thin wrapper/dispatcher |

Since Shadow SSDT functions can be distributed across these three modules, name resolution requires traversing the export tables of all win32k* modules.

### 10.5 Monitor Mode

```c
#define SSDT_MONITOR_OFF        0    /* Monitoring disabled */
#define SSDT_MONITOR_ALL        1    /* Monitor all syscalls */
#define SSDT_MONITOR_FILTERED   2    /* Monitor specified indices only */
```

FILTERED mode allows specifying up to 64 system call indices for targeted monitoring.

### 10.6 SSDT_HOOK_MAPPING → GenericHookInstall Delegation Mechanism

The SSDT Hook module does not manipulate EPT/NPT directly, but instead delegates to the generic Hook framework:

```c
typedef struct _SSDT_HOOK_MAPPING {
    struct _SSDT_HOOK_MAPPING *Next;
    ULONG       SyscallIndex;       /* SSDT Index */
    ULONG       GenericHookId;      /* Hook ID allocated by generic framework */
    BOOLEAN     IsMonitorHook;      /* Automatically installed for Monitor mode */
} SSDT_HOOK_MAPPING;

NTSTATUS SsdtHookByIndex(ULONG Index, PHOOK_RULE Rule, PULONG OutHookId)
{
    ULONG64 FuncVa = g_SsdtState.ResolvedAddresses[Index];

    /* Delegate to the generic Hook framework */
    Status = GenericHookInstall(
        FuncVa,                                 /* Target virtual address */
        0,                                      /* PID=0 (kernel-level) */
        g_SsdtState.NameCache[Index],           /* Function name */
        Rule,                                   /* Hook rule */
        &HookId                                 /* Returned Hook ID */
    );

    /* Log SSDT Index → HookId mapping */
    PSSDT_HOOK_MAPPING Mapping = AllocMapping();
    Mapping->SyscallIndex = Index;
    Mapping->GenericHookId = HookId;
}
```

---

## Chapter 11: Driver-User Mode Communication Architecture

> 📊 Architecture Diagram Reference: `ioctl_communication_protocol.drawio`

### 11.1 IOCTL Protocol Overview

All communication occurs via `DeviceIoControl` to the device `\\.\VMXToolbox`, totaling **27 IOCTL codes** divided into **6 functional groups**:

```
Group 1: Hypervisor Lifecycle (0x800-0x806)
┌─────────────────────────────────────────────────┐
│ IOCTL_VMX_INIT          (0x800) Initialize VMX/SVM │
│ IOCTL_VMX_SET_TARGET    (0x801) Set target process │
│ IOCTL_VMX_REMOVE_TARGET (0x802) Remove target process │
│ IOCTL_VMX_SET_CONFIG    (0x803) Update process config │
│ IOCTL_VMX_GET_LOG       (0x804) Retrieve logs      │
│ IOCTL_VMX_STOP          (0x805) Stop Hypervisor    │
│ IOCTL_VMX_QUERY_STATUS  (0x806) Query status       │
└─────────────────────────────────────────────────┘

Group 2: Memory Read/Write (0x807-0x808)
┌─────────────────────────────────────────────────┐
│ IOCTL_VMX_READ_MEMORY   (0x807) Read process mem │
│ IOCTL_VMX_WRITE_MEMORY  (0x808) Write process mem│
└─────────────────────────────────────────────────┘

Group 3: Generic Hook (0x809-0x80C)
┌─────────────────────────────────────────────────┐
│ IOCTL_VMX_INSTALL_HOOK  (0x809) Install Hook     │
│ IOCTL_VMX_REMOVE_HOOK   (0x80A) Remove Hook     │
│ IOCTL_VMX_LIST_HOOKS    (0x80B) List all Hooks   │
│ IOCTL_VMX_GET_HOOK_EVENTS(0x80C) Get event log    │
└─────────────────────────────────────────────────┘

Group 4: SSDT Monitoring (0x80D-0x813)
┌─────────────────────────────────────────────────┐
│ IOCTL_VMX_SSDT_INIT        (0x80D) Init SSDT    │
│ IOCTL_VMX_SSDT_DUMP        (0x80E) Dump SSDT    │
│ IOCTL_VMX_SSDT_HOOK        (0x80F) Hook syscall │
│ IOCTL_VMX_SSDT_UNHOOK      (0x810) Remove Hook  │
│ IOCTL_VMX_SSDT_UNHOOK_ALL  (0x811) Remove all   │
│ IOCTL_VMX_SSDT_LIST_HOOKS  (0x812) List Hooks   │
│ IOCTL_VMX_SSDT_MONITOR     (0x813) Set monitor  │
└─────────────────────────────────────────────────┘

Group 5: Shadow SSDT Monitoring (0x814-0x81A)
┌─────────────────────────────────────────────────┐
│ IOCTL_VMX_SHADOW_SSDT_INIT       (0x814)       │
│ IOCTL_VMX_SHADOW_SSDT_DUMP       (0x815)       │
│ IOCTL_VMX_SHADOW_SSDT_HOOK       (0x816)       │
│ IOCTL_VMX_SHADOW_SSDT_UNHOOK     (0x817)       │
│ IOCTL_VMX_SHADOW_SSDT_UNHOOK_ALL (0x818)       │
│ IOCTL_VMX_SHADOW_SSDT_LIST_HOOKS (0x819)       │
│ IOCTL_VMX_SHADOW_SSDT_MONITOR    (0x81A)       │
└─────────────────────────────────────────────────┘
```

All IOCTLs use `METHOD_BUFFERED`, with input and output buffers passed via `SystemBuffer`.

### 11.2 Variable-Length Output Buffer Pattern (Count + Entries[1])

For queries returning a variable number of entries, all response structures unify under the **Count + Entries[1] flexible array** pattern:

```c
/* Log Buffer */
typedef struct _VMX_LOG_BUFFER {
    ULONG           Count;          /* Actual number of entries */
    VMX_LOG_ENTRY   Entries[1];     /* Flexible array */
} VMX_LOG_BUFFER;

/* Hook List */
typedef struct _VMX_HOOK_LIST {
    ULONG           Count;
    VMX_HOOK_INFO   Hooks[1];
} VMX_HOOK_LIST;

/* SSDT Dump */
typedef struct _VMX_SSDT_DUMP_RESPONSE {
    ULONG           TotalServices;
    ULONG           ReturnedCount;
    SSDT_ENTRY_INFO Entries[1];
} VMX_SSDT_DUMP_RESPONSE;

/* Hook Events */
typedef struct _VMX_HOOK_EVENT_BUFFER {
    ULONG       Count;
    HOOK_EVENT  Events[1];
} VMX_HOOK_EVENT_BUFFER;
```

User-mode clients calculate the required buffer size:

```c
/* Client Example: Query SSDT Hook List */
ULONG BufSize = sizeof(VMX_SSDT_HOOK_LIST) +
                (MaxExpectedHooks - 1) * sizeof(SSDT_HOOK_INFO);
PVMX_SSDT_HOOK_LIST List = (PVMX_SSDT_HOOK_LIST)malloc(BufSize);
DeviceIoControl(hDevice, IOCTL_VMX_SSDT_LIST_HOOKS,
                NULL, 0, List, BufSize, &BytesReturned, NULL);
```

### 11.3 CLI Command Mapping and Typical Usage Scenarios

`VMXToolbox.exe` provides a comprehensive command-line interface:

```
Anti-Anti-Debugging Commands:
  --pid <PID>                     Set target process
  --hide-all                      Enable all 10 stealth techniques
  --hide-debugger                 Hide PEB.BeingDebugged only
  --hide-hwbp                     Hide hardware breakpoints only
  --hide-timing                   Compensate TSC timing only
  --remove <PID>                  Stop protecting specified process

Hook Management Commands:
  --install-hook <name|addr>      Install EPT/NPT Hook
    --action <pass|log|block|modify>
    --block-retval <value>
    --new-retval <value>
    --target-pid <PID>
  --list-hooks                    List all active Hooks
  --remove-hook <id>              Remove specified Hook
  --hook-events                   Read Hook event logs

Memory Operation Commands:
  --read-mem <PID> <addr> <size>  Read process memory
  --write-mem <PID> <addr> <hex>  Write process memory

SSDT Monitoring Commands:
  --ssdt-init                     Initialize SSDT module
  --ssdt-dump [start] [count]     Dump SSDT entries
  --ssdt-hook <name|index>        Hook syscall
  --ssdt-monitor <off|all|filtered>

Shadow SSDT Commands:
  --shadow-ssdt-init              Initialize Shadow SSDT
  --shadow-ssdt-dump              Dump win32k syscalls
  --shadow-ssdt-hook <name>       Hook NtUser/NtGdi

Diagnostic Commands:
  --status                        Query Hypervisor status
  --log                           Retrieve kernel logs
```

**Typical Usage Scenarios**:

```bash
# Scenario 1: Enable full anti-anti-debugging protection for process 1234
VMXToolbox.exe --pid 1234 --hide-all

# Scenario 2: Monitor NtCreateFile syscall
VMXToolbox.exe --ssdt-init
VMXToolbox.exe --ssdt-hook NtCreateFile --action log

# Scenario 3: Read 256 bytes from process 5678 at 0x7FF12340000
VMXToolbox.exe --read-mem 5678 0x7FF12340000 256

# Scenario 4: Block NtTerminateProcess and return STATUS_ACCESS_DENIED
VMXToolbox.exe --ssdt-hook NtTerminateProcess --action block --block-retval 0xC0000022
```

---

## Appendix

### A. Key Data Structures Reference Table

| Structure | File | Purpose |
|--------|------|------|
| `HV_OPS` | `hv_ops.h` | Hypervisor operation virtual function table (30+ function pointers) |
| `HV_CPU_CONTEXT` | `hv_ops.h` | Generic per-CPU context |
| `VMX_STATE` | `vmx.h` | Intel VMX global state |
| `VMX_CPU_CONTEXT` | `vmx.h` | VMX per-CPU: VMXON/VMCS/MSR Bitmap/Stack |
| `SVM_STATE` | `svm.h` | AMD SVM global state |
| `SVM_CPU_CONTEXT` | `svm.h` | SVM per-CPU: VMCB/HostSaveArea/MSRPM |
| `VMCB` | `svm.h` | AMD VMCB control + state save areas |
| `EPT_STATE` | `ept.h` | EPT page tables: PML4/PDPT/PD/EPTP |
| `EPT_HOOK_STATE` | `ept.h` | EPT Hook registry |
| `EPT_HOOK_ENTRY` | `ept.h` | Single EPT Hook: original page/hook page/trampoline |
| `EPT_SPLIT_PAGE` | `ept.c` | 2MB→4KB split page (512 PTEs) |
| `GENERIC_HOOK_STATE` | `hv_hook.h` | Generic Hook framework global state |
| `GENERIC_HOOK_ENTRY` | `hv_hook.h` | Single generic Hook entry |
| `HOOK_DECISION` | `hv_hook.h` | ASM↔C shared decision structure (40B) |
| `THUNK_PAGE` | `hv_hook.h` | Thunk code page (170 stubs/page) |
| `AAD_STATE` | `anti_anti_debug.h` | Anti-anti-debugging global state |
| `SSDT_STATE` | `ssdt.h` | SSDT global: addresses/names/Hook mappings |
| `SHADOW_SSDT_STATE` | `shadow_ssdt.h` | Shadow SSDT: per-session state |
| `KSERVICE_TABLE_DESCRIPTOR` | `ssdt.c` | Windows Service Table descriptor |
| `HV_VMX_ENLIGHTENED_VMCS` | `vmx_enlightened.h` | Enlightened VMCS 4KB structure |
| `HV_VP_ASSIST_PAGE` | `vmx_enlightened.h` | VP Assist Page 4KB structure |
| `HOOK_RULE` | `shared.h` | Hook behavior rules (action/PID/return value) |
| `HOOK_EVENT` | `shared.h` | Hook event log entry |

### B. List of All IOCTL Codes

| IOCTL Name | Code | Direction | Input Structure | Output Structure |
|-----------|------|------|----------|----------|
| `IOCTL_VMX_INIT` | 0x800 | → | None | None |
| `IOCTL_VMX_SET_TARGET` | 0x801 | → | `VMX_TARGET_INFO` | None |
| `IOCTL_VMX_REMOVE_TARGET` | 0x802 | → | `VMX_REMOVE_TARGET` | None |
| `IOCTL_VMX_SET_CONFIG` | 0x803 | → | `VMX_CONFIG_INFO` | None |
| `IOCTL_VMX_GET_LOG` | 0x804 | ← | None | `VMX_LOG_BUFFER` |
| `IOCTL_VMX_STOP` | 0x805 | → | None | None |
| `IOCTL_VMX_QUERY_STATUS` | 0x806 | ← | None | `VMX_STATUS` |
| `IOCTL_VMX_READ_MEMORY` | 0x807 | ↔ | `VMX_MEMORY_REQUEST` | Raw bytes |
| `IOCTL_VMX_WRITE_MEMORY` | 0x808 | → | `VMX_MEMORY_REQUEST` + data | None |
| `IOCTL_VMX_INSTALL_HOOK` | 0x809 | ↔ | `VMX_HOOK_REQUEST` | `VMX_HOOK_RESPONSE` |
| `IOCTL_VMX_REMOVE_HOOK` | 0x80A | → | `VMX_UNHOOK_REQUEST` | None |
| `IOCTL_VMX_LIST_HOOKS` | 0x80B | ← | None | `VMX_HOOK_LIST` |
| `IOCTL_VMX_GET_HOOK_EVENTS` | 0x80C | ← | None | `VMX_HOOK_EVENT_BUFFER` |
| `IOCTL_VMX_SSDT_INIT` | 0x80D | ← | None | `VMX_SSDT_INIT_RESPONSE` |
| `IOCTL_VMX_SSDT_DUMP` | 0x80E | ↔ | `VMX_SSDT_DUMP_REQUEST` | `VMX_SSDT_DUMP_RESPONSE` |
| `IOCTL_VMX_SSDT_HOOK` | 0x80F | ↔ | `VMX_SSDT_HOOK_REQUEST` | `VMX_SSDT_HOOK_RESPONSE` |
| `IOCTL_VMX_SSDT_UNHOOK` | 0x810 | → | `VMX_SSDT_UNHOOK_REQUEST` | None |
| `IOCTL_VMX_SSDT_UNHOOK_ALL` | 0x811 | → | None | None |
| `IOCTL_VMX_SSDT_LIST_HOOKS` | 0x812 | ← | None | `VMX_SSDT_HOOK_LIST` |
| `IOCTL_VMX_SSDT_MONITOR` | 0x813 | → | `VMX_SSDT_MONITOR_REQUEST` | None |
| `IOCTL_VMX_SHADOW_SSDT_INIT` | 0x814 | ← | None | `VMX_SHADOW_SSDT_INIT_RESPONSE` |
| `IOCTL_VMX_SHADOW_SSDT_DUMP` | 0x815 | ↔ | `VMX_SHADOW_SSDT_DUMP_REQUEST` | `VMX_SHADOW_SSDT_DUMP_RESPONSE` |
| `IOCTL_VMX_SHADOW_SSDT_HOOK` | 0x816 | ↔ | `VMX_SHADOW_SSDT_HOOK_REQUEST` | `VMX_SHADOW_SSDT_HOOK_RESPONSE` |
| `IOCTL_VMX_SHADOW_SSDT_UNHOOK` | 0x817 | → | `VMX_SHADOW_SSDT_UNHOOK_REQUEST` | None |
| `IOCTL_VMX_SHADOW_SSDT_UNHOOK_ALL` | 0x818 | → | None | None |
| `IOCTL_VMX_SHADOW_SSDT_LIST_HOOKS` | 0x819 | ← | None | `VMX_SHADOW_SSDT_HOOK_LIST` |
| `IOCTL_VMX_SHADOW_SSDT_MONITOR` | 0x81A | → | `VMX_SHADOW_SSDT_MONITOR_REQUEST` | None |

### C. References

1. **Intel® 64 and IA-32 Architectures Software Developer's Manual (SDM)**
   - Volume 3C: Chapter 23-33 (VMX)
   - Volume 3A: Chapter 4 (Paging), Chapter 28 (EPT)

2. **AMD64 Architecture Programmer's Manual (APM)**
   - Volume 2: Chapter 15 (SVM)
   - Volume 2: Appendix B (VMCB Layout)

3. **Microsoft Hypervisor Top-Level Functional Specification (TLFS)**
   - Version 6.0b: Chapters 10-16 (Nested Virtualization, Enlightenments)
   - VP Assist Page, Enlightened VMCS, Partition Assist Page

4. **Windows Internals, 7th Edition** (Yosifovich, Ionescu, Russinovich, Solomon)
   - Part 2: Chapter 8 (System Mechanisms - PatchGuard)
   - Part 1: Chapter 4 (Memory Management - Page Tables)

5. **Related Open Source Projects**
   - HyperPlatform (Satoshi Tanda)
   - hvpp (wbenny)
   - SimpleVisor (Alex Ionescu)

---

> 📊 **List of Architecture Diagram Files Referenced in this Article**:
> 1. `vmx_nested_virtualization.drawio` — Nested Virtualization Three-Layer Model (Chapter 1, Chapter 4)
> 2. `vmx_init_flow.drawio` — VMX Initialization Flow (Chapter 1, Chapter 6)
> 3. `svm_vs_vmx_architecture.drawio` — Intel/AMD Architecture Comparison (Chapter 2)
> 4. `vmx_hook_framework.drawio` — EPT/NPT Hook Framework (Chapter 3, Chapter 7)
> 5. `late_launch_virtualization.drawio` — Late-Launch Virtualization (Chapter 5)
> 6. `anti_anti_debug_engine.drawio` — Anti-Anti-Debugging Engine (Chapter 8)
> 7. `hypervisor_memory_engine.drawio` — Hypervisor Memory Engine (Chapter 9)
> 8. `ssdt_shadow_ssdt_framework.drawio` — SSDT/Shadow SSDT Framework (Chapter 10)
> 9. `ioctl_communication_protocol.drawio` — IOCTL Communication Protocol (Chapter 11)
