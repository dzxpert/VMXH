[简体中文](readme_CN.md) | English

# VMX Hypervisor Toolbox

A Windows x64 hypervisor toolbox based on Intel VT-x (VMX) and AMD SVM. By inserting a lightweight Type-2 Hypervisor underneath the operating system, it provides various low-level capabilities running at the Ring -1 level. These include anti-anti-debugging, a kernel hook framework that bypasses PatchGuard, process memory reading/writing based on direct physical memory access, etc. More advanced VMX-based features will be continuously added in the future.

**Dual-Platform Support**: Automatically detects CPU vendor (Intel/AMD) and selects the corresponding virtualization backend.

---

## License

> ⚠️ **IMPORTANT: This project uses a custom license, not a standard open-source license like MIT, BSD, or GPL.**
>
> - ✅ **Allowed**: Personal learning, research, private experimentation, security research, and academic (non-profit) use.
> - ❌ **Prohibited**: Any form of commercial use (including internal use within companies, paid product integration, SaaS services, game cheats / anti-cheat products, AI training data, etc.), **unless prior written consent is obtained from the author**.
> - 🚫 **Strictly Prohibited**: Use for any illegal or malicious destructive purposes, including but not limited to: unauthorized intrusion, malware/ransomware/Rootkits, data theft, privacy invasion, tracking and monitoring, fraud and financial crimes, DDoS/botnets, harming minors, illegal goods/service platforms, and all other illegal behaviors. This prohibition **also applies to personal use** and is non-negotiable and non-exemptible. Violators will automatically lose all rights of use and will bear civil and criminal liabilities under the Criminal Law, Cybersecurity Law, Data Security Law, Personal Information Protection Law, and equivalent extraterritorial laws; the author reserves the right to cooperate with law enforcement investigations.
> - 🛡️ **Exception for Lawful Security Research**: Conducting research solely on systems you own or have obtained written authorization for, under the premises of good faith, responsible disclosure, and minimal necessary harm—see Section 4A.3 of the [`LICENSE`](LICENSE) for specific conditions.
> - 📜 See the [`LICENSE`](LICENSE) file in the root directory for the full terms (in bilingual Chinese and English, with English as the official text).
> - 📬 Commercial Licensing Negotiations: Please contact the author via GitHub Issues in this repository or the contact channels listed at the end of this README.
>
> Using, downloading, compiling, modifying, or distributing this software indicates your acceptance of all terms of the [`LICENSE`](LICENSE). Violating the agreement will automatically terminate your right to use it and may result in legal liability for infringement.

> **2026-04 Stability Review (Two Rounds)**: Completed a comprehensive code review targeting bare-metal execution followed by a stricter second round of review, fixing a total of **36 cross-level issues** (17 in the first round + 19 in the second cleanup round, including critical bugs like BSODs due to missing host-state in SVM VMSAVE/VMLOAD, AAD VMX side never actually working, and incomplete nonce authentication), see [docs/BAREMETAL_REVIEW_FIXES.md](docs/BAREMETAL_REVIEW_FIXES.md) for details. Important API changes:<br>• `AsmSvmLaunch` signature changed to `(VmcbPa, VmcbVa, HostVmcbPa)`, where Host VMCB is used for VMSAVE/VMLOAD to protect host extra-state.<br>• Shutdown VMCALL/VMMCALL now requires complete authentication using `g_VmcallShutdownNonce` + long-mode + CS.L + kernel-RIP.<br>• `VmxSetExceptionInterceptBp/Db` new API — VMX-side AAD_HIDE_EXCEPTIONS now actually works.<br>• `ProcessRegisterExceptionHideToggle` decouples the process module from the SVM/VMX backends.<br>• VMCALL memory operation path now **injects #UD failure**; user-mode must use IOCTL.<br>• EPT/NPT identity mapping now dynamically scales to support > 512GB of physical memory (`g_EptPdptTotal / g_NptPdptTotal`).

---

## Table of Contents

- [Project Overview](#project-overview)
  - [Core Capabilities](#core-capabilities)
  - [Design Philosophy](#design-philosophy)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Core Technical Details](#core-technical-details)
  - [VMX Initialization Flow](#vmx-initialization-flow)
  - [VMCS Configuration](#vmcs-configuration)
  - [VM-Exit Handling Framework](#vm-exit-handling-framework)
  - [EPT Engine and Hook Mechanism](#ept-engine-and-hook-mechanism)
  - [Process Tracking and EPROCESS Dynamic Offset Discovery](#process-tracking-and-eprocess-dynamic-offset-discovery)
  - [Anti-Anti-Debugging Engine](#anti-anti-debugging-engine)
  - [MSR Interception](#msr-interception)
  - [Logging System](#logging-system)
- [AMD SVM Technical Details](#amd-svm-technical-details)
- [Virtualization Hiding](#virtualization-hiding)
- [Per-CPU EPT/NPT Hook Page Isolation](#per-cpu-eptnpt-hook-page-isolation)
- [Hypervisor Memory Read/Write](#hypervisor-memory-readwrite)
- [Late-load Virtualization and Memory Continuity](#late-load-virtualization-and-memory-continuity)
- [Universal EPT/NPT Hook Framework](#universal-eptnpt-hook-framework)
- [SSDT Monitoring and Hook Framework](#ssdt-monitoring-and-hook-framework)
- [Shadow SSDT (Win32k) Monitoring and Hook Framework](#shadow-ssdt-win32k-monitoring-and-hook-framework)
- [Anti-Anti-Debugging Capability List](#anti-anti-debugging-capability-list)
- [User-Mode Control Utility](#user-mode-control-utility)
  - [Anti-Anti-Debugging Commands](#anti-anti-debugging-commands)
  - [Hook Framework Commands](#hook-framework-commands)
  - [Memory Read/Write Commands](#memory-readwrite-commands)
  - [SSDT Commands](#ssdt-commands)
  - [Shadow SSDT Commands](#shadow-ssdt-commands)
  - [Typical Use Cases](#typical-use-cases)
- [Driver to User-Mode Communication Protocol](#driver-to-user-mode-communication-protocol)
- [Data Flow Analysis](#data-flow-analysis)
- [Module Dependencies](#module-dependencies)
- [Compilation and Deployment](#compilation-and-deployment)
- [Future Roadmap](#future-roadmap)
- [Critical Risks and Precautions](#critical-risks-and-precautions)

---

## Project Overview

| Attribute | Description |
|------|------|
| Platform | Windows 10/11 x64 |
| CPU | Intel (VT-x/VMX/EPT) and AMD (SVM/NPT) |
| Architecture | Type-2 Hypervisor (Parasitic, Blue Pill) + `hv_ops` Abstraction Layer |
| Environment | Bare metal execution only |
| Language | C + x64 MASM |
| Toolchain | WDK 7600 (GRMWDK_EN_7600_1) |
| Core Features | Anti-Anti-Debugging / Kernel Hook Framework / Process Memory R/W / More under extension |
| Work Principle | Loaded at runtime underneath the running OS, intercepting sensitive operations via VMX non-root mode |

### Core Capabilities

| Module | Capability | Technical Principle |
|------|------|---------|
| **Anti-Anti-Debugging** | Makes debuggers completely invisible to the target process | Intercepts PEB/NtQuery/DR/RDTSC/CPUID detections and returns spoofed results |
| **Kernel Hook Framework** | Hooks arbitrary kernel/user-mode functions at runtime, bypassing PatchGuard | EPT/NPT Execute-Only page isolation — reads see original code, execution runs hooked code |
| **Process Memory R/W** | Directly reads/writes arbitrary process memory, bypassing all kernel callbacks and anti-cheat hooks | CR3 page table traversal → Physical Address → `MmMapIoSpace` direct access |
| **SSDT Monitor & Hook** | Discovers, dumps, and hooks any SSDT function by name/index, supporting full/filtered monitoring | Maps `ntoskrnl.exe` from disk (via `SEC_IMAGE`) to obtain pristine SSDT addresses, reusing the EPT Hook framework |
| **Shadow SSDT (Win32k) Hook** | Discovers, dumps, and hooks `NtUser*`/`NtGdi*` functions, supporting full/filtered monitoring | Scans `KTHREAD` offsets to locate `KeServiceDescriptorTableShadow`, parsing `win32k` within the Session context |
| **Virtualization Hiding** | Hides the presence of the Hypervisor completely from the Guest | Intercepts CPUID/MSR/VMX/SVM instructions and masquerades as a bare-metal environment |
| **Per-CPU EPT/NPT Isolation** | Multi-core hooks with zero race conditions | Independent EPT/NPT page table chain per CPU, ensuring PTE permission switches do not interfere with each other |
| **More Extensions** | Continuously adding advanced VMX-based features in the future | — |

### Design Philosophy

This project is not a single-purpose tool, but rather an **extensible low-level capability platform based on VMX/SVM**:

- **Ring -1 Execution**: All functions run at the Hypervisor level, above the OS kernel, and are not restricted by kernel protection mechanisms such as PatchGuard or anti-cheat drivers.
- **Unified Dual Platforms**: The `hv_ops` abstraction layer shields Intel/AMD differences, allowing all upper-level functions to be completely shared between the two platforms.
- **Modular Extension**: Each functional module (anti-anti-debugging, hooks, memory read/write) is implemented independently, making it easy to extend new capabilities in the future (such as SSDT monitoring, virtualization protection, driver communication hiding, etc.).
- **Unified CLI Entry**: All features are controlled through the same `VMXToolbox.exe` command-line utility.

---

## System Architecture

```
+---------------------------------------------------+
|                  User Mode (Ring 3)               |
|                                                     |
|   VMXToolbox.exe (CLI)                              |
|   +-- Anti-Anti-Debug Commands (--pid --hide-*)     |
|   +-- Hook Framework Commands (--install-hook ...)  |
|   +-- Memory R/W Commands     (--read-mem ...)      |
|      |                                              |
|      | DeviceIoControl                              |
+------+----------------------------------------------+
|      v              Kernel Mode (Ring 0)            |
|                                                     |
|   VMXToolboxDrv.sys (Kernel Driver)                 |
|   +-----------------------------------------------+ |
|   | DriverEntry / CPU Detection / IOCTL Dispatch   | |
|   +-----------------------------------------------+ |
|   |            hv_ops Abstraction Layer (hv_ops.h)  | |
|   |     +------------------+-------------------+   | |
|   |     |   Intel VMX      |    AMD SVM        |   | |
|   |     |  (vmx_init.c)    |  (svm_init.c)     |   | |
|   |     |  (vmx_exit.c)    |  (svm_exit.c)     |   | |
|   |     |  (vmx_asm.asm)   |  (svm_asm.asm)    |   | |
|   |     |  (ept.c)         |  (npt.c)          |   | |
|   |     +------------------+-------------------+   | |
|   +-----------------------------------------------+ |
|   | Anti-Anti | Hook      | Memory   | Process    | |
|   | Debug     | Framework | R/W      | Tracking   | |
|   | (anti_*.c)| (hv_hook*)| (hv_mem*)| (process.c)| |
|   +-----------------------------------------------+ |
|   | SSDT Monitor & Hook  (ssdt.c)                  | |
|   | (Discovery / Parsing / Name / Hook / Monitor)  | |
|   +-----------------------------------------------+ |
|   | Shadow SSDT (Win32k) Monitor & Hook            | |
|   | (shadow_ssdt.c - NtUser*/NtGdi* Hook/Monitor)  | |
|   +-----------------------------------------------+ |
+-----------------------------------------------------+
|              Hardware Virtualization                  |
|   Intel VT-x: VMCS | EPT | MSR Bitmap               |
|   AMD SVM:    VMCB | NPT | MSRPM | IOPM             |
+-----------------------------------------------------+
```

### Dual-Platform Abstraction Architecture (hv_ops)

```
Anti-Anti-Debugging Engine / VM-Exit Handling / EPT/NPT Hook
         |
    hv_ops Abstraction Interface (g_HvOps)
    /                        \
vmx_backend                 svm_backend
(Existing VMX Code)         (New SVM Code)
- VMCS read/write           - VMCB field access
- VMLAUNCH/VMRESUME         - VMRUN/VMLOAD/VMSAVE
- EPT + Execute-Only        - NPT + Read+Execute
- INVEPT                    - ASID Flush
- MTF single-step           - RFLAGS.TF single-step
    |                           |
    |                           |
    v                           v
 VMREAD/VMWRITE              VMCB Direct
 (Intel Native)              Memory R/W
```

---

## Project Structure

```
VMXToolbox/
+-- common/
|   +-- shared.h              IOCTL codes, AAD_HIDE_* flags, shared data structures
+-- driver/                    Kernel driver (VMXToolboxDrv.sys)
|   +-- hv_ops.h              [New] Hypervisor abstraction layer interface (HV_OPS struct)
|   +-- hv_detect.h           [New] CPU vendor detection interface
|   +-- hv_detect.c           [New] CPU vendor detection (Intel/AMD) + capability probing
|   +-- vmx.h                 VMX core definitions (VMCS encoding, Exit Reason, control bits)
|   +-- vmxdrv.c              Driver entry, CPU detection, backend selection, IOCTL handling
|   +-- vmx_init.c            VMX initialization + HV_OPS backend registration
|   +-- vmx_exit.c            VMX VM-Exit main dispatcher
|   +-- vmx_asm.asm           Intel x64 assembly (VMLAUNCH/VMRESUME/INVEPT)
|   +-- ept.h                 EPT data structure definitions
|   +-- ept.c                 EPT identity mapping, hook engine, violation handling
|   +-- svm.h                 [New] SVM core definitions (VMCB, Exit Codes, Intercepts)
|   +-- svm_init.c            [New] SVM initialization + HV_OPS backend registration
|   +-- svm_exit.c            [New] SVM #VMEXIT dispatcher
|   +-- svm_asm.asm           [New] AMD x64 assembly (VMRUN/VMLOAD/VMSAVE/CLGI/STGI)
|   +-- npt.h                 [New] NPT structure definitions
|   +-- npt.c                 [New] NPT identity mapping + Hook engine (AMD version of EPT)
|   +-- hv_mem.h              [New] Hypervisor memory R/W interface (page table traversal, VMCALL definition)
|   +-- hv_mem.c              [New] Guest page table traversal + direct physical memory R/W engine
|   +-- hv_hook.h             [New] Universal Hook framework interface (dynamic Thunk, rules, event logs)
|   +-- hv_hook.c             [New] Hook framework core (Install/Remove/Decide/PostCall)
|   +-- hv_hook_asm.asm       [New] Hook ASM dispatcher (save/restore parameters, Trampoline invocation)
|   +-- ssdt.h               [New] SSDT monitoring framework interface (status struct, API declarations)
|   +-- ssdt.c               [New] SSDT discovery/parsing/name resolution/Hook/monitoring complete implementation
|   +-- shadow_ssdt.h       [New] Shadow SSDT (Win32k) framework interface
|   +-- shadow_ssdt.c       [New] Shadow SSDT discovery/Win32k parsing/NtUser*/NtGdi* Hook
|   +-- process.h             Process tracking interface
|   +-- process.c             Process tracking implementation, EPROCESS dynamic offset discovery
|   +-- anti_anti_debug.h     Anti-anti-debugging engine interface
|   +-- anti_anti_debug.c     Anti-anti-debugging core (abstracted via hv_ops, shared by dual platforms)
|   +-- msr.c                 MSR interception (abstracted via hv_ops)
|   +-- log.h                 Logging interface
|   +-- log.c                 Logging implementation
+-- client/                    User-mode control utility (VMXToolbox.exe)
|   +-- main.c                CLI entry point, argument parsing, command dispatching
|   +-- driver_comm.h         Driver communication interface
|   +-- driver_comm.c         DeviceIoControl encapsulation
+-- scripts/
|   +-- do_build.bat          One-click compilation script
|   +-- build.bat             Compilation instruction script
|   +-- sign_test.bat         Test signing script
+-- readme.md                  This document
```

---

## Core Technical Details

### VMX Initialization Flow

**File**: `vmx_init.c`

Initialization is divided into two phases: global preparation and per-core virtualization:

#### 1. Global Preparation

```
VmxInitialize()
  +-- VmxCheckCapabilities()      Read capability MSRs, confirm EPT/VPID support
  |     +-- IA32_VMX_BASIC        Get VMCS Revision ID, True Controls support
  |     +-- IA32_VMX_PROCBASED_CTLS   Primary processor controls capabilities
  |     +-- IA32_VMX_PROCBASED_CTLS2  Secondary processor controls capabilities (EPT, VPID)
  |     +-- IA32_VMX_EPT_VPID_CAP    EPT/VPID capabilities
  +-- VmxAllocateCpuContext() x N  Allocate for each logical core:
  |     +-- VMXON Region (4KB, physically contiguous, page-aligned)
  |     +-- VMCS Region  (4KB, physically contiguous, page-aligned)
  |     +-- MSR Bitmap   (4KB, physically contiguous)
  |     +-- Host Stack    (32KB, NonPagedPool)
  +-- EptInitialize()             Build EPT identity mapping
```

#### 2. VMX Support Detection

```c
VmxIsSupported():
  1. CPUID.1:ECX[5] == 1     // VMX bit
  2. IA32_FEATURE_CONTROL.Lock == 1 && VMXON_ENABLED == 1
```

#### 3. Control Field Adjustment

Follows Intel SDM Vol. 3C, Section 31.5.1:

```c
VmxAdjustControls(Requested, Capability):
  Low32  = Capability & 0xFFFFFFFF   // Bits that must be 1
  High32 = Capability >> 32          // Bits that are allowed to be 1
  Result = (Requested | Low32) & High32
```

#### 4. Per-Core Enablement

```
VmxEnableOnCpu():
  1. Save original CR4
  2. CR4 |= VMXE (bit 13)
  3. Adjust CR0 to satisfy VMX fixed bits
  4. VMXON (using VMXON Region physical address)
```

### VMCS Configuration

**File**: `vmx_init.c` - `VmxSetupVmcs()`

VMCS configuration is the core of the entire Hypervisor, deciding which events trigger a VM-Exit:

#### VM-Execution Controls

| Control Category | Enabled Bits | Purpose |
|---------|---------|------|
| **Pin-Based** | NMI Exiting | Intercepts NMI |
| **Primary Proc** | Use MSR Bitmaps | Selectively intercepts MSR accesses |
| | Use I/O Bitmaps | I/O port interception control (all zeros = no I/O exit) |
| | Secondary Controls | Enables secondary controls |
| | CR3 Load Exiting | Monitors process switches (CR3 writes) |
| | MOV-DR Exiting | Intercepts debug register accesses |
| | Use TSC Offsetting | Hardware TSC offsetting (anti-timing detection) |
| **Secondary Proc** | Enable EPT | Enables Extended Page Tables |
| | Enable RDTSCP | Allows RDTSCP instruction (intercept and handle) |
| | Enable VPID | Virtual Processor Identifier (TLB optimization) |
| | Enable INVPCID | Allows INVPCID instruction |
| | Enable XSAVES | Allows XSAVES/XRSTORS instructions |
| **Exception Bitmap** | #DB (bit 1) | Intercepts debug exceptions |
| | #BP (bit 3) | Intercepts breakpoint exceptions |

#### Guest State (Mirroring Current CPU)

- Segment registers: CS/SS/DS/ES/FS/GS/TR/LDTR (Selector, Base, Limit, AccessRights)
- Control registers: CR0, CR3, CR4
- Descriptor tables: GDTR, IDTR (Base + Limit)
- MSRs: IA32_DEBUGCTL, IA32_EFER, SYSENTER_CS/ESP/EIP
- RFLAGS, DR7, VMCS Link Pointer (0xFFFFFFFFFFFFFFFF)

#### Host State (VM-Exit Recovery Target)

- Host RSP: Points to the top of the Host Stack (32KB, 16-byte aligned - 8)
- Host RIP: Points to `AsmVmxExitHandler` (assembly entry point)
- Segment selectors: RPL cleared to zero (& 0xFFF8)
- CR4.VMXE: Kept set
- IA32_EFER: Automatically saved/loaded on VM-Exit

#### CR0/CR4 Guest-Host Mask and Read Shadow

```c
// CR0: Intercept VMX Fixed Bits (PE, NE, PG, etc., bits that must be 1)
// Guest modifications to these bits trigger a VM-Exit -> HandleCrAccess applies Fixed0/Fixed1 adjustment
// Prevents Guest from writing CR0 values that violate VMX constraints, which would cause VM-Entry failure
ULONG64 Cr0Fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
VmxWrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, Cr0Fixed0);
VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, Cr0 & Cr0Fixed0);

// CR4: Only intercept VMXE bit, hiding VMX operations from Guest
VmxWrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMXE);
VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, Cr4 & ~CR4_VMXE);
```

### VM-Exit Handling Framework

**File**: `vmx_asm.asm` (assembly entry point) + `vmx_exit.c` (C dispatcher)

#### Assembly Entry Point (`AsmVmxExitHandler`)

When a VM-Exit occurs, the CPU automatically jumps to Host RIP, which is this function:

```
1. sub rsp, 128          // Allocate GUEST_CONTEXT (16 registers x 8 bytes)
2. Save RAX~R15 to stack // According to GUEST_CONTEXT structure layout
3. mov rcx, rsp          // First parameter = PGUEST_CONTEXT
4. sub rsp, 28h          // x64 Shadow Space
5. call VmxExitHandler   // Call C dispatcher
6. add rsp, 28h
7. if AL != 0:           // Continue Guest
     Restore RAX~R15
     add rsp, 128
     vmresume            // Resume Guest execution
   else:                 // Shut down VMX (IRETQ method)
     vmread Guest RSP/RIP/RFLAGS/CS/SS  // Read before vmxoff
     vmxoff                              // Exit VMX operation
     Build IRETQ frame on Guest stack    // [RIP, CS, RFLAGS, RSP, SS]
     Restore RAX~R15
     mov rsp, Guest Stack
     iretq               // Atomically restore CS:RIP + SS:RSP + RFLAGS
```

#### C Dispatcher (`VmxExitHandler`)

```c
BOOLEAN VmxExitHandler(PGUEST_CONTEXT GuestContext) {
    GuestContext->Rsp = VmxRead(VMCS_GUEST_RSP);  // Synchronize Guest RSP
    ExitReason = VmxRead(VMCS_EXIT_REASON) & 0xFFFF;
    InterlockedIncrement64(&CpuContext->ExitCount);

    switch (ExitReason) {
        case EXIT_REASON_CPUID:          -> AadHandleCpuid() (including 0x4CAFE000 backdoor)
        case EXIT_REASON_RDMSR:          -> HandleRdmsrImpl()
        case EXIT_REASON_WRMSR:          -> HandleWrmsrImpl()
        case EXIT_REASON_CR_ACCESS:      -> HandleCrAccess() (CR0 Fixed Bits protection)
        case EXIT_REASON_DR_ACCESS:      -> AadHandleDrAccess()
        case EXIT_REASON_EXCEPTION_NMI:  -> HandleException() (NMI re-injection)
        case EXIT_REASON_EPT_VIOLATION:  -> HandleEptViolation()
        case EXIT_REASON_MTF:            -> HandleMtf() (per-CPU hook restoration)
        case EXIT_REASON_VMCALL:         -> HandleVmcall() (shutdown/memory read/write)
        case EXIT_REASON_XSETBV:         -> HandleXsetbv() (XCR0 validation)
        case EXIT_REASON_HLT:           -> Activity State = HLT
        case EXIT_REASON_IO:            -> I/O passthrough emulation
        ...
    }

    // IDT-Vectoring event re-injection (prevents Guest from losing exceptions)
    if (IDT_VECTORING_INFO.Valid && !VMENTRY_INT_INFO.Valid)
        Re-inject original IDT event;

    VmxWrite(VMCS_GUEST_RSP, GuestContext->Rsp);  // Write back Guest RSP
    return TRUE;  // VMRESUME
    return FALSE; // VMXOFF (IRETQ recovery)
}
```

#### Exit Reason Handling Strategy

| Exit Reason | Strategy | Description |
|-------------|------|------|
| CPUID | Backdoor + Modify Return Value | 0x4CAFE000 backdoor, clear VMX/Hypervisor bits |
| RDMSR/WRMSR | Proxy Execution + Spoofing | Modify `IA32_DEBUGCTL` return values |
| CR3 Load | Passthrough + Record | Monitor process switches |
| CR0 Write | Fixed Bits Adjustment | Apply VMX CR0 Fixed0/Fixed1 constraints |
| DR Access | Spoofed Read / Allowed Write | DR0-3 = 0, DR7 = 0x400 |
| Exception/NMI| Re-injection / NMI-window | NMI always re-injected, exceptions passed to Guest |
| EPT Violation| Page Switching + MTF | Execute-Only Hook core |
| MTF | Restore EPT Permissions | Restore Execute-Only after hook reads/writes |
| VMCALL | Control Channel | 0xDEADCAFE = Shutdown, memory read/write |
| HLT | Activity State = HLT | Guest safe sleep |
| XSETBV | Validate + Execute | XCR0 validity check |
| I/O | Passthrough Execution | Emulate IN/OUT (must-be-1 bits enforced) |
| IDT-Vectoring| Automatic Re-injection | Prevent VM-Exit from losing Guest exceptions |

### EPT Engine and Hook Mechanism

**File**: `ept.h` + `ept.c`

EPT (Extended Page Tables) is the core technology of this project, implementing transparent function hooking.

#### EPT Page Table Hierarchy

```
EPT 4-level page tables (identity mapping 512GB physical address space):

PML4[0] ──> PDPT[512] ──> PD[512][512] ──> 2MB Large Pages
                                |
                         EptSplitLargePage()
                                |
                                v
                          PT[512] ──> 4KB Pages (used for hooks)
```

#### Identity Mapping Construction

```c
EptInitialize():
  1. Allocate 512 PD pages (each covering 1GB)
  2. Each PD page contains 512 2MB Large Page entries
  3. Total coverage: 512 PD x 512 entries x 2MB = 512GB
  4. PML4[0] -> PDPT -> PD (Read+Write+Execute)
  5. EPTP = WB memory type + 4-level page walk + PML4 physical address
```

#### 2MB -> 4KB Splitting

When different permissions need to be set for a specific 4KB page, the 2MB large page containing it must be split first:

```c
EptSplitLargePage(PhysicalAddress):
  1. Calculate the 2MB-aligned base address
  2. Take a free page from the pre-allocated Split Page pool
  3. Fill 512 PTEs, each mapping 4KB (R+W+X, WB)
  4. Update PDE: LargePage=0, pointing to the new PT page
```

Pre-allocated Split Page pool size: `MAX_SPLIT_PAGES = 32`

#### Execute-Only Hook Mechanism

This is the most ingenious design of the entire project — utilizing the R/W/X permission separation of EPT to achieve **undetectable** function hooks:

```
                    +------------------+
                    |   Target Function Page    |
                    |   (Original Code)      |
                    +--------+---------+
                             |
                    EptHookFunction()
                             |
              +--------------+--------------+
              |                             |
     +--------v--------+         +---------v--------+
     | Original Page (Backup)   |         |   Hook Page (Modified)  |
     | Original Byte Content    |         |   JMP HookFunc    |
     |                  |         |   (14-byte abs)   |
     +--------+---------+         +---------+--------+
              |                             |
              |    EPT PTE Configuration:             |
              |    Execute-Only -> Hook Page   |
              |    Read/Write   -> Original Page     |
              |                             |
     +--------v---------+        +---------v--------+
     | When Anti-debugging Code Reads:  |        | When CPU Executes:       |
     | Sees Unmodified Original   |        | Executes JMP to       |
     | Bytes (Integrity Check   |        | Hook Function         |
     | Passes)             |        |                   |
     +------------------+        +-------------------+
```

#### Hook Installation Flow

```c
EptHookFunction(TargetVa, HookFunction, &OriginalFunction):
  1. Translate VA -> PA (MmGetPhysicalAddress)
  2. Split 2MB large page (EptSplitLargePage)
  3. Get PTE of the target 4KB page
  4. Allocate and copy original page content
  5. Allocate Hook page, write 14-byte absolute jump:
       FF 25 00000000           // JMP QWORD PTR [RIP+0]
       <8-byte HookFunction address>
  6. Build Trampoline (call original function):
       <Original bytes (14 bytes)>
       FF 25 00000000
       <8-byte TargetVa+14 address>
  7. Set PTE:
       Read=0, Write=0, Execute=1
       PhysAddr = Hook Page Physical Address
  8. INVEPT Flush TLB
```

#### EPT Violation Handling

```c
HandleEptViolation():
  Read: GuestPhysAddr, ExitQualification

  if Read/Write Access:
    // Anti-debugging code is reading function bytes (integrity check)
    PTE -> Read=1, Write=1, Execute=0, PhysAddr=Original Page
    Enable MTF (Monitor Trap Flag)
    // Trigger MTF VM-Exit after executing one read/write instruction

  if Execution Access:
    // Restore to execute Hook page
    PTE -> Read=0, Write=0, Execute=1, PhysAddr=Hook Page

HandleMtf():
  // Read/write instruction executed, restore Execute-Only
  Disable MTF
  Iterate over all hooks:
    PTE -> Read=0, Write=0, Execute=1, PhysAddr=Hook Page
  INVEPT
```

### Process Tracking and EPROCESS Dynamic Offset Discovery

**File**: `process.h` + `process.c`

#### EPROCESS Dynamic Offset Discovery

The offset of `EPROCESS.DirectoryTableBase` varies across Windows versions. This project automatically determines it via **runtime scanning**:

```c
ProcessResolveOffsets():
  // Method 1: CR3 scan (most reliable)
  CurrentProcess = PsGetCurrentProcess()
  CurrentCr3 = __readcr3()
  for offset = 0 to 0x700 step 8:
    value = *(ULONG64*)(EPROCESS + offset)
    if (value & ~0xFFF) == (CurrentCr3 & ~0xFFF):
      if ValidateDtbOffset(offset):
        -> Found! offset is the DirectoryTableBase offset

  // Method 2: Known offset table (fallback)
  Try: 0x028 (Win10/11), 0x018 (Win7/8), 0x02C (Insider)
  Validate each offset using ValidateDtbOffset()
```

Validation logic:

```c
ValidateDtbOffset(offset):
  1. Read the value at this offset in the System process EPROCESS
  2. Compare with the current CR3 (mask out the lower 12 bits of PCID)
  3. Check that the value is non-zero and within the valid physical address range (< 2^48)
```

#### CR3 Process Identification

Quickly identify the target process via CR3 in the VM-Exit handler:

```c
ProcessFindByCr3(Cr3):
  Cr3Masked = Cr3 & ~0xFFF    // Strip PCID bits
  for i = 0 to MAX_TARGET_PROCESSES:
    if Targets[i].Active && (Targets[i].Cr3 & ~0xFFF) == Cr3Masked:
      return &Targets[i]
  return NULL
```

**Design Considerations**:
- Linear scan (MAX_TARGET_PROCESSES=16), lock-free read
- Safe execution under high IRQL in the VM-Exit handler
- PCID (Process Context Identifier) bit masking guarantees compatibility

### Anti-Anti-Debugging Engine

**File**: `anti_anti_debug.h` + `anti_anti_debug.c`

#### Feature Overview

The anti-anti-debugging engine operates at two levels:

1. **VM-Exit Handler Level**: Intercepts CPUID / DR / RDTSC / exceptions
2. **EPT Hook Level**: Intercepts Nt* kernel API calls

#### The Four Hooked Nt APIs via EPT

**1. NtQueryInformationProcess** (Most Important)

```c
HookNtQueryInformationProcess():
  Call original function to obtain real results
  if target process && AAD_HIDE_DEBUGGER:
    switch (InformationClass):
      ProcessDebugPort (0x07):
        -> Changed to 0 (no debug port)
      ProcessDebugObjectHandle (0x1E):
        -> Returns STATUS_PORT_NOT_SET
      ProcessDebugFlags (0x1F):
        -> Changed to 1 (not being debugged)
```

**2. NtQuerySystemInformation**

```c
HookNtQuerySystemInformation():
  Call original function
  if target process && AAD_HIDE_SYSINFO:
    if class == SystemKernelDebuggerInformation (0x23):
      KernelDebuggerEnabled = FALSE
      KernelDebuggerNotPresent = TRUE
```

**3. NtSetInformationThread**

```c
HookNtSetInformationThread():
  if target process && class == ThreadHideFromDebugger (0x11):
    return STATUS_SUCCESS   // Pretend success, do not actually execute
  else:
    Call original function
```

**4. NtClose**

```c
HookNtClose():
  if target process:
    __try { Call original function }
    __except { Swallow exception }   // Prevent INVALID_HANDLE exception from leaking debug status
```

#### Debug Register Spoofing (DR0-DR7)

```c
AadHandleDrAccess():
  Exit Qualification parsing:
    DrNumber  = bits[2:0]    // DR index
    Direction = bit[4]       // 0=write DR, 1=read DR
    GpReg     = bits[11:8]   // General-purpose register index

  if target process && AAD_HIDE_HWBP:
    if Read DR:
      DR0-DR3 -> Returns 0           (hide hardware breakpoint addresses)
      DR6     -> Returns 0xFFFF0FF0  (clear breakpoint hit flags)
      DR7     -> Returns 0x400       (default value, no breakpoints enabled)
    if Write DR:
      Normal write (breakpoints still work, just hidden during reads)
  else:
    Normal execution of DR operations
```

#### RDTSC/RDTSCP Timing Compensation

```c
AadHandleRdtsc():
  RealTsc = __rdtsc()
  if target process && AAD_HIDE_TIMING:
    RealTsc -= CpuContext->TscOffset   // Subtract cumulative debug pause time
  GuestContext->RAX = lower 32 bits of RealTsc
  GuestContext->RDX = upper 32 bits of RealTsc

// TSC offset management:
AadNotifyDebugPause():  Record TSC at pause start
AadNotifyDebugResume(): TscOffset += (Current TSC - Pause Start TSC)
```

#### CPUID Hiding

```c
AadHandleCpuid():
  // CPUID backdoor: Fast check if hypervisor is active
  if Leaf == 0x4CAFE000:
    EAX = 0x564D5854 ("VMXT"), EBX=ECX=EDX=0
    return   // Do not execute real CPUID

  Execute real CPUID
  if target process && AAD_HIDE_CPUID:
    Leaf 1:
      ECX &= ~(1 << 31)       // Clear Hypervisor Present bit
    Leaf 0x40000000~0x400000FF:
      EAX=EBX=ECX=EDX = 0     // Masquerade as bare metal
```

#### Exception Behavior Standardization

```c
AadHandleException():
  Read interruption info: Vector, Type, ErrorCode
  // Regardless of whether it is the target process, re-inject the exception into the Guest
  // Allow the Guest's SEH/VEH to handle it normally
  // This ensures that the behavior of INT 2D, INT 3, etc. is consistent with non-debugged environments

  VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, InjectInfo)
```

### MSR Interception

**File**: `msr.c`

#### MSR Bitmap Layout

```
4KB Bitmap:
  [0x000..0x3FF]  Read bitmap  for MSR 0x00000000 - 0x00001FFF
  [0x400..0x7FF]  Read bitmap  for MSR 0xC0000000 - 0xC0001FFF
  [0x800..0xBFF]  Write bitmap for MSR 0x00000000 - 0x00001FFF
  [0xC00..0xFFF]  Write bitmap for MSR 0xC0000000 - 0xC0001FFF

bit = 1 -> This MSR access triggers a VM-Exit
bit = 0 -> Passed through directly (no VM-Exit)
```

By default, all are passed through, only intercepting `IA32_DEBUGCTL` (0x01D9):

```c
MsrBitmapInitialize():
  RtlZeroMemory(bitmap, 4096)     // Pass through all
  SetBit(IA32_DEBUGCTL, Read+Write)  // Intercept debug control MSR
```

#### IA32_DEBUGCTL Spoofing

```c
HandleRdmsrImpl():
  if MSR == IA32_DEBUGCTL && target process:
    Value &= ~0x43    // Clear:
                      //   Bit 0 (LBR): Last Branch Record
                      //   Bit 1 (BTF): Single-Step on Branches
                      //   Bit 6 (TR):  Trace Messages
```

### Logging System

**File**: `log.h` + `log.c`

#### Design Principles

Hypervisor logging faces a core challenge: **`DbgPrintEx` cannot be called under VMX root mode**. The reason is that `DbgPrintEx` internally uses spinlocks and `INT 3` to trigger debugger interrupts, whereas VMX root mode executes on the Host stack (32KB of memory allocated via `ExAllocatePool`), which is not a Windows thread kernel stack — making SEH exception chains invalid, and causing an `INT 3` to lead to recursive VM-Exits or deadlocks.

Solution: **A unified Lock-free Ring Buffer + Flush Thread architecture**.

#### Lock-free Ring Buffer

```
8192 entries, 256 bytes per entry

                   Lock-free write (InterlockedIncrement)
                            |
+---+---+---+---+---+---+---+---+
| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | ... [8192 entries]
+---+---+---+---+---+---+---+---+
          ^                   ^                ^
          |                   |                |
      FlushIndex         ReadIndex        WriteIndex

Ready[i] = 0: empty slot or writing in progress
Ready[i] = 1: data fully written, safe to read
```

**Lock-free Publication Protocol** (Multi-writer safe):
```
Writer (LogWrite, safe at any IRQL / VMX root):
  1. InterlockedIncrement(&WriteIndex)    — Atomic slot allocation
  2. Fill Entry (Level, Pid, Timestamp, Message)
  3. InterlockedExchange(&Ready[Idx], 1)  — RELEASE barrier, publish

Reader (Flush Thread / LogRead):
  1. Check Ready[Idx] == 1                 — ACQUIRE barrier
  2. Read all fields of the Entry (integrity guaranteed)
  3. InterlockedExchange(&Ready[Idx], 0)  — Release slot
```

Zero spinlocks, zero IRQL modifications, and pure `Interlocked*` atomic operations throughout.

#### Flush Thread (System Thread)

```
LogFlushThreadRoutine():
  Execution level: PASSIVE_LEVEL (ordinary kernel thread stack)
  Polling interval: 5ms
  
  loop:
    KeWaitForSingleObject(StopEvent, 5ms timeout)
    while (FlushIndex < WriteIndex):
      if Ready[Idx] == 1:
        DbgPrintEx(...)    ← Safely called at PASSIVE_LEVEL
        Ready[Idx] = 0
        FlushIndex++
      else:
        break              ← Writer hasn't finished, try again next time
```

The latency from logging write to WinDbg display is about **5ms** (Flush Thread polling interval).

#### Unified Macro Interface

```c
/* Normal Context (DriverEntry, IOCTL handler, etc.) */
LOG_ERROR(fmt, ...)     // → LogWrite → Ring Buffer
LOG_WARN(fmt, ...)
LOG_INFO(fmt, ...)
LOG_DEBUG(fmt, ...)

/* VMX Root Mode (within VM-Exit handler) — identical to above */
VMXROOT_LOG_ERROR(fmt, ...)  // → LogWrite → Ring Buffer
VMXROOT_LOG_WARN(fmt, ...)
VMXROOT_LOG_INFO(fmt, ...)
VMXROOT_LOG_DEBUG(fmt, ...)
```

Both macro sets ultimately call the same `LogWrite()`, unifying the path through the Ring Buffer. The Flush Thread is responsible for all `DbgPrintEx` outputs.

#### Output Filtering

| Level | Value | WinDbg Output | Ring Buffer | Purpose |
|------|---|------------|-------------|------|
| ERROR | 0 | ✅ (Flush Thread) | ✅ | Fatal errors |
| WARN  | 1 | ✅ (Flush Thread) | ✅ | Warning messages |
| INFO  | 2 | ✅ (Flush Thread) | ✅ | General information (driver load, hook install, etc.) |
| DEBUG | 3 | ❌ (Ring Buffer only) | ✅ | Debug information (high frequency, read via IOCTL) |

#### User-Mode Reading

Entries in the Ring Buffer are read via `IOCTL_VMX_GET_LOG` using an independent `ReadIndex` (not interfering with the Flush Thread's `FlushIndex`).

---

## AMD SVM Technical Details

### SVM Overview

AMD SVM (Secure Virtual Machine) is AMD's hardware virtualization technology, equivalent to Intel VT-x. Core differences:

| Concept | Intel VMX | AMD SVM |
|------|-----------|---------|
| Control Structure | VMCS (via vmread/vmwrite) | VMCB (direct memory access) |
| Guest Entry | VMLAUNCH / VMRESUME | VMRUN |
| State Saving | Automatic (VMCS fields) | VMSAVE / VMLOAD |
| Nested Page Tables | EPT (Extended Page Tables) | NPT (Nested Page Tables) |
| TLB Management | INVEPT / INVVPID | ASID + TLB Control |
| Interrupt Control | External-Interrupt Exiting | GIF (Global Interrupt Flag) |
| Single-step Debugging | MTF (Monitor Trap Flag) | RFLAGS.TF + #DB intercept |
| Execute-Only Pages | Supported | **Not Supported** |
| Instruction Length | Exit Instruction Length | NRIP Save (Next RIP) |

### VMCB (Virtual Machine Control Block)

VMCB is a 4KB page containing two regions:

```
+---------------------------+
| Control Area (0x000-0x3FF)|  Intercept configuration, exit information, NPT settings
|   intercept_cr/dr/excps   |
|   intercept (64-bit)      |
|   iopm_base_pa            |
|   msrpm_base_pa           |
|   tsc_offset              |
|   asid                    |
|   exit_code / exit_info   |
|   nested_ctl / nested_cr3 |
|   event_inj               |
|   next_rip                |
+---------------------------+
| Save Area (0x400-0xFFF)   |  Guest CPU state
|   Segment registers (ES~TR) |
|   CR0/CR2/CR3/CR4         |
|   DR6/DR7                 |
|   RFLAGS/RIP/RSP/RAX      |
|   EFER/STAR/LSTAR/CSTAR   |
|   SYSENTER_CS/ESP/EIP     |
|   G_PAT/DBGCTL            |
+---------------------------+
```

### SVM VMRUN Loop

```
SvmEnableOnCpu():
  1. EFER |= SVME (bit 12)        Enable SVM
  2. MSR_VM_HSAVE_PA = host_save   Set host state save area

VMRUN Loop (svm_asm.asm):
  Save host callee-saved registers
  Load guest GP registers
  RAX = VMCB physical address
  VMLOAD                           Load guest segment registers, etc.
  VMRUN                            Enter guest, returns on #VMEXIT
  VMSAVE                           Save guest segment registers, etc.
  Save guest GP registers
  Restore host callee-saved registers
  Call SvmExitHandler()            C dispatcher
```

### NPT vs EPT Hook Strategy

| Feature | Intel EPT | AMD NPT |
|------|-----------|---------|
| Execute-Only | Supported (R=0, W=0, X=1) | **Not Supported** |
| Hook Default Mapping | Execute-Only -> Hook Page | Read+Execute -> Hook Page |
| On Read | EPT Violation -> Original Page | Sees Hook Page directly |
| On Write | EPT Violation -> Original Page + MTF | NPF -> Original Page + TF |
| Integrity Check Resistance | Extremely high (reads see original) | Medium (reads see Hook) |
| Single-step Restoration | MTF VM-Exit | #DB Exception |

Specific NPT Hook Strategy:

```
Hook Installation:
  PTE -> Read=1, Write=0, Execute=1, PhysAddr=Hook Page
  (Execution and reads go to Hook page, writes trigger NPF)

Write Triggers NPF:
  PTE -> Read=1, Write=1, Execute=1, PhysAddr=Original Page
  RFLAGS.TF = 1 (Set Trap Flag)
  Re-execute write instruction

#DB Exception (Single-step completed):
  PTE -> Read=1, Write=0, Execute=1, PhysAddr=Hook Page
  RFLAGS.TF = 0
  TLB Flush (ASID switch)
```

### SVM Anti-Anti-Debugging Capabilities

The SVM backend provides the exact same anti-anti-debugging capabilities as VMX:

| Feature | VMX Implementation | SVM Implementation |
|------|---------|---------|
| DR Register Spoofing | MOV-DR Exiting | DR Read/Write Intercept |
| CPUID Hiding | CPUID unconditional Exit | CPUID Intercept |
| RDTSC Compensation | RDTSC Exiting | RDTSC Intercept |
| Exception Standardization | Exception Bitmap | Exception Intercept |
| API Hook | EPT Execute-Only | NPT Read+Execute |
| MSR Spoofing | MSR Bitmap (4KB) | MSRPM (8KB) |

---

## Virtualization Hiding

### Background

To prevent software inside the Guest (including virtualization detection by anti-cheat drivers and Hypervisor probing by anti-debugging code), we comprehensively intercept **CPUID / MSR / VMX instructions / SVM instructions** in the VM-Exit handler, making the Guest believe it is running on bare metal without virtualization capabilities.

### Direction of Modification Effects

```
VMXToolbox Hypervisor                  ← Modifications happen here
        ↓ VM-Exit handler modifies values returned to Guest
Guest OS + Application                 ← Sees spoofed bare-metal environment
```

**All modifications only affect the Hypervisor -> Guest direction**.

### CPUID Hiding

**File**: `anti_anti_debug.c` — `AadHandleCpuid()`

**CPUID Backdoor** (unconditionally active for all processes):

| Leaf | Return Value | Purpose |
|------|--------|------|
| `CPUID(0x4CAFE000)` | `EAX=0x564D5854` ("VMXT") | Fast check if Hypervisor is active |

```c
// User-mode/kernel-mode detection code example:
int info[4];
__cpuid(info, 0x4CAFE000);
if (info[0] == 0x564D5854) printf("Hypervisor active!\n");
```

**Virtualization Hiding** (unconditionally active for all processes):

| Leaf | Modification | Purpose |
|------|------|------|
| `CPUID.1:ECX` | Clear bit 31 (Hypervisor Present) | Hide Hypervisor presence |
| `CPUID.1:ECX` | Clear bit 5 (VMX) | Hide Intel VT-x support |
| `CPUID.0x80000001:ECX` | Clear bit 2 (SVM) | Hide AMD-V support |
| `CPUID.0x8000000A` | Return all zeros | Hide SVM feature leaves (NASID/NPT support, etc.) |
| `CPUID.0x40000000~0x40000006` | Return all zeros | Hide Hypervisor vendor string and interface leaves |

```c
if (Leaf == 1) {
    CpuInfo[2] &= ~(1 << CPUID_HYPERVISOR_BIT);   /* Hide hypervisor present */
    CpuInfo[2] &= ~(1 << 5);                       /* Hide VMX (Intel VT-x) */
}
else if (Leaf == 0x80000001) {
    CpuInfo[2] &= ~(1 << 2);                       /* Hide SVM (AMD-V) */
}
else if (Leaf == 0x8000000A) {
    CpuInfo[0] = CpuInfo[1] = CpuInfo[2] = CpuInfo[3] = 0;
}
else if (Leaf >= 0x40000000 && Leaf <= 0x40000006) {
    CpuInfo[0] = CpuInfo[1] = CpuInfo[2] = CpuInfo[3] = 0;
}
```

**Security Note**: `__cpuidex()` executes the real CPUID first (returned by L0). The modification occurs in the VM-Exit handler, altering only the result returned to the L2 Guest. L0 is completely unaware of what we modified.

### MSR Interception — Hiding Virtualization Capabilities

**File**: `msr.c`

#### MSR Bitmap Configuration

Intercept the following MSRs in `MsrBitmapInitialize()`:

| MSR Range | Name | Intercept Mode |
|----------|------|---------|
| `0x003A` | IA32_FEATURE_CONTROL | Read+Write |
| `0x0480~0x0491` | IA32_VMX_BASIC ~ IA32_VMX_VMFUNC | Read+Write |
| `0xC0010114` | MSR_VM_CR (AMD) | Read+Write (SVM MSRPM) |
| `0xC0010117` | MSR_VM_HSAVE_PA (AMD) | Read+Write (SVM MSRPM) |

#### RDMSR Spoofing Strategy

| MSR | Return Value | Meaning |
|-----|--------|------|
| `0x0480~0x0491` (VMX MSRs) | All zeros | VMX unavailable |
| `0x003A` (IA32_FEATURE_CONTROL) | `1` (Lock=1, VMXON=0) | VMX locked and disabled in BIOS |
| `0xC0010114` (MSR_VM_CR) | Real Value \| SVMDIS \| LOCK | SVM disabled and locked |
| `0xC0010117` (MSR_VM_HSAVE_PA) | `0` | SVM Host Save Area unconfigured |

#### WRMSR Blocking Strategy

All write operations to virtualization-related MSRs inject a `#GP(0)` to emulate bare-metal behavior (VMX MSRs are read-only; writing to `IA32_FEATURE_CONTROL` after locking causes a `#GP`; writing to `VM_CR` after locking causes a `#GP`).

### VMX Instruction Interception

**File**: `vmx_exit.c`

When the Guest attempts to execute any VMX instruction (even if CPUID has hidden the VMX bit), the CPU unconditionally triggers a VM-Exit. We inject a `#UD` (Undefined Opcode) for all VMX instructions, consistent with CPU behavior when VMX is disabled:

```c
case EXIT_REASON_VMCLEAR:
case EXIT_REASON_VMLAUNCH:
case EXIT_REASON_VMPTRLD:
case EXIT_REASON_VMPTRST:
case EXIT_REASON_VMREAD:
case EXIT_REASON_VMRESUME:
case EXIT_REASON_VMWRITE:
case EXIT_REASON_VMXOFF:
case EXIT_REASON_VMXON:
case EXIT_REASON_INVEPT:
case EXIT_REASON_INVVPID:
    /* Inject #UD (vector 6) */
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, INTERRUPT_INFO_VALID |
             (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) | 6);
    break;
```

### SVM Instruction Interception

**File**: `svm_exit.c`

The AMD SVM backend likewise intercepts all SVM management instructions and injects a `#UD`:

- `VMRUN` / `VMLOAD` / `VMSAVE`
- `STGI` / `CLGI`
- `SKINIT` / `INVLPGA`

### Security Summary

| Modification Point | Direction of Effect | Effect on Outer HV | Description |
|--------|---------|--------------|------|
| CPUID hide VMX/SVM bits | L1→L2 | ❌ None | Only modifies values returned to Guest |
| MSR bitmap interception | L1→L2 | ❌ None | Only controls Guest MSR access |
| RDMSR spoofing | L1→L2 | ❌ None | Only modified inside Exit handler |
| WRMSR blocking (#GP) | L1→L2 | ❌ None | Only injects #GP into Guest |
| VMX instructions -> #UD | L1→L2 | ❌ None | Only intercepts Guest VMX instructions |
| SVM instructions -> #UD | L1→L2 | ❌ None | Only intercepts Guest SVM instructions |

**Initialization Safety**: `VmxCheckCapabilities()` and `SvmCheckCapabilities()` calls like `__readmsr(MSR_IA32_VMX_BASIC)` are executed in `DriverEntry` before VMX/SVM is started and before MSR Bitmaps are active, so they are unaffected.

---

## Per-CPU EPT/NPT Hook Page Isolation

On multi-core systems, the three phases of EPT/NPT Hooks (**Violation -> Single-step -> Restoration**) suffer from race conditions:

```
CPU 0: EPT Violation -> Relax PTE (R+W) -> Enable MTF
CPU 1: EPT Violation -> Relax PTE (R+W) -> Enable MTF    ← Same PTE!
CPU 0: MTF Triggered -> Restore PTE (X-Only)                  ← Also restores the PTE currently in use by CPU 1!
CPU 1: Still executing the relaxed instruction -> PTE has been restored by CPU 0 -> EPT Violation again -> Infinite loop / Lockup
```

### Solution

Each CPU owns an independent EPT/NPT page table chain (PML4 -> PDPT -> PD -> PT), so that PTE permission changes only affect the address translation of the current CPU.

**Key Constraint**: Isolation is only done at the PT level. For non-hooked regions, all CPUs still share the same PD/PT pages.

### Overall Architecture

```
        ┌──────────────────────────────────────────────┐
        │  Shared Template (EPT_STATE / NPT_STATE)     │
        │  PML4 → PDPT → PD Pages → Split PT Pages     │
        │  (Shared by all CPUs in non-hooked regions)  │
        └──────────────────────────────────────────────┘

Per-CPU Level (Hooked regions only):

  CPU 0:  PML4[0] → PDPT[0]                CPU 1:  PML4[1] → PDPT[1]
            │                                        │
            ├─ PDPT[x] → Shared PD (not hooked)      ├─ PDPT[x] → Shared PD
            │                                        │
            └─ PDPT[y] → per-CPU PD[0][y]           └─ PDPT[y] → per-CPU PD[1][y]
                           │                                       │
                           ├─ PD[z] → per-CPU PT[0]              ├─ PD[z] → per-CPU PT[1]
                           │   (Hooked 2MB region)                 │   (Hooked 2MB region)
                           │                                      │
                           └─ PD[other] → Shared PT               └─ PD[other] → Shared PT
```

**Layered Isolation Strategy**:
- **PML4 + PDPT**: Independent per-CPU replicas (cloned from the template during initialization), used to make PDPT entries point to different PDs.
- **PD pages**: **Cloned on-demand** — a per-CPU replica is created only for 1GB regions containing hooks.
- **PT (split) pages**: **Cloned on-demand** — a per-CPU replica is created only for 2MB regions containing hooks.
- **Non-hooked regions**: All CPUs share the same PD/PT pages.

### Data Structures

```c
// Per-CPU EPT root structure (ept.h)
typedef struct _EPT_CPU_STATE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[512];  // Independent PML4
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[512];  // Independent PDPT
    EPT_POINTER Eptp;     // This CPU's EPTP value (written to VMCS)
    ULONG64     Pml4Pa;   // Physical address of PML4
} EPT_CPU_STATE;

// Per-CPU split PT page replica (ept.c)
typedef struct _EPT_PER_CPU_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[512];  // 512 4KB PTEs
    ULONG64     PhysicalAddress;    // Physical address of this page table page
    BOOLEAN     Allocated;          // Whether allocated
} EPT_PER_CPU_SPLIT;

// Global arrays
PEPT_CPU_STATE   g_EptCpuStates;                // [g_MaxProcessors] per-CPU EPT root
PEPT_PER_CPU_SPLIT  *g_PerCpuSplitPages;        // [g_MaxProcessors] -> [MAX_SPLIT_PAGES]
EPT_PER_CPU_PD_PAGE **g_PerCpuPdPages;          // [g_MaxProcessors] -> [MAX_PD_PAGES]
```

The AMD NPT side (`npt.h`/`npt.c`) structures are completely mirrored with Intel EPT.

### Initialization Flow

```
DriverEntry
  └─ VmxInitialize / SvmInitialize
       ├─ EptInitialize / NptInitialize        ← Create shared template page tables
       ├─ EptInitPerCpu / NptInitPerCpu        ← Create per-CPU PML4+PDPT
       └─ For each CPU:
            └─ EptSetupIdentityMap / SvmInitVmcb
                 └─ Write per-CPU EPTP / nested_cr3 to VMCS / VMCB
```

`EptInitPerCpu()` clones the PML4 and PDPT for each CPU, and points PML4[0] to their respective PDPTs. At this point, the PDPT entries for all CPUs still point to the shared PD pages. Per-CPU PD and PT pages are created on-demand only when a hook is installed.

### Per-CPU Setup During Hook Installation

```c
// Per-CPU block in EptHookFunction() (ept.c)
if (g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages) {
    // 1. Ensure the PD page for this 1GB region is per-CPU isolated
    EptEnsurePerCpuPdForRegion(PdptIdx);

    // 2. Ensure the split PT page for this 2MB region is per-CPU isolated
    EptEnsurePerCpuSplitPage(splitIdx, PdptIdx, PdIdx);

    // 3. Copy hook PTE permissions to the private replicas of all CPUs
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

### Runtime: EPT Violation / NPF Handling

Core change: Use **per-CPU PTEs** instead of shared PTEs to eliminate multi-core race conditions.

**Intel EPT (ept.c — HandleEptViolation)**:

```c
CpuIndex = KeGetCurrentProcessorNumber();
Hook = EptFindHookByPhysicalAddress(GuestPhysAddr);

// ★ Core: Use per-CPU PTE
Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
if (!Pte) Pte = Hook->TargetPte;  // fallback to shared

// Subsequent Pte->Read/Write/Execute modifications only affect the translation of the current CPU
// Enable MTF single-step, record which page is relaxed for the current CPU via EptMtfTrackRelaxedPage()
```

**Intel MTF Restoration (vmx_exit.c — HandleMtf)**:

```c
CpuIndex = KeGetCurrentProcessorNumber();
RelaxedPa = EptMtfGetAndClearRelaxedPage();  // Get the relaxed page for the current CPU

// ★ Restore using per-CPU PTE (restores current CPU only)
PEPT_PTE Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
Pte->Read = 0; Pte->Write = 0; Pte->Execute = 1;  // Restore to hook state
Pte->PhysAddr = Hook->HookPagePa >> 12;
EptInvalidateSingleContext(CpuEptp);  // Only flush TLB for the current CPU
```

The AMD NPT side `NptHandlePageFault` and `SvmHandleDbException` adopt the same strategy.

### INVEPT Optimization

After per-CPU isolation, PTE modifications only affect the current CPU. Therefore, **INVEPT SINGLE_CONTEXT** is used instead of ALL_CONTEXTS to avoid unnecessary cross-CPU TLB flushes:

```c
ULONG64 CpuEptp = EptGetPerCpuEptp(CpuIndex);
if (CpuEptp)
    EptInvalidateSingleContext(CpuEptp);
else
    EptInvalidateAllContexts();  // fallback
```

### Memory Allocation Summary

| Pool Tag | Purpose | Allocation Timing | Size |
|----------|------|---------|------|
| `'tpEC'` | per-CPU EPT root (PML4+PDPT+EPTP) | `EptInitPerCpu` | `CPUs × sizeof(EPT_CPU_STATE)` |
| `'tpES'` | per-CPU split PT pages | On-demand: `EptEnsurePerCpuSplitPage` | `MAX_SPLIT_PAGES × sizeof(EPT_PER_CPU_SPLIT)` per CPU |
| `'tpEP'` | per-CPU PD pages | On-demand: `EptEnsurePerCpuPdForRegion` | `MAX_PD_PAGES × sizeof(EPT_PER_CPU_PD_PAGE)` per CPU |
| `'tpNC'` / `'tpNS'` / `'tpNP'` | AMD NPT Side (Mirrored) | Same as EPT | Same as EPT |

> **On-Demand Allocation**: Split PT and PD pages are allocated only when hooks are installed in the corresponding regions. If no hooks are installed, no allocation occurs.

### Fault-Tolerance Design

1. **Initialization failure is non-fatal**: When `EptInitPerCpu`/`NptInitPerCpu` returns a failure, it only logs a warning (`LOG_WARN`) and continues, falling back hooks to shared PTEs (no isolation).
2. **Fallback to shared PTE**: Anywhere per-CPU PTEs are used, there is a fallback: `if (!Pte) Pte = Hook->TargetPte;`
3. **NULL Check**: All per-CPU paths check that `g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages` are non-NULL.

---

## Hypervisor Memory Read/Write

### Overview

**File**: `hv_mem.h` + `hv_mem.c` + `vmxdrv.c` (IOCTL handlers)

Leveraging the privilege of the Hypervisor running at Ring -1, it directly reads and writes the virtual address space of any Guest process via physical memory access. **This completely bypasses all software-level protections inside the Guest**, including memory protection mechanisms of anti-cheat drivers.

### Why It Bypasses Anti-Cheat Drivers

```
Ring -1  ┃  VMXToolbox (Hypervisor)        ← Memory read/write is executed here
━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Ring 0   ┃  Anti-cheat drivers (EAC/BE/VGK)  ← Its protections are all here
         ┃  Windows Kernel
━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Ring 3   ┃  Game Process
```

All operations that anti-cheat drivers can monitor reside inside the Guest:

| Anti-Cheat Method | Why It Fails |
|-----------|-----------|
| `ObRegisterCallbacks` stripping handle permissions | No `OpenProcess` used, bypasses handles |
| Hooking NtReadVirtualMemory | Does not call any memory R/W APIs |
| Monitoring `KeStackAttachProcess` | No need to Attach to target process |
| Scanning suspicious driver call stacks | R/W completed in Ring -1, invisible to Guest |
| Detecting `MmCopyVirtualMemory` | Does not call this function |

### Work Principle

```
User-mode request: Read 4096 bytes from game process PID=1234 at address 0x7FF612340000

IOCTL_VMX_READ_MEMORY
  |
  v
[Kernel Driver] HandleIoctlReadMemory()
  |
  +-- 1. PID -> CR3: PsLookupProcessByProcessId(1234)
  |       Read EPROCESS + DirectoryTableBase offset
  |       Obtain target process CR3 = 0x1A3000
  |
  +-- 2. Traverse Guest 4-level page table (VA -> PA translation):
  |       CR3(0x1A3000) -> PML4[index] -> PDPT -> PD -> PT
  |       0x7FF612340000 -> Physical Address 0x3F8A5000
  |
  +-- 3. Map physical memory and copy:
  |       MmMapIoSpace(0x3F8A5000, PAGE_SIZE)
  |       RtlCopyMemory(Output Buffer, Mapped Address, 4096)
  |       MmUnmapIoSpace()
  |
  +-- 4. Return data to user-mode
```

### Guest Page Table Traversal (4-Level)

```
CR3 (DirectoryTableBase)
 ──[PML4 Index = VA[47:39]]──> PML4E
                                  │
                  ──[PDPT Index = VA[38:30]]──> PDPTE
                                                   │
                                                   ├─ If PS=1: 1GB Large Page, PA = PDPTE[51:30] | VA[29:0]
                                                   │
                                    ──[PD Index = VA[29:21]]──> PDE
                                                                   │
                                                                   ├─ If PS=1: 2MB Large Page, PA = PDE[51:21] | VA[20:0]
                                                                   │
                                                   ──[PT Index = VA[20:12]]──> PTE
                                                                                  │
                                                                                  ──> PA = PTE[51:12] | VA[11:0]
```

Critical implementation (`KernelGuestVaToPa`):
- Each level maps the physical page table page via `MmMapIoSpace`.
- Read the page table entry of the corresponding index.
- Check the Present bit and the Large Page bit.
- Handle three page sizes: 4KB / 2MB / 1GB.
- Automatically split cross-page reads/writes into multiple single-page operations.

### IOCTL Interface

#### `IOCTL_VMX_READ_MEMORY` (0x807)

Reads memory from the target process.

```c
// Request structure
typedef struct _VMX_MEMORY_REQUEST {
    ULONG       Pid;                /* Target Process ID */
    ULONG       Size;               /* Bytes count (max 64KB) */
    ULONG64     VirtualAddress;     /* Virtual address in target process */
} VMX_MEMORY_REQUEST;

// Usage
VMX_MEMORY_REQUEST req;
req.Pid = 1234;
req.Size = 4096;
req.VirtualAddress = 0x7FF612340000;

BYTE buffer[4096];
DeviceIoControl(hDevice, IOCTL_VMX_READ_MEMORY,
    &req, sizeof(req),          // Input: Request header
    buffer, sizeof(buffer),     // Output: Read data
    &bytesReturned, NULL);
```

#### `IOCTL_VMX_WRITE_MEMORY` (0x808)

Writes memory to the target process.

```c
// Input layout: [VMX_MEMORY_REQUEST header][Data to write...]
// Total InputBufferLength = sizeof(VMX_MEMORY_REQUEST) + Size

// Example: Write an int value to target address
BYTE packet[sizeof(VMX_MEMORY_REQUEST) + sizeof(int)];
VMX_MEMORY_REQUEST *hdr = (VMX_MEMORY_REQUEST *)packet;
hdr->Pid = 1234;
hdr->Size = sizeof(int);
hdr->VirtualAddress = 0x7FF612340000;
*(int *)(packet + sizeof(VMX_MEMORY_REQUEST)) = 99999;  // Value to write

DeviceIoControl(hDevice, IOCTL_VMX_WRITE_MEMORY,
    packet, sizeof(packet),     // Input: Header + Data
    NULL, 0,                    // No output
    &bytesReturned, NULL);
```

### VMCALL Memory Operation Interface (Fallback Path)

In addition to the IOCTL -> direct physical memory access route in the kernel, a VMCALL path is also implemented, which can trigger the Hypervisor from Guest kernel to perform reads and writes in Ring -1:

```
VMCALL Convention:
  RAX = 0xCAFE0001  (VMCALL_MAGIC | READ_MEMORY)
  RAX = 0xCAFE0002  (VMCALL_MAGIC | WRITE_MEMORY)
  RDX = Guest virtual address of VMCALL_MEM_PARAMS struct

typedef struct _VMCALL_MEM_PARAMS {
    ULONG64     TargetCr3;      /* Target Process CR3 */
    ULONG64     TargetVa;       /* Target Virtual Address */
    ULONG64     BufferVa;       /* Caller Buffer Address */
    ULONG       Size;           /* Bytes count */
    NTSTATUS    Status;         /* [out] Return status */
} VMCALL_MEM_PARAMS;
```

In the VMCALL path, the Hypervisor leverages the EPT/NPT identity mapping (Guest PA == Host VA) to access physical memory directly via pointers, completely bypassing the need for `MmMapIoSpace`.

### Use Cases

```bash
# Scenario 1: Read the PE header (MZ header) of the target process
VMXToolbox.exe --read-mem 1234 7FF600000000 64

# Scenario 2: Read memory region of specified size
VMXToolbox.exe --read-mem 1234 7FF612345678 128

# Scenario 3: Write NOP sled (4 bytes), automatically read back to verify
VMXToolbox.exe --write-mem 1234 7FF600001000 90909090

# Scenario 4: Write INT3 breakpoint
VMXToolbox.exe --write-mem 1234 7FF600001000 CC

# Scenario 5: Large block memory dump (Hex+ASCII format)
VMXToolbox.exe --dump-mem 1234 7FF600000000 4096

# Scenario 6: Use in conjunction with anti-anti-debugging
VMXToolbox.exe --pid 1234 --hide-all              # Hide debugger first
VMXToolbox.exe --read-mem 1234 7FF600000000 256   # Then read memory

# Scenario 7: Read kernel memory (System process, PID=4)
VMXToolbox.exe --read-mem 4 FFFFF78000000000 64
```

### Security Restrictions

| Restriction | Description |
|------|------|
| Max 64KB per call | `VMX_MEM_MAX_SIZE = 64 * 1024`, larger R/W requests must be split into multiple IOCTLs |
| Page must be Present | Unmapped pages (swapped out to disk) cannot be read, returning STATUS_INVALID_ADDRESS |
| Cross-page automatic handling | Automatically split into multiple physical page accesses when reads/writes cross 4KB page boundaries |
| No page fault triggered | Unlike ReadProcessMemory, this does not trigger a Page Fault in the Guest |

---

## Late-load Virtualization and Memory Continuity

### Core Question

VMXToolbox is a **parasitic hypervisor** (Blue Pill / late-launch), loaded only after both the operating system and target processes are already running. A natural question arises:

> Since processes are already running and a large amount of memory has already been allocated in physical DRAM, what happens to this existing memory when virtualization (EPT/NPT) is enabled at this point? Does it need to be moved?

**Answer: Not a single byte needs to be moved. The physical memory remains untouched; we simply insert a transparent mapping layer in the CPU's address translation pipeline.**

### Address Translation Comparison Before and After Virtualization

Before enablement — running normally, CPU performs one translation:

```
Process Virtual Address              [Guest CR3 Page Table]              Physical DRAM
0x7FF612340000  ─────────────────────────>  PA 0x3F8A5000  ────>  Actual Memory Chip
                                                                  (Data resides here)

                   Sole translation layer
                   Maintained by Windows memory manager
```

After enablement — CPU performs two translations, but the second one is transparent:

```
Process Virtual Address          [Guest CR3 Page Table]        [EPT/NPT]            Physical DRAM
0x7FF612340000  ───────────────>  GPA 0x3F8A5000  ──────────>  HPA 0x3F8A5000
                                                                     │
                  This layer is unchanged         This layer is new  │
                  Windows is unaware              Identity mapping   ▼
                  Page table content identical    Output = Input    Same DRAM
                                                                    Data untouched
```

**Key Point**: The identity mapping of EPT/NPT ensures that `GPA == HPA`, which makes the second level of translation equivalent to no translation. The CPU ultimately accesses the exact same physical memory.

### How Identity Mapping Guarantees Seamless Transition

Check the initialization code in `ept.c` / `npt.c`:

```c
// Cover 512GB physical address space, each 2MB region maps to itself
for (i = 0; i < 512; i++) {            // 512 PDPT entries, each covering 1GB
    for (j = 0; j < 512; j++) {        // 512 PD entries, each covering 2MB
        PhysAddr = (i * 512 + j) * 2MB;

        PD[i][j].Read    = 1;          // Allow reads
        PD[i][j].Write   = 1;          // Allow writes
        PD[i][j].Execute = 1;          // Allow execution
        PD[i][j].LargePage = 1;        // 2MB large page
        PD[i][j].PhysAddr = PhysAddr;  // ★ Point to itself! GPA == HPA
    }
}
```

| GPA Range | HPA Range | Effect |
|----------|----------|------|
| 0x00000000 ~ 0x001FFFFF | 0x00000000 ~ 0x001FFFFF | First 2MB, mapped as-is |
| 0x00200000 ~ 0x003FFFFF | 0x00200000 ~ 0x003FFFFF | Second 2MB |
| ... | ... | ... |
| 0x3F800000 ~ 0x3F9FFFFF | 0x3F800000 ~ 0x3F9FFFFF | A 2MB block containing game data |
| ... | ... | ... |
| Up to 512GB | Same | Full coverage |

**Every physical address maps to itself**, so any existing memory — whether process code, data, heap, stack, or kernel code — accesses the exact same DRAM before and after virtualization is enabled, with content completely unaltered.

### Complete Enablement Timeline

```
Timeline
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

T0: System runs normally, game process is already running
    ──────────────────────────────────────────────────────
    Physical DRAM Layout (simplified):
    [0x00000000] OS Kernel code/data
    [0x10000000] Other processes
    [0x3F8A5000] ← Game code page (VA 0x7FF612340000 mapped here via CR3)
    [0x52100000] ← Game data page (HP/Gold resides here)
    [0x8A200000] ← Game heap memory
    ...

    Address translation: VA ──[CR3 Page Table]──> PA  (Single-layer)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

T1: User executes IOCTL_VMX_INIT, driver begins initialization
    ──────────────────────────────────────────────────────
    1. EptInitialize() / NptInitialize()
       Build EPT/NPT page tables in kernel memory
       These page tables themselves occupy ~10MB physical memory (PD pages + split pool)
       ★ But page table contents are identity-mapped, not affecting any existing data

    2. For each CPU core:
       VmxEnableOnCpu():
         CR4 |= VMXE          // Enable VMX operation
         VMXON                 // Enter VMX root mode
       VmxSetupVmcs():
         Guest CR3 = Current CR3  // ★ Guest page table is the existing page table, unchanged
         Guest RIP = Next Instruction // ★ Continue execution from current position
         Guest RSP = Current RSP
         EPTP = EPT page table address   // Insert EPT translation layer
         VMLAUNCH               // Current CPU enters Guest mode

    ★ After VMLAUNCH, all code on this CPU (including OS kernel and all processes)
      runs in VMX non-root (Guest) mode, but they are completely unaware!

    Physical DRAM layout: Completely unchanged!
    [0x3F8A5000] ← Still game code page, content identical
    [0x52100000] ← Still game data page, HP/Gold identical

    Address translation: VA ──[CR3 Page Table]──> GPA ──[EPT Identity Mapping]──> HPA=GPA  (Two layers, but equivalent to one)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

T2: Virtualization enabled, game continues running
    ──────────────────────────────────────────────────────
    Game code: MOV EAX, [HP Address]
      VA → CR3 Page Table → GPA 0x52100XXX → EPT → HPA 0x52100XXX → Read real HP
                                         │
                                    Identity mapping, completely transparent

    Windows memory management: Works normally, completely unaware of Hypervisor presence
      - Allocate new pages: Normal operation (EPT identity mapping covers all physical addresses)
      - Page swap out: Normal operation (modifies Guest CR3 page table, EPT unaffected)
      - Process creation: Normal operation

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

T3: User reads game memory via IOCTL_VMX_READ_MEMORY
    ──────────────────────────────────────────────────────
    Driver obtains game CR3, traverses the page table itself:
      Game VA → Traverse game CR3 → GPA 0x52100XXX
      MmMapIoSpace(0x52100XXX) → Directly read real data

    ★ During this process:
      - The game is unaware (no APIs in game address space called)
      - Anti-cheat drivers are unaware (no OpenProcess / ReadProcessMemory)
      - Windows is unaware (merely mapped the physical address)
```

### Why Windows and All Guest Software Are Completely Unaware

| Aspect | Why Unaware |
|------|-----------|
| **Guest page tables unmodified** | Guest CR3 in VMCS/VMCB = Real CR3; Windows memory management continues using its own page tables |
| **Physical memory unmoved** | EPT/NPT identity mapped, GPA==HPA, physical data remains untouched |
| **Instruction execution uninterrupted** | Guest RIP = Current RIP at VMLAUNCH, seamlessly continuing from the next instruction |
| **No time jumps** | TSC increments continuously; VMLAUNCH itself only takes a few hundred clock cycles |
| **Minimal performance impact** | EPT/NPT has hardware TLB caching (EPTP-tagged), so most accesses do not require a second-level traversal |
| **Newly allocated memory** | Automatically covered since identity mapping spans the entire 512GB physical space |

### EPT/NPT Performance Overhead

```
No Virtualization: VA -> CR3 (4-level traversal, ~4 memory accesses, 0 if TLB hits)
With Virtualization: VA -> CR3 (4 levels) × EPT (4 levels) = 24 memory accesses worst case
             However, with EPT TLB (VPID-tagged) cached, actual overhead is ~1-5%

Measured: After hypervisor is enabled, game frame rate drops are typically < 3%
     (VM-Exit handling is the primary overhead, not EPT traversal)
```

### Fundamental Difference from Traditional Virtual Machines

```
Traditional Virtual Machines (VirtualBox / VMware / Hyper-V):
  Create empty VM first -> Install OS -> Allocate virtual disk -> Physical memory is "borrowed" from the host
  Guest physical address space is fabricated, and EPT maps to real pages allocated by the host
  GPA ≠ HPA (Guest believes its PA is 0x0, which might actually reside at HPA 0x7000000000)

VMXToolbox (Blue Pill):
  OS is already running -> Insert a layer underneath it -> Identity mapping
  Guest physical address space IS the real physical address space
  GPA == HPA (one-to-one mapping across the entire 512GB)
  Guest never "moved into a VM"; it remains in place, simply with a transparent floor underneath
```

In summary: **VMXToolbox does not create a virtual environment, but rather turns reality into one — everything remains in place, while the CPU gains a layer of translation invisible to you.**

---

## Generic EPT/NPT Hook Framework

**File**: `hv_hook.h` + `hv_hook.c` + `hv_hook_asm.asm`

Leveraging the EPT/NPT page table permission splitting, it implements transparent hooking of any kernel or user-mode function. PatchGuard cannot detect this because the physical memory of kernel code pages is never modified.

### Core Features

| Feature | Description |
|------|------|
| Dynamic install/uninstall | Install and remove hooks at runtime via IOCTL |
| No quantity limit | Dynamically allocate Thunk pages, 170 hooks per page, growing on-demand |
| Hook by name | Pass in function name (e.g., `NtCreateFile`) to automatically resolve its address |
| Hook by address | Directly specify kernel or user-mode virtual addresses |
| PID filtering | Hooks can be global or only effective for specified processes |
| 4 actions | PASSTHROUGH (count), LOG (logging), BLOCK (interception), MODIFY_RETVAL (modify return value) |
| Event logs | 512-entry ring buffer, logging detailed info of each hook trigger |
| PatchGuard safe | EPT Execute-Only mechanism: reads see original code, executions run hook code |

### IOCTL Interface

| IOCTL | Function |
|-------|------|
| `IOCTL_VMX_INSTALL_HOOK` (0x809) | Install hook (input function name/address + rule, returns HookId) |
| `IOCTL_VMX_REMOVE_HOOK` (0x80A) | Remove hook (input HookId) |
| `IOCTL_VMX_LIST_HOOKS` (0x80B) | Query all active hooks and their hit counts |
| `IOCTL_VMX_GET_HOOK_EVENTS` (0x80C) | Read hook event logs |

### Usage Examples

**CLI Command Mode** (via VMXToolbox.exe):

```bash
# Hook NtCreateFile, log all calls
VMXToolbox.exe --install-hook NtCreateFile --action 1 --hook-log

# Block ObRegisterCallbacks for PID 1234, return ACCESS_DENIED
VMXToolbox.exe --install-hook ObRegisterCallbacks --action 2 --block-retval C0000022 --hook-pid 1234

# Modify NtClose return value to STATUS_SUCCESS
VMXToolbox.exe --install-hook NtClose --action 3 --new-retval 0

# Hook non-exported function by address
VMXToolbox.exe --install-hook-addr FFFFF80012345678 --action 1 --hook-log

# View hook list and events
VMXToolbox.exe --list-hooks
VMXToolbox.exe --hook-events

# Remove hook
VMXToolbox.exe --remove-hook 1
```

**C Code Mode** (directly calling IOCTL):

```c
// Hook NtCreateFile, log all calls
VMX_HOOK_REQUEST req = {0};
VMX_HOOK_RESPONSE resp = {0};
req.ByName = TRUE;
wcscpy(req.FunctionName, L"NtCreateFile");
req.Rule.Action = HOOK_ACTION_LOG_ONLY;
req.Rule.LogEnabled = TRUE;
DeviceIoControl(hDev, IOCTL_VMX_INSTALL_HOOK, &req, sizeof(req), &resp, sizeof(resp), &ret, NULL);

// Block ObRegisterCallbacks for PID 1234, return ACCESS_DENIED
req.ByName = TRUE;
wcscpy(req.FunctionName, L"ObRegisterCallbacks");
req.Rule.Action = HOOK_ACTION_BLOCK;
req.Rule.BlockReturnValue = 0xC0000022;  // STATUS_ACCESS_DENIED
req.Rule.TargetPid = 1234;
DeviceIoControl(hDev, IOCTL_VMX_INSTALL_HOOK, &req, sizeof(req), &resp, sizeof(resp), &ret, NULL);
```

> **Detailed Technical Document**: For the complete architectural design, ASM dispatcher flow, Thunk mechanism, `HOOK_DECISION` structure layout, etc., please refer to **[hook_framework.md](hook_framework.md)**

---

## SSDT Monitoring and Hook Framework

**File**: `ssdt.h` + `ssdt.c`

Provides complete discovery, parsing, name resolution, hooking by index/name, and full/filtered monitoring capabilities for Windows x64 SSDT (System Service Descriptor Table). All actual hooking operations completely reuse the existing `GenericHookInstall()` EPT/NPT framework.

### Design Rationale

The SSDT module acts as a **thin coordination layer**:

- **Discovery & Parsing**: Responsible for KiServiceTable localization, SSDT entry decoding, and Nt* function name resolution.
- **syscall index ↔ hookId Mapping**: Maintained via `SSDT_HOOK_MAPPING` linked list, tracking which syscalls are hooked.
- **Actual Hooking**: Fully delegated to `GenericHookInstall()` / `GenericHookRemove()` (with Thunk generation, EPT paging, decision logic, and event logging already in place).

### Two-Tier SSDT Discovery and Address Resolution

The trustworthiness of SSDT addresses directly determines the correctness of hooking targets. The framework employs a **two-tier strategy**, prioritizing unpolluted data from the disk:

#### Tier 1: Parsing from Disk-Mapped ntoskrnl.exe (Preferred)

```
SsdtGetNtoskrnlBase()
  → ZwQuerySystemInformation(SystemModuleInformation)
  → Obtain ntoskrnl load base address + disk path

SsdtMapNtoskrnlFromDisk()
  → ZwOpenFile(ntoskrnl.exe)
  → ZwCreateSection(SEC_IMAGE)    ← Critical: alignment-expanded as a PE section
  → ZwMapViewOfSection()          ← Map to kernel address space

SsdtDiscoverAndResolveFromDisk()
  → Traverse mapped PE export table, locate KeServiceDescriptorTable
  → Read .Base (unrelocated value = PreferredBase + TableRva)
  → TableRva = .Base - PreferredBase
  → Read .Limit → ServiceCount
  → Directly read LONG array from MapBase + TableRva
  → Relocate: FuncVA = NtoskrnlBase + TableRva + (entry >> 4)
```

**Why use SEC_IMAGE?**

| Comparison | ZwReadFile (Raw File) | ZwCreateSection(SEC_IMAGE) |
|--------|----------------------|----------------------------|
| Memory Layout | Raw file bytes (raw) | PE section-aligned expansion (virtual) |
| RVA Usage | Requires manual RVA -> file offset conversion | **RVA directly used as offset** |
| Memory Consumption | Requires allocating NonPagedPool matching full file size (~10MB) | On-demand paging |
| Helper Functions | Requires Section Header traversal | **Not required** |

**Why is obtaining from disk safer than from memory?**

- ntoskrnl.exe on disk is protected by Windows File Protection (WFP/WRP) and bears a Microsoft digital signature.
- Even if a rootkit tampers with the memory-resident KiServiceTable during the short window before PatchGuard activates, disk data remains the original Microsoft version.
- All read bytes originate from PE files validated via digital signature; zero memory data is trusted (the only memory value used is `NtoskrnlBase` from the trusted kernel API `ZwQuerySystemInformation`).

#### Tier 2: Resolving from Memory-Exported Symbols (Fallback)

```
SsdtDiscoverAndResolveFromMemory()
  → MmGetSystemRoutineAddress(L"KeServiceDescriptorTable")
  → Read .Base (relocated = real KiServiceTable VA) + .Limit
  → Directly read LONG entry array from memory KiServiceTable
  → FuncVA = KiServiceTableVa + (entry >> 4)
```

`KeServiceDescriptorTable` is an exported symbol of ntoskrnl across all x64 Windows versions, and the layout of the `KSERVICE_TABLE_DESCRIPTOR` structure has never changed. Under PatchGuard protection, the memory-resident table is equally reliable.

This approach is only used if the disk scheme fails (e.g., extreme situations in virtualized environments where the host file system cannot be accessed).

### SSDT Entry Format (x64)

```c
// KiServiceTable is a LONG array, with each entry encoded as:
LONG entry = KiServiceTable[index];

ULONG64 FunctionVA = KiServiceTableVA + (entry >> 4);   // Upper 28 bits = relative offset
ULONG   ArgCount   = entry & 0xF;                       // Lower 4 bits = argument count
```

### Name Resolution

By traversing the ntoskrnl PE export table in memory, addresses of exported functions with the `Nt*` prefix are matched to SSDT entry addresses:

```
SsdtPopulateNames()
  → Read ntoskrnl PE export directory
  → Traverse all Nt* exports (skip Zw* prefix)
  → Calculate FuncVA = NtoskrnlBase + FuncRva
  → Match within the ResolvedAddresses[] array
  → Match successful -> store in NameCache[index]
```

`SsdtFindIndexByName()` queries NameCache first, and falls back to matching the resolved address of `MmGetSystemRoutineAddress` upon a cache miss.

### Hooking Operations

SSDT Hooking completely reuses the existing `GenericHookInstall()` framework:

```
SsdtHookByIndex(Index, Rule)
  1. Check for duplicates (SSDT_HOOK_MAPPING linked list protected by spinlock)
  2. FuncVa = ResolvedAddresses[Index]
  3. Call GenericHookInstall(FuncVa, 0/*kernel*/, Name, Rule, &HookId)
     → Allocate Thunk -> EPT page isolation -> Installation complete
  4. Create SSDT_HOOK_MAPPING node to record Index ↔ HookId

SsdtHookByName(Name, Rule)
  → SsdtFindIndexByName(Name) → SsdtHookByIndex(Index)
```

Hook events are automatically logged via the existing 512-entry ring buffer, viewable with `--hook-events`.

### Monitoring Modes

| Mode | Description |
|------|------|
| `SSDT_MONITOR_OFF` | Stop monitoring, remove all monitoring hooks |
| `SSDT_MONITOR_ALL` | Install LOG_ONLY hooks for all ~460 syscalls |
| `SSDT_MONITOR_FILTERED` | Install hooks only for a specified list of syscall indices |

Monitoring hooks are flagged as `IsMonitorHook=TRUE`. `SsdtStopMonitoring()` only removes hooks created for monitoring, not affecting manually-installed SSDT hooks.

### Lifecycle

```
SsdtInitialize()
  → Read LSTAR (diagnostic info)
  → SsdtGetNtoskrnlBase() (Obtain load base + disk path)
  → Tier 1: SsdtMapNtoskrnlFromDisk() + SsdtDiscoverAndResolveFromDisk() + SsdtUnmapFileImage()
  → Failure -> Tier 2: SsdtDiscoverAndResolveFromMemory()
  → SsdtPopulateNames() (Name resolution, best-effort)
  → Initialized = TRUE

SsdtCleanup()       [Called in DriverUnload before GenericHookCleanup]
  → SsdtStopMonitoring()
  → SsdtUnhookAll()
  → SsdtUnmapFileImage()
```

---

## Shadow SSDT (Win32k) Monitoring and Hook Framework

**File**: `shadow_ssdt.h` + `shadow_ssdt.c`

Extends the SSDT module architecture to **Win32k Shadow SSDT** (`W32pServiceTable`), covering `NtUser*`/`NtGdi*` system calls. Shadow SSDT entry formats are identical to normal SSDT entries (LONG array, `entry >> 4` yields the offset), and the EPT Hook mechanism is fully compatible.

### Core Challenges and Solutions

| Challenge | Solution |
|------|---------|
| `KeServiceDescriptorTableShadow` not exported | Obtained indirectly from KTHREAD.ServiceTable |
| `KTHREAD.ServiceTable` offset changes across Windows versions | Dynamically discovered via QWORD scanning of System process threads |
| win32k.sys is per-Session mapped | Use `KeStackAttachProcess` to attach to GUI process context |
| Win10+ splits win32k into three modules | Enumerate all win32k* modules, traverse multiple export tables to resolve names |

### KTHREAD.ServiceTable Offset Dynamic Discovery

```
KthreadResolveServiceTableOffset()
  1. Obtain KeServiceDescriptorTable address (MmGetSystemRoutineAddress)
  2. Enumerate threads of PID=4 (System) -> KTHREAD*
     (System threads never initialize win32k; ServiceTable must point to KeServiceDescriptorTable)
  3. QWORD scan the first 0x400 bytes of KTHREAD:
     for (Offset = 0; Offset < 0x400; Offset += 8)
         if (*(QWORD*)(KTHREAD + Offset) == KeServiceDescriptorTable)
             → Candidate = Offset
  4. Cross-validate the same offset with a second System thread
```

### KeServiceDescriptorTableShadow Acquisition

```
ShadowSsdtDiscover()
  1. Enumerate all threads of all processes:
     for each Thread:
         Value = *(QWORD*)(Thread + ServiceTableOffset)
         if (Value != KeServiceDescriptorTable && IsKernelAddress(Value)):
             ShadowCandidate = Value, GuiPid = this process's PID
             break
  2. Triple validation:
     - Shadow[0].Base == KeServiceDescriptorTable[0].Base
     - Shadow[0].Limit == KeServiceDescriptorTable[0].Limit
     - Shadow[1].Limit ∈ (0, SHADOW_SSDT_MAX_SERVICES)
  3. PsLookupProcessByProcessId(GuiPid) -> Hold reference for subsequent Attach
```

### Win32k Module Discovery & Name Resolution

```
ShadowSsdtGetWin32kModules()
  → ZwQuerySystemInformation(SystemModuleInformation)
  → Match module filenames containing "win32k" (supports win32kbase/win32kfull/win32k)

ShadowSsdtPopulateNames()
  → KeStackAttachProcess(GuiProcess)
  → for each win32k module:
      Traverse PE export tables, match NtUser*/NtGdi* names
      Match with VA in ResolvedAddresses[] -> NameCache[index]
  → KeUnstackDetachProcess()
```

### Shadow SSDT Entry Resolution

```
ShadowSsdtResolveAllAddresses()
  → KeStackAttachProcess(GuiProcess)
  → Table = (PLONG)W32pServiceTableVa
  → for (i = 0; i < ServiceCount; i++):
        FuncVa = W32pServiceTableVa + (Table[i] >> 4)
        ResolvedAddresses[i] = FuncVa
  → KeUnstackDetachProcess()
```

### Hooking Operations

Hooking must be executed in the GUI process context to ensure valid win32k VA->PA mappings:

```c
ShadowSsdtHookByIndex(Index, Rule, &HookId)
  → Check duplicates (spinlock)
  → FuncVa = ResolvedAddresses[Index]
  → KeStackAttachProcess(GuiProcess)
  → GenericHookInstall(FuncVa, 0, Name, Rule, &HookId)
  → KeUnstackDetachProcess()
  → Create SSDT_HOOK_MAPPING node
```

### Lifecycle

```
ShadowSsdtInitialize()    [Requires SSDT module initialized first]
  → KthreadResolveServiceTableOffset()
  → ShadowSsdtDiscover()
  → ShadowSsdtGetWin32kModules()
  → ShadowSsdtResolveAllAddresses()
  → ShadowSsdtPopulateNames()
  → Initialized = TRUE

ShadowSsdtCleanup()       [Called in DriverUnload before SsdtCleanup]
  → ShadowSsdtStopMonitoring()
  → ShadowSsdtUnhookAll()
  → ObDereferenceObject(GuiProcess)
```

---

## Anti-Anti-Debugging Capability Inventory

| Priority | Detection Method | Interception Method | Feature Flag |
|--------|---------|---------|---------|
| **P0** | `IsDebuggerPresent` / PEB.BeingDebugged | EPT Hook NtQueryInformationProcess | `AAD_HIDE_DEBUGGER` |
| **P0** | `CheckRemoteDebuggerPresent` | Same as above (calls NtQueryInformationProcess underneath) | `AAD_HIDE_DEBUGGER` |
| **P0** | `NtQueryInformationProcess` (DebugPort/DebugObjectHandle/DebugFlags) | EPT Hook | `AAD_HIDE_DEBUGGER` |
| **P0** | DR0-DR7 hardware breakpoint detection | MOV-DR Exiting + returns spoofed values | `AAD_HIDE_HWBP` |
| **P0** | RDTSC/RDTSCP timing difference detection | RDTSC Exiting + TSC Offset compensation | `AAD_HIDE_TIMING` |
| **P1** | CPUID Hypervisor detection (ECX[31]) | CPUID unconditional Exit + clear bit | `AAD_HIDE_CPUID` |
| **P1** | `NtQuerySystemInformation` (KernelDebugger) | EPT Hook | `AAD_HIDE_SYSINFO` |
| **P1** | INT 2D / INT 3 exception behavior discrepancy | Exception Bitmap + standardized injection | `AAD_HIDE_EXCEPTIONS` |
| **P2** | `NtClose` invalid handle exception | EPT Hook + exception suppression | `AAD_HIDE_NTCLOSE` |
| **P2** | `NtSetInformationThread` (ThreadHideFromDebugger) | EPT Hook + blocking | `AAD_HIDE_THREADINFO` |

---

## User-Mode Controller

**File**: `client/main.c` + `client/driver_comm.c`

All features are controlled through a single `VMXToolbox.exe` CLI tool.

### Anti-Anti-Debugging Commands

```
VMXToolbox.exe --pid <PID> [options]      Set target process
VMXToolbox.exe --pid <PID> --remove      Remove target process
VMXToolbox.exe --status                  Query VMX status
VMXToolbox.exe --stop                    Stop VMX engine
VMXToolbox.exe --log                     Display interception log
```

Hiding options:

```
--hide-debugger     Hide debugger presence (PEB, NtQuery*)
--hide-hwbp         Hide hardware breakpoints (DR0-DR7)
--hide-timing       Counter timing detection (RDTSC compensation)
--hide-cpuid        Hide Hypervisor (CPUID)
--hide-sysinfo      Spoof system info (KernelDebugger)
--hide-exceptions   Standardize exception behavior (INT 2D/3)
--hide-ntclose      Suppress NtClose exception
--hide-threadinfo   Block ThreadHideFromDebugger
--hide-all          Enable all of the above
```

### Hook Framework Commands

```
VMXToolbox.exe --install-hook <name>         Hook kernel function by export name
VMXToolbox.exe --install-hook-addr <hex>     Hook function by virtual address
VMXToolbox.exe --remove-hook <id>            Remove hook by ID
VMXToolbox.exe --list-hooks                  List all active hooks
VMXToolbox.exe --hook-events                 Display hook event logs
```

Hook options (used with `--install-hook` / `--install-hook-addr`):

```
--action <0-3>       Hook action: 0=passthrough count, 1=log, 2=block, 3=modify return value
--hook-pid <PID>     PID filter (0=global, default=0)
--block-retval <hex> Return value when blocked (action=2)
--new-retval <hex>   Modified return value (action=3)
--hook-log           Enable event logging
```

### Memory Read/Write Commands

```
VMXToolbox.exe --read-mem <PID> <addr> [size]   Read target process memory (default 64 bytes)
VMXToolbox.exe --write-mem <PID> <addr> <hex>   Write hex bytes to target process
VMXToolbox.exe --dump-mem <PID> <addr> <size>   Hex+ASCII large block memory dump
### SSDT Commands

```
VMXToolbox.exe --ssdt-unhook-all                    Remove all SSDT hooks
VMXToolbox.exe --ssdt-list                          List active SSDT hooks
VMXToolbox.exe --ssdt-monitor <off|all|filtered>    Set SSDT monitoring mode
VMXToolbox.exe --ssdt-filter <idx1,idx2,...>        Specify monitored syscall index list
```

### Shadow SSDT Commands

```
VMXToolbox.exe --shadow-ssdt-init                          Initialize Shadow SSDT discovery
VMXToolbox.exe --shadow-ssdt-dump [start] [count]          Dump Shadow SSDT table entries
VMXToolbox.exe --shadow-ssdt-hook <index|NtUserName>       Hook Shadow SSDT function (used with --action, --hook-pid, etc.)
VMXToolbox.exe --shadow-ssdt-unhook <index|hookid:N>       Remove hook by index or hookid:N
VMXToolbox.exe --shadow-ssdt-unhook-all                    Remove all Shadow SSDT hooks
VMXToolbox.exe --shadow-ssdt-list                          List active Shadow SSDT hook
VMXToolbox.exe --shadow-ssdt-monitor <off|all|filtered>    Set Shadow SSDT monitoring mode
VMXToolbox.exe --shadow-ssdt-filter <idx1,idx2,...>        Specify monitored Shadow SSDT index list
```

### Typical Use Cases

```bash
# ===================== Anti-Anti-Debugging =====================

# 1. Enable all anti-anti-debugging features for PID 1234
VMXToolbox.exe --pid 1234 --hide-all

# 2. Hide debugger and hardware breakpoints only
VMXToolbox.exe --pid 1234 --hide-debugger --hide-hwbp

# 3. View VMX status
VMXToolbox.exe --status

# 4. View interception logs
VMXToolbox.exe --log

# 5. Remove protection
VMXToolbox.exe --pid 1234 --remove

# ===================== Kernel Hooking =====================

# 6. Monitor NtOpenProcess calls (global, logged)
VMXToolbox.exe --install-hook NtOpenProcess --action 1 --hook-log

# 7. Block NtQuerySystemInformation, return STATUS_ACCESS_DENIED
VMXToolbox.exe --install-hook NtQuerySystemInformation --action 2 --block-retval C0000022

# 8. Modify NtClose return value to STATUS_SUCCESS, for PID 1234 only
VMXToolbox.exe --install-hook NtClose --action 3 --new-retval 0 --hook-pid 1234

# 9. Install hook by address
VMXToolbox.exe --install-hook-addr FFFFF80012345678 --action 1 --hook-log


# 10. View active hook list / event log
VMXToolbox.exe --list-hooks
VMXToolbox.exe --hook-events

# 11. Remove hook
VMXToolbox.exe --remove-hook 1

# ===================== Memory Read/Write =====================

# 12. Read target process PE header (default 64 bytes)
VMXToolbox.exe --read-mem 1234 7FF600000000

# 13. Read 128 bytes
VMXToolbox.exe --read-mem 1234 7FF600000000 128

# 14. Write NOP sled + automatic verification
VMXToolbox.exe --write-mem 1234 7FF600001000 90909090

# 15. Write INT3 breakpoint
VMXToolbox.exe --write-mem 1234 7FF600001000 CC

# 16. Large block memory dump (256 bytes)
VMXToolbox.exe --dump-mem 1234 7FF600000000 256

# 17. Read kernel memory (System process PID=4)
VMXToolbox.exe --read-mem 4 FFFFF78000000000 64

# ===================== General =====================

# 18. Stop VMX engine
VMXToolbox.exe --stop

# ===================== SSDT Monitoring =====================

# 19. Initialize SSDT discovery
VMXToolbox.exe --ssdt-init

# 20. Dump the first 20 SSDT entries
VMXToolbox.exe --ssdt-dump 0 20

# 21. Hook SSDT by function name (logging only)
VMXToolbox.exe --ssdt-hook NtOpenProcess --action 1 --hook-log

# 22. Hook SSDT by syscall index (block, return STATUS_ACCESS_DENIED)
VMXToolbox.exe --ssdt-hook 38 --action 2 --block-retval 0xC0000022

# 23. View SSDT Hook events (reuses existing --hook-events)
VMXToolbox.exe --hook-events

# 24. List active SSDT hooks
VMXToolbox.exe --ssdt-list

# 25. Monitor all syscalls (only for PID 1234)
VMXToolbox.exe --ssdt-monitor all --hook-pid 1234

# 26. Filtered monitoring of specific syscall indices
VMXToolbox.exe --ssdt-monitor filtered --ssdt-filter 35,38,55 --hook-pid 1234

# 27. Stop monitoring
VMXToolbox.exe --ssdt-monitor off

# 28. Remove hook by syscall index
VMXToolbox.exe --ssdt-unhook 38

# 29. Remove hook by hookId
VMXToolbox.exe --ssdt-unhook hookid:5

# 30. Remove all SSDT hooks
VMXToolbox.exe --ssdt-unhook-all

# ===================== Shadow SSDT (Win32k) Monitoring =====================

# 31. Initialize Shadow SSDT discovery (requires --ssdt-init first)
VMXToolbox.exe --shadow-ssdt-init

# 32. Dump the first 20 Shadow SSDT entries
VMXToolbox.exe --shadow-ssdt-dump 0 20

# 33. Hook NtUserGetForegroundWindow by function name (logging only)
VMXToolbox.exe --shadow-ssdt-hook NtUserGetForegroundWindow --action 1 --hook-log

# 34. Hook Shadow SSDT function by index (block, return NULL)
VMXToolbox.exe --shadow-ssdt-hook 10 --action 2 --block-retval 0

# 35. View Shadow SSDT Hook events (reuses existing --hook-events)
VMXToolbox.exe --hook-events

# 36. List active Shadow SSDT hooks
VMXToolbox.exe --shadow-ssdt-list

# 37. Monitor all Win32k syscalls (only for PID 1234)
VMXToolbox.exe --shadow-ssdt-monitor all --hook-pid 1234

# 38. Filtered monitoring of specific Shadow SSDT indices
VMXToolbox.exe --shadow-ssdt-monitor filtered --shadow-ssdt-filter 10,20,30 --hook-pid 1234

# 39. Stop Shadow SSDT monitoring
VMXToolbox.exe --shadow-ssdt-monitor off

# 40. Remove all Shadow SSDT hooks
VMXToolbox.exe --shadow-ssdt-unhook-all

## Driver and User-Mode Communication Protocol

Communication is established via `DeviceIoControl` using custom IOCTL codes:

| IOCTL | Direction | Input Structure | Output Structure | Functionality |
|-------|-----------|-----------------|------------------|---------------|
| `IOCTL_VMX_INIT` (0x800) | -> | None | None | Initialize VMX |
| `IOCTL_VMX_SET_TARGET` (0x801) | -> | `VMX_TARGET_INFO` (PID+Flags) | None | Add target process |
| `IOCTL_VMX_REMOVE_TARGET` (0x802) | -> | `VMX_REMOVE_TARGET` (PID) | None | Remove target process |
| `IOCTL_VMX_SET_CONFIG` (0x803) | -> | `VMX_CONFIG_INFO` (PID+Flags) | None | Update configuration |
| `IOCTL_VMX_GET_LOG` (0x804) | <- | None | `VMX_LOG_BUFFER` | Read logs |
| `IOCTL_VMX_STOP` (0x805) | -> | None | None | Stop VMX |
| `IOCTL_VMX_QUERY_STATUS` (0x806) | <- | None | `VMX_STATUS` | Query status |
| `IOCTL_VMX_READ_MEMORY` (0x807) | <-> | `VMX_MEMORY_REQUEST` (PID+VA+Size) | Raw bytes | Read target process memory (direct physical access) |
| `IOCTL_VMX_WRITE_MEMORY` (0x808) | -> | `VMX_MEMORY_REQUEST` + payload | None | Write target process memory (direct physical access) |
| `IOCTL_VMX_INSTALL_HOOK` (0x809) | <-> | `VMX_HOOK_REQUEST` (Name/Addr+Rule) | `VMX_HOOK_RESPONSE` (HookId) | Install Hook |
| `IOCTL_VMX_REMOVE_HOOK` (0x80A) | -> | `VMX_UNHOOK_REQUEST` (HookId) | None | Remove Hook |
| `IOCTL_VMX_LIST_HOOKS` (0x80B) | <- | None | `VMX_HOOK_LIST` | Query all active hooks |
| `IOCTL_VMX_GET_HOOK_EVENTS` (0x80C) | <- | None | `VMX_HOOK_EVENT_BUFFER` | Read Hook event logs |
| `IOCTL_VMX_SSDT_INIT` (0x80D) | <- | None | `VMX_SSDT_INIT_RESPONSE` | Initialize SSDT discovery |
| `IOCTL_VMX_SSDT_DUMP` (0x80E) | <-> | `VMX_SSDT_DUMP_REQUEST` (Start+Count) | `VMX_SSDT_DUMP_RESPONSE` | Dump SSDT entries |
| `IOCTL_VMX_SSDT_HOOK` (0x80F) | <-> | `VMX_SSDT_HOOK_REQUEST` (Index/Name+Rule) | `VMX_SSDT_HOOK_RESPONSE` | Hook SSDT function |
| `IOCTL_VMX_SSDT_UNHOOK` (0x810) | -> | `VMX_SSDT_UNHOOK_REQUEST` (HookId/Index) | None | Remove SSDT Hook |
| `IOCTL_VMX_SSDT_UNHOOK_ALL` (0x811) | -> | None | None | Remove all SSDT Hooks |
| `IOCTL_VMX_SSDT_LIST_HOOKS` (0x812) | <- | None | `VMX_SSDT_HOOK_LIST` | Query active SSDT Hooks |
| `IOCTL_VMX_SSDT_MONITOR` (0x813) | -> | `VMX_SSDT_MONITOR_REQUEST` (Mode+PID+Filter) | None | Set SSDT monitoring mode |
| `IOCTL_VMX_SHADOW_SSDT_INIT` (0x814) | <- | None | `VMX_SHADOW_SSDT_INIT_RESPONSE` | Initialize Shadow SSDT discovery |
| `IOCTL_VMX_SHADOW_SSDT_DUMP` (0x815) | <-> | `VMX_SHADOW_SSDT_DUMP_REQUEST` (Start+Count) | `VMX_SHADOW_SSDT_DUMP_RESPONSE` | Dump Shadow SSDT entries |
| `IOCTL_VMX_SHADOW_SSDT_HOOK` (0x816) | <-> | `VMX_SHADOW_SSDT_HOOK_REQUEST` (Index/Name+Rule) | `VMX_SHADOW_SSDT_HOOK_RESPONSE` | Hook Shadow SSDT function |
| `IOCTL_VMX_SHADOW_SSDT_UNHOOK` (0x817) | -> | `VMX_SHADOW_SSDT_UNHOOK_REQUEST` (HookId/Index) | None | Remove Shadow SSDT Hook |
| `IOCTL_VMX_SHADOW_SSDT_UNHOOK_ALL` (0x818) | -> | None | None | Remove all Shadow SSDT Hooks |
| `IOCTL_VMX_SHADOW_SSDT_LIST_HOOKS` (0x819) | <- | None | `VMX_SHADOW_SSDT_HOOK_LIST` | Query active Shadow SSDT Hooks |
| `IOCTL_VMX_SHADOW_SSDT_MONITOR` (0x81A) | -> | `VMX_SHADOW_SSDT_MONITOR_REQUEST` (Mode+PID+Filter) | None | Set Shadow SSDT monitoring mode |

### Key Data Structures

```c
// Add target process
typedef struct _VMX_TARGET_INFO {
    ULONG   Pid;     // Process ID
    ULONG   Flags;   // AAD_HIDE_* bitmask
} VMX_TARGET_INFO;

// Query status
typedef struct _VMX_STATUS {
    BOOLEAN VmxActive;       // Whether VMX is running
    ULONG   ActiveTargets;   // Number of protected processes
    ULONG   TotalExits;      // Cumulative VM-Exit count
    ULONG   CpuCount;        // Number of virtualized CPUs
} VMX_STATUS;

// Log entry
typedef struct _VMX_LOG_ENTRY {
    ULONG       Level;       // 0=Error, 1=Warn, 2=Info, 3=Debug
    ULONG       Pid;         // Source Process ID
    LARGE_INTEGER Timestamp; // Kernel timestamp
    CHAR        Message[256];
} VMX_LOG_ENTRY;

// Memory read/write request
typedef struct _VMX_MEMORY_REQUEST {
    ULONG       Pid;             // Target Process ID
    ULONG       Size;            // Byte count (max 64KB)
    ULONG64     VirtualAddress;  // Target virtual address
} VMX_MEMORY_REQUEST;

// Hook rule
typedef struct _HOOK_RULE {
    ULONG       Action;             // 0=Passthrough, 1=Log, 2=Block, 3=Modify Return Value
    ULONG       TargetPid;          // 0=Global, >0=Specific PID
    ULONG64     BlockReturnValue;   // Return value when blocked
    ULONG64     NewReturnValue;     // Modified return value
    BOOLEAN     LogEnabled;         // Whether to write event logs
} HOOK_RULE;

// Install Hook request
typedef struct _VMX_HOOK_REQUEST {
    BOOLEAN     ByName;             // TRUE=By Name, FALSE=By Address
    WCHAR       FunctionName[128];  // Kernel export name
    ULONG64     TargetAddress;      // Direct virtual address
    ULONG       ProcessId;          // 0=Kernel Hook
    HOOK_RULE   Rule;
} VMX_HOOK_REQUEST;

// Hook event log
typedef struct _HOOK_EVENT {
    ULONG       HookId;             // Triggered Hook ID
    ULONG       ProcessId;          // Caller Process ID
    ULONG64     Timestamp;          // Kernel timestamp
    ULONG64     ReturnAddress;      // Caller return address
    ULONG64     FinalRetVal;        // Final return value
    ULONG       ActionTaken;        // Action executed
} HOOK_EVENT;

// SSDT entry info
typedef struct _SSDT_ENTRY_INFO {
    ULONG       SyscallIndex;       // Syscall number
    ULONG       ArgCount;           // Argument count (entry & 0xF)
    LONG        RawOffset;          // SSDT table raw entry
    ULONG64     FunctionVa;         // Resolved function virtual address
    WCHAR       FunctionName[128];  // Nt* function name (can be empty)
} SSDT_ENTRY_INFO;

// SSDT Hook request
typedef struct _VMX_SSDT_HOOK_REQUEST {
    BOOLEAN     ByName;             // TRUE=By Name, FALSE=By Index
    ULONG       SyscallIndex;       // Used when ByName=FALSE
    WCHAR       FunctionName[128];  // Used when ByName=TRUE
    HOOK_RULE   Rule;               // Reuses existing HOOK_RULE
} VMX_SSDT_HOOK_REQUEST;

// SSDT monitor request
typedef struct _VMX_SSDT_MONITOR_REQUEST {
    ULONG       Mode;               // SSDT_MONITOR_OFF/ALL/FILTERED
    ULONG       TargetPid;          // 0=Global
    ULONG       FilterCount;        // Number of valid FilterIndices
    ULONG       FilterIndices[64];  // Syscall index list under FILTERED mode
} VMX_SSDT_MONITOR_REQUEST;
```

---

## Data Flow Analysis

### Initialization Flow

```
User: VMXToolbox.exe --pid 1234 --hide-all
  |
  v
DriverOpen() -> CreateFile("\\\\.\\VmxDbg")
  |
  v
DriverInitVmx() -> IOCTL_VMX_INIT
  |
  v
[Kernel] HandleIoctlInit()
  +-- VmxInitialize()
       +-- VmxCheckCapabilities()     // Read capability MSRs
       +-- VmxAllocateCpuContext() x N // Allocate memory
       +-- EptInitialize()            // Construct EPT Identity Mapping
  |
  v
DriverSetTarget(1234, AAD_HIDE_ALL) -> IOCTL_VMX_SET_TARGET
  |
  v
[Kernel] HandleIoctlSetTarget()
  +-- ProcessAddTarget(1234, 0xFFFFFFFF)
       +-- GetProcessCr3(1234)        // PsLookupProcessByProcessId
       |    +-- Read EPROCESS + dynamic offset
       +-- Store in TARGET_PROCESS array
```

### VM-Exit Processing Flow (CPUID as an example)

```
[Guest] Target process executes CPUID instruction
  |
  v
[CPU] VM-Exit (reason = EXIT_REASON_CPUID)
  |
  v
[Host] AsmVmxExitHandler
  +-- Save 16 general-purpose registers
  +-- call VmxExitHandler(PGUEST_CONTEXT)
       |
       +-- HandleCpuid() -> AadHandleCpuid()
            +-- GuestCr3 = VmxRead(VMCS_GUEST_CR3)
            +-- __cpuidex(CpuInfo, Leaf, SubLeaf)  // Execute real CPUID
            +-- IsFeatureEnabled(GuestCr3, AAD_HIDE_CPUID)?
            |     +-- ProcessFindByCr3(GuestCr3)
            |     +-- Check Flags & AAD_HIDE_CPUID
            +-- if Leaf == 1:
            |     CpuInfo[ECX] &= ~(1 << 31)  // Clear Hypervisor Present bit
            +-- if Leaf == 0x40000000~0x400000FF:
            |     CpuInfo = {0, 0, 0, 0}       // Return all zeros
            +-- GuestContext->RAX/RBX/RCX/RDX = CpuInfo
            +-- VmxAdvanceGuestRip()
            +-- return TRUE
  |
  +-- Restore general-purpose registers
  +-- VMRESUME -> Guest continues execution
```

### EPT Hook Data Flow (NtQueryInformationProcess as an example)

```
[Guest] Target process calls NtQueryInformationProcess
  |
  v
[CPU] Executes at ntoskrnl!NtQueryInformationProcess address
  |
  v
[EPT] PTE = Execute-Only, PhysAddr = Hook Page
  -> Execute JMP instruction on Hook Page
  |
  v
[Host] HookNtQueryInformationProcess()
  +-- Call Trampoline (original function)
  |     +-- Execute original 14 bytes
  |     +-- JMP to NtQueryInformationProcess + 14
  |     +-- Original function executes normally and returns
  +-- CurrentCr3 = __readcr3()
  +-- Target = ProcessFindByCr3(CurrentCr3)
  +-- if Target && AAD_HIDE_DEBUGGER:
  |     switch (InformationClass):
  |       ProcessDebugPort:       *Output = 0
  |       ProcessDebugObjectHandle: return STATUS_PORT_NOT_SET
  |       ProcessDebugFlags:      *Output = 1
  +-- return Status
  |
  v
[Guest] Target process receives "not debugged" result

---

If the anti-debugging code reads the NtQueryInformationProcess function bytes for integrity check:

[Guest] MOV RAX, [NtQueryInformationProcess]   // Read function bytes
  |
  v
[EPT] PTE = Execute-Only, read triggers EPT Violation
  |
  v
[Host] HandleEptViolation()
  +-- PTE -> Read=1, Write=1, Execute=0, PhysAddr=Original Page
  +-- Enable MTF
  +-- Return (do not advance RIP, re-execute read instruction)
  |
  v
[Guest] Reads original unmodified function bytes (integrity check passes!)
  |
  v
[CPU] MTF VM-Exit (single-step completed)
  |
  v
[Host] HandleMtf()
  +-- PTE -> Read=0, Write=0, Execute=1, PhysAddr=Hook Page
  +-- Disable MTF
  +-- INVEPT
```

### Memory Read/Write Data Flow (Bypassing Anti-Cheat)

```
[User Mode] DeviceIoControl(IOCTL_VMX_READ_MEMORY, {Pid=1234, VA=0x7FF6xxx, Size=4096})
  |
  v
[Kernel Driver] HandleIoctlReadMemory()
  |
  +-- ResolvePidToCr3(1234)
  |     +-- PsLookupProcessByProcessId()
  |     +-- Read EPROCESS[DirectoryTableBase]
  |     +-- Get TargetCr3 = 0x1A3000
  |
  +-- KernelCopyProcessMemory(TargetCr3, 0x7FF6xxx, buffer, 4096, READ)
       |
       +-- while (remaining bytes to process):
            |
            +-- KernelGuestVaToPa(0x1A3000, currentVA)
            |     |
            |     +-- MmMapIoSpace(CR3 Base)  → Read PML4E
            |     +-- MmMapIoSpace(PML4E points to) → Read PDPTE
            |     +-- MmMapIoSpace(PDPTE points to) → Read PDE
            |     +-- MmMapIoSpace(PDE points to)   → Read PTE
            |     +-- Get physical address = 0x3F8A5000
            |
            +-- MmMapIoSpace(0x3F8A5000, 4096)
            +-- RtlCopyMemory(buffer, mappedAddress + offset, chunkSize)
            +-- MmUnmapIoSpace()

  *** No calls to: OpenProcess / NtReadVirtualMemory / KeStackAttachProcess ***
  *** Anti-cheat driver ObCallbacks / SSDT Hook / Call Stack Check are all completely bypassed ***
```

The write flow is completely symmetrical, only the direction of `RtlCopyMemory` is reversed.

---

## Module Dependency Relationship

```
vmxdrv.c (Driver Entry)
+-- hv_ops.h (Abstraction Layer Interface)
+-- hv_detect.h/c (CPU Vendor Detection + VMX/SVM Capability Probing)
+-- hv_mem.h/c (Physical Memory Read/Write Engine, Guest Page Table Walk)
+-- hv_hook.h/c (General Hook Framework, Dynamic Thunk, Rule Engine)
|   +-- hv_hook_asm.asm (ASM dispatcher)
+-- log.h/c (Logging)
+-- process.h/c (Process Tracking)
+-- vmx.h + vmx_init.c (Intel VMX Backend)
|   +-- ept.h/c (EPT)
|   +-- vmx_asm.asm (VMLAUNCH)
+-- svm.h + svm_init.c (AMD SVM Backend)
|   +-- npt.h/c (NPT)
|   +-- svm_asm.asm (VMRUN)
+-- vmx_exit.c (Intel Exit Dispatcher)
+-- svm_exit.c (AMD Exit Dispatcher)
|   +-- hv_mem.h/c (VMCALL Memory Operation Handling)
|   +-- anti_anti_debug.h/c (Anti-Anti-Debugging, Shared between Dual Platforms)
|   |   +-- hv_ops macros (HvReadGuestCr3, HvAdvanceGuestRip, ...)
|   |   +-- process.h/c (Process Lookup)
|   +-- msr.c (MSR Handling, via hv_ops)
+-- shared.h (IOCTL Definitions)

client/main.c (User-Mode CLI)
+-- driver_comm.h/c (Driver Communication)
+-- shared.h (Shared Definitions)
```

---

## Compilation and Deployment

### Compilation Environment

- **WDK**: GRMWDK_EN_7600_1.ISO (Windows DDK 7600.16385.1)
- **Installation Path**: `C:\WinDDK\7600.16385.1` (Default path, hardcoded in `do_build.bat`)
- **Target**: x64 Checked Build, Windows 7 Target
- **No Extra Config Required**: The `do_build.bat` script self-contains complete WDK environment variables setup. No need to run it inside the WDK Build Environment command prompt.

### Compilation Method

**Method 1: One-Click Build using do_build.bat (Recommended)**

`scripts\do_build.bat` is a self-contained build script that fully configures all WDK 7600 environment variables (Include / Lib / PATH / Build Target, etc.). You can run it directly from any command prompt:

```cmd
:: Run directly (no need to open WDK Build Environment)
<Project Root>\scripts\do_build.bat
```

The script automatically performs the following steps:

1. Configures WDK 7600 build environment (`BASEDIR=C:\WinDDK\7600.16385.1`)
2. Sets target platform to AMD64, Checked Build, and Win7 Target
3. Configures Include paths (`inc\api` + `inc\crt` + `inc\ddk`)
4. Configures Lib paths (`lib\win7\amd64`)
5. Configures compiler paths (`bin\x86\amd64` cross-compilation toolchain)
6. Changes directory to the project root
7. Executes `build.exe -cZg` (-c for clean build, -Z to stop on errors, -g for colorized output)

Expected compilation output:

```
BUILD: Compile and Link for AMD64
BUILD: Examining <Project Root> directory tree for files to compile.
    <Project Root>
    <Project Root>\driver
    <Project Root>\client
BUILD: Compiling <Project Root>\driver directory
Compiling - driver\vmxdrv.c
Compiling - driver\vmx_init.c
...
Assembling - driver\vmx_asm.asm
Assembling - driver\svm_asm.asm
Assembling - driver\hv_hook_asm.asm
BUILD: Linking for <Project Root>\driver directory
Linking Executable - driver\...\VMXToolboxDrv.sys
BUILD: Compiling and Linking <Project Root>\client directory
Compiling - client\main.c
Compiling - client\driver_comm.c
Linking Executable - client\...\VMXToolbox.exe
BUILD: Done

    23 files compiled
    2 executables built
```

> **Note**: If your WDK installation path is not the default `C:\WinDDK\7600.16385.1`, you need to modify the `BASEDIR` variable on line 6 of `do_build.bat`.

**Method 2: Manual Build via WDK Build Environment**

```cmd
:: Open WDK Build Environment
C:\Windows\System32\cmd.exe /k C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1\ chk x64 WIN7

:: Switch to project directory
cd /d <Project Root>

:: Build
build -cZg
```

### Build Outputs

| File | Path |
|------|------|
| VMXToolboxDrv.sys | `driver\objchk_win7_amd64\amd64\VMXToolboxDrv.sys` |
| VMXToolbox.exe | `client\objchk_win7_amd64\amd64\VMXToolbox.exe` |

### Deployment Steps

```cmd
:: 1. Enable Test Signing (Requires Administrator privilege, requires reboot)
bcdedit /set testsigning on

:: 2. Load Driver
sc create VMXToolboxDrv type=kernel binPath="<Project Root>\driver\objchk_win7_amd64\amd64\VMXToolboxDrv.sys"
sc start VMXToolboxDrv

:: 3. Use Control Utility
VMXToolbox.exe --pid <TARGET_PID> --hide-all
VMXToolbox.exe --install-hook NtOpenProcess --action 1 --hook-log
VMXToolbox.exe --read-mem <TARGET_PID> 7FF600000000 64

:: 4. Unload Driver
sc stop VMXToolboxDrv
sc delete VMXToolboxDrv
```

---

## Future Roadmap

As an extensible low-level capabilities platform based on VMX/SVM, this project will continuously add more features:

| Direction | Feature | Status |
|-----------|---------|--------|
| Anti-Anti-Debugging | Comprehensive anti-detection suite for PEB/NtQuery/DR/RDTSC/CPUID, etc. | ✅ Completed |
| Kernel Hooking | Generic EPT/NPT hook framework bypassing PatchGuard | ✅ Completed |
| Memory R/W | Direct physical memory access bypassing all kernel callbacks | ✅ Completed |
| SSDT Monitoring | SSDT analysis from disk image + EPT Hook monitoring/blocking/filtering syscalls | ✅ Completed |
| Shadow SSDT | Win32k Shadow SSDT discovery + NtUser*/NtGdi* Hook/monitoring | ✅ Completed |
| Bare-metal execution | Dedicated bare-metal environment execution | ✅ Completed |
| Driver Hiding | Hiding the driver object itself to prevent enumeration | 📋 Planned |
| Virtualization Protection | Encrypting and protecting target process code segments at VMX level | 📋 Planned |
| Stealthy Communication | VMCALL-based covert driver communication channel | 📋 Planned |

---

## Key Risks and Precautions

| Risk | Description | Mitigation Measure |
|------|-------------|--------------------|
| **Blue Screen (BSOD)** | Any error inside VMX code can cause a BSOD | Test inside virtual machine, use dual-machine debugging |
| **PatchGuard** | Windows Kernel Patch Protection may detect anomalies | EPT Hooks do not modify kernel code pages physically, usually safe |
| **HVCI** | Hypervisor-protected Code Integrity blocks custom Hypervisors | HVCI must be disabled |
| **Driver Signing** | Windows 10+ requires valid signatures | Use testsigning for development; EV certificate required for production |
| **EPROCESS Offsets** | Offsets differ across Windows versions | Dynamic discovery implemented, covering Win7 to Win11 |
| **Multi-core Sync** | VM-Exit handlers run concurrently across different cores | Leverage atomic operations and lock-free/spinlock mechanisms |
| **Process Exit** | CR3 of target process might be reused after exit | Requires a process exit notification callback (TODO) |



