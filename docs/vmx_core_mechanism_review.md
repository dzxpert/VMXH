[简体中文](vmx_core_mechanism_review_CN.md) | English

# VMX Core Execution Mechanism Review Report

> **Date**: 2026-04-11  
> **Review Scope**: VMX bare-metal virtualization engine (excluding EPT Hook logic)  
> **Files involved**: `vmx_init.c`, `vmx_exit.c`, `vmx_asm.asm`, `vmx.h`, `vmxdrv.c`, `msr.c`, `hv_detect.c`  
> **Status**: ✅ Fixed

---

## Table of Contents

- [1. Architectural Overview](#1-architectural-overview)
- [2. Identified Issues](#2-identified-issues)
  - [Issue A: VmxOpsGetCurrentCpuContext uses static local variable (Not Thread-Safe)](#issue-a-vmxopsgetcurrentcpucontext-uses-static-local-variable-not-thread-safe)
  - [Issue B: HandleCrAccess writes incorrect value to ReadShadow for MOV to CR0](#issue-b-handlecraccess-writes-incorrect-value-to-readshadow-for-mov-to-cr0)
  - [Issue C: External interrupt handling lacks Interruptibility State check](#issue-c-external-interrupt-handling-lacks-interruptibility-state-check)
  - [Issue D: HandleRdtscp risk of double-advancing RIP](#issue-d-handlerdtscp-risk-of-double-advancing-rip)
  - [Issue E: DPC initialization context poses stack lifetime risk](#issue-e-dpc-initialization-context-poses-stack-lifetime-risk)
  - [Issue F: NMI re-injection in HandleException lacks NMI-window control](#issue-f-nmi-re-injection-in-handleexception-lacks-nmi-window-control)
  - [Issue G: LMSW handling fails to apply CR0 fixed bits](#issue-g-lmsw-handling-fails-to-apply-cr0-fixed-bits)
  - [Issue H: RFLAGS not restored in VmxShutdown path](#issue-h-rflags-not-restored-in-vmxshutdown-path)
- [3. Code Quality Observations (Non-Bugs, but noteworthy)](#3-code-quality-observations-non-bugs-but-noteworthy)
- [4. Overall Assessment](#4-overall-assessment)
- [5. Summary of Modified Files](#5-summary-of-modified-files)

---

## 1. Architectural Overview

The overall VMX engine adopts a classic Blue Pill architecture:

```
DriverEntry (vmxdrv.c)
  → VmxInitialize (vmx_init.c)
    → VmxCheckCapabilities()        Read MSR capabilities
    → EptInitialize()               Global EPT initialization
    → for each CPU:
        DPC → VmxInitDpcRoutine()
          → VmxEnableOnCpu()        CR4.VMXE + VMXON
          → VmxSetupVmcs()          Write all VMCS fields
          → AsmVmxLaunch()          VMLAUNCH into Guest
            (CPU is now running in VMX non-root)

VM-Exit → AsmVmxExitHandler (vmx_asm.asm)
  → save GP regs → call VmxExitHandler (vmx_exit.c)
    → dispatch by exit reason
    → return TRUE → vmresume
    → return FALSE → VmxShutdown → vmxoff → ret to guest

VmxTerminate (vmx_init.c)
  → for each CPU:
      DPC → VmxTerminateDpcRoutine()
        → VMCALL(VMCALL_MAGIC_SHUTDOWN) → vmxoff
  → EptCleanup()
  → free per-CPU resources
```

**Overall Code Quality**: Excellent. The VMCS fields are fully configured, GDT parsing is correct, the True Controls path is implemented properly, and Enlightened VMCS nested mode support is complete. Below are the issues discovered during the review.

---

## 2. Identified Issues

---

### Issue A: VmxOpsGetCurrentCpuContext uses static local variable (Not Thread-Safe)

**Severity**: 🟡 Medium → ✅ Fixed

**Location**: `vmx_init.c` — `VmxOpsGetCurrentCpuContext()`

**Problem Description**:

```c
static PHV_CPU_CONTEXT VmxOpsGetCurrentCpuContext(VOID)
{
    static HV_CPU_CONTEXT VmxHvCtx;  // ← Globally unique static variable!
    ULONG Cpu = KeGetCurrentProcessorNumber();
    if (Cpu < MAX_PROCESSORS) {
        VmxHvCtx.ProcessorNumber = g_VmxState.CpuContexts[Cpu].ProcessorNumber;
        VmxHvCtx.HvEnabled = g_VmxState.CpuContexts[Cpu].VmxEnabled;
        // ...fill in other fields...
    }
    return &VmxHvCtx;
}
```

`VmxHvCtx` is a `static` local variable—**globally unique**. If two CPUs call this function concurrently (or near-concurrently), CPU 0 fills in its own data and returns the pointer, and CPU 1 overwrites the contents of `VmxHvCtx` before CPU 0 actually uses that pointer → **CPU 0 reads CPU 1's data**.

Although interrupts are disabled in VMX root mode (VM-Exit handler) and a single CPU will not be preempted, **different CPUs can enter the VM-Exit handler simultaneously**, making this race condition real.

**Impact Analysis**: This depends on the callers of `GetCurrentCpuContext`. If a caller only briefly reads the returned value and discards it (without holding the pointer across code segments where interrupts could occur), the issue might not manifest immediately. However, this is a **latent ticking time bomb**.

#### ✅ Resolution

**Modified File**: `vmx_init.c`

Change the single `static HV_CPU_CONTEXT` to a per-CPU `static HV_CPU_CONTEXT[MAX_PROCESSORS]` array, allowing each CPU to use its own slot, completely eliminating the race condition:

```c
static PHV_CPU_CONTEXT VmxOpsGetCurrentCpuContext(VOID)
{
    static HV_CPU_CONTEXT VmxHvCtx[MAX_PROCESSORS];
    ULONG Cpu = KeGetCurrentProcessorNumber();
    if (Cpu < MAX_PROCESSORS) {
        VmxHvCtx[Cpu].ProcessorNumber = g_VmxState.CpuContexts[Cpu].ProcessorNumber;
        VmxHvCtx[Cpu].HvEnabled = g_VmxState.CpuContexts[Cpu].VmxEnabled;
        VmxHvCtx[Cpu].GuestLaunched = g_VmxState.CpuContexts[Cpu].VmcsLaunched;
        VmxHvCtx[Cpu].TscOffset = g_VmxState.CpuContexts[Cpu].TscOffset;
        VmxHvCtx[Cpu].LastDebugPauseTsc = g_VmxState.CpuContexts[Cpu].LastDebugPauseTsc;
        VmxHvCtx[Cpu].InDebugPause = g_VmxState.CpuContexts[Cpu].InDebugPause;
        VmxHvCtx[Cpu].ExitCount = g_VmxState.CpuContexts[Cpu].ExitCount;
        return &VmxHvCtx[Cpu];
    }
    return NULL;
}
```

**Key Changes**:
- `static HV_CPU_CONTEXT VmxHvCtx` → `static HV_CPU_CONTEXT VmxHvCtx[MAX_PROCESSORS]`
- All field accesses changed to `VmxHvCtx[Cpu].xxx`
- Returns `NULL` instead of uninitialized data when `Cpu >= MAX_PROCESSORS`

---

### Issue B: HandleCrAccess writes incorrect value to ReadShadow for MOV to CR0

**Severity**: 🟡 Medium → ✅ Fixed

**Location**: `vmx_exit.c` — `HandleCrAccess()` in `CR_ACCESS_TYPE_MOV_TO_CR, CrNum == 0`

**Problem Description**:

`HandleCrAccess` correctly applies VMX fixed bits (`VMX_CR0_FIXED0` / `FIXED1`) to `MOV to CR0`, but writes the **adjusted value** to the ReadShadow:

```c
if (CrNum == 0) {
    NewValue |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);  // ✅ Correct
    NewValue &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    VmxWrite(VMCS_GUEST_CR0, NewValue);
    VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, NewValue);    // ← BUG: Should be the original value
}
```

The Intel SDM recommends: **the Read Shadow should store the value that the guest expects to see** (i.e., the original value written by the guest), while the **actual Guest CR0 field** stores the adjusted value. This ensures that the guest's `MOV from CR0` reads back the value it wrote itself (excluding VMX-enforced bits), achieving transparent virtualization.

**Note**: Since `CR0_GUEST_HOST_MASK = 0` (CR0 is not intercepted) currently, this code block is not executed. This is a **latent bug** that would trigger once the guest/host mask is modified.

#### ✅ Resolution

**Modified File**: `vmx_exit.c`

Save the guest's original value before applying the fixed bits, and write this original value to the ReadShadow:

```c
else if (CrNum == 0) {
    ULONG64 ShadowValue = NewValue;             /* Save guest's original value */
    NewValue |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    NewValue &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    VmxWrite(VMCS_GUEST_CR0, NewValue);
    VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, ShadowValue);  /* shadow = original value */
}
```

**Also Updated**: Explanatory comments were added to the initial ReadShadow configuration in `VmxSetupVmcs()` inside `vmx_init.c` (even though the initial CR0 already contains the VMX fixed bits and thus the values are identical, comments were added for consistency).

---

### Issue C: External interrupt handling lacks Interruptibility State check

**Severity**: 🔴 High → ✅ Fixed

**Location**: `vmx_exit.c` — `EXIT_REASON_EXTERNAL_INT` handling

**Problem Description**:

The `EXIT_REASON_EXTERNAL_INT` handling code only checks `RFLAGS.IF` before injecting an interrupt:

```c
ULONG64 GuestRflags = VmxRead(VMCS_GUEST_RFLAGS);
if (GuestRflags & (1ULL << 9)) {
    // IF=1: inject immediately
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, ...);
}
```

However, Intel SDM Vol. 3C, Section 26.3.1.5 stipulates that the prerequisites for VM-Entry to inject an external interrupt are not just `RFLAGS.IF=1`, but also include:

- The following bits of the **Guest Interruptibility State** must be 0:
  - Bit 0: Blocking by STI (the instruction window immediately following an `STI` instruction)
  - Bit 1: Blocking by MOV SS (the instruction window immediately following a `MOV SS` instruction)

**Triggering Scenario**:

```asm
; Guest Code
cli             ; IF=0
; ...certain operations...
sti             ; IF=1, but "blocking by STI" = 1 for the next instruction
nop             ; ← If a VM-Exit happens to occur exactly here
```

At the time of VM-Exit, `RFLAGS.IF=1` but `Interruptibility.BlockingBySTI=1` → direct injection of the interrupt → VM-Entry failure → BSOD.

#### ✅ Resolution

**Modified File**: `vmx_exit.c`

Before injection, check both `RFLAGS.IF` and the blocking bits (bit 0 and bit 1) of `VMCS_GUEST_INTERRUPTIBILITY`:

```c
ULONG64 GuestRflags = VmxRead(VMCS_GUEST_RFLAGS);
ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);

if ((GuestRflags & (1ULL << 9)) && !(Interruptibility & 0x3)) {
    /* IF=1 and not blocked by STI/MOV SS: safe to inject */
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, ...);
} else {
    /* IF=0 or blocked: defer to interrupt window */
    // ...save pending + request INT_WINDOW_EXIT...
}
```

**Key Changes**: The injection condition is updated from `if (GuestRflags & IF_BIT)` to `if ((GuestRflags & IF_BIT) && !(Interruptibility & 0x3))`. If the condition is not met, the code falls back to the deferred injection path.

---

### Issue D: HandleRdtscp risk of double-advancing RIP

**Severity**: 🟢 Low → ✅ Addressed (Defensive documentation added)

**Location**: `vmx_exit.c` — `HandleRdtscp()`

**Problem Description**:

```c
static BOOLEAN HandleRdtscp(PGUEST_CONTEXT Ctx)
{
    AadHandleRdtsc(Ctx);               // ← Internally calls HvAdvanceGuestRip()
    Ctx->Rcx = __readmsr(MSR_IA32_TSC_AUX) & 0xFFFFFFFF;
    /* Note: AadHandleRdtsc already advanced RIP */
    return TRUE;
}
```

There is an **implicit coupling risk**:
- If `AadHandleRdtsc` is modified to not advance the RIP → the guest falls into an infinite loop.
- If someone mistakenly appends `VmxAdvanceGuestRip()` to this function → double advancement → skips instruction → crash.

#### ✅ Resolution

**Modified File**: `vmx_exit.c`

Add a detailed defensive comment block in `HandleRdtscp` to explicitly document the design contract that `AadHandleRdtsc` internally advances the RIP, along with considerations for future refactoring:

```c
static BOOLEAN HandleRdtscp(PGUEST_CONTEXT Ctx)
{
    /*
     * BUG FIX (Problem D): Document the implicit coupling.
     * AadHandleRdtsc() internally calls HvAdvanceGuestRip().
     * Do NOT add another VmxAdvanceGuestRip() here.
     * If AadHandleRdtsc is refactored to NOT advance RIP,
     * a VmxAdvanceGuestRip() call MUST be added here.
     */
    AadHandleRdtsc(Ctx);
    Ctx->Rcx = __readmsr(MSR_IA32_TSC_AUX) & 0xFFFFFFFF;
    return TRUE;
}
```

---

### Issue E: DPC initialization context poses stack lifetime risk

**Severity**: 🟢 Low → ✅ Addressed (Safety comments added)

**Location**: `vmx_init.c` — `VmxInitialize()` DPC loop

**Problem Description**:

```c
for (i = 0; i < CpuCount; i++) {
    KDPC            Dpc;
    VMX_DPC_CONTEXT DpcCtx;       // ← Stack-allocated
    // ...
    KeWaitForSingleObject(&DpcCtx.Event, ...);  // ← Blocking wait ensures safety
}
```

The current code is correct (the `KeWaitForSingleObject` call guarantees the lifetime of the stack object). However, this pattern is brittle: if someone removes the wait or changes the loop to execute in parallel in the future, the stack variables could be overwritten before the DPC finishes executing → BSOD.

#### ✅ Resolution

**Modified File**: `vmx_init.c`

Add a prominent safety comment block before the DPC loop, explicitly stating:
1. `Dpc` and `DpcCtx` must remain valid until `KeSetEvent` is called.
2. Under no circumstances should `KeWaitForSingleObject` be removed or deferred.
3. If parallel initialization is required in the future, memory must be allocated from the `NonPagedPool`.

---

### Issue F: NMI re-injection in HandleException lacks NMI-window control

**Severity**: 🟡 Medium → ✅ Fixed

**Location**: `vmx_exit.c` — `HandleException()` NMI branch

**Problem Description**:

```c
if (IntType == INTERRUPT_TYPE_NMI) {
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
             INTERRUPT_INFO_VALID |
             (INTERRUPT_TYPE_NMI << INTERRUPT_INFO_TYPE_SHIFT) |
             2);
    return TRUE;
}
```

Directly re-injecting the NMI without checking the "blocking by NMI" bit is problematic. If certain CPUs force-enable `VIRTUAL_NMIS` via the must-be-1 bits of `VmxAdjustControls`, the NMI blocking status might not be cleared automatically, leading to VM-Entry failure.

#### ✅ Resolution

**Modified File**: `vmx_exit.c`

1. Check bit 3 (blocking by NMI) of `VMCS_GUEST_INTERRUPTIBILITY` before NMI injection.
2. If blocked, set `PROC_BASED_NMI_WINDOW_EXIT` to defer injection.
3. Add a new dispatch branch for `EXIT_REASON_NMI_WINDOW` to clear the NMI-window exiting bit and inject the NMI.

```c
if (IntType == INTERRUPT_TYPE_NMI) {
    ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);

    if (!(Interruptibility & (1ULL << 3))) {
        /* Not blocked: inject immediately */
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, ...);
    } else {
        /* Blocked: request NMI-window exiting */
        ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
        ProcBased |= PROC_BASED_NMI_WINDOW_EXIT;
        VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
    }
    return TRUE;
}
```

**New Dispatch Branch**:

```c
case EXIT_REASON_NMI_WINDOW:
    /* Clear NMI-window exiting and inject deferred NMI */
    ProcBased &= ~PROC_BASED_NMI_WINDOW_EXIT;
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, NMI_INFO);
    break;
```

---

### Issue G: LMSW handling fails to apply CR0 fixed bits

**Severity**: 🟡 Medium → ✅ Fixed

**Location**: `vmx_exit.c` — `HandleCrAccess()` in `CR_ACCESS_TYPE_LMSW`

**Problem Description**:

```c
case CR_ACCESS_TYPE_LMSW:
    {
        ULONG64 Cr0 = VmxRead(VMCS_GUEST_CR0);
        USHORT  Msw = (USHORT)(ExitQual >> 16);
        Cr0 = (Cr0 & ~0xFFFFULL) | Msw;
        Cr0 |= CR0_PE;
        VmxWrite(VMCS_GUEST_CR0, Cr0);  // ← VMX fixed bits are not applied here
    }
```

VMX requires certain bits of Guest CR0 to be fixed to 1 or 0. If the LMSW instruction changes any restricted bits (such as clearing NE), the subsequent VM-Entry will fail.

**Note**: Since `CR0_GUEST_HOST_MASK = 0` currently, LMSW will not trigger a VM-Exit. However, this becomes a real bug once the mask is modified.

#### ✅ Resolution

**Modified File**: `vmx_exit.c`

Apply VMX fixed bits at the end of the LMSW handling before writing back to Guest CR0:

```c
case CR_ACCESS_TYPE_LMSW:
    {
        ULONG64 Cr0 = VmxRead(VMCS_GUEST_CR0);
        USHORT  Msw = (USHORT)(ExitQual >> 16);
        Cr0 = (Cr0 & ~0xFFFFULL) | Msw;
        Cr0 |= CR0_PE;
        /* Apply VMX fixed bits (Problem G fix) */
        Cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
        Cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
        VmxWrite(VMCS_GUEST_CR0, Cr0);
    }
    break;
```

---

### Issue H: RFLAGS not restored in VmxShutdown path

**Severity**: 🟢 Low → ✅ Fixed

**Location**: `vmx_asm.asm` — `VmxShutdown` label

**Problem Description**:

`VmxShutdown` restores all GP registers (RAX~R15) after executing `vmxoff`, but **fails to restore Guest RFLAGS**. After `vmxoff`, the RFLAGS contains Host context values instead of Guest values.

**Impact Analysis**: The practical impact is relatively small (subsequent C code typically overwrites most flags), but special flags such as TF (Trap Flag) will not be restored correctly.

#### ✅ Resolution

**Modified File**: `vmx_asm.asm`

1. Add the `VMCS_GUEST_RFLAGS_ENCODING EQU 06820h` constant.
2. Read Guest RFLAGS via `vmread` prior to calling `vmxoff`.
3. Push Guest RFLAGS onto the Guest stack.
4. After restoring GP registers, restore RFLAGS using `popfq`.
5. Finally, use `ret` to jump to Guest RIP.

```asm
VmxShutdown:
    ; 1. vmread Guest RSP, RIP, RFLAGS
    mov     rcx, VMCS_GUEST_RSP_ENCODING
    vmread  rdx, rcx            ; rdx = Guest RSP
    mov     rcx, VMCS_GUEST_RIP_ENCODING
    vmread  rax, rcx            ; rax = Guest RIP
    mov     rcx, VMCS_GUEST_RFLAGS_ENCODING
    vmread  rcx, rcx            ; rcx = Guest RFLAGS

    ; 2. Push Guest RIP onto Guest stack
    sub     rdx, 8
    mov     [rdx], rax

    ; 3. Push Guest RFLAGS onto Guest stack
    sub     rdx, 8
    mov     [rdx], rcx
    mov     [rsp + 020h], rdx   ; save adjusted Guest RSP

    ; 4. vmxoff
    vmxoff

    ; 5. Restore GP registers
    mov     rax, [rsp + 000h]
    ; ...restore all 15 registers...
    mov     r15, [rsp + 078h]

    ; 6. Switch to Guest stack, restore RFLAGS, ret to Guest RIP
    mov     rsp, [rsp + 020h]
    popfq                       ; restore Guest RFLAGS
    ret                         ; pop Guest RIP, resume
```

**Guest Stack Layout** (High to Low):
```
[Guest RSP - 8]  = Guest RIP   (Popped by ret)
[Guest RSP - 16] = Guest RFLAGS (Popped by popfq)
```

---

## 3. Code Quality Observations (Non-Bugs, but noteworthy)

### 1. Handling of Unlocked IA32_FEATURE_CONTROL

**Location**: `vmx_init.c` lines 62-68 / `hv_detect.c` lines 81-83

When the `IA32_FEATURE_CONTROL` MSR is not locked (bit 0 = 0), the code only prints a warning and continues. According to the Intel SDM, in some scenarios `VMXON` will fail if the MSR is unlocked. It is recommended to attempt to lock the MSR by setting bit 0 and bit 2:

```c
if (!(FeatureControl & FEATURE_CONTROL_LOCKED)) {
    __writemsr(MSR_IA32_FEATURE_CONTROL,
               FeatureControl | FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_ENABLED);
}
```

### 2. MSR Bitmap Only Intercepts IA32_DEBUGCTL

**Location**: `msr.c` lines 63-77

Currently, only reads and writes to `MSR_IA32_DEBUGCTL` are intercepted. If more MSRs (e.g., `IA32_EFER`, `IA32_KERNEL_GS_BASE`) need to be intercepted in the future, they should be added in `MsrBitmapInitialize`. The current design is clean (bitmap default of all 0s = all passthrough), but it is recommended to explicitly document this design decision in code comments.

### 3. 16KB Host Stack May Be Insufficient

**Location**: `vmx_init.c` lines 203-204

```c
CpuCtx->HostStackSize = 4 * PAGE_SIZE_4KB;  // 16KB
```

The VM-Exit handler runs on the Host Stack, which includes executing `VmxExitHandler` and all its child functions (EPT violation handler, anti-anti-debug, logging, etc.). If the call stack gets deep, 16KB might be insufficient (Windows kernel default thread stack is 12KB-24KB, and DPC stack is 16KB). If a stack overflow occurs, it manifests as random memory corruption, which is extremely difficult to debug.

It is recommended to increase the stack size to 32KB (`8 * PAGE_SIZE_4KB`) or place a guard page at the bottom of the Host Stack.

### 4. Duplicate Functionality in VmxIsSupported and HvCheckVmxSupport

**Location**: `vmx_init.c` lines 42-71 / `hv_detect.c` lines 61-87

These two functions do almost exactly the same thing. `VmxIsSupported` is defined in `vmx_init.c` but is actually pointed to by `g_VmxOps.IsSupported`, while `HvCheckVmxSupport` is defined in `hv_detect.c` and is called by `DriverEntry`. It is recommended to consolidate these into a single function.

### 5. XSETBV Handling Lacks XCR0 Validity Check → ✅ Fixed

**Location**: `vmx_exit.c` — `HandleXsetbv()`

**Original Issue**: The code directly writes the guest-requested XCR0 value to the physical XCR0 register without any validity checks. If the guest writes an invalid combination of XCR0 values (e.g., setting the AVX bit but not setting the SSE bit), `XSETBV` triggers a `#GP`. Since this execution occurs in the Host context, it results in a **Hypervisor-level #GP** → BSOD.

**Resolution**: Add XCR0 validation checks before executing `AsmXsetbv`:
- The XCR index must be 0 (only XCR0 is valid).
- Bit 0 (x87 FPU) must be 1.
- AVX (bit 2) requires SSE (bit 1) to be set.

When validation fails, inject a `#GP(0)` into the guest instead of executing the invalid operation:

```c
if (Ecx != 0) goto InjectGp;               /* Only XCR0 is valid */
if (!(Value & 1)) goto InjectGp;            /* x87 must be 1 */
if ((Value & 4) && !(Value & 2)) goto InjectGp;  /* AVX requires SSE */

AsmXsetbv(Ecx, Value);
VmxAdvanceGuestRip();
return TRUE;

InjectGp:
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, GP_FAULT_INFO);
    VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, 0);
    return TRUE;
```

---

## 4. Overall Assessment

| Category | Evaluation |
|------|------|
| **VMCS Initialization** | ✅ Complete and correct: All Guest/Host state fields, control fields, True Controls, and segment descriptor parsing are correct. |
| **VM-Exit Dispatching** | ✅ Comprehensive coverage: CPUID, MSR, CR, DR, Exception, RDTSC, XSETBV, INVD, INVLPG, WBINVD, Triple Fault, etc., are all handled. |
| **External Interrupts** | ✅ Complete logic (IF + Interruptibility check + interrupt window) —— Issue C is fixed. |
| **NMI Handling** | ✅ NMI blocking check + NMI-window deferred injection —— Issue F is fixed. |
| **VMLAUNCH / VMRESUME** | ✅ Correct ASM implementation: Register save/restore sequence is correct, RSP alignment is correct, and shutdown path includes RFLAGS restoration. |
| **Nested Mode** | ✅ Complete Enlightened VMCS support: VP Assist Page, eVMCS allocation/activation, and Clean Fields management. |
| **DPC Serialization** | ✅ Proper use of per-CPU DPC + Event to implement serial initialization/termination, with safety comments added. |
| **Memory Management** | ✅ Correct allocation zeroing, release checks, and physical address retrieval. |
| **Error Handling** | ✅ The `InitFailed` path in `VmxInitialize` correctly rolls back already-started CPUs. |
| **CR0/CR4 Handling** | ✅ ReadShadow stores the Guest's original value, LMSW applies fixed bits —— Issues B and G are fixed. |
| **XSETBV** | ✅ XCR0 validity validation; invalid values inject `#GP(0)` instead of causing a crash. |

**Overall Conclusion**: All 8 identified issues + 1 code quality issue (XSETBV) have been successfully resolved.

---

## 5. Summary of Modified Files

| File | Fixed Issues | Changes |
|------|--------------|---------|
| `vmx_init.c` | A, B, E | A: Changed `VmxOpsGetCurrentCpuContext` to a per-CPU array; B: Added comments to initial CR0 ReadShadow; E: Added safety comments to the DPC loop. |
| `vmx_exit.c` | B, C, D, F, G, XSETBV | B: CR0 ReadShadow stores the original value; C: Added Interruptibility check for external interrupts; D: Added coupling documentation for RDTSCP; F: Added NMI blocking check + NMI-window processing branch; G: Applied CR0 fixed bits in LMSW; XSETBV: Added XCR0 validity check. |
| `vmx_asm.asm` | H | VmxShutdown path: vmread Guest RFLAGS → push onto Guest stack → vmxoff → restore GP registers → popfq → ret. |

**C89 Compatibility**: All newly added variable declarations are placed at the top of their respective code blocks, adhering to MSVC C89 requirements for WDK 7600.

---

*End of document. All issues have been resolved and documented in this report.*
