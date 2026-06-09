[简体中文](vmware_hang_root_cause_analysis_CN.md) | English

# VMXHypervisorToolbox Complete Bug Analysis and Resolution Report

> **Date**: 2026-04-11 ~ 2026-04-12  
> **Project**: VMXHypervisorToolbox (Intel VT-x Blue Pill Hypervisor)  
> **Environment**: VMware Workstation (L0 Hypervisor) → VMXToolbox (L1 Hypervisor) → Windows Guest (L2)  
> **Status**: ✅ All Fixed, Running Normally

---

## Table of Contents

### Part 1: VMware Nested Virtualization Hang (2026-04-12)

- [Symptoms](#symptoms)
- [Background: Nested Virtualization Architecture](#background-nested-virtualization-architecture)
- [Troubleshooting Process and Iterations](#troubleshooting-process-and-iterations)
- [Root Cause #1: External Interrupt Handler Discards All Interrupts (IPI Loss)](#root-cause-1-external-interrupt-handler-discards-all-interrupts-ipi-loss)
- [Root Cause #2: HLT Handler Executing _enable() + __halt() in VMX Root Mode](#root-cause-2-hlt-handler-executing-_enable--__halt-in-vmx-root-mode)
- [Optimization #3: Neutralizing UNCONDITIONAL_IO_EXIT Storm via I/O Bitmap](#optimization-3-neutralizing-unconditional_io_exit-storm-via-io-bitmap)
- [Optimization #4: CR3 Load Exit / MOV DR Exit / Exception Bitmap Optimizations](#optimization-4-cr3-load-exit--mov-dr-exit--exception-bitmap-optimizations)

### Part 2: EPT Hook Engine & Driver Framework Bugs (2026-04-11)

- [Bug #A: Trampoline Instruction Truncation Leading to #UD → BSOD](#bug-a-trampoline-instruction-truncation-leading-to-ud--bsod)
- [Bug #B: HandleMtf Multi-Core Race Condition Leading to Infinite EPT Violation Loop](#bug-b-handlemtf-multi-core-race-condition-leading-to-infinite-ept-violation-loop)
- [Bug #C: EPT Misconfiguration Due to Missing INVEPT After EptSplitLargePage](#bug-c-ept-misconfiguration-due-to-missing-invept-after-eptsplitlargepage)
- [Bug #D: Uninitialized IoStatus.Information in IOCTL Dispatch](#bug-d-uninitialized-iostatusinformation-in-ioctl-dispatch)

### Overview

- [Summary of All Resolutions](#summary-of-all-resolutions)
- [Complete List of Modified Files](#complete-list-of-modified-files)
- [Compilation Compatibility Notes](#compilation-compatibility-notes)
- [Key Lessons Learned](#key-lessons-learned)

---

# Part 1: VMware Nested Virtualization Hang

## Symptoms

When running the VMXToolbox driver in VMware Workstation, executing `IOCTL_VMX_INIT` to initialize the hypervisor causes the **entire virtual machine to freeze (hang)**. WinDbg stops printing any information, and the VMware window becomes completely unresponsive.

The issue progressed through several stages:

| Stage | Symptom | Hang Location |
|------|------|---------|
| Initial | CPU 0 VMLAUNCH succeeded; CPU 1 never receives DPC | `KeWaitForSingleObject` timeout |
| Middle | Both CPU 0 and 1 VMLAUNCH succeeded, but the system immediately froze | No log output after VMLAUNCH |
| Final | Running normally | ✅ No longer hanging |

---

## Background: Nested Virtualization Architecture

```
┌──────────────────────────────────────────────┐
│                  Physical Hardware           │
├──────────────────────────────────────────────┤
│  L0: VMware Workstation (Host Hypervisor)     │
│    ├─ Intercepts all L1 VMXON/VMCS/VMLAUNCH  │
│    ├─ Emulates VMX instructions for L1       │
│    └─ Every L1 VM-Exit goes through L1→L0→L1 │
├──────────────────────────────────────────────┤
│  L1: VMXToolbox (Our Blue Pill Hypervisor)    │
│    ├─ Uses VMXON/VMLAUNCH to virtualize Guest │
│    ├─ Handles VM-Exits (CPUID/MSR/EPT/Intr)  │
│    └─ Guest = Original Windows OS (Transparent)│
├──────────────────────────────────────────────┤
│  L2: Windows Guest (Virtualized Original OS) │
│    ├─ Unaware of running under a hypervisor  │
│    └─ Runs kernel + user-mode normally       │
└──────────────────────────────────────────────┘
```

**Key Characteristics**:
- **Blue Pill Architecture**: The Guest is the originally running Windows OS. The hypervisor "slips in" and takes over execution transparently at runtime.
- **Nested Virtualization Overhead**: Each L1 VM-Exit actually goes through the full path of `L2 → L1 → L0 → L1 → L2`, introducing overhead that is **100–1000x** higher than bare-metal virtualization.
- **must-be-1 bits**: VMware enforces certain control bits in MSRs like `IA32_VMX_PROCBASED_CTLS` to be 1 (e.g., `HLT_EXIT`, `UNCONDITIONAL_IO_EXIT`, `EXTERNAL_INT_EXIT`), even if L1 does not wish to intercept these events.

---

## Troubleshooting Process and Iterations

The entire debugging process went through **5 iterations**, shifting from superficial hotfixes to diving deep into the true root causes:

### Iteration 1: Disabling High-Frequency VM-Exit Sources

**Hypothesis**: A VM-Exit storm overloaded VMware L0.  
**Actions**:
- Disabled `PROC_BASED_CR3_LOAD_EXIT` (triggered VM-Exits on every process switch).
- Disabled `PROC_BASED_MOV_DR_EXIT` (frequent saving/restoring of DR registers in `SwapContext`).
- Set Exception Bitmap to 0 (do not intercept any exceptions).

**Result**: ❌ Still hung. This reduced the number of VM-Exits but did not resolve the fundamental issue.

### Iteration 2: Systematic Code Review

**Pivot**: Shifted from guestimate fixes to a comprehensive code review of all VM-Exit handlers.

**Discovered three fundamental bugs**:
1. The External Interrupt handler discarded all interrupts.
2. The HLT handler turned HLT into a NOP (busy-wait).
3. The Interrupt Window handler did not inject saved pending interrupts.

### Iteration 3: Fixing Discarded Interrupts + HLT Busy-Wait

**Actions**:
- External Interrupt handler: Re-inject the interrupt vector back into the Guest.
- HLT handler: Executed `_enable() + __halt()` to force the CPU to enter HLT while in VMX root mode.
- Interrupt Window handler: Injected pending interrupts.

**Result**: ⚡ **VMLAUNCH succeeded on both CPU 0 and CPU 1!** However, the system froze immediately after VMLAUNCH. This indicated that the interrupt fix successfully resolved the IPI loss (allowing CPU 1's DPC to arrive), but the HLT fix introduced a new, critical bug.

### Iteration 4: Analyzing the Fatal Issue in the HLT Handler

**Discovery**: Executing `_enable() + __halt()` in VMX root mode causes incoming interrupts to be delivered on the Host stack using the Host IDT. This corrupts the execution flow of the VM-Exit handler and can trigger stack overflow.

**Actions**:
- Modified the HLT handler to set `Guest Activity State = HLT` (allowing hardware to enter HLT mode in the Guest state).
- Added HLT Activity State wake-up logic to the External Interrupt handler.
- Added HLT Activity State wake-up logic to the NMI handler.
- Added I/O Bitmaps to neutralize the UNCONDITIONAL_IO_EXIT storm.

### Iteration 5 (Final): Running Normally ✅

With all fixes in place, the hypervisor runs normally under the VMware nested virtualization environment.

---

## Root Cause #1: External Interrupt Handler Discards All Interrupts (IPI Loss)

### Severity: 🔴 Critical — Directly prevents inter-processor DPC delivery

### Issue Analysis

When `PIN_BASED_EXTERNAL_INT_EXIT` is set (enforced as must-be-1 by VMware), **all external interrupts** (timer interrupts, IPIs, device interrupts, etc.) cause a VM-Exit, with the interrupt vector saved in `VMCS_EXIT_INTERRUPTION_INFO`.

**Old Code**:

```c
case EXIT_REASON_EXTERNAL_INT:
    /* Did nothing, directly broke out */
    break;
```

This meant:
- ⏱️ Timer Interrupts → **Discarded** → The scheduler could not schedule threads.
- 📨 IPIs (Inter-Processor Interrupts) → **Discarded** → DPCs could not be dispatched across CPUs.
- 🔌 Device Interrupts → **Discarded** → Device drivers could not respond.

### Why It Caused the Hang

VMXToolbox uses **sequential CPU initialization**: CPU 0 executes VMLAUNCH first, and upon success, the main thread on CPU 0 (already in Guest mode) queues a DPC to execute on CPU 1.

```
Main thread (CPU 0, virtualized):
  KeInsertQueueDpc(DPC for CPU 1)
      → Kernel sends IPI to CPU 1
      → CPU 1 receives the interrupt → VM-Exit (EXTERNAL_INT)
      → Handler discards the interrupt → IPI lost!
      → CPU 1 never knows a DPC is waiting to run
      → Main thread's KeWaitForSingleObject times out
      → VMware hangs
```

### Resolution

Re-inject the interrupt vector into the Guest using `VMCS_CTRL_VMENTRY_INT_INFO`:

```c
case EXIT_REASON_EXTERNAL_INT:
{
    ULONG64 IntInfo = VmxRead(VMCS_EXIT_INTERRUPTION_INFO);
    if (IntInfo & INTERRUPT_INFO_VALID) {
        ULONG Vector = (ULONG)(IntInfo & INTERRUPT_INFO_VECTOR_MASK);
        ULONG64 GuestRflags = VmxRead(VMCS_GUEST_RFLAGS);
        ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);
        ULONG64 ActivityState = VmxRead(VMCS_GUEST_ACTIVITY_STATE);

        if ((GuestRflags & (1ULL << 9)) &&    /* IF=1 */
            !(Interruptibility & 0x3)) {       /* No STI/MOV SS blocking */
            /* Inject immediately */
            VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                     INTERRUPT_INFO_VALID |
                     (INTERRUPT_TYPE_EXTERNAL << INTERRUPT_INFO_TYPE_SHIFT) |
                     Vector);
        } else {
            /* Deferred injection: Save as pending, enable interrupt-window exiting */
            CpuContext->PendingInterrupt = TRUE;
            CpuContext->PendingInterruptVector = Vector;

            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased |= PROC_BASED_INT_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

            /* If the Guest is in HLT state, it must be woken up */
            if (ActivityState == 1)
                VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 0);
        }
    }
    break;
}
```

**Key Design Points**:
- When Guest `RFLAGS.IF=1` and there is no STI/MOV SS blocking, inject immediately.
- When the Guest is non-interruptible, save the interrupt to `PendingInterrupt` and enable interrupt-window exiting.
- If the Guest is in the `HLT` Activity State, it must be reset to `Active` (0), otherwise the Guest will never execute `STI` to enable interrupts.

---

## Root Cause #2: HLT Handler Executing _enable() + __halt() in VMX Root Mode

### Severity: 🔴 Critical — Directly freezes the system immediately after VMLAUNCH

### Issue Evolution

The HLT handler went through three versions:

| Version | Implementation | Issue |
|------|------|------|
| V1 (Original) | `VmxAdvanceGuestRip(); break;` | HLT became NOP → Idle CPU busy-waits at 100% |
| V2 (First Fix) | `_enable(); __halt(); _disable();` | Interrupt delivery in VMX root mode → Fatal |
| V3 (Final Fix) | `VmxAdvanceGuestRip(); VmxWrite(ACTIVITY_STATE, 1);` | ✅ Correct |

### V1 Issue: HLT to NOP

```
Guest idle loop:
    HLT
    ↓ VM-Exit (EXIT_REASON_HLT)
    ↓ Handler: AdvanceGuestRip → skip HLT
    ↓ VMRESUME
    ↓ Guest: JMP back to HLT (idle loop cycle)
    ↓ HLT
    ↓ VM-Exit...
    ↓ (Infinite loop, each traversing the L1→L0→L1 path)
```

Each idle CPU generated **tens of thousands of VM-Exits per second**. Under nested virtualization, each exit takes several microseconds, which quickly accumulated to occupy 100% of VMware's L0 CPU.

### V2 Issue: Fatal Interrupt Delivery in VMX Root Mode

```
┌─────────────────────────────────────────────────────┐
│ VM-Exit Handler (Running on Host Stack, 16KB)        │
│                                                      │
│   case EXIT_REASON_HLT:                              │
│     _enable();    ← CPU interrupts enabled (VMX root mode!) │
│     __halt();     ← CPU halts, waiting for interrupt │
│       │                                               │
│       │  ←── Interrupt arrives!                       │
│       │                                               │
│   ┌───▼──────────────────────────────────────────┐   │
│   │ Interrupt delivered via Host IDT (= Guest IDT)│   │
│   │ ISR runs on the Host Stack!                  │   │
│   │                                               │   │
│   │ Issue 1: Host Stack is only 16KB. The ISR     │   │
│   │         call chain may cause stack overflow  │   │
│   │                                               │   │
│   │ Issue 2: ISR runs inside the call stack       │   │
│   │         frame of the VM-Exit handler,        │   │
│   │         overwriting local variables           │   │
│   │                                               │   │
│   │ Issue 3: Code in ISR (e.g., KeInsertQueueDpc) │   │
│   │         assumes a normal kernel stack        │   │
│   │                                               │   │
│   │ Issue 4: IRET returns execution to after     │   │
│   │         __halt(), but the stack frame may    │   │
│   │         be corrupted                         │   │
│   └──────────────────────────────────────────────┘   │
│                                                      │
│     _disable();   ← Might never be reached            │
│     break;                                           │
└─────────────────────────────────────────────────────┘
```

**Why there was no log output**: Once an interrupt is delivered in VMX root mode, the ISR executes on a corrupted stack, placing the system in an unrecoverable state. Since WinDbg's `DbgPrintEx` relies on the interrupt system functioning normally, not even diagnostic information could be output.

### V3 Final Fix: Guest Activity State = HLT

```c
case EXIT_REASON_HLT:
    VmxAdvanceGuestRip();
    VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 1);  /* 1 = HLT */
    break;
```

**How It Works**:

```
Guest idle loop:
    HLT
    ↓ VM-Exit (EXIT_REASON_HLT)
    ↓ Handler: AdvanceGuestRip, set Activity State = HLT
    ↓ VMRESUME → CPU enters HLT state in Guest mode
    ↓ (CPU stops, waiting with zero power consumption)
    ↓
    ↓ External interrupt arrives
    ↓ VM-Exit (EXIT_REASON_EXTERNAL_INT)
    ↓ Handler: Inject interrupt into Guest
    ↓   → Hardware automatically changes Activity State from HLT to Active on injection
    ↓ VMRESUME → Guest wakes up, ISR executes correctly on Guest kernel stack
```

**Advantages**:
- ✅ The CPU enters `HLT` in **Guest Mode**, allowing interrupts to be processed via standard VM-Exit paths.
- ✅ Eliminates any risks associated with VMX root mode interrupt delivery.
- ✅ True energy efficiency — the CPU hardware actually halts, preventing busy-waiting.
- ✅ On interrupt injection, hardware automatically wakes the CPU from the HLT state (Intel SDM Vol. 3C, Section 26.6.2).

---

## Optimization #3: Neutralizing UNCONDITIONAL_IO_EXIT Storm via I/O Bitmap

### Severity: 🟡 Medium — Significantly reduces the number of VM-Exits

### Issue

VMware forces the `UNCONDITIONAL_IO_EXIT` control bit to be 1, causing **every IN/OUT instruction** (including PCI configuration, ACPI timer reads, serial port accesses, etc.) to trigger a VM-Exit. Although the I/O handler processed these correctly, each exit cost several microseconds under nested virtualization.

### Resolution

Utilized the rule in the Intel SDM: **When both `USE_IO_BITMAPS` and `UNCONDITIONAL_IO_EXIT` are set, the I/O Bitmaps take precedence.**

```c
/* Add to VMX_CPU_CONTEXT in vmx.h */
PVOID       IoBitmapAVa;    /* 4KB, covers ports 0x0000-0x7FFF */
ULONG64     IoBitmapAPa;
PVOID       IoBitmapBVa;    /* 4KB, covers ports 0x8000-0xFFFF */
ULONG64     IoBitmapBPa;

/* Configure in VmxSetupVmcs in vmx_init.c */
RequestedProcBased |= PROC_BASED_USE_IO_BITMAPS;
VmxWrite(VMCS_CTRL_IO_BITMAP_A, CpuCtx->IoBitmapAPa);  /* All zeros = does not trigger exit */
VmxWrite(VMCS_CTRL_IO_BITMAP_B, CpuCtx->IoBitmapBPa);
```

An all-zero Bitmap means no I/O ports trigger a VM-Exit, effectively neutralizing the `UNCONDITIONAL_IO_EXIT` enforcement.

---

## Optimization #4: CR3 Load Exit / MOV DR Exit / Exception Bitmap Optimizations

### Severity: 🟢 Low — Minimizes unnecessary VM-Exits

| Optimization | Reason | Impact |
|--------|------|------|
| Disable `CR3_LOAD_EXIT` | Every process context switch (`SwapContext`) writes to CR3 → triggers VM-Exit | Reduces thousands of exits per second |
| Disable `MOV_DR_EXIT` | `SwapContext` saves/restores DR0-DR7 → multiple exits per context switch | Reduces thousands of exits per second |
| Set Exception Bitmap to 0 | No need to intercept exceptions (#BP/#DB are unused when debugging features are disabled) | Eliminates unnecessary exception exits |

While these optimizations alone could not resolve the hang, they significantly reduced the total volume of VM-Exits in the nested virtualization environment, improving overall system responsiveness.

---

---

# Part 2: EPT Hook Engine & Driver Framework Bugs

> The following bugs were resolved prior to fixing the nested virtualization hang (on 2026-04-11). They concern the correctness of the EPT Hook engine and the robustness of the driver framework.

---

## Bug #A: Trampoline Instruction Truncation Leading to #UD → BSOD

### Severity: 🔴 Critical

### Issue Description

When building a trampoline, `EptHookFunction()` needs to "steal" at least 12 bytes from the head of the target function (e.g., `48 B8 [imm64] FF E0` = `MOV RAX, addr; JMP RAX`), copy these original bytes to the trampoline, and then append a JMP at the end of the trampoline back to the target function +12 bytes.

The original code hardcoded a 14-byte copy:

```c
// Original code (buggy)
Hook->OriginalBytesSize = 14;  // Hardcoded
RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, 14);
```

x86-64 instructions are variable-length (1–15 bytes). Copying exactly 14 bytes is highly likely to cut an instruction in half:

```
Target function prefix:
  48 89 5C 24 08    MOV [RSP+8], RBX     (5 bytes)
  48 89 6C 24 10    MOV [RSP+10h], RBP   (5 bytes)
  48 89 74 24 18    MOV [RSP+18h], RSI   (5 bytes)  ← The 14th byte lies inside this instruction!
```

The trampoline would execute the truncated `48 89 74` and then branch into garbage bytes, leading to an `#UD` (Undefined Opcode) exception in kernel mode, resulting in a **BSOD**.

### Resolution

1. **Implemented the `EptGetInstructionLength()` function**: A minimal x64 instruction length decoder (~300 lines) covering common prefix instructions encountered in kernel functions:
   - Prefix handling: Legacy prefixes (LOCK/REP/Segment overrides), `66h`/`67h`, and REX (`40h`–`4Fh`).
   - Single-byte opcodes: `PUSH`/`POP` reg, `MOV` reg, imm, `JMP`/`CALL` rel, ALU operations, etc.
   - Double-byte opcodes (0Fh): `Jcc` rel32, `MOVZX`/`MOVSX`, `CMOVcc`, `SETcc`, etc.
   - Complete decoding of ModRM + SIB + Displacement.

2. **Modified trampoline construction logic**:

```c
// Fixed Code
{
    ULONG TotalLen = 0;
    PUCHAR Code = (PUCHAR)TargetVa;
    while (TotalLen < 12) {
        ULONG InsnLen = EptGetInstructionLength(Code + TotalLen);
        if (InsnLen == 0) {
            LOG_ERROR("EPT Hook: Cannot decode instruction at VA 0x%llX + 0x%X",
                      TargetVa, TotalLen);
            return STATUS_UNSUCCESSFUL;
        }
        TotalLen += InsnLen;
    }
    Hook->OriginalBytesSize = TotalLen;  // Could be 12, 13, 14, 15...
}
RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, Hook->OriginalBytesSize);
```

3. **Added `OriginalBytes` buffer overflow protection**:

Expanded `OriginalBytes[16]` to `OriginalBytes[32]` (theoretical maximum `TotalLen` is 11 + 15 = 26, so 32 bytes provides a safe margin) and added out-of-bounds checks inside the loop.

4. **Synchronized fix on the AMD-V side (`npt.c`)**: `NptHookFunction()` suffered from the same issue and was fixed in the same manner.

### Affected Files

| File | Changes |
|------|------|
| `driver/ept.c` | Added `EptGetInstructionLength()` (~300 lines); modified trampoline construction logic; added out-of-bounds protection. |
| `driver/ept.h` | Declared `EptGetInstructionLength`; expanded `OriginalBytes[16]` to `OriginalBytes[32]`. |
| `driver/npt.c` | Replaced 14-byte hardcoding with instruction boundary alignment + out-of-bounds protection (consistent with `ept.c`). |

---

## Bug #B: HandleMtf Multi-Core Race Condition Leading to Infinite EPT Violation Loop

### Severity: 🔴 Critical

### Issue Description

The EPT Hook engine implements hidden hooks using **execute-only** pages:
- **Resting state**: Hooked page is marked `R=0, W=0, X=1` (execute-only, no read/write access).
- **Data access** (e.g., PatchGuard scan): Triggers an EPT Violation → switches to the original page (`R=1, W=1, X=0`) → enables Monitor Trap Flag (MTF) → MTF triggers after one instruction → restores the hooked page.

The original `HandleMtf` code restored all 1024 hooks when MTF triggered:

```c
// Original code (buggy)
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    // Loop through all hooks and restore them all
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
            Pte->Read = 0;
            Pte->Write = 0;
            // ...restore hooked page...
        }
    }
}
```

**Multi-Core Race Condition Scenario**:

```
Timeline:
  T1: CPU 0 → EPT Violation for Hook A → Switches to R=1, W=1 → Enables MTF
  T2: CPU 1 → EPT Violation for Hook B → Switches to R=1, W=1 → Enables MTF
  T3: CPU 0 → MTF triggers → Restores ALL hooks (including Hook B!) → Hook B goes back to R=0, W=0
  T4: CPU 1 → Has not finished executing the data access instruction → EPT Violation again (Hook B)
  T5: CPU 1 → Switches back to R=1, W=1 → Enables MTF
  T6: CPU 0 → Possibly another MTF triggers → Restores ALL hooks again...
  → Infinite Loop! CPU 1 is permanently blocked from completing that single instruction.
```

### Resolution

Introduced a **per-CPU tracking mechanism**, ensuring each CPU only restores hooks on the specific physical page it previously relaxed:

```c
// Each CPU slot records which physical page it has relaxed
static volatile ULONG64 g_MtfRelaxedPagePa[64] = { 0 };

// Track the relaxed page for the current CPU in HandleEptViolation
EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);

// Modify HandleMtf to only restore the page relaxed by the current CPU
RelaxedPa = EptMtfGetAndClearRelaxedPage();
for (i = 0; i < MAX_EPT_HOOKS; i++) {
    if (RelaxedPa != 0 &&
        g_EptHookState.Hooks[i].TargetPhysicalAddr != RelaxedPa) {
        continue;  // ★ Skip pages that were not relaxed by the current CPU
    }
    // ...restore hook...
}
```

**Safety Fallback**: If `RelaxedPa == 0` (which theoretically should not occur), fall back to restoring all hooks.

### Affected Files

| File | Changes |
|------|------|
| `driver/ept.c` | Added `g_MtfRelaxedPagePa[64]`, `EptMtfTrackRelaxedPage()`, and `EptMtfGetAndClearRelaxedPage()`. |
| `driver/ept.h` | Declared the two tracking functions above. |
| `driver/vmx_exit.c` | Modified `HandleMtf` to query the per-CPU tracking array and only restore the targeted page. |

---

## Bug #C: EPT Misconfiguration Due to Missing INVEPT After EptSplitLargePage

### Severity: 🔴 Critical

### Issue Description

Before installing a hook, `EptHookFunction()` must split a 2MB large page into 512 4KB pages. The original code modified the page tables without invalidating the EPT TLB afterwards:

```c
// Original code (buggy)
EptSplitLargePage(TargetPa);
// ← Missing INVEPT!
Pte = EptGetPteForPhysicalAddress(TargetPa);
```

**Consequences**:

```
CPU 0:  Executes EptSplitLargePage()
        → Modifies PDE: 2MB large page entry → points to new 4KB page table
        
CPU 1-N: TLB still caches the old 2MB PDE
        → On subsequent memory access, CPU interprets new structure using the old 2MB PDE layout
        → PDE format mismatch with the new page table layout → EPT Misconfiguration
        → VMX shutdown → BSOD
```

An EPT Misconfiguration is fatal and unrecoverable, leading directly to a VMX shutdown.

### Resolution

Immediately call `EptInvalidateFromGuest()` after executing `EptSplitLargePage()`:

```c
EptSplitLargePage(TargetPa);
EptInvalidateFromGuest();  // ← New: Invalidate EPT TLB on all CPUs
Pte = EptGetPteForPhysicalAddress(TargetPa);
```

> `EptInvalidateFromGuest()` utilizes a generation counter mechanism (`InterlockedIncrement`). Each CPU checks this counter on its next VM-Exit and executes an `INVEPT` if needed.

### Affected Files

| File | Changes |
|------|------|
| `driver/ept.c` | Added `EptInvalidateFromGuest()` after `EptSplitLargePage()` inside `EptHookFunction()`. |

---

## Bug #D: Uninitialized IoStatus.Information in IOCTL Dispatch

### Severity: 🟡 Medium

### Issue Description

`DispatchDeviceControl` processes IOCTL requests under the `METHOD_BUFFERED` mode. `Irp->IoStatus.Information` informs the I/O Manager how many bytes of data to copy back to user mode.

The original code did not initialize this field before dispatching the request:

```c
// Original code (buggy)
IoStack = IoGetCurrentIrpStackLocation(Irp);
IoControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;
// ← Irp->IoStatus.Information is not initialized

switch (IoControlCode) {
    case IOCTL_VMX_INIT:
        Status = HandleIoctlInit(Irp, IoStack);
        break;
    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;  // ← Information remains an uninitialized dirty value!
}
```

**Issues**:
- In error paths or the `default` case, `Information` remains an uninitialized dirty value.
- The I/O Manager copies bytes based on this dirty value, risking either **kernel information disclosure** or an **out-of-bounds copy → BSOD**.

### Resolution

```c
Irp->IoStatus.Information = 0;  // ← Unified initialization before the switch statement

switch (IoControlCode) {
    // ...
}
```

### Affected Files

| File | Changes |
|------|------|
| `driver/vmxdrv.c` | Added `Irp->IoStatus.Information = 0` before the switch block in `DispatchDeviceControl`. |

---

# Overview

## Summary of All Resolutions

### Part 1: Nested Virtualization Hang

| # | Resolution | Resolved Issue | Impact |
|---|------|-----------|------|
| 1 | External Interrupt Re-injection | IPI loss → inter-processor DPCs could not be delivered | 🔴 Primary Cause: CPU 1 initialization hang |
| 2 | HLT → Guest Activity State | Interrupt delivery in VMX root mode → system crash | 🔴 Primary Cause: System froze after VMLAUNCH |
| 3 | Interrupt Window injection of pending interrupts | Deferred interrupts could not be delivered | 🟠 Co-resolution for Fix #1 |
| 4 | NMI handler HLT wake-up | NMI cannot wake Guest from HLT state | 🟠 Co-resolution for Fix #2 |
| 5 | All-zero I/O Bitmap | UNCONDITIONAL_IO_EXIT storm | 🟡 Performance optimization |
| 6 | Disable CR3 Load Exit | Context switch VM-Exit storm | 🟢 Performance optimization |
| 7 | Disable MOV DR Exit | DR access VM-Exit storm | 🟢 Performance optimization |
| 8 | Exception Bitmap = 0 | Unnecessary exception interception | 🟢 Performance optimization |

**Causal Chain**:

```
Fix #1 (Interrupt Re-injection) resolved:
  IPIs no longer lost → DPCs dispatched correctly → CPU 1 receives initialization DPC → VMLAUNCH succeeds

Fix #2 (HLT Activity State) resolved:
  Interrupts no longer delivered in VMX root mode → Host stack remains intact →
  VM-Exit handler runs normally → Interrupts injected back to the Guest correctly →
  Scheduler/Timers/Device Drivers function normally → System no longer freezes
```

### Part 2: EPT Hook Engine & Driver Framework Bugs

| # | Resolution | Resolved Issue | Impact |
|---|------|-----------|------|
| A | Trampoline instruction boundary alignment | Truncated instructions → #UD → BSOD | 🔴 Fatal crash during hook |
| B | HandleMtf per-CPU tracking | Multi-core MTF race → infinite EPT Violation loop | 🔴 Deadlock during multi-core hook |
| C | INVEPT after EptSplitLargePage | Outdated TLB → EPT Misconfiguration → BSOD | 🔴 Random crash during initial hook |
| D | Initialize IoStatus.Information | Dirty value → information disclosure or out-of-bounds copy | 🟡 Triggered when IOCTL fails |

---

## Complete List of Modified Files

| File | Source | Changes |
|------|------|---------|
| `driver/vmx.h` | Part 1 | Added `IoBitmapAVa/Pa` and `IoBitmapBVa/Pa` fields to `VMX_CPU_CONTEXT` |
| `driver/vmx_init.c` | Part 1 | `VmxAllocateCpuContext()`: Allocate I/O Bitmaps A and B (4KB each, all zeros) |
| `driver/vmx_init.c` | Part 1 | `VmxFreeCpuContext()`: Free I/O Bitmaps A and B |
| `driver/vmx_init.c` | Part 1 | `VmxSetupVmcs()`: Enable `PROC_BASED_USE_IO_BITMAPS` and write physical addresses of I/O Bitmaps |
| `driver/vmx_init.c` | Part 1 | `VmxSetupVmcs()`: Disabled `CR3_LOAD_EXIT` and `MOV_DR_EXIT`, set Exception Bitmap to 0 |
| `driver/vmx_init.c` | Part 1 | `VmxInitialize()`: Added direct `DbgPrintEx` diagnostics after the initialization loop |
| `driver/vmx_exit.c` | Part 1 | `EXIT_REASON_HLT`: Refactored V1 (NOP) → V2 (`__halt()`) → V3 (Activity State = HLT) |
| `driver/vmx_exit.c` | Part 1 | `EXIT_REASON_EXTERNAL_INT`: Refactored discard → re-injection, including HLT wake-up logic |
| `driver/vmx_exit.c` | Part 1 | `EXIT_REASON_INT_WINDOW`: Added pending interrupt injection |
| `driver/vmx_exit.c` | Part 1 | NMI handler: Added HLT Activity State wake-up in deferred paths |
| `driver/vmx_exit.c` | Part 2 | `HandleMtf`: Modified to use per-CPU tracking to only restore pages relaxed by the current CPU |
| `driver/ept.c` | Part 2 | Added `EptGetInstructionLength()` (~300-line x64 instruction decoder) |
| `driver/ept.c` | Part 2 | Modified trampoline construction: replaced 14-byte hardcoding with instruction boundary alignment (≥12 bytes) |
| `driver/ept.c` | Part 2 | Added `g_MtfRelaxedPagePa[64]` per-CPU tracking array and helper functions |
| `driver/ept.c` | Part 2 | `HandleEptViolation`: Added `EptMtfTrackRelaxedPage` calls in both execution paths |
| `driver/ept.c` | Part 2 | `EptHookFunction()`: Added `EptInvalidateFromGuest()` after `EptSplitLargePage()` |
| `driver/ept.h` | Part 2 | Declared `EptGetInstructionLength`; expanded `OriginalBytes[16]` to `OriginalBytes[32]` |
| `driver/ept.h` | Part 2 | Declared `EptMtfTrackRelaxedPage` and `EptMtfGetAndClearRelaxedPage` |
| `driver/npt.c` | Part 2 | Replaced 14-byte hardcoding with instruction boundary alignment + out-of-bounds protection (consistent with `ept.c`) |
| `driver/vmxdrv.c` | Part 2 | `DispatchDeviceControl`: Added `Irp->IoStatus.Information = 0` before switch |

---

## Compilation Compatibility Notes

This project uses the **WDK 7600** (Windows 7 DDK), whose MSVC compiler mandates **C89-style** variable declarations (all variables must be declared at the beginning of a block, not interspersed with statements).

All local variables in the `EptGetInstructionLength()` function have been moved to the beginning of the function:

```c
ULONG EptGetInstructionLength(PUCHAR Code)
{
    ULONG   Pos = 0;
    BOOLEAN HasRex = FALSE;
    BOOLEAN OperandSize66 = FALSE;
    BOOLEAN AddressSize67 = FALSE;
    UCHAR   Rex = 0;
    UCHAR   Opcode;
    UCHAR   ModRM;
    UCHAR   Mod, RM;
    BOOLEAN HasModRM = FALSE;
    ULONG   ImmSize = 0;
    UCHAR   b, Op2, Group, SubOp, SIB, SibBase, EffRM;
    // ...function body...
}
```

All other modifications (per-CPU arrays, I/O Bitmaps, interrupt injection, etc.) are free of C89 compatibility issues.

---

## Key Lessons Learned

### 1. Interrupt Handling is the absolute core of a Blue Pill Hypervisor

Under the Blue Pill architecture, the Guest is the original OS. **All interrupts must be correctly delivered back to the Guest**, including:
- Timer interrupts (critical for the scheduler)
- IPIs (critical for inter-processor communication)
- Device interrupts (critical for driver operation)
- NMIs (critical for system diagnostic checks)

If any type of interrupt is discarded, it leads to malfunctioning or a complete system freeze.

### 2. Never Deliver Interrupts in VMX Root Mode

VMX root mode runs on a dedicated Host stack (which is typically very small). Delivering interrupts through the Host IDT causes:
- The ISR to execute on the wrong stack
- Potential stack overflows
- Disruption of the VM-Exit handler's execution flow
- Unrecoverable system states

The correct approach is to utilize the hardware mechanisms provided by Intel VT-x (`VM-Entry injection`, `Activity State`, `interrupt-window exiting`) to deliver interrupts in **Guest mode**.

### 3. The must-be-1 Bits in Nested Virtualization Must Be Fully Handled

Control bits forced to 1 by VMware via MSRs like `IA32_VMX_PROCBASED_CTLS` are not optional — **they must be handled correctly**. For every forced-on VM-Exit source, the handler must implement correct behavior; otherwise, it is a ticking time bomb.

### 4. EPT Operations in Multi-Core Environments Require Precise Synchronization

EPT page tables are global structures shared by all CPUs:
- **INVEPT is mandatory after modifying page tables**: Otherwise, other CPUs will have stale TLB entries → EPT Misconfiguration.
- **MTF restoration must be isolated per-CPU**: Otherwise, one CPU's MTF processing will corrupt another CPU's active EPT permission transitions.
- **Instruction boundaries must be calculated precisely**: The variable-length nature of x86-64 instructions means byte counts cannot be hardcoded.

### 5. Superficial Fixes vs. Systematic Reviews

The early iterations of "disabling CR3 Exits" and "disabling DR Exits" only mitigated symptoms without addressing the core issues. Resolving the problems fully required:
1. Listing all VM-Exit types and their corresponding handlers.
2. Verifying the correctness of each handler individually.
3. Paying special attention to interrupt/exception handling paths (which are the most error-prone and have the highest impact).
4. Paying special attention to multi-core race condition paths (which cannot be reproduced in single-core testing).

### 6. The Logging System Can Also Be a Victim

When interrupt handling is broken, the log-flushing thread (which relies on scheduler interrupts) might not run. **Adding direct `DbgPrintEx` calls in critical paths** (bypassing ring buffers) is vital for debugging.

### 7. Defensive Programming: Initialize All Output Fields

Leaving `IoStatus.Information` uninitialized in the IOCTL handler might seem minor, but it can lead to kernel information disclosure or a BSOD on failure paths. **All output fields should be uniformly initialized to a safe value (e.g., 0) prior to dispatching.**

---

## Open Questions / Items to Confirm

1. **Bug #A - Instruction Decoder Coverage**: The current decoder covers the vast majority of common instruction prefixes found in kernel function headers. If a target function uses extremely rare instruction prefixes (e.g., SSE/AVX), the decoder returns 0 and safely rejects the hook installation. Is there a need to expand this coverage?

2. **Bug #B - per-CPU Array Size**: Currently hardcoded to 64 processor slots. If a system has more than 64 logical processors (e.g., large servers), CPUs out of range will not be tracked (falling back to restoring all hooks). Do we need to allocate this dynamically or increase the limit?

3. **Bug #C - INVEPT Timing**: Currently uses a generation counter + lazy INVEPT mechanism. Theoretically, there is a small window of vulnerability between `EptSplitLargePage` and the next VM-Exit on other CPUs. Do we need a more aggressive synchronization mechanism (e.g., IPI)?

---

*End of Document.*
