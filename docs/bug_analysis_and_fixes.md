[简体中文](bug_analysis_and_fixes_CN.md) | English

# VMXHypervisorToolbox Bug Analysis and Fix Report

> **Date**: 2026-04-11  
> **Affected Modules**: EPT Hook Engine / VMX Exit Handler / Driver IOCTL Dispatch  
> **Status**: Pending Review

---

## Table of Contents

- [Bug #1: Trampoline Instruction Truncation Leading to #UD → BSOD](#bug-1-trampoline-instruction-truncation-leading-to-ud--bsod)
- [Bug #3: HandleMtf Multi-core Race Condition Leading to Infinite EPT Violation Loop](#bug-3-handlemtf-multi-core-race-condition-leading-to-infinite-ept-violation-loop)
- [Bug #5: Missing INVEPT after EptSplitLargePage Leading to EPT Misconfiguration](#bug-5-missing-invept-after-eptsplitlargepage-leading-to-ept-misconfiguration)
- [Bug #6: Uninitialized IoStatus.Information in IOCTL Dispatch](#bug-6-uninitialized-iostatusinformation-in-ioctl-dispatch)
- [Modified Files List](#modified-files-list)
- [Compilation Compatibility Notes](#compilation-compatibility-notes)
- [Pending Confirmations](#pending-confirmations)

---

## Bug #1: Trampoline Instruction Truncation Leading to #UD → BSOD

### Severity: 🔴 Critical

### Problem Description

When `EptHookFunction()` constructs a trampoline, it needs to "steal" at least 12 bytes from the head of the target function (`48 B8 [imm64] FF E0` = MOV RAX, addr; JMP RAX). It then copies these original bytes into the trampoline, and appends a JMP instruction at the end of the trampoline to jump back to the original function + 12 bytes.

**Original Code** hardcoded copying 14 bytes:

```c
// Original code (buggy)
Hook->OriginalBytesSize = 14;  // Hardcoded
RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, 14);
```

This presents a fatal issue: x86-64 instructions are **variable-length** (1 to 15 bytes), and 14 bytes could easily cut through the middle of an instruction. For example:

```
Target function prefix:
  48 89 5C 24 08    MOV [RSP+8], RBX     (5 bytes)
  48 89 6C 24 10    MOV [RSP+10h], RBP   (5 bytes)
  48 89 74 24 18    MOV [RSP+18h], RSI   (5 bytes)  ← The 14th byte falls in the middle of this instruction!
```

The trampoline would execute the truncated `48 89 74`, and then jump into garbage bytes, resulting in an `#UD` (Undefined Opcode) exception in kernel-mode, triggering a **BSOD**.

### Fix

1. **Implement the `EptGetInstructionLength()` function**: A minimal x64 instruction length decoder (~300 lines of code) that covers all common instructions found in kernel function prefixes:
   - Prefix parsing: Legacy prefixes (LOCK/REP/Segment override), 66h/67h, REX prefixes (40h to 4Fh).
   - Single-byte opcodes: PUSH/POP reg, MOV reg, imm, JMP/CALL rel, ALU operations (ADD/SUB/XOR/CMP/etc.), Group 1/3/5, Shift/Rotate, etc.
   - Double-byte opcodes (0Fh): Jcc rel32, MOVZX/MOVSX, CMOVcc, SETcc, NOP (multi-byte), SYSCALL, etc.
   - Complete ModRM + SIB + Displacement decoding.

2. **Modify the trampoline construction logic in `EptHookFunction()`**:

```c
// Fixed code
{
    ULONG TotalLen = 0;
    PUCHAR Code = (PUCHAR)TargetVa;
    while (TotalLen < 12) {                          // Cover at least 12 bytes
        ULONG InsnLen = EptGetInstructionLength(Code + TotalLen);
        if (InsnLen == 0) {
            // Cannot decode instruction → exit safely without installing hook
            LOG_ERROR("EPT Hook: Cannot decode instruction at VA 0x%llX + 0x%X",
                      TargetVa, TotalLen);
            // ...release resources...
            return STATUS_UNSUCCESSFUL;
        }
        TotalLen += InsnLen;
    }
    Hook->OriginalBytesSize = TotalLen;              // Can be 12, 13, 14, 15...
}
RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, Hook->OriginalBytesSize);
```

**Key Improvements**:
- Accumulate the length instruction by instruction until the total length is ≥ 12 bytes.
- Ensure that no instruction is truncated.
- Safely exit if an instruction cannot be decoded, rather than copying blindly and causing a crash.

### Additional Fix: OriginalBytes Buffer Overflow Protection

In the original fix, `TotalLen` is aligned to instruction boundaries and is variable (12, 13, 14, 15...). However, `Hook->OriginalBytes` was only declared as `UCHAR[16]`. In extreme cases (e.g., if the function prefix contains long instructions), `TotalLen` could exceed 16 bytes. This would lead to an out-of-bounds write during `RtlCopyMemory`, corrupting subsequent fields of the structure (such as the `HookFunction` pointer, etc.).

**Additional Fix Details**:

1. **Increase Buffer Size**: Change `OriginalBytes[16]` to `OriginalBytes[32]`. (The maximum length of a single x64 instruction is 15 bytes. Theoretically, the maximum `TotalLen` = 11 + 15 = 26 bytes, so a 32-byte buffer provides plenty of headroom and alignment margin.)

2. **Add Out-of-Bounds Check**: Check if adding the next instruction length will exceed the buffer size before accumulating it in the loop:

```c
if (TotalLen + InsnLen > sizeof(((EPT_HOOK_ENTRY*)0)->OriginalBytes)) {
    LOG_ERROR("EPT Hook: OriginalBytes overflow at VA 0x%llX "
              "(TotalLen=%u + InsnLen=%u > %u)",
              TargetVa, TotalLen, InsnLen,
              (ULONG)sizeof(((EPT_HOOK_ENTRY*)0)->OriginalBytes));
    // ...release resources...
    return STATUS_BUFFER_TOO_SMALL;
}
```

3. **Synchronize AMD-V Side (`npt.c`)**: `NptHookFunction()` originally hardcoded `OriginalBytesSize = 14`, suffering from the same instruction truncation issue. It has been replaced with the same instruction boundary alignment and out-of-bounds protection logic as in `ept.c`.

### Affected Files

| File | Changes |
|------|------|
| `driver/ept.c` | Added `EptGetInstructionLength()` function implementation (~300 lines); modified trampoline construction logic; added out-of-bounds protection check. |
| `driver/ept.h` | Added `EptGetInstructionLength` function prototype; changed `OriginalBytes[16]` to `OriginalBytes[32]`. |
| `driver/npt.c` | Replaced hardcoded 14-byte copy with instruction boundary alignment and out-of-bounds protection (matching `ept.c`). |

---

## Bug #3: HandleMtf Multi-core Race Condition Leading to Infinite EPT Violation Loop

### Severity: 🔴 Critical

### Problem Description

The EPT Hook engine utilizes **execute-only** pages to implement hidden hooks:
- Normal state: Hooked page `R=0, W=0, X=1` (execute-only, no read/write access).
- Data access (e.g., PatchGuard scanning): EPT Violation → switch to the original page `R=1, W=1, X=0` → enable MTF (Monitor Trap Flag) → after executing one instruction, MTF fires → restore to the hooked page `R=0, W=0, X=1`.

**Original `HandleMtf` Code** restored **all 1024 hooks** when MTF fired:

```c
// Original code (buggy)
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    // ...disable MTF...
    
    // Iterate through all hooks and restore them all
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
            PEPT_PTE Pte = g_EptHookState.Hooks[i].TargetPte;
            if (Pte->Read || Pte->Write) {
                Pte->Read = 0;
                Pte->Write = 0;
                // ...restore hook page...
            }
        }
    }
}
```

**Multi-core Race Condition Scenario**:

```
Timeline:
  T1: CPU 0 → EPT Violation on Hook A → switch to R=1, W=1 → enable MTF
  T2: CPU 1 → EPT Violation on Hook B → switch to R=1, W=1 → enable MTF
  T3: CPU 0 → MTF fires → restore ALL hooks (including Hook B!) → Hook B changes back to R=0, W=0
  T4: CPU 1 → before finishing that single data access instruction → triggers another EPT Violation (Hook B)
  T5: CPU 1 → switch back to R=1, W=1 → enable MTF
  T6: CPU 0 → potentially another MTF → restore ALL hooks again...
  → Infinite loop! CPU 1 can never finish executing that instruction.
```

### Fix

Introduce a **per-CPU tracking mechanism**, so that each CPU only restores the hook on the page **that it specifically relaxed (unprotected)**:

**1. Add per-CPU tracking arrays and helper functions in `ept.c`**:

```c
// Record the physical page currently relaxed by each CPU slot
static volatile ULONG64 g_MtfRelaxedPagePa[64] = { 0 };

// Called by HandleEptViolation: record the page relaxed by the current CPU
VOID EptMtfTrackRelaxedPage(ULONG64 PagePhysicalAddr)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    if (CpuIndex < 64) {
        g_MtfRelaxedPagePa[CpuIndex] = PagePhysicalAddr;
    }
}

// Called by HandleMtf: retrieve and clear the page relaxed by the current CPU
ULONG64 EptMtfGetAndClearRelaxedPage(VOID)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    ULONG64 Pa = 0;
    if (CpuIndex < 64) {
        Pa = g_MtfRelaxedPagePa[CpuIndex];
        g_MtfRelaxedPagePa[CpuIndex] = 0;
    }
    return Pa;
}
```

**2. Record the relaxed page each time a page is relaxed in `HandleEptViolation`**:

```c
// Inside EPT Violation handler (added in both Mode A and Mode B execution paths)
EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);  // ← Added
ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
```

**3. Modify `HandleMtf` to only restore the page associated with the current CPU**:

```c
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    // ...disable MTF...
    
    // Retrieve the page relaxed by the current CPU
    RelaxedPa = EptMtfGetAndClearRelaxedPage();
    
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
            // ★ Only restore the page relaxed by the current CPU, skip others
            if (RelaxedPa != 0 &&
                g_EptHookState.Hooks[i].TargetPhysicalAddr != RelaxedPa) {
                continue;
            }
            // ...restore hook...
        }
    }
}
```

**Fallback Safety Net**: If `RelaxedPa == 0` (which theoretically should not happen), fall back to restoring all hooks to prevent any pages from remaining permanently relaxed.

### Affected Files

| File | Changes |
|------|------|
| `driver/ept.c` | Added `g_MtfRelaxedPagePa[64]` array; added `EptMtfTrackRelaxedPage()`; added `EptMtfGetAndClearRelaxedPage()`; added `EptMtfTrackRelaxedPage` call in both execution paths inside `HandleEptViolation`. |
| `driver/ept.h` | Added declarations for `EptMtfTrackRelaxedPage` and `EptMtfGetAndClearRelaxedPage`. |
| `driver/vmx_exit.c` | Modified `HandleMtf` to query the per-CPU tracking array and only restore the specified page. |

---

## Bug #5: Missing INVEPT after EptSplitLargePage Leading to EPT Misconfiguration

### Severity: 🔴 Critical

### Problem Description

Before installing a hook, `EptHookFunction()` must split the 2MB large page containing the target address into 512 4KB pages (since hooks require fine-grained page-level permission control). The splitting operation is performed via `EptSplitLargePage()`, which modifies the EPT Page Directory Entry (PDE), changing it from a 2MB large page entry to point to a new 4KB page table.

**Original Code** did not invalidate the EPT TLB after splitting:

```c
// Original code (buggy)
EptSplitLargePage(TargetPa);
// ← Missing INVEPT!
Pte = EptGetPteForPhysicalAddress(TargetPa);  // Retrieve the 4KB PTE
```

**Issue**:

```
CPU 0:  Executes EptSplitLargePage()
        → Modifies PDE: 2MB large page entry → points to new 4KB page table
        
CPU 1-N: Still have the old 2MB PDE cached in their TLB
        → On the next memory access, these CPUs interpret the new data using the old 2MB PDE format
        → PDE format mismatch with the new Page Table → EPT Misconfiguration
        → VMX shutdown → BSOD (BSOD code is typically UNEXPECTED_STORE_EXCEPTION or similar)
```

Unlike EPT Violation (which is a permission issue and is recoverable), EPT Misconfiguration indicates an invalid page table structure (which is typically unrecoverable, causing the CPU to shut down VMX directly).

### Fix

Execute `EptInvalidateFromGuest()` **immediately** after calling `EptSplitLargePage()` to flush the EPT TLB on all CPUs:

```c
// Fixed code
EptSplitLargePage(TargetPa);

/*
 * BUG FIX: After splitting a 2MB page into 4KB pages, other CPUs may
 * still have stale TLB entries pointing to the old 2MB PDE.  If they
 * access memory in this range before seeing the new 4KB PTEs, the CPU
 * will detect an EPT Misconfiguration (the old PDE format doesn't match
 * the new PT) and trigger HandleEptMisconfig → VMX shutdown → BSOD.
 *
 * Fix: Invalidate EPT TLB immediately after page split so all CPUs
 * pick up the new page table structure before any further accesses.
 */
EptInvalidateFromGuest();  // ← Added

Pte = EptGetPteForPhysicalAddress(TargetPa);
```

> **Note**: `EptInvalidateFromGuest()` uses a generation counter mechanism (`InterlockedIncrement`), where each CPU checks and executes `INVEPT` on its next VM-Exit. This approach is more compatible than invoking VMCALLs directly (avoiding interception issues under nested virtualization environments like VMware).

### Affected Files

| File | Changes |
|------|------|
| `driver/ept.c` | Added `EptInvalidateFromGuest()` call immediately after `EptSplitLargePage()` inside `EptHookFunction()`. |

---

## Bug #6: Uninitialized IoStatus.Information in IOCTL Dispatch

### Severity: 🟡 Medium

### Problem Description

The `DispatchDeviceControl` function handles user-mode IOCTL requests using `METHOD_BUFFERED`. Under this method, the `Irp->IoStatus.Information` field informs the I/O manager of the number of bytes to copy back from the system buffer to the user-mode buffer.

**Original Code** did not initialize this field prior to dispatching:

```c
// Original code (buggy)
IoStack = IoGetCurrentIrpStackLocation(Irp);
IoControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;
// ← Irp->IoStatus.Information is not initialized

switch (IoControlCode) {
    case IOCTL_VMX_INIT:
        Status = HandleIoctlInit(Irp, IoStack);
        break;
    // ...
    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
}
```

**Issue**:
- Success paths: Individual handlers typically set `Information` correctly → No issue.
- **Failure paths**: If a handler returns an error status but forgets to set `Information`, or if the control flow hits the `default` branch:
  - `Information` remains uninitialized (potentially holding stale/dirty data from a recycled IRP).
  - The I/O manager copies data to user-mode based on this stale value → **Information Leak** (kernel memory leaked to user-mode).
  - Alternatively, if the stale value is very large → Out-of-bounds copy → **BSOD**.

### Fix

Initialize the field in a unified manner before the `switch` dispatch:

```c
// Fixed code
IoStack = IoGetCurrentIrpStackLocation(Irp);
IoControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;

/*
 * BUG FIX: Initialize IoStatus.Information to 0 before dispatching.
 * Individual handlers set it to the correct output size on success.
 * Without this, on failure paths where handlers don't set Information,
 * the I/O manager would copy garbage data back to the user-mode buffer
 * (METHOD_BUFFERED uses Information as the output byte count).
 */
Irp->IoStatus.Information = 0;  // ← Added

switch (IoControlCode) {
```

This ensures that even if a handler fails to set `Information`, no data leakage or out-of-bounds copy occurs.

### Affected Files

| File | Changes |
|------|------|
| `driver/vmxdrv.c` | Added `Irp->IoStatus.Information = 0` before the `switch` statement in `DispatchDeviceControl`. |

---

## Modified Files List

| File | Bug # | Change Summary |
|------|-------|----------------|
| `driver/ept.c` | #1 | Added `EptGetInstructionLength()` function (~300 lines minimal x64 instruction decoder). |
| `driver/ept.c` | #1 | Modified trampoline construction logic: changed from a hardcoded 14-byte copy to accumulating ≥12 bytes aligned to instruction boundaries. |
| `driver/ept.c` | #3 | Added `g_MtfRelaxedPagePa[64]` per-CPU tracking array. |
| `driver/ept.c` | #3 | Added `EptMtfTrackRelaxedPage()` and `EptMtfGetAndClearRelaxedPage()`. |
| `driver/ept.c` | #3 | Added `EptMtfTrackRelaxedPage` calls in both paths (Mode A / Mode B) of `HandleEptViolation`. |
| `driver/ept.c` | #5 | Added `EptInvalidateFromGuest()` after `EptSplitLargePage()` in `EptHookFunction()`. |
| `driver/ept.h` | #1 | Added declaration for `EptGetInstructionLength`. |
| `driver/ept.h` | #3 | Added declarations for `EptMtfTrackRelaxedPage` and `EptMtfGetAndClearRelaxedPage`. |
| `driver/vmx_exit.c` | #3 | Modified `HandleMtf` to call `EptMtfGetAndClearRelaxedPage()` and only restore the page relaxed by the current CPU. |
| `driver/vmxdrv.c` | #6 | Added `Irp->IoStatus.Information = 0` before the `switch` statement in `DispatchDeviceControl`. |

---

## Compilation Compatibility Notes

This project targets **WDK 7600** (Windows 7 DDK), whose MSVC compiler mandates **C89-style** variable declarations (all variables must be declared at the beginning of a block, rather than interspersed among statements).

All local variables inside the `EptGetInstructionLength()` function have been moved to the beginning of the function:

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
    UCHAR   b;        // Used within loops
    UCHAR   Op2;      // Two-byte opcode
    UCHAR   Group;    // ALU grouping
    UCHAR   SubOp;    // ALU sub-opcode
    UCHAR   SIB;      // SIB byte
    UCHAR   SibBase;  // SIB.Base field
    UCHAR   EffRM;    // Effective RM (including REX.B extension)
    // ...function body...
}
```

All other modifications (per-CPU arrays, `Information` initialization, etc.) do not introduce C89 compatibility issues.

---

## Pending Confirmations

1. **Bug #1 - Instruction Decoder Coverage**: The current decoder covers the vast majority of common instructions found in kernel function prefixes. If a target function utilizes extremely rare instruction prefixes (such as SSE/AVX, etc.), the decoder will return 0 and safely reject the hook installation. Is there a need to expand the instruction coverage?

2. **Bug #3 - per-CPU Array Size**: Currently hardcoded to 64 processor slots. If the system has more than 64 logical processors (such as on large servers), any CPU beyond this range cannot be tracked (falling back to restoring all hooks). Should we allocate this dynamically or increase the upper limit?

3. **Bug #5 - INVEPT Timing**: Currently relies on a generation counter + lazy INVEPT mechanism. Theoretically, there is a small timing window between `EptSplitLargePage` and the next VM-Exit. Do we need a more aggressive synchronization mechanism (e.g., IPI)?

---

*End of document. Please review the above analysis and fixes.*
