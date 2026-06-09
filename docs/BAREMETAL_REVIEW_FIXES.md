[简体中文](BAREMETAL_REVIEW_FIXES_CN.md) | English

# Bare-Metal Run Stability Review & Fixes Log

This document summarizes the **code review findings** and **corresponding fixes** for VMX/SVM virtualization and the hook engine in bare-metal execution scenarios in April 2026. Please cross-reference this with the fix tags labeled as `H-#` / `M-#` / `L-#` / `C-#` in the source code comments.

Total fixes: **17 + 19 remedies** (First round: 6 High + 5 Medium + 3 Low + 3 Cross-platform; Second round: 19 review remedies). All changes are idempotent or platform-specific for both Intel and AMD platforms. For API modifications, please refer to the "Important API Changes" at the end of this document.

---

## Second Round Review (post-2nd-review) Remedies

After the first round of fixes, a more rigorous secondary review was conducted, revealing several **incomplete features / uncovered boundary conditions**. All of these have been reworked:

### Critical (Will cause BSOD or render fixes completely ineffective)

1. **Missing SVM VMSAVE/VMLOAD host state** — The original `AsmSvmLaunch` only executed `VMLOAD guest VMCB` to load the guest values of FS/GS/TR/LDTR.base, KernelGsBase, and SYSCALL MSRs into the CPU. After VMEXIT, these registers **remained as guest values**. As a result, the Windows kernel would immediately BSOD upon reading `gs:KPCR` during the first C handler invocation.  
   Fix: Added a separate `HostVmcbPa` (distinct from HSAVE). Executed `VMSAVE [HostVmcbPa]` once during startup. After each VMEXIT, the sequence is: `VMSAVE [guestVmcb] → VMLOAD [hostVmcb] → STGI` (the order is critical: save guest extra state first, then restore host extra state) before entering the C code. The signature was updated to `AsmSvmLaunch(VmcbPa, VmcbVa, HostVmcbPa)`.

2. **Erroneous `HvAdvanceGuestRip` after `#UD` injection** — In `SvmHandleVmmcall`, a `#UD` was injected followed by calling `AdvanceRip`, which caused the guest's saved RIP for the `#UD` to skip the `VMMCALL` instruction. This resulted in unpredictable behavior.  
   Fix: Since `#UD` is a fault, `AdvanceRip` must **not** be called after injection. All occurrences of `HvInjectException + HvAdvanceGuestRip` combinations have been decoupled.

3. **`EptInvalidateAllCpusSync` CPUID callback fails during teardown** — If the CPU has already executed VMXOFF, CPUID will not trigger a VMEXIT, and the TLB will not be flushed.  
   Fix: Inside the IPI callback, `EptInvalidateAllContexts()` is called **directly** (INVEPT is legal in root mode), and a guard check for `g_VmxState.Initialized` has been added. On the SVM side, because `INVLPGA` lacks the ability to flush the entire page table, CPUID is still used to force the VMEXIT/VMRUN path, but it is now protected by a `g_SvmState.Initialized` guard to prevent redundant overhead during teardown.

4. **Missing CR3 verification in `NptDbMatchesRelaxedRip`** — A `#DB` on different processes or threads on the same CPU could happen to have its RIP fall within the 15-byte instruction window, leading to erroneous suppression/consumption of the exception.  
   Fix: Added `g_NptDbRelaxedCr3[]` to the tracker. The write sequence of `Pa, Rip, Cr3` is modified using `_WriteBarrier()` to ensure that the "arm flag (PagePa) is written last". The reader side uses `_ReadBarrier()`. When comparing CR3 values, the PCID is masked out to ensure consistency.

5. **Overly conservative `CleanBits = 0` in `SvmApplyExceptionIntercepts`** — This caused the next `VMRUN` to reload the entire VMCB state (impacting performance) and introduced a race condition with in-flight `VMRUN`s.  
   Fix: Changed it to `InterlockedAnd(&CleanBits, ~(1UL << 0))` to clear only the INTERCEPTS bit. The `InterceptExceptions` field is now written atomically using a 32-bit aligned write. The lazy-init pattern has been completely removed, replaced by `SvmInterceptLockInitialize()` which performs one-time initialization at the beginning of `SvmInitialize`.

6. **VMCALL/VMMCALL nonce validation only checks CPL** — Failed to check long mode / CS.L / kernel-half RIP; 32-bit compatibility-mode ROP gadgets could still bypass this check.  
   Fix: Refactored into a unified helper `HvIsAuthenticShutdownCaller(Rcx, Rip, Cpl, Efer, CsL)` that validates: nonce, EFER.LMA, CS.L, CPL==0, and RIP ≥ 0xFFFF_8000_0000_0000. Both VMX and SVM call this same helper.

7. **`HandleEptViolation` fixup used `EptInvalidateFromGuest`** — Only bumped the generation counter. When the current CPU executes VMRESUME to go back to the same instruction, the TLB was still stale, **immediately** triggering another violation → infinite loop.  
   Fix: Restored `EptInvalidateAllContexts()` to flush the current CPU immediately, followed by calling `EptInvalidateFromGuest()` to notify other CPUs.

8. **VMX/SVM `VMCALL_SUBCMD_READ/WRITE_MEMORY` routed to disabled stubs** — In the stubs, `HvAdvanceGuestRip+return TRUE` made the caller assume success; it should fail explicitly.  
   Fix: Both platforms now directly inject a `#UD` for this subcmd instead of invoking the stub.

### Medium Remedies

9. **Missing DR6.BS during NPT #DB reinjection** — The Guest's `#DB` handler reads DR6 to distinguish between Single-Step (TF) and hardware breakpoints. However, the hardware does not write to DR6 for "injected" `#DB`s.  
   Fix: Before injection, set `Vmcb->Save.Dr6 = 0xFFFF0FF0 | (1<<14)` (reserved-1 + BS).

10. **Race condition in SVM exception intercept lazy-init** — `g_SvmInterceptLockInited` lacked Interlocked protection.  
    Fix: Call `SvmInterceptLockInitialize()` synchronously at the beginning of `SvmInitialize()`, removing the lazy-init branch.

11. **Incomplete Activity-State constraints in `HandleHlt`** — Only checked RFLAGS.IF + STI/MOV-SS shadow. Intel SDM §26.3.1.5 also requires that `VMCS_GUEST_PENDING_DBG_EXCEPTIONS == 0`.  
    Fix: Added validation for this field; otherwise, remain in the Active state.

12. **AAD_HIDE_EXCEPTIONS never worked on the VMX side** — VMX `EXCEPTION_BITMAP = 0` and lacked a dynamic update mechanism, meaning `#BP` would never trigger a VMEXIT when a process enabled `AAD_HIDE_EXCEPTIONS`.  
    Fix: Provided symmetric `VmxSetExceptionInterceptBp / VmxSetExceptionInterceptDb` APIs, maintaining a global expected mask and a per-CPU "applied gen" counter. The VMEXIT handler lazy-syncs at the top using `VmxSyncExceptionBitmap()` (no IPIs, no VMCS ownership switching).

13. **Hard dependency from process.c on svm.h** — `ProcessSyncSvmInterceptsAfterConfigChange` directly invoked `SvmSetExceptionInterceptBp` — tight coupling across modules.  
    Fix: `process.c` now exports `ProcessRegisterExceptionHideToggle(Callback)`. SVM/VMX register their respective callbacks at the end of their initialization, and `process.c` no longer includes `svm.h`.

14. **Insufficient comments on `FreeThunk` timing + failure to guarantee instruction cache (icache) correctness** — Required documenting an RCU-like contract specifying "zero-safety after IPI synchronization".  
    Fix: The `GenericHookRemove` path is: `HvUnhookFunction` (which internally does `Ept/NptInvalidateAllCpusSync`) → acquire lock → `FreeThunk`. The sequence is correct, and detailed comments have been added to establish this contract.

15. **Infinite wait in SVM DPC** — `SvmInitDpcRoutine` similarly used a `NULL` timeout. If the DPC hung, the upper-level `goto InitFailed` would free the stack-allocated `DpcCtx`, leading to corruption.  
    Fix: Aligned with the VMX side: use a 60-second sliced wait. If timed out → `KeRemoveQueueDpc`. If the DPC has already started, **wait indefinitely for completion** (to prevent stack corruption, choosing to hang and wait for the OS watchdog instead).

16. **`hv_mem.c/SafeReadPhysU64` dereferenced PA as a pointer** — Even though the comments stated "only used for page-table walks", it was still unsafe under VMX root mode.  
    Fix: Switched to `MmGetVirtualForPhysical(Pa)` to retrieve the OS-mapped VA. Added a `KeGetCurrentIrql() > DISPATCH_LEVEL` guard check at the top of `HvGuestVaToPa`, returning 0 if mistakenly invoked under root mode.

17. **Failure paths for `g_NptDbRelaxedRip` failed to release allocated memory** — `NptInitialize` has 5 early-return paths, multiple of which only released `PagePa` but leaked `Rip`.  
    Fix: Added release logic for both `Rip` and `Cr3` in every path.

18. **VMX Exception Bitmap did not perform per-CPU synchronization** — After changing the global expected value, there must be a mechanism to apply the changes to each CPU's VMCS. IPI + VMCLEAR/VMPTRLD is too heavy.  
    Fix: Implemented a lazy-sync design (using a generation counter + comparison at the top of the VMEXIT handler). This requires no IPIs and zero `VMWRITE`s in the steady state.

19. **Added `AsmVmxVmcall2` interface** — Added support for a 2-parameter nonce `VMCALL`. Symmetrically added `AsmSvmVmmcall2` for SVM.

---

## First Round Review Fixes

## P0 — Critical Fixes (Affecting Functionality / Stability)

### C-5 · `AsmSvmLaunch` Lacks a Genuine VMRUN Loop → AMD Platform Completely Non-functional

| Location | `driver/svm_asm.asm` |
|------|----------------------|
| Problem | The original `AsmSvmLaunch` returned immediately after executing `VMRUN` once, without calling `SvmExitHandler` or looping. After the guest's first VMEXIT, the DPC would misinterpret it as a "VMRUN failure" and immediately run `SvmDisableOnCpu` → **The SVM subsystem in fact never functioned**. |
| Fix | Rewrote `AsmSvmLaunch` into a genuine blue-pill loop: allocating a `GUEST_CONTEXT` on the stack along with a dedicated anchor slot (VMCB PA/VA). For each VMEXIT, it saves general-purpose (GP) registers → calls `SvmExitHandler` → resumes VMRUN or exits gracefully based on the return value.<br>• The initial VMRUN uses `VMCB.Save.Rip = _SvmLaunchGuest` + `Save.Rsp = current RSP` to allow the Guest to return naturally from the DPC — "Windows becomes the Guest".<br>• All 15 context-tracked GP registers are passed back and forth via `GUEST_CONTEXT` in each iteration. Anchors are stored in stack slots rather than CPU registers, avoiding the trap where VMRUN does not save or restore GP registers. |
| Verification Points | The guest should continue to run normally after loading the driver on bare-metal AMD EPYC / Ryzen systems. The logs from `SvmExitHandler` will show the flow of ExitCodes (CPUID, CR3 write, NPF, etc.). |

### C-1 · SVM Lacks CR3 Write Interception → AAD TSC Offsetting Fails

| Location | `driver/svm_init.c` `SvmSetupVmcb` |
|------|-----------------------------------|
| Fix | Set `InterceptCr |= (1 << SVM_INTERCEPT_CR3_WRITE)`. The AAD `AadUpdateHwTscOffset` logic, which updates the TSC Offset during process context switches, now works on AMD. |

### C-2 · SVM HLT Intercept Only Advances RIP → 100% CPU Usage

| Location | `driver/svm_init.c` `SvmSetupVmcb` |
|------|-----------------------------------|
| Fix | Removed `SVM_INTERCEPT_HLT` from the `Intercept` bitmap. The CPU hardware now handles the Guest HLT directly, transitioning into local C1/C2 idle states. HLT handling inside the VMEXIT handler is preserved as a defensive fallback. |

### H-5 · `EptUnhookAll` / `NptUnhookAll` UAF (HLT CPU Fails to Flush TLB)

| Location | `driver/ept.c`, `driver/npt.c` |
|------|--------------------------------|
| Problem | After uninstalling hooks, `EptInvalidateFromGuest()` only incremented the generation counter. CPUs in HLT/C-state would not VM-Exit, and their TLBs would continue pointing to the `HookPage` that is about to be freed by `ExFreePool` → **UAF → BSOD**. |
| Fix | Added `EptInvalidateAllCpusSync` / `NptInvalidateAllCpusSync`: `KeIpiGenericCall` broadcasts a callback at `IPI_LEVEL`. Within the callback, `__cpuid(0)` is executed (which is intercepted and forces a VMEXIT). The return of the callback guarantees that all CPUs have executed INVEPT / TLB flush in root mode. This new API is called prior to freeing hooked pages during unhooking. |

### M-7 · `hv_mem.c` VMCALL Memory Path Dereferences PA as HVA in VMX-Root Mode

| Location | `driver/hv_mem.c` |
|------|-------------------|
| Fix | Modified `HvReadGuestMemory` / `HvWriteGuestMemory` / `HvHandleMemoryVmcall` to safe stubs that return `STATUS_NOT_SUPPORTED`. The original logic attempted `RtlCopyMemory((PVOID)PhysAddr, ...)` under VMX root mode wrapped in a `__try/__except` block — which was both incorrect (host VA != PA under root mode) and dangerous (SEH is unreliable under root mode). User-mode paths have been unified to use `vmxdrv.c` IOCTLs and `MmMapIoSpace`. |

### H-6 · Stack-allocated DPC May Still Be Queued on DriverEntry DPC Timeout

| Location | `driver/vmx_init.c` `VmxInitialize` |
|------|-------------------------------------|
| Fix | The 60-second timeout branch first attempts `KeRemoveQueueDpc(&Dpc)`. Success indicates the DPC has not yet executed and can be safely unwound; failure indicates the DPC has already started (system anomaly), in which case it switches to `KeWaitForSingleObject(..., NULL)` to wait indefinitely, preventing memory corruption caused by the DPC callback accessing the stack-allocated `DpcCtx`. |

---

## P1 — Performance / Scalability / Security

### M-6 · VMCALL Shutdown Lacks Authentication → Arbitrary Ring-0 Code Can Disable Protection

| Location | `driver/vmx_exit.c` `HandleVmcall`, `driver/svm_exit.c` `SvmHandleVmmcall`, `driver/vmxdrv.c` DriverEntry |
|------|---------------------------------------------------------------------------------------------|
| Fix | `DriverEntry` utilizes `KeQueryPerformanceCounter`/`__rdtsc`/`KeQueryInterruptTime` + Murmur finalizer to generate a boot-randomized 64-bit `g_VmcallShutdownNonce`. The shutdown VMCALL callers `AsmVmxVmcall2 / AsmSvmVmmcall2` (newly added 2-parameter versions) place the nonce in `RCX`. The handler validates that `RCX == g_VmcallShutdownNonce` and `Guest CPL == 0`; otherwise, it injects a `#UD`. The nonce is never exposed outside the kernel module via IOCTL or logging. |

### C-3 · SVM #DB/#BP Interception Permanently Enabled → Performance Loss for Unrelated Processes

| Location | `driver/svm_init.c`, `driver/npt.c`, `driver/process.c` |
|------|---------------------------------------------------------|
| Fix | VMCB defaults to `InterceptExceptions = 0`. Introduced two bitwise idempotent toggles:<br>• `SvmSetExceptionInterceptDb(BOOLEAN)` — Set to `TRUE` upon successful NPT hook installation, and `FALSE` when the last hook is uninstalled.<br>• `SvmSetExceptionInterceptBp(BOOLEAN)` — `process.c` aggregates the state of `AAD_HIDE_EXCEPTIONS` across all targets during every `Add`/`Remove`/`UpdateConfig` call.<br>Internally, `VMCB.Control.CleanBits = 0` is set to force the next `VMRUN` to reread the intercept bitmap. |

### L-4 · Hook Target Too Close to Page Boundary Causes Multi-Page Overwrite

| Location | `driver/ept.c` `EptHookFunction`, `driver/npt.c` `NptHookFunction` |
|------|--------------------------------------------------------------------|
| Fix | Added an entry check `PageOffset + 12 > PAGE_SIZE`, returning `STATUS_INVALID_PARAMETER` if true. This protects against arbitrary user-mode `TargetAddress` inputs passed via IOCTLs. |

### L-5 · User-Mode Hook Lacks `KeStackAttachProcess` → May Hook the Wrong Physical Page

| Location | `driver/hv_hook.c` `GenericHookInstall` |
|------|----------------------------------------|
| Fix | When `TargetVa < 0x0000_8000_0000_0000` (user-mode space) and `ProcessId != 0`: `PsLookupProcessByProcessId` → `KeStackAttachProcess` → `HvHookFunction` → `KeUnstackDetachProcess` → `ObDereferenceObject`. Kernel-space VAs do not require attachment. |

### M-2 · Incomplete Mask in `ProcessFindByCr3`

| Location | `driver/process.c` |
|------|-------------------|
| Fix | Uses the physical address mask `0x000F_FFFF_FFFF_F000` (bits [51:12]) to clear the lower 12 bits of PCID, bit 63 ("preserve TLB"), and the upper reserved bits in one operation. |

### L-8 · `HandleHlt` Fails to Check RFLAGS.IF / Interruptibility Before Entering ACTIVE_HLT

| Location | `driver/vmx_exit.c` |
|------|---------------------|
| Fix | Checks that `RFLAGS.IF=1 && (Interruptibility & 0x3)==0` before setting `VMCS_GUEST_ACTIVITY_STATE=HLT`. If conditions are not met, the state remains ACTIVE, preventing VM-Entry failures triggered by pathologic code like `CLI; HLT`. |

### M-8 · `HandleEptViolation` Non-Hook Page Fixup Only Flushes the Current CPU

| Location | `driver/ept.c` |
|------|----------------|
| Fix | After modifying a shared PTE, the generation-based mechanism `EptInvalidateFromGuest()` (which eventually flushes all CPUs) is used instead of `EptInvalidateAllContexts()` which only affects the current CPU. |

---

## P2 — Quality / Robustness

### H-3 · Thunk Slots Are Never Reclaimed

| Location | `driver/hv_hook.h`, `driver/hv_hook.c` |
|------|----------------------------------------|
| Fix | Added `SlotBitmap[THUNK_BITMAP_WORDS]` to `THUNK_PAGE`. `AllocateThunk` searches for the first free bit (supporting reuse of internal gaps). Added `FreeThunk(PVOID)` to locate the owning page, clear the corresponding bit, and zero out the stub bytes. `GenericHookRemove` / `GenericHookRemoveAll` now invoke `FreeThunk`. |

### M-4 · NPT #DB Erroneously Suppresses Guest's Own #DB Exceptions

| Location | `driver/npt.c`, `driver/npt.h`, `driver/svm_exit.c` |
|------|-----------------------------------------------------|
| Fix | Added `g_NptDbRelaxedRip[cpu]`. `NptDbTrackRelaxedPage` now also records `Vmcb->Save.Rip` when relaxing the page protection. Added `NptDbMatchesRelaxedRip(CurrentRip)` which checks if `CurrentRip - Recorded <= 15` (the maximum x86 instruction length). `SvmHandleDbException` invokes this matching check before executing `NptDbGetAndClearRelaxedPage`; if it does not match, it directly reinjects the `#DB` without altering the PTE relaxation state. |

### L-1 · `ProcessResolveOffsets` May Match `UserDirectoryTableBase`

| Location | `driver/process.c` |
|------|-------------------|
| Fix | Scans and gathers **all** matching offsets (up to 8 offsets), prioritizing the minimum value (historically, `DirectoryTableBase` resides in the early portion of `EPROCESS`, whereas `UserDirectoryTableBase` was added by KPTI patches). `ValidateDtbOffset` performs the final validation. |

---

## H-2 · Dynamically Extend PD Count (Support > 512GB Physical Memory)

Implemented in the previous round, recorded here for list completeness:

| Location | `driver/ept.c`, `driver/ept.h`, `driver/npt.c`, `driver/npt.h` |
|------|-----------------------------------------------------------------|
| Key Points | `MmGetPhysicalMemoryRanges()` detects the upper limit during boot → `g_EptPdptTotal` / `g_NptPdptTotal` are determined at runtime. PML4[1..] dynamically allocates additional PDPT pages, with per-CPU extended PDPT pages managed accordingly. `EptPaToFlatPdptIdx` / `NptPaToFlatPdptIdx` provide a unified flat index, eliminating the `(PA>>30)&0x1FF` truncation issue. `HandleEptViolation` triggers a fatal-shutdown of VMX for any GPA exceeding the mapped range to prevent infinite loops. |

---

## Future Recommendations

1. **Hardware Verification**: Perform stress testing on actual bare-metal Intel (VT-x) and AMD (SVM-V) platforms, with a focus on:
   - Multi-core + frequent hook/unhook cycles (evaluating the IPI overhead of `EptInvalidateAllCpusSync`).
   - TLB consistency during long periods of idle state (HLT / C-state).
   - EPT/NPT scaling coverage on `> 512GB` server environments.
   - AMD platform: Windows' `ntoskrnl!KxSwapIdtEntry` / `KeInitializeIdtEntry` / any code path accessing `gs:KPCR` after the initial VMRUN — to verify that Host VMCB save/restore works correctly.
2. **Driver Verifier**: Run for 24 hours with "Special Pool", "DPC Checking", and "Low Resource Simulation" enabled.
3. **Stress Testing Tools**: Use a stress test suite — concurrent `InstallHook/RemoveHook` + SSDT Monitor fully enabled + WinDbg attached to the Guest.
4. **Unhandled Known Limitations** (refer to code comments):
   - Performance degradation on platforms that do not support NPT + Intel execute-only (Mode B, slow path for REP-prefixed instruction MTF).
   - Disabling of VMCALL memory operation paths (see explanation in M-7); user-mode must exclusively use IOCTLs.

---

## Important API Changes (post-2nd-review)

| Change | Type | Description |
|------|------|------|
| `AsmSvmLaunch` | **Signature Change** | `(VmcbPa, VmcbVa)` → `(VmcbPa, VmcbVa, HostVmcbPa)` — Added Host VMCB physical address for VMSAVE/VMLOAD host state |
| `SVM_CPU_CONTEXT::HostVmcbVa/HostVmcbPa` | New Fields | Independent from `HostSaveAreaVa/Pa` (hardware HSAVE); `SvmAllocateCpuContext` / `SvmFreeCpuContext` updated synchronously |
| `AsmVmxVmcall2` / `AsmSvmVmmcall2` | New APIs | 2-parameter VMCALL/VMMCALL for nonce authentication |
| `HvIsAuthenticShutdownCaller(Rcx, Rip, Cpl, Efer, CsL)` | New Helper | Unified authentication for shutdown VMCALL/VMMCALL |
| `VmxSetExceptionInterceptDb/Bp`, `VmxSyncExceptionBitmap` | New APIs | Dynamic exception interception on the VMX side (previously missing) |
| `SvmSetExceptionInterceptDb/Bp`, `SvmInterceptLockInitialize` | New APIs | Race-free initialization versions on the SVM side |
| `ProcessRegisterExceptionHideToggle(Callback)` | New API | Decoupled `process.c` from the SVM/VMX backends |
| `ProcessAnyTargetHasExceptionHiding()` | New API | Query whether `#BP` interception is currently required |
| `NptDbMatchesRelaxedRip` | Semantic Change | Now compares both CR3 and the 15-byte RIP window; internally utilizes `NptDbSnapshotRelaxedTracker` with memory barriers |
| `EptInvalidateAllCpusSync` / `NptInvalidateAllCpusSync` | Implementation Change | Behavior is equivalent, but the IPI callback now directly executes INVEPT / triggers VMEXIT instead of relying on the indirect CPUID-VMEXIT-CheckPending path |
| `HvGuestVaToPa` | Behavior Change | Internal `SafeReadPhysU64` updated to use `MmGetVirtualForPhysical`; added `KeGetCurrentIrql` guard check at the top to prevent misuse in VMX root mode |
| `HvHandleMemoryVmcall` | **Disabled** | `VMCALL_SUBCMD_READ/WRITE_MEMORY` now directly injects `#UD`; user-mode must use IOCTLs |
| `g_VmcallShutdownNonce` | New Global | Boot-randomized; shutdown VMCALL must carry this nonce |

Reviewers / Fix Submitters: Hypervisor Maintenance Team · April 2026 (Secondary Review: 2026-04-18)
