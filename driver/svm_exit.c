/*
 * svm_exit.c - VMX Anti-Anti-Debug Hypervisor
 * SVM #VMEXIT dispatcher: routes exit codes to appropriate handlers.
 *
 * Key design: Reuses anti_anti_debug.c handlers (AadHandle*) via the
 * hv_ops abstraction layer. The AAD handlers call g_HvOps-> functions
 * which resolve to SVM implementations when on AMD hardware.
 */

#include "svm.h"
#include "npt.h"
#include "vmx.h"        /* For VMCALL_MAGIC_SHUTDOWN */
#include "log.h"
#include "process.h"
#include "anti_anti_debug.h"
#include "hv_ops.h"
#include "hv_mem.h"
#include "../common/shared.h"

/* ========================================================================= */
/*  Forward Declarations                                                     */
/* ========================================================================= */

static BOOLEAN SvmHandleMsr(PGUEST_CONTEXT Ctx);
static BOOLEAN SvmHandleCrAccess(PGUEST_CONTEXT Ctx, ULONG ExitCode);
static BOOLEAN SvmHandleDrAccess(PGUEST_CONTEXT Ctx, ULONG ExitCode);
static BOOLEAN SvmHandleVmmcall(PGUEST_CONTEXT Ctx);
static BOOLEAN SvmHandleDbException(PGUEST_CONTEXT Ctx);

/* Helper: get GP register by SVM register index */
static ULONG64 SvmGetGpReg(PGUEST_CONTEXT Ctx, ULONG RegIndex);
static VOID    SvmSetGpReg(PGUEST_CONTEXT Ctx, ULONG RegIndex, ULONG64 Value);

/* MSR handlers (reuse from msr.c via hv_ops) */
extern BOOLEAN HandleRdmsrImpl(PGUEST_CONTEXT Ctx);
extern BOOLEAN HandleWrmsrImpl(PGUEST_CONTEXT Ctx);

/* ========================================================================= */
/*  Main SVM Exit Handler                                                    */
/* ========================================================================= */

/*
 * SvmExitHandler - Main #VMEXIT dispatch function for AMD SVM
 *
 * Called after guest GP registers are saved (by C VMRUN loop or ASM handler).
 * Returns TRUE to resume guest, FALSE to shut down SVM.
 *
 * Note: Guest RAX is in VMCB.save.rax, not in GuestContext->Rax.
 * We sync it here for compatibility with shared handlers.
 */
BOOLEAN SvmExitHandler(PGUEST_CONTEXT GuestContext)
{
    PSVM_CPU_CONTEXT CpuCtx;
    PVMCB           Vmcb;
    ULONG           ExitCode;
    BOOLEAN         Result = TRUE;

    CpuCtx = &g_SvmState.CpuContexts[KeGetCurrentProcessorNumber()];
    Vmcb = CpuCtx->VmcbVa;

    if (!Vmcb) {
        LOG_ERROR("SVM Exit: NULL VMCB!");
        return FALSE;
    }

    ExitCode = Vmcb->Control.ExitCode;

    /* Sync guest RAX from VMCB to GuestContext for shared handlers */
    GuestContext->Rax = Vmcb->Save.Rax;

    /*
     * CRITICAL: Sync Guest RSP from VMCB into GuestContext at #VMEXIT entry.
     *
     * Same rationale as the VMX side (vmx_exit.c): the ASM stub pushes GP
     * registers onto the Host stack, so GuestContext->Rsp is a placeholder.
     * The real Guest RSP lives in VMCB.Save.Rsp.
     *
     * By syncing here, ALL subsequent handlers (DR access, CR access, etc.)
     * can use GpRegs[4] / GuestContext->Rsp directly without special-casing.
     * On exit, we write it back to VMCB.Save.Rsp.
     */
    GuestContext->Rsp = Vmcb->Save.Rsp;

    /* Increment exit counter */
    InterlockedIncrement64(&CpuCtx->Common.ExitCount);

    /* Reset TLB control for next VMRUN (don't keep flushing) */
    Vmcb->Control.TlbCtl = TLB_CONTROL_DO_NOTHING;

    /* Dispatch by exit code */
    switch (ExitCode) {

    /* ===== Instruction Intercepts ===== */

    case SVM_EXIT_CPUID:
        Result = AadHandleCpuid(GuestContext);
        break;

    case SVM_EXIT_MSR:
        Result = SvmHandleMsr(GuestContext);
        break;

    case SVM_EXIT_VMMCALL:
        Result = SvmHandleVmmcall(GuestContext);
        break;

    case SVM_EXIT_HLT:
        HvAdvanceGuestRip();
        break;

    case SVM_EXIT_INVD:
        __wbinvd();
        HvAdvanceGuestRip();
        break;

    case SVM_EXIT_WBINVD:
        __wbinvd();
        HvAdvanceGuestRip();
        break;

    case SVM_EXIT_XSETBV:
        /*
         * BUG FIX: Validate XCR0 before executing XSETBV.
         *
         * If the Guest writes an illegal XCR0 combination, the XSETBV instruction
         * would execute in Host context and trigger a #GP, crashing the Hypervisor.
         *
         * Intel/AMD SDM — XCR0 constraints:
         *   - Bit 0 (x87) must always be 1
         *   - If bit 2 (AVX) is set, bit 1 (SSE) must also be set
         *   - XCR index must be 0 (only XCR0 is currently defined)
         *
         * If validation fails, inject #GP(0) into the Guest instead.
         */
        {
            ULONG   Ecx = (ULONG)GuestContext->Rcx;
            ULONG64 Value = (GuestContext->Rax & 0xFFFFFFFF) |
                            ((GuestContext->Rdx & 0xFFFFFFFF) << 32);

            if (Ecx != 0) {
                /* Only XCR0 (index 0) is valid; all others -> #GP(0) */
                Vmcb->Control.EventInj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT |
                                         SVM_EVTINJ_VALID_ERR | 13;
                Vmcb->Control.EventInjErr = 0;
                break;
            }

            if (!(Value & 1)) {
                /* Bit 0 (x87 FPU) must be 1 */
                Vmcb->Control.EventInj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT |
                                         SVM_EVTINJ_VALID_ERR | 13;
                Vmcb->Control.EventInjErr = 0;
                break;
            }

            if ((Value & (1ULL << 2)) && !(Value & (1ULL << 1))) {
                /* AVX (bit 2) requires SSE (bit 1) */
                Vmcb->Control.EventInj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT |
                                         SVM_EVTINJ_VALID_ERR | 13;
                Vmcb->Control.EventInjErr = 0;
                break;
            }

            /* Valid XCR0 - execute the real XSETBV */
            AsmXsetbv(Ecx, Value);
            HvAdvanceGuestRip();
        }
        break;

    /* ===== CR Access ===== */

    case SVM_EXIT_WRITE_CR0:
    case SVM_EXIT_WRITE_CR3:
    case SVM_EXIT_WRITE_CR4:
    case SVM_EXIT_READ_CR0:
    case SVM_EXIT_READ_CR3:
    case SVM_EXIT_READ_CR4:
        Result = SvmHandleCrAccess(GuestContext, ExitCode);
        break;

    /* ===== DR Access ===== */

    case SVM_EXIT_READ_DR0: case SVM_EXIT_READ_DR1:
    case SVM_EXIT_READ_DR2: case SVM_EXIT_READ_DR3:
    case SVM_EXIT_READ_DR6: case SVM_EXIT_READ_DR7:
    case SVM_EXIT_WRITE_DR0: case SVM_EXIT_WRITE_DR1:
    case SVM_EXIT_WRITE_DR2: case SVM_EXIT_WRITE_DR3:
    case SVM_EXIT_WRITE_DR6: case SVM_EXIT_WRITE_DR7:
        Result = SvmHandleDrAccess(GuestContext, ExitCode);
        break;

    /* ===== Exceptions ===== */

    case SVM_EXIT_EXCP_DB:  /* #DB */
        Result = SvmHandleDbException(GuestContext);
        break;

    case SVM_EXIT_EXCP_BP:  /* #BP */
        Result = AadHandleException(GuestContext);
        break;

    /* ===== Nested Page Fault ===== */

    case SVM_EXIT_NPF:
        Result = NptHandlePageFault(GuestContext);
        break;

    /* ===== Interrupts ===== */

    case SVM_EXIT_INTR:
        /* Physical interrupt - just resume, interrupt will be delivered */
        break;

    case SVM_EXIT_NMI:
        /*
         * BUG FIX (Review Issue #3): Check NMI blocking before re-injection.
         *
         * AMD APM Vol.2: VMCB IntState bit 2 (NmiMask) indicates the guest
         * has NMI blocked. Re-injecting while blocked may be silently dropped
         * or cause undefined behavior on some CPU revisions.
         *
         * Fix: If NmiMask is set, enable IRET intercept. When the guest
         * executes IRET, the NMI mask is cleared, and we inject then.
         * Aligned with VMX side's NMI-window exiting mechanism.
         */
        if (!(Vmcb->Control.IntState & SVM_INTSTATE_NMI_MASK)) {
            /* Not blocked by NMI: safe to inject immediately */
            Vmcb->Control.EventInj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_NMI | 2;
        } else {
            /* Blocked by NMI: enable IRET intercept for deferred injection */
            Vmcb->Control.Intercept |= (1ULL << SVM_INTERCEPT_IRET);
        }
        break;

    case SVM_EXIT_IRET:
        /*
         * BUG FIX (Review Issue #3): Deferred NMI injection via IRET intercept.
         *
         * Guest executed IRET — NMI blocking is now cleared by hardware.
         * Disable IRET intercept and inject the pending NMI.
         */
        Vmcb->Control.Intercept &= ~(1ULL << SVM_INTERCEPT_IRET);
        Vmcb->Control.EventInj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_NMI | 2;
        break;

    /* ===== SVM Instruction Intercepts (required) ===== */

    case SVM_EXIT_VMRUN:
    case SVM_EXIT_VMLOAD:
    case SVM_EXIT_VMSAVE:
    case SVM_EXIT_STGI:
    case SVM_EXIT_CLGI:
    case SVM_EXIT_SKINIT:
        /* Inject #UD for nested SVM instructions */
        Vmcb->Control.EventInj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT | 6;
        break;

    case SVM_EXIT_SHUTDOWN:
        LOG_ERROR("SVM: Guest shutdown event!");
        Result = FALSE;
        break;

    default:
        LOG_WARN("SVM: Unhandled exit code=0x%X, RIP=0x%llX, Info1=0x%llX",
                 ExitCode, Vmcb->Save.Rip, Vmcb->Control.ExitInfo1);
        /*
         * BUG FIX (Review Issue #1): Do NOT advance RIP for unknown exits.
         * Non-instruction exits (interrupts, preemption timer, etc.) have
         * undefined instruction length. Blindly adding it to RIP causes the
         * guest to jump to garbage addresses -> state corruption / BSOD.
         * Aligned with VMX side (vmx_exit.c default handler).
         */
        break;
    }

    /* Sync guest RAX back to VMCB (handlers may have modified it) */
    Vmcb->Save.Rax = GuestContext->Rax;

    /* Sync guest RSP back to VMCB (handlers may have modified it) */
    Vmcb->Save.Rsp = GuestContext->Rsp;

    return Result;
}

/* ========================================================================= */
/*  MSR Handler                                                              */
/* ========================================================================= */

/*
 * SVM MSR intercept: exit_info_1 = 0 for RDMSR, 1 for WRMSR
 */
static BOOLEAN SvmHandleMsr(PGUEST_CONTEXT Ctx)
{
    PSVM_CPU_CONTEXT CpuCtx = &g_SvmState.CpuContexts[KeGetCurrentProcessorNumber()];
    ULONG64 ExitInfo1 = CpuCtx->VmcbVa->Control.ExitInfo1;

    if (ExitInfo1 == 0) {
        /* RDMSR */
        return HandleRdmsrImpl(Ctx);
    } else {
        /* WRMSR */
        return HandleWrmsrImpl(Ctx);
    }
}

/* ========================================================================= */
/*  CR Access Handler                                                        */
/* ========================================================================= */

static BOOLEAN SvmHandleCrAccess(PGUEST_CONTEXT Ctx, ULONG ExitCode)
{
    PSVM_CPU_CONTEXT CpuCtx = &g_SvmState.CpuContexts[KeGetCurrentProcessorNumber()];
    PVMCB Vmcb = CpuCtx->VmcbVa;
    ULONG GpReg;
    ULONG64 Value;

    /*
     * For SVM CR access, exit_info_1 contains the GP register number
     * (for MOV to/from CR instructions).
     */
    GpReg = (ULONG)(Vmcb->Control.ExitInfo1 & 0x0F);

    switch (ExitCode) {
    case SVM_EXIT_WRITE_CR0:
        Value = SvmGetGpReg(Ctx, GpReg);
        Vmcb->Save.Cr0 = Value;
        break;

    case SVM_EXIT_WRITE_CR3:
        Value = SvmGetGpReg(Ctx, GpReg);
        Vmcb->Save.Cr3 = Value;
        /* Update hardware TSC Offset for the new process context */
        AadUpdateHwTscOffset(Value);
        break;

    case SVM_EXIT_WRITE_CR4:
        Value = SvmGetGpReg(Ctx, GpReg);
        Vmcb->Save.Cr4 = Value;
        break;

    case SVM_EXIT_READ_CR0:
        SvmSetGpReg(Ctx, GpReg, Vmcb->Save.Cr0);
        break;

    case SVM_EXIT_READ_CR3:
        SvmSetGpReg(Ctx, GpReg, Vmcb->Save.Cr3);
        break;

    case SVM_EXIT_READ_CR4:
        SvmSetGpReg(Ctx, GpReg, Vmcb->Save.Cr4);
        break;
    }

    HvAdvanceGuestRip();
    return TRUE;
}

/* ========================================================================= */
/*  DR Access Handler                                                        */
/* ========================================================================= */

/*
 * SVM provides separate exit codes for each DR read/write.
 * We extract the DR number and direction, then delegate to the shared
 * anti-anti-debug DR handler via a compatible interface.
 *
 * For SVM, exit_info_1 contains the GP register number used in the MOV DR instruction.
 */
static BOOLEAN SvmHandleDrAccess(PGUEST_CONTEXT Ctx, ULONG ExitCode)
{
    PSVM_CPU_CONTEXT CpuCtx = &g_SvmState.CpuContexts[KeGetCurrentProcessorNumber()];
    PVMCB       Vmcb = CpuCtx->VmcbVa;
    ULONG       DrNumber;
    BOOLEAN     IsWrite;
    ULONG       GpReg;
    ULONG64     GuestCr3;
    PULONG64    RegPtr;
    ULONG64     *GpRegs;

    /* Determine DR number and direction from exit code */
    if (ExitCode >= SVM_EXIT_WRITE_DR0 && ExitCode <= SVM_EXIT_WRITE_DR7) {
        DrNumber = ExitCode - SVM_EXIT_WRITE_DR0;
        IsWrite = TRUE;
    } else {
        DrNumber = ExitCode - SVM_EXIT_READ_DR0;
        IsWrite = FALSE;
    }

    /* GP register from exit_info_1 */
    GpReg = (ULONG)(Vmcb->Control.ExitInfo1 & 0x0F);
    GuestCr3 = Vmcb->Save.Cr3;

    GpRegs = (ULONG64 *)Ctx;
    if (GpReg > 15) {
        HvAdvanceGuestRip();
        return TRUE;
    }
    RegPtr = &GpRegs[GpReg];

    /* Check if target process with DR hiding */
    if (!IsFeatureEnabled(GuestCr3, AAD_HIDE_HWBP)) {
        /* Non-target: execute DR access normally */
        if (!IsWrite) {
            /*
             * MOV FROM DR (read): Read real DR value and write to guest GP register.
             *
             * VERIFIED CORRECT: Same write-back pattern as AadHandleDrAccess().
             * `*RegPtr = DrValue` writes directly into GpRegs[GpReg] in GUEST_CONTEXT.
             * With unified RSP sync at SvmExitHandler() entry, GpRegs[4] (RSP) is
             * also valid. No special case needed for any register index.
             */
            ULONG64 DrValue = 0;
            switch (DrNumber) {
                case 0: DrValue = __readdr(0); break;
                case 1: DrValue = __readdr(1); break;
                case 2: DrValue = __readdr(2); break;
                case 3: DrValue = __readdr(3); break;
                case 6: DrValue = __readdr(6); break;
                case 7: DrValue = __readdr(7); break;
            }
            *RegPtr = DrValue;
        } else {
            ULONG64 Value = *RegPtr;
            switch (DrNumber) {
                case 0: __writedr(0, Value); break;
                case 1: __writedr(1, Value); break;
                case 2: __writedr(2, Value); break;
                case 3: __writedr(3, Value); break;
                case 6: __writedr(6, Value); break;
                case 7: __writedr(7, Value); break;
            }
        }
        HvAdvanceGuestRip();
        return TRUE;
    }

    /* Target process: spoof DR values */
    if (!IsWrite) {
        ULONG64 FakeValue = 0;
        switch (DrNumber) {
        case 0: case 1: case 2: case 3:
            FakeValue = 0;
            break;
        case 6:
            FakeValue = DR6_DEFAULT_VALUE;
            break;
        case 7:
            FakeValue = DR7_DEFAULT_VALUE;
            break;
        }
        *RegPtr = FakeValue;
    } else {
        /* Write: allow the real write but hide from reads */
        ULONG64 Value = *RegPtr;
        switch (DrNumber) {
            case 0: __writedr(0, Value); break;
            case 1: __writedr(1, Value); break;
            case 2: __writedr(2, Value); break;
            case 3: __writedr(3, Value); break;
            case 6: __writedr(6, Value); break;
            case 7: __writedr(7, Value); break;
        }
    }

    HvAdvanceGuestRip();
    return TRUE;
}

/* ========================================================================= */
/*  #DB Exception Handler (Single-Step for NPT hooks)                        */
/* ========================================================================= */

/*
 * Handles #DB exceptions which serve dual purpose:
 * 1. NPT hook single-step completion (TF was set for write-through)
 * 2. Anti-anti-debug exception handling
 *
 * BUG FIX: The original code restored ALL hooks globally, which caused a
 * multi-core race condition.  For example:
 *   - CPU 0 triggers NPF on hook A → switches to permissive → TF
 *   - CPU 1 triggers NPF on hook B → switches to permissive
 *   - CPU 0's #DB fires → restores ALL hooks including B
 *   - CPU 1 hasn't finished executing its instruction → re-faults → infinite loop
 *
 * Fix: Each CPU only restores the specific hook(s) on pages that IT made
 * permissive.  We use a per-CPU tracking array (in npt.c) to record which
 * physical page was relaxed.  The #DB handler queries it and only restores
 * hooks on that specific page.
 */
static BOOLEAN SvmHandleDbException(PGUEST_CONTEXT Ctx)
{
    ULONG CpuNum = KeGetCurrentProcessorNumber();
    PSVM_CPU_CONTEXT CpuCtx;
    PVMCB Vmcb;
    ULONG64 RelaxedPa;
    BOOLEAN RestoredAny = FALSE;

    if (CpuNum >= g_MaxProcessors || !g_SvmState.CpuContexts) return FALSE;
    CpuCtx = &g_SvmState.CpuContexts[CpuNum];
    Vmcb = CpuCtx->VmcbVa;

    /*
     * Get which page THIS CPU relaxed (stored by NptHandlePageFault).
     * Only restore hooks on that specific page.
     */
    RelaxedPa = NptDbGetAndClearRelaxedPage();

    /*
     * Restore hook on the page this CPU relaxed.
     *
     * OPTIMIZATION: Use O(1) hash table lookup instead of O(n) linear scan.
     * The previous code iterated over all NPT_MAX_HOOKS (1024) entries on
     * every #DB exit — a hot path. Since hooks are indexed by physical page
     * address and only ONE hook can exist per 4KB page, a single hash lookup
     * suffices.
     *
     * When RelaxedPa is 0 (shouldn't happen), fall back to O(n) scan.
     *
     * Per-CPU hook page isolation: use this CPU's private PTE so that
     * restoring permissions only affects THIS CPU's NPT translation.
     */
    if (RelaxedPa != 0) {
        /* O(1) path: direct hash lookup for the specific hooked page */
        PEPT_HOOK_ENTRY Hook = NptFindHookByPhysicalAddress(RelaxedPa);
        if (Hook && Hook->Active && Hook->TargetPte) {
            PEPT_PTE Pte = NptGetPerCpuPte(CpuNum, Hook->TargetPhysicalAddr);
            if (!Pte) Pte = Hook->TargetPte;

            if (Pte->Read && Pte->Write && Pte->Execute) {
                Pte->Read = 1;
                Pte->Write = 0;
                Pte->Execute = 1;
                Pte->PhysAddr = Hook->HookPagePa >> 12;
                RestoredAny = TRUE;
            }
        }
    } else {
        /* Fallback O(n) path: RelaxedPa unknown, restore ALL hooks (safety) */
        ULONG i;
        for (i = 0; i < NPT_MAX_HOOKS; i++) {
            if (g_NptHookState.Hooks[i].Active && g_NptHookState.Hooks[i].TargetPte) {
                PEPT_PTE Pte = NptGetPerCpuPte(CpuNum,
                    g_NptHookState.Hooks[i].TargetPhysicalAddr);
                if (!Pte) Pte = g_NptHookState.Hooks[i].TargetPte;

                if (Pte->Read && Pte->Write && Pte->Execute) {
                    Pte->Read = 1;
                    Pte->Write = 0;
                    Pte->Execute = 1;
                    Pte->PhysAddr = g_NptHookState.Hooks[i].HookPagePa >> 12;
                    RestoredAny = TRUE;
                }
            }
        }
    }

    /* Clear TF flag */
    Vmcb->Save.Rflags &= ~(1ULL << 8);

    NptInvalidateAll();

    /*
     * If we restored any hooks, this was our single-step — don't re-inject.
     * If nothing was restored and this is a target process, it may be a
     * real #DB for anti-anti-debug — delegate to AAD handler.
     */
    if (!RestoredAny) {
        ULONG64 GuestCr3 = Vmcb->Save.Cr3;
        if (IsTargetProcess(GuestCr3)) {
            return AadHandleException(Ctx);
        }

        /* Not a target process and not from our hook - re-inject #DB normally */
        Vmcb->Control.EventInj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT | 1;
    }

    return TRUE;
}

/* ========================================================================= */
/*  VMMCALL Handler                                                          */
/* ========================================================================= */

/* VMCALL_MAGIC_SHUTDOWN is defined in vmx.h */

static BOOLEAN SvmHandleVmmcall(PGUEST_CONTEXT Ctx)
{
    ULONG64 Rax = Ctx->Rax;
    ULONG   SubCmd;

    /* Legacy shutdown path */
    if (Rax == VMCALL_MAGIC_SHUTDOWN) {
        LOG_INFO("VMMCALL shutdown request received");
        HvAdvanceGuestRip();
        return FALSE;
    }

    /* New VMCALL dispatch: RAX high 16 bits = VMCALL_MAGIC */
    if ((Rax & VMCALL_MAGIC_MASK) == VMCALL_MAGIC) {
        SubCmd = (ULONG)(Rax & 0xFFFF);

        switch (SubCmd) {
        case VMCALL_SUBCMD_SHUTDOWN:
            LOG_INFO("VMMCALL shutdown request received (new)");
            HvAdvanceGuestRip();
            return FALSE;

        case VMCALL_SUBCMD_READ_MEMORY:
        case VMCALL_SUBCMD_WRITE_MEMORY:
            return HvHandleMemoryVmcall(Ctx, SubCmd);

        default:
            break;
        }
    }

    /* Unknown VMMCALL — inject #UD */
    {
        static volatile LONG s_UnknownVmmcallCount = 0;
        LONG Count = InterlockedIncrement(&s_UnknownVmmcallCount);
        if (Count <= 10) {
            VMXROOT_LOG_WARN("Unknown VMMCALL: RAX=0x%llX RCX=0x%llX",
                             Ctx->Rax, Ctx->Rcx);
        }
    }
    HvInjectException(6, INTERRUPT_TYPE_HARDWARE_EXCEPTION, FALSE, 0);
    HvAdvanceGuestRip();
    return TRUE;
}

/* ========================================================================= */
/*  GP Register Helpers                                                      */
/* ========================================================================= */

/*
 * NOTE: RSP (index 4) is now valid in GuestContext because SvmExitHandler()
 * syncs VMCB.Save.Rsp → GuestContext->Rsp at entry and writes it back at exit.
 * No special-case needed for RegIndex==4 anymore.
 */
static ULONG64 SvmGetGpReg(PGUEST_CONTEXT Ctx, ULONG RegIndex)
{
    ULONG64 *Regs = (ULONG64 *)Ctx;

    if (RegIndex <= 15) {
        return Regs[RegIndex];
    }
    return 0;
}

static VOID SvmSetGpReg(PGUEST_CONTEXT Ctx, ULONG RegIndex, ULONG64 Value)
{
    ULONG64 *Regs = (ULONG64 *)Ctx;

    if (RegIndex <= 15) {
        Regs[RegIndex] = Value;
    }
}
