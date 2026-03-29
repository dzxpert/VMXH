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

    case SVM_EXIT_RDTSC:
        Result = AadHandleRdtsc(GuestContext);
        break;

    case SVM_EXIT_RDTSCP:
        /* Handle TSC part same as RDTSC */
        AadHandleRdtsc(GuestContext);
        /* Also return IA32_TSC_AUX in ECX */
        GuestContext->Rcx = __readmsr(MSR_TSC_AUX) & 0xFFFFFFFF;
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
        {
            ULONG   Ecx = (ULONG)GuestContext->Rcx;
            ULONG64 Value = (GuestContext->Rax & 0xFFFFFFFF) |
                            ((GuestContext->Rdx & 0xFFFFFFFF) << 32);
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
        /* NMI - re-inject */
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
        HvAdvanceGuestRip();
        break;
    }

    /* Sync guest RAX back to VMCB (handlers may have modified it) */
    Vmcb->Save.Rax = GuestContext->Rax;

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
 */
static BOOLEAN SvmHandleDbException(PGUEST_CONTEXT Ctx)
{
    PSVM_CPU_CONTEXT CpuCtx = &g_SvmState.CpuContexts[KeGetCurrentProcessorNumber()];
    PVMCB Vmcb = CpuCtx->VmcbVa;
    ULONG i;

    /*
     * Check if this #DB was from our NPT hook single-step (TF flag).
     * If any hooks are temporarily in R+W+X mode, restore them.
     */
    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        if (g_NptHookState.Hooks[i].Active && g_NptHookState.Hooks[i].TargetPte) {
            PEPT_PTE Pte = g_NptHookState.Hooks[i].TargetPte;

            /* Check if currently in write-through mode (R+W+X with original page) */
            if (Pte->Read && Pte->Write && Pte->Execute) {
                /* Restore to R+X with hook page */
                Pte->Read = 1;
                Pte->Write = 0;
                Pte->Execute = 1;
                Pte->PhysAddr = g_NptHookState.Hooks[i].HookPagePa >> 12;
            }
        }
    }

    /* Clear TF flag */
    Vmcb->Save.Rflags &= ~(1ULL << 8);

    NptInvalidateAll();

    /* If this was truly from our single-step, don't re-inject */
    /* If it's a real debug exception for AAD, re-inject it */
    /* For simplicity, check if any hook was in write-through mode */
    /* If not, delegate to anti-anti-debug */
    {
        ULONG64 GuestCr3 = Vmcb->Save.Cr3;
        if (IsTargetProcess(GuestCr3)) {
            /* Might be a real #DB for the target - re-inject via AAD */
            return AadHandleException(Ctx);
        }
    }

    /* Not a target process and not from our hook - re-inject #DB normally */
    Vmcb->Control.EventInj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT | 1;

    return TRUE;
}

/* ========================================================================= */
/*  VMMCALL Handler                                                          */
/* ========================================================================= */

#define VMCALL_MAGIC_SHUTDOWN   0xDEADCAFE

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

    /* Unknown VMMCALL - inject #UD */
    {
        PSVM_CPU_CONTEXT CpuCtx = &g_SvmState.CpuContexts[KeGetCurrentProcessorNumber()];
        CpuCtx->VmcbVa->Control.EventInj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT | 6;
    }
    return TRUE;
}

/* ========================================================================= */
/*  GP Register Helpers                                                      */
/* ========================================================================= */

static ULONG64 SvmGetGpReg(PGUEST_CONTEXT Ctx, ULONG RegIndex)
{
    ULONG64 *Regs = (ULONG64 *)Ctx;

    if (RegIndex == 4) {
        /* RSP from VMCB */
        return HvReadGuestRsp();
    }
    if (RegIndex <= 15) {
        return Regs[RegIndex];
    }
    return 0;
}

static VOID SvmSetGpReg(PGUEST_CONTEXT Ctx, ULONG RegIndex, ULONG64 Value)
{
    ULONG64 *Regs = (ULONG64 *)Ctx;

    if (RegIndex == 4) {
        HvWriteGuestRsp(Value);
        return;
    }
    if (RegIndex <= 15) {
        Regs[RegIndex] = Value;
    }
}
