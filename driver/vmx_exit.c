/*
 * vmx_exit.c - VMX Anti-Anti-Debug Hypervisor
 * VM-Exit main dispatcher and individual exit handlers
 */

#include "vmx.h"
#include "ept.h"
#include "hv_ops.h"
#include "hv_mem.h"
#include "log.h"
#include "process.h"
#include "anti_anti_debug.h"
#include "../common/shared.h"

/* ========================================================================= */
/*  Forward Declarations                                                     */
/* ========================================================================= */

static BOOLEAN HandleCpuid(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleRdmsr(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleWrmsr(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleCrAccess(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleDrAccess(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleException(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleRdtsc(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleRdtscp(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleXsetbv(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleInvd(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleVmcall(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleEptViol(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleEptMisconfig(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleInvlpg(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleWbinvd(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleTripleFault(PGUEST_CONTEXT Ctx);

/* MSR handlers from msr.c */
extern BOOLEAN HandleRdmsrImpl(PGUEST_CONTEXT Ctx);
extern BOOLEAN HandleWrmsrImpl(PGUEST_CONTEXT Ctx);

/* Helper: get GP register value by index */
static ULONG64 GetGpRegValue(PGUEST_CONTEXT Ctx, ULONG RegIndex);
static VOID    SetGpRegValue(PGUEST_CONTEXT Ctx, ULONG RegIndex, ULONG64 Value);

/* ========================================================================= */
/*  Main VM-Exit Handler (called from ASM)                                   */
/* ========================================================================= */

/*
 * VmxExitHandler - Main VM-Exit dispatch function
 *
 * Called from AsmVmxExitHandler after guest GP registers are saved.
 * Returns TRUE to resume guest, FALSE to shut down VMX.
 */
BOOLEAN VmxExitHandler(PGUEST_CONTEXT GuestContext)
{
    ULONG   ExitReason;
    ULONG   CpuIndex;
    BOOLEAN Result = TRUE;

    ExitReason = (ULONG)VmxRead(VMCS_EXIT_REASON);
    CpuIndex = KeGetCurrentProcessorNumber();

    /* Increment exit counter */
    if (CpuIndex < MAX_PROCESSORS) {
        InterlockedIncrement64(&g_VmxState.CpuContexts[CpuIndex].ExitCount);
    }

    /* Check if Guest requested an EPT TLB flush */
    EptCheckPendingInvept();

    /* Check for VM-Entry failure (bit 31) */
    if (ExitReason & 0x80000000) {
        LOG_ERROR("VM-Entry failure! Reason: %u, Qualification: 0x%llX",
                  ExitReason & 0xFFFF, VmxRead(VMCS_EXIT_QUALIFICATION));
        return FALSE;   /* Shut down VMX */
    }

    /* Dispatch by exit reason */
    switch (ExitReason & 0xFFFF) {

    case EXIT_REASON_CPUID:
        Result = HandleCpuid(GuestContext);
        break;

    case EXIT_REASON_RDMSR:
        Result = HandleRdmsr(GuestContext);
        break;

    case EXIT_REASON_WRMSR:
        Result = HandleWrmsr(GuestContext);
        break;

    case EXIT_REASON_CR_ACCESS:
        Result = HandleCrAccess(GuestContext);
        break;

    case EXIT_REASON_DR_ACCESS:
        Result = HandleDrAccess(GuestContext);
        break;

    case EXIT_REASON_EXCEPTION_NMI:
        Result = HandleException(GuestContext);
        break;

    case EXIT_REASON_RDTSC:
        Result = HandleRdtsc(GuestContext);
        break;

    case EXIT_REASON_RDTSCP:
        Result = HandleRdtscp(GuestContext);
        break;

    case EXIT_REASON_EPT_VIOLATION:
        Result = HandleEptViol(GuestContext);
        break;

    case EXIT_REASON_EPT_MISCONFIG:
        Result = HandleEptMisconfig(GuestContext);
        break;

    case EXIT_REASON_MTF:
        Result = HandleMtf(GuestContext);
        break;

    case EXIT_REASON_VMCALL:
        Result = HandleVmcall(GuestContext);
        break;

    case EXIT_REASON_XSETBV:
        Result = HandleXsetbv(GuestContext);
        break;

    case EXIT_REASON_INVD:
        Result = HandleInvd(GuestContext);
        break;

    case EXIT_REASON_INVLPG:
        Result = HandleInvlpg(GuestContext);
        break;

    case EXIT_REASON_WBINVD:
        Result = HandleWbinvd(GuestContext);
        break;

    case EXIT_REASON_TRIPLE_FAULT:
        Result = HandleTripleFault(GuestContext);
        break;

    case EXIT_REASON_HLT:
        /* HLT - just advance RIP and resume */
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_EXTERNAL_INT:
        /* External interrupt - acknowledged via ACK_INT_ON_EXIT, just resume */
        break;

    case EXIT_REASON_INT_WINDOW:
        /* Interrupt window - clear the interrupt-window exiting bit */
        {
            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased &= ~PROC_BASED_INT_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
        }
        break;

    default:
        LOG_WARN("Unhandled VM-Exit: reason=%u, qual=0x%llX, RIP=0x%llX",
                 ExitReason & 0xFFFF,
                 VmxRead(VMCS_EXIT_QUALIFICATION),
                 VmxRead(VMCS_GUEST_RIP));
        /* Try to skip the instruction to avoid infinite loop */
        VmxAdvanceGuestRip();
        break;
    }

    return Result;
}

/* ========================================================================= */
/*  Individual Exit Handlers                                                 */
/* ========================================================================= */

/* CPUID - delegate to anti-anti-debug engine */
static BOOLEAN HandleCpuid(PGUEST_CONTEXT Ctx)
{
    return AadHandleCpuid(Ctx);
}

/* RDMSR */
static BOOLEAN HandleRdmsr(PGUEST_CONTEXT Ctx)
{
    return HandleRdmsrImpl(Ctx);
}

/* WRMSR */
static BOOLEAN HandleWrmsr(PGUEST_CONTEXT Ctx)
{
    return HandleWrmsrImpl(Ctx);
}

/*
 * CR Access - primarily for CR3 load monitoring (process switch detection)
 */
static BOOLEAN HandleCrAccess(PGUEST_CONTEXT Ctx)
{
    ULONG64     ExitQual;
    ULONG       CrNum;
    ULONG       AccessType;
    ULONG       GpReg;
    ULONG64     NewValue;

    ExitQual = VmxRead(VMCS_EXIT_QUALIFICATION);
    CrNum     = (ULONG)(ExitQual & CR_ACCESS_CR_NUM_MASK);
    AccessType = (ULONG)((ExitQual >> CR_ACCESS_TYPE_SHIFT) & 0x3);
    GpReg     = (ULONG)((ExitQual >> CR_ACCESS_GP_REG_SHIFT) & CR_ACCESS_GP_REG_MASK);

    switch (AccessType) {
    case CR_ACCESS_TYPE_MOV_TO_CR:
        NewValue = GetGpRegValue(Ctx, GpReg);

        if (CrNum == 3) {
            /* CR3 load - process switch */
            VmxWrite(VMCS_GUEST_CR3, NewValue);

            /* We could log process switches for targets here */
        }
        else if (CrNum == 0) {
            /* Adjust for VMX fixed bits */
            NewValue |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
            NewValue &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
            VmxWrite(VMCS_GUEST_CR0, NewValue);
            VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, NewValue);
        }
        else if (CrNum == 4) {
            /* Keep VMXE bit set in actual CR4, but hide from guest */
            ULONG64 ActualCr4 = NewValue | CR4_VMXE;
            VmxWrite(VMCS_GUEST_CR4, ActualCr4);
            VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, NewValue);
        }
        break;

    case CR_ACCESS_TYPE_MOV_FROM_CR:
        if (CrNum == 3) {
            SetGpRegValue(Ctx, GpReg, VmxRead(VMCS_GUEST_CR3));
        }
        else if (CrNum == 0) {
            SetGpRegValue(Ctx, GpReg, VmxRead(VMCS_CTRL_CR0_READ_SHADOW));
        }
        else if (CrNum == 4) {
            /* Return CR4 without VMXE to hide VMX from guest */
            SetGpRegValue(Ctx, GpReg, VmxRead(VMCS_CTRL_CR4_READ_SHADOW));
        }
        break;

    case CR_ACCESS_TYPE_CLTS:
        /* CLTS - clear Task Switched flag in CR0 */
        {
            ULONG64 Cr0 = VmxRead(VMCS_GUEST_CR0);
            Cr0 &= ~(1ULL << 3);  /* Clear TS bit */
            VmxWrite(VMCS_GUEST_CR0, Cr0);
        }
        break;

    case CR_ACCESS_TYPE_LMSW:
        /* LMSW - load machine status word (low 16 bits of CR0) */
        {
            ULONG64 Cr0 = VmxRead(VMCS_GUEST_CR0);
            USHORT  Msw = (USHORT)(ExitQual >> 16);
            Cr0 = (Cr0 & ~0xFFFFULL) | Msw;
            Cr0 |= CR0_PE;  /* PE cannot be cleared by LMSW */
            VmxWrite(VMCS_GUEST_CR0, Cr0);
        }
        break;
    }

    VmxAdvanceGuestRip();
    return TRUE;
}

/* DR Access - delegate to anti-anti-debug */
static BOOLEAN HandleDrAccess(PGUEST_CONTEXT Ctx)
{
    return AadHandleDrAccess(Ctx);
}

/* Exception/NMI - delegate to anti-anti-debug */
static BOOLEAN HandleException(PGUEST_CONTEXT Ctx)
{
    ULONG64 IntInfo = VmxRead(VMCS_EXIT_INTERRUPTION_INFO);
    ULONG   IntType = (ULONG)((IntInfo & INTERRUPT_INFO_TYPE_MASK) >> INTERRUPT_INFO_TYPE_SHIFT);

    /* NMI - re-inject directly */
    if (IntType == INTERRUPT_TYPE_NMI) {
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_NMI << INTERRUPT_INFO_TYPE_SHIFT) |
                 2);  /* NMI vector */
        return TRUE;
    }

    return AadHandleException(Ctx);
}

/* RDTSC - delegate to anti-anti-debug */
static BOOLEAN HandleRdtsc(PGUEST_CONTEXT Ctx)
{
    return AadHandleRdtsc(Ctx);
}

/* RDTSCP - like RDTSC but also sets ECX = IA32_TSC_AUX */
static BOOLEAN HandleRdtscp(PGUEST_CONTEXT Ctx)
{
    /* Handle TSC part same as RDTSC */
    AadHandleRdtsc(Ctx);

    /* Also return IA32_TSC_AUX in ECX */
    Ctx->Rcx = __readmsr(MSR_IA32_TSC_AUX) & 0xFFFFFFFF;

    /* Note: AadHandleRdtsc already advanced RIP */
    return TRUE;
}

/* EPT Violation - delegate to EPT module */
static BOOLEAN HandleEptViol(PGUEST_CONTEXT Ctx)
{
    return HandleEptViolation(Ctx);
}

/* EPT Misconfiguration - critical error */
static BOOLEAN HandleEptMisconfig(PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    LOG_ERROR("EPT misconfiguration at GPA=0x%llX, GuestRIP=0x%llX",
              VmxRead(VMCS_GUEST_PHYSICAL_ADDRESS),
              VmxRead(VMCS_GUEST_RIP));

    /* This is a fatal error - stop VMX */
    return FALSE;
}

/*
 * Monitor Trap Flag - single-step completed.
 * Used by EPT hook engine to restore execute-only after a read/write.
 */
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    ULONG64 ProcBased;
    ULONG i;

    UNREFERENCED_PARAMETER(Ctx);

    /* Disable MTF */
    ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
    ProcBased &= ~PROC_BASED_MONITOR_TRAP_FLAG;
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

    /*
     * Restore all EPT hooks to Execute-Only.
     * The EPT violation handler temporarily set RW on the hooked page
     * for a single instruction. Now we need to switch back.
     */
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
            PEPT_PTE Pte = g_EptHookState.Hooks[i].TargetPte;

            /* Only restore if currently in read/write mode */
            if (Pte->Read || Pte->Write) {
                Pte->Read = 0;
                Pte->Write = 0;
                Pte->Execute = 1;
                Pte->PhysAddr = g_EptHookState.Hooks[i].HookPagePa >> 12;
            }
        }
    }

    EptInvalidateAllContexts();

    return TRUE;
}

/*
 * VMCALL - Used for hypervisor control.
 * Magic value in RAX signals shutdown request.
 */
#define VMCALL_MAGIC_SHUTDOWN   0xDEADCAFE

static BOOLEAN HandleVmcall(PGUEST_CONTEXT Ctx)
{
    ULONG64 Rax = Ctx->Rax;
    ULONG   SubCmd;

    /* Legacy shutdown path */
    if (Rax == VMCALL_MAGIC_SHUTDOWN) {
        LOG_INFO("VMCALL shutdown request received");
        VmxAdvanceGuestRip();
        return FALSE;   /* Signal VMX shutdown */
    }

    /* New VMCALL dispatch: RAX high 16 bits = VMCALL_MAGIC */
    if ((Rax & VMCALL_MAGIC_MASK) == VMCALL_MAGIC) {
        SubCmd = (ULONG)(Rax & 0xFFFF);

        switch (SubCmd) {
        case VMCALL_SUBCMD_SHUTDOWN:
            LOG_INFO("VMCALL shutdown request received (new)");
            VmxAdvanceGuestRip();
            return FALSE;

        case VMCALL_SUBCMD_READ_MEMORY:
        case VMCALL_SUBCMD_WRITE_MEMORY:
            return HvHandleMemoryVmcall(Ctx, SubCmd);

        default:
            break;
        }
    }

    /* Unknown VMCALL - inject #UD (Invalid Opcode) */
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
             INTERRUPT_INFO_VALID |
             (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
             6);  /* #UD vector */
    return TRUE;
}

/* XSETBV - Extended Control Register write */
static BOOLEAN HandleXsetbv(PGUEST_CONTEXT Ctx)
{
    ULONG   Ecx = (ULONG)Ctx->Rcx;
    ULONG64 Value = (Ctx->Rax & 0xFFFFFFFF) | ((Ctx->Rdx & 0xFFFFFFFF) << 32);

    /* Execute the real XSETBV via ASM wrapper (WDK 7600 has no _xsetbv intrinsic) */
    AsmXsetbv(Ecx, Value);

    VmxAdvanceGuestRip();
    return TRUE;
}

/* INVD - Invalidate cache without writeback */
static BOOLEAN HandleInvd(PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    /* Convert INVD to WBINVD for safety (write back then invalidate) */
    __wbinvd();

    VmxAdvanceGuestRip();
    return TRUE;
}

/* INVLPG - Invalidate TLB entry */
static BOOLEAN HandleInvlpg(PGUEST_CONTEXT Ctx)
{
    ULONG64 LinearAddr;

    UNREFERENCED_PARAMETER(Ctx);

    LinearAddr = VmxRead(VMCS_EXIT_QUALIFICATION);
    __invlpg((PVOID)LinearAddr);

    VmxAdvanceGuestRip();
    return TRUE;
}

/* WBINVD - Write back and invalidate cache */
static BOOLEAN HandleWbinvd(PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    __wbinvd();

    VmxAdvanceGuestRip();
    return TRUE;
}

/* Triple Fault - fatal */
static BOOLEAN HandleTripleFault(PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    LOG_ERROR("Triple fault! Shutting down VMX.");
    return FALSE;
}

/* ========================================================================= */
/*  GP Register Helpers                                                      */
/* ========================================================================= */

/*
 * Map register index (from exit qualification) to GUEST_CONTEXT offset.
 * Register encoding: 0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI
 *                    8=R8,  9=R9,  10=R10, 11=R11, 12=R12, 13=R13, 14=R14, 15=R15
 */
static ULONG64 GetGpRegValue(PGUEST_CONTEXT Ctx, ULONG RegIndex)
{
    ULONG64 *Regs = (ULONG64 *)Ctx;

    if (RegIndex == 4) {
        /* RSP comes from VMCS, not the context */
        return VmxRead(VMCS_GUEST_RSP);
    }

    if (RegIndex <= 15) {
        return Regs[RegIndex];
    }

    return 0;
}

static VOID SetGpRegValue(PGUEST_CONTEXT Ctx, ULONG RegIndex, ULONG64 Value)
{
    ULONG64 *Regs = (ULONG64 *)Ctx;

    if (RegIndex == 4) {
        VmxWrite(VMCS_GUEST_RSP, Value);
        return;
    }

    if (RegIndex <= 15) {
        Regs[RegIndex] = Value;
    }
}
