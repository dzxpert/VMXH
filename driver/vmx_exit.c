/*
 * vmx_exit.c - VMX Anti-Anti-Debug Hypervisor
 * VM-Exit main dispatcher and individual exit handlers
 */

#include "vmx.h"
#include "ept.h"
#include "hv_ops.h"
#include "hv_mem.h"
#include "hv_hypercall.h"
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
    if (CpuIndex < g_MaxProcessors) {
        InterlockedIncrement64(&g_VmxState.CpuContexts[CpuIndex].ExitCount);
    }

    /* Check if Guest requested an EPT TLB flush */
    EptCheckPendingInvept();

    /* Check for VM-Entry failure (bit 31) */
    if (ExitReason & 0x80000000) {
        LOG_ERROR("VM-Entry failure! Reason: %u, Qualification: 0x%llX",
                  ExitReason & 0xFFFF, VmxRead(VMCS_EXIT_QUALIFICATION));
        /*
         * Mark CPU as no longer in VMX operation.
         * VmxShutdown ASM path will execute vmxoff and restore guest state.
         * We must clear both flags so VmxTerminate won't try vmcall or vmxoff.
         */
        if (CpuIndex < g_MaxProcessors) {
            g_VmxState.CpuContexts[CpuIndex].VmcsLaunched = FALSE;
            g_VmxState.CpuContexts[CpuIndex].VmxEnabled = FALSE;
        }
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

    /* ===== VMX Instruction Intercepts (nested virtualization) ===== */
    /*
     * When the guest executes VMX/EPT/VPID instructions (VMXON, VMXOFF,
     * VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMREAD, VMRESUME, VMWRITE,
     * INVEPT, INVVPID), these unconditionally cause VM-Exit in VMX
     * non-root operation (Intel SDM Vol. 3C, Section 25.1.2).
     *
     * Since we don't implement full nested virtualization, inject #UD
     * to the guest. The CPUID handler already hides the VMX capability
     * bit (CPUID.1:ECX[5]), so well-behaved software won't attempt these.
     * This handles malicious or VMX-probing code gracefully.
     *
     * Note: VMCALL is handled separately above as our hypercall interface.
     */
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
        /* Inject #UD (vector 6) - no error code */
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                 6);  /* #UD vector */
        break;

    case EXIT_REASON_HLT:
        /* HLT - just advance RIP and resume */
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_INVPCID:
        /*
         * INVPCID causes VM-Exit when both "INVLPG exiting" (primary bit 9)
         * and "enable INVPCID" (secondary bit 12) are set.
         * VmxAdjustControls may force "INVLPG exiting" on via must-be-1 bits.
         *
         * We just execute the equivalent INVLPG/INVPCID effect (full TLB
         * flush via INVVPID) and advance RIP.
         */
        {
            INVVPID_DESCRIPTOR VpidDesc;
            RtlZeroMemory(&VpidDesc, sizeof(VpidDesc));
            AsmVmxInvvpid(INVVPID_ALL_CONTEXTS, &VpidDesc);
        }
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_PREEMPT_TIMER:
        /* VMX-preemption timer expired. Just resume. */
        break;

    case EXIT_REASON_XSAVES:
    case EXIT_REASON_XRSTORS:
        /*
         * XSAVES/XRSTORS VM-Exit.
         * This should not happen if XSS exiting bitmap is 0, but handle
         * it gracefully: advance RIP and resume (instruction was not executed).
         * Guest will retry.
         * NOTE: Ideally we'd emulate the instruction, but for now just
         * re-inject #UD to let the guest fall back to a different path.
         */
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                 6);  /* #UD vector */
        break;

    case EXIT_REASON_GETSEC:
        /* GETSEC unconditionally causes VM-exit; inject #UD */
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                 6);
        break;

    case EXIT_REASON_RDPMC:
        /* RDPMC - inject #GP(0) if not supported, or pass through */
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                 INTERRUPT_INFO_DELIVER_ERR_CODE |
                 13);  /* #GP vector */
        VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, 0);
        break;

    case EXIT_REASON_MONITOR:
    case EXIT_REASON_MWAIT:
        /* MONITOR/MWAIT - just advance RIP and resume as NOPs */
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_PAUSE:
        /* PAUSE - just advance RIP */
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_GDTR_IDTR_ACCESS:
    case EXIT_REASON_LDTR_TR_ACCESS:
        /* Descriptor table accesses - advance RIP and resume */
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_TASK_SWITCH:
        /*
         * Task switch VM-Exit. Intel SDM: task switches unconditionally
         * cause VM-exit. This should be rare in 64-bit Windows, but can
         * happen (e.g., double-fault via task gate).
         *
         * For now, inject #GP to let the guest handle the error.
         * Full task switch emulation is extremely complex.
         */
        LOG_WARN("Task switch VM-Exit: qual=0x%llX, RIP=0x%llX",
                 VmxRead(VMCS_EXIT_QUALIFICATION),
                 VmxRead(VMCS_GUEST_RIP));
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                 INTERRUPT_INFO_DELIVER_ERR_CODE |
                 13);  /* #GP */
        VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, 0);
        break;

    case EXIT_REASON_IO_INSTRUCTION:
        /*
         * I/O instruction intercept.
         *
         * If VmxAdjustControls forced "unconditional I/O exiting" (bit 24)
         * or "use I/O bitmaps" (bit 25) via must-be-1 bits, every IN/OUT
         * instruction will cause a VM-Exit. Without handling this, the guest
         * re-executes the instruction → VM-Exit → infinite loop → VMware hangs.
         *
         * We emulate by executing the I/O instruction natively in host mode.
         * For simplicity, we use a pass-through approach: re-inject by
         * advancing RIP (the instruction already executed from the CPU's
         * point of view if it completed the access) — NO! For I/O exits
         * the instruction was NOT executed. We must emulate it.
         *
         * Exit Qualification bits for I/O:
         *   Bits 2:0  = Size (0=1 byte, 1=2 bytes, 3=4 bytes)
         *   Bit 3     = Direction (0=OUT, 1=IN)
         *   Bit 4     = String instruction
         *   Bit 5     = REP prefixed
         *   Bit 6     = Operand encoding (0=DX, 1=immediate)
         *   Bits 31:16 = Port number
         */
        {
            ULONG64 IoQual = VmxRead(VMCS_EXIT_QUALIFICATION);
            USHORT  Port = (USHORT)((IoQual >> 16) & 0xFFFF);
            ULONG   Size = (ULONG)(IoQual & 0x7);
            BOOLEAN IsIn = (IoQual & (1 << 3)) != 0;
            BOOLEAN IsString = (IoQual & (1 << 4)) != 0;
            
            if (!IsString) {
                /* Simple IN/OUT (not string) */
                if (IsIn) {
                    ULONG Value = 0;
                    switch (Size) {
                    case 0: Value = __inbyte(Port); break;
                    case 1: Value = __inword(Port); break;
                    case 3: Value = __indword(Port); break;
                    }
                    /* IN puts result in AL/AX/EAX (lower bits of RAX) */
                    switch (Size) {
                    case 0: GuestContext->Rax = (GuestContext->Rax & ~0xFFULL) | (Value & 0xFF); break;
                    case 1: GuestContext->Rax = (GuestContext->Rax & ~0xFFFFULL) | (Value & 0xFFFF); break;
                    case 3: GuestContext->Rax = (ULONG64)(ULONG)Value; break;
                    }
                } else {
                    /* OUT */
                    ULONG Value = (ULONG)GuestContext->Rax;
                    switch (Size) {
                    case 0: __outbyte(Port, (UCHAR)Value); break;
                    case 1: __outword(Port, (USHORT)Value); break;
                    case 3: __outdword(Port, Value); break;
                    }
                }
            } else {
                /*
                 * String I/O (INS/OUTS) is complex to emulate properly
                 * (needs RSI/RDI/RCX handling). For now, just advance RIP.
                 * The instruction was not executed, so guest data may be wrong,
                 * but this is better than an infinite loop.
                 */
                /* TODO: Full string I/O emulation */
            }
            VmxAdvanceGuestRip();
        }
        break;

    case EXIT_REASON_EXTERNAL_INT:
        /*
         * External interrupt exit (with ACK_INT_ON_EXIT enabled).
         *
         * The CPU has acknowledged the interrupt and stored the vector in
         * VMCS_EXIT_INTERRUPTION_INFO.  We must re-inject it into the guest.
         *
         * IMPORTANT: Intel SDM Vol. 3C, Section 26.3.1.5 - VM-Entry checks
         * for event injection require:
         *   1. RFLAGS.IF = 1
         *   2. Guest Interruptibility State bits 0-1 = 0
         *      (not blocking by STI or MOV SS)
         *
         * BUG FIX (Problem C): The original code only checked RFLAGS.IF.
         * After a STI instruction, IF=1 but "blocking by STI" is set for
         * one instruction. Injecting an external interrupt in this state
         * causes VM-Entry failure. We now check both conditions.
         */
        {
            ULONG64 IntInfo = VmxRead(VMCS_EXIT_INTERRUPTION_INFO);
            if (IntInfo & INTERRUPT_INFO_VALID) {
                ULONG Vector = (ULONG)(IntInfo & 0xFF);
                ULONG64 GuestRflags = VmxRead(VMCS_GUEST_RFLAGS);
                ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);

                if ((GuestRflags & (1ULL << 9)) &&
                    !(Interruptibility & 0x3)) {
                    /* IF=1 and not blocked by STI/MOV SS: safe to inject */
                    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                             INTERRUPT_INFO_VALID |
                             (INTERRUPT_TYPE_EXTERNAL << INTERRUPT_INFO_TYPE_SHIFT) |
                             Vector);
                } else {
                    /* IF=0 or blocked by STI/MOV SS: defer injection */
                    ULONG CpuIdx = KeGetCurrentProcessorNumber();
                    if (CpuIdx < g_MaxProcessors) {
                        g_VmxState.CpuContexts[CpuIdx].PendingInterrupt = TRUE;
                        g_VmxState.CpuContexts[CpuIdx].PendingInterruptVector = Vector;
                    }

                    /* Request interrupt-window exit */
                    {
                        ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
                        ProcBased |= PROC_BASED_INT_WINDOW_EXIT;
                        VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
                    }
                }
            }
        }
        break;

    case EXIT_REASON_INT_WINDOW:
        /*
         * Interrupt window opened: guest RFLAGS.IF is now 1.
         * Inject the pending interrupt that was deferred, then clear
         * the interrupt-window exiting bit.
         */
        {
            ULONG CpuIdx = KeGetCurrentProcessorNumber();
            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);

            /* Clear interrupt-window exiting */
            ProcBased &= ~PROC_BASED_INT_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

            /* Inject the saved interrupt */
            if (CpuIdx < g_MaxProcessors &&
                g_VmxState.CpuContexts[CpuIdx].PendingInterrupt) {
                ULONG Vector = g_VmxState.CpuContexts[CpuIdx].PendingInterruptVector;
                g_VmxState.CpuContexts[CpuIdx].PendingInterrupt = FALSE;

                VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                         INTERRUPT_INFO_VALID |
                         (INTERRUPT_TYPE_EXTERNAL << INTERRUPT_INFO_TYPE_SHIFT) |
                         Vector);
            }
        }
        break;

    case EXIT_REASON_NMI_WINDOW:
        /*
         * NMI window opened (Problem F): Guest is now ready to accept NMIs.
         * This exit happens when we deferred NMI injection because "blocking
         * by NMI" was set. Clear the NMI-window exiting bit and inject the NMI.
         */
        {
            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased &= ~PROC_BASED_NMI_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

            VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                     INTERRUPT_INFO_VALID |
                     (INTERRUPT_TYPE_NMI << INTERRUPT_INFO_TYPE_SHIFT) |
                     2);  /* NMI vector */
        }
        break;

    default:
        /*
         * BUG FIX: Unknown VM-Exit handling with infinite loop protection.
         *
         * If the same exit reason fires repeatedly at the same RIP, we're
         * in an infinite loop (instruction re-executes → same VM-Exit →
         * resume → repeat). This makes VMware appear to "hang".
         *
         * Strategy: Track the last unhandled exit. If the same reason fires
         * from the same RIP more than a threshold number of times, shut down
         * VMX to avoid freezing the entire VM.
         */
        {
            static volatile LONG s_UnhandledCount = 0;
            static volatile ULONG64 s_LastUnhandledRip = 0;
            static volatile ULONG s_LastUnhandledReason = 0;
            ULONG64 GuestRip = VmxRead(VMCS_GUEST_RIP);
            ULONG Reason = ExitReason & 0xFFFF;

            if (Reason == s_LastUnhandledReason && GuestRip == s_LastUnhandledRip) {
                LONG Count = InterlockedIncrement(&s_UnhandledCount);
                if (Count <= 5) {
                    LOG_WARN("Repeated unhandled VM-Exit[%d]: reason=%u, RIP=0x%llX",
                             (int)Count, Reason, GuestRip);
                }
                if (Count >= 100) {
                    /*
                     * Infinite loop detected - shut down VMX to prevent
                     * the entire VMware guest from freezing.
                     */
                    LOG_ERROR("Infinite VM-Exit loop detected! reason=%u, RIP=0x%llX - shutting down",
                              Reason, GuestRip);
                    Result = FALSE;
                    break;
                }
            } else {
                s_LastUnhandledReason = Reason;
                s_LastUnhandledRip = GuestRip;
                s_UnhandledCount = 1;
                LOG_WARN("Unhandled VM-Exit: reason=%u, qual=0x%llX, RIP=0x%llX",
                         Reason, VmxRead(VMCS_EXIT_QUALIFICATION), GuestRip);
            }
        }
        break;
    }

    return Result;
}

/* ========================================================================= */
/*  VMRESUME Failure Handler (called from ASM)                               */
/* ========================================================================= */

/*
 * VmxResumeFailedHandler - Called when vmresume fails.
 * This is invoked from AsmVmxExitHandler's VmxResumeFailed path.
 * We're still in VMX root mode, so VMCS reads still work.
 */
VOID VmxResumeFailedHandler(ULONG64 VmInstructionError)
{
    ULONG64 GuestRip = 0, GuestRsp = 0, ExitReason = 0;

    __try {
        GuestRip = VmxRead(VMCS_GUEST_RIP);
        GuestRsp = VmxRead(VMCS_GUEST_RSP);
        ExitReason = VmxRead(VMCS_EXIT_REASON);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Ignore - VMCS may be corrupted */
    }

    LOG_ERROR("*** VMRESUME FAILED ***");
    LOG_ERROR("  VM-instruction error: %llu", VmInstructionError);
    LOG_ERROR("  Guest RIP: 0x%llX, RSP: 0x%llX", GuestRip, GuestRsp);
    LOG_ERROR("  Last exit reason: %llu", ExitReason & 0xFFFF);
    LOG_ERROR("  CPU: %u", KeGetCurrentProcessorNumber());
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
    ULONG64     ShadowValue;

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
            /*
             * BUG FIX (Problem B): CR0 ReadShadow must store the Guest's
             * original value, not the VMX-adjusted value. This way, when
             * Guest reads CR0 (MOV from CR0), it sees what it wrote, not
             * the value with VMX fixed bits forced. The actual Guest CR0
             * field stores the adjusted value required by VMX operation.
             *
             * Intel SDM Vol. 3C, Section 25.1.3: "Bits owned by the host
             * are returned from the corresponding read shadow."
             */
            ShadowValue = NewValue;                      /* Guest's original value */
            NewValue |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
            NewValue &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
            VmxWrite(VMCS_GUEST_CR0, NewValue);
            VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, ShadowValue);  /* shadow = original */
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
            /*
             * BUG FIX (Problem G): Apply VMX CR0 fixed bits.
             *
             * VMX requires certain CR0 bits to always be 1 (e.g., NE) and
             * certain bits to always be 0. If LMSW modifies these restricted
             * bits without adjustment, the next VM-Entry will fail because
             * Guest CR0 violates fixed bit constraints.
             *
             * Intel SDM Vol. 3C, Section 26.3.1.1:
             * "If the value of bit X of CR0 is fixed to Y in VMX operation,
             *  then the corresponding bit in the guest CR0 field must be Y."
             */
            Cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
            Cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
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

    /*
     * BUG FIX (Problem F): NMI re-injection with blocking check.
     *
     * When NMI exits, we must re-inject the NMI back to the Guest.
     * However, Intel SDM Vol. 3C, Section 26.3.1.5 states that injecting
     * an NMI via VM-Entry interruption-information field requires that
     * "blocking by NMI" (Interruptibility State bit 3) is 0.
     *
     * Without PIN_BASED_VIRTUAL_NMIS enabled (current config), the CPU
     * clears "blocking by NMI" on NMI-induced VM-Exit (Intel SDM Table 27-3),
     * so direct re-injection is typically safe. However, on some CPU models
     * or if VmxAdjustControls forces VIRTUAL_NMIS on (must-be-1 bits),
     * the behavior differs and blocking may still be set.
     *
     * Fix: Check the NMI blocking bit. If set, request NMI-window exiting
     * to defer injection until the Guest is ready.
     */
    if (IntType == INTERRUPT_TYPE_NMI) {
        ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);

        if (!(Interruptibility & (1ULL << 3))) {
            /* Not blocked by NMI: safe to inject immediately */
            VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                     INTERRUPT_INFO_VALID |
                     (INTERRUPT_TYPE_NMI << INTERRUPT_INFO_TYPE_SHIFT) |
                     2);  /* NMI vector */
        } else {
            /* Blocked by NMI: request NMI-window exiting for deferred injection */
            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased |= PROC_BASED_NMI_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
        }
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
    /*
     * BUG FIX (Problem D): Document the implicit coupling with AadHandleRdtsc.
     *
     * AadHandleRdtsc() internally calls HvAdvanceGuestRip() — this is by design
     * so that both RDTSC and RDTSCP exits share the same TSC compensation logic.
     * Do NOT add another VmxAdvanceGuestRip() here, or Guest RIP will be advanced
     * twice, skipping the instruction after RDTSCP and causing corruption.
     *
     * If AadHandleRdtsc is ever refactored to NOT advance RIP internally,
     * a VmxAdvanceGuestRip() call MUST be added here.
     */
    AadHandleRdtsc(Ctx);

    /* Also return IA32_TSC_AUX in ECX (RDTSCP-specific) */
    Ctx->Rcx = __readmsr(MSR_IA32_TSC_AUX) & 0xFFFFFFFF;

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
 * Used by EPT hook engine to restore hook page after a read/write.
 *
 * BUG FIX: The original code restored ALL hooks globally, which caused a
 * multi-core race condition.  For example:
 *   - CPU 0 triggers EPT violation on hook A → switches to permissive → MTF
 *   - CPU 1 triggers EPT violation on hook B → switches to permissive
 *   - CPU 0's MTF fires → restores ALL hooks including B
 *   - CPU 1 hasn't finished executing its instruction → re-faults → infinite loop
 *
 * Fix: Each CPU only restores the specific hook(s) on pages that IT made
 * permissive.  We use a per-CPU tracking array (in ept.c) to record which
 * physical page was relaxed.  The MTF handler queries it and only restores
 * hooks on that specific page.
 */
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    ULONG64 ProcBased;
    ULONG64 RelaxedPa;
    ULONG   CpuIndex;

    UNREFERENCED_PARAMETER(Ctx);

    CpuIndex = KeGetCurrentProcessorNumber();

    /* Disable MTF */
    ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
    ProcBased &= ~PROC_BASED_MONITOR_TRAP_FLAG;
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

    /* Get which page THIS CPU relaxed (stored by HandleEptViolation) */
    RelaxedPa = EptMtfGetAndClearRelaxedPage();

    /*
     * Restore hook on the page this CPU relaxed.
     *
     * OPTIMIZATION: Use O(1) hash table lookup instead of O(n) linear scan.
     * The previous code iterated over all MAX_EPT_HOOKS (1024) entries on
     * every MTF exit — a hot path in VMX root mode. Since hooks are indexed
     * by physical page address and only ONE hook can exist per 4KB page, a
     * single hash lookup suffices.
     *
     * When RelaxedPa is 0 (shouldn't happen — indicates a logic error),
     * we fall back to the O(n) scan as a safety measure.
     *
     * Per-CPU hook page isolation: use this CPU's private PTE so that
     * restoring permissions only affects THIS CPU's EPT translation.
     * Other CPUs' temporarily relaxed PTEs remain untouched.
     */
    if (RelaxedPa != 0) {
        /* O(1) path: direct hash lookup for the specific hooked page */
        PEPT_HOOK_ENTRY Hook = EptFindHookByPhysicalAddress(RelaxedPa);
        if (Hook && Hook->Active && Hook->TargetPte) {
            PEPT_PTE Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
            if (!Pte) Pte = Hook->TargetPte;

            if (Pte->Read || Pte->Write) {
                Pte->Read = 0;
                Pte->Write = 0;
                Pte->PhysAddr = Hook->HookPagePa >> 12;

                if (g_EptHookState.ExecuteOnlySupported) {
                    Pte->Execute = 1;
                } else {
                    Pte->Execute = 0;
                }
            }
        }
    } else {
        /* Fallback O(n) path: RelaxedPa unknown, restore ALL hooks (safety) */
        ULONG i;
        for (i = 0; i < MAX_EPT_HOOKS; i++) {
            if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
                PEPT_PTE Pte = EptGetPerCpuPte(CpuIndex,
                    g_EptHookState.Hooks[i].TargetPhysicalAddr);
                if (!Pte) Pte = g_EptHookState.Hooks[i].TargetPte;

                if (Pte->Read || Pte->Write) {
                    Pte->Read = 0;
                    Pte->Write = 0;
                    Pte->PhysAddr = g_EptHookState.Hooks[i].HookPagePa >> 12;

                    if (g_EptHookState.ExecuteOnlySupported) {
                        Pte->Execute = 1;
                    } else {
                        Pte->Execute = 0;
                    }
                }
            }
        }
    }

    /*
     * BUG FIX (Issue #11): Use INVEPT SINGLE_CONTEXT when per-CPU EPT is active.
     * MTF handler only restores this CPU's private PTEs, so only this CPU's
     * EPT TLB needs flushing.
     */
    {
        ULONG64 CpuEptp = EptGetPerCpuEptp(CpuIndex);
        if (CpuEptp)
            EptInvalidateSingleContext(CpuEptp);
        else
            EptInvalidateAllContexts();
    }

    return TRUE;
}

/*
 * VMCALL - Used for hypervisor control.
 * Magic value in RAX signals shutdown request.
 * VMCALL_MAGIC_SHUTDOWN is defined in vmx.h.
 */

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

    /*
     * Unknown VMCALL - not ours.
     *
     * Windows issues VMCALL for Hyper-V enlightenments (TLB flush,
     * VP scheduling hints, etc.) when it detects a hypervisor via
     * CPUID.  VMware/KVM also trigger this.  We must NOT inject #UD
     * or the OS will crash (e.g. SwapContext uses VMCALL for TLB flush).
     *
     * FIX: Instead of blindly returning HV_STATUS_INVALID_HYPERCALL_CODE
     * (0x0002) — which causes SwapContext to crash because TLB is not
     * actually flushed — we now parse the Hyper-V hypercall input value
     * in RCX and emulate the critical TLB flush hypercalls.
     *
     * For emulated calls: RAX = 0 (HV_STATUS_SUCCESS)
     * For unknown calls:  RAX = 2 (HV_STATUS_INVALID_HYPERCALL_CODE)
     */
    {
        static volatile LONG s_VmcallLogCount = 0;
        LONG Count = InterlockedIncrement(&s_VmcallLogCount);
        if (Count <= 10) {
            ULONG64 GuestRip = VmxRead(VMCS_GUEST_RIP);
            LOG_INFO("VMCALL[%d]: RAX=0x%llX RCX=0x%llX RDX=0x%llX R8=0x%llX RIP=0x%llX",
                     (int)Count, Rax, Ctx->Rcx, Ctx->Rdx, Ctx->R8, GuestRip);
        }
        Ctx->Rax = HvEmulateHypercall(Ctx->Rcx, Ctx->Rdx, Ctx->R8);
    }
    VmxAdvanceGuestRip();
    return TRUE;
}

/* XSETBV - Extended Control Register write */
static BOOLEAN HandleXsetbv(PGUEST_CONTEXT Ctx)
{
    ULONG   Ecx = (ULONG)Ctx->Rcx;
    ULONG64 Value = (Ctx->Rax & 0xFFFFFFFF) | ((Ctx->Rdx & 0xFFFFFFFF) << 32);

    /*
     * BUG FIX (Code Quality #5): Validate XCR0 before executing XSETBV.
     *
     * If the Guest writes an illegal XCR0 combination, the XSETBV instruction
     * would execute in Host context and trigger a #GP, crashing the Hypervisor.
     *
     * Intel SDM Vol. 1, Section 13.3 — XCR0 constraints:
     *   - Bit 0 (x87) must always be 1
     *   - If bit 2 (AVX) is set, bit 1 (SSE) must also be set
     *   - XCR index must be 0 (only XCR0 is currently defined)
     *
     * If validation fails, inject #GP(0) into the Guest instead.
     */
    if (Ecx != 0) {
        /* Only XCR0 (index 0) is valid; all others → #GP(0) */
        goto InjectGp;
    }

    if (!(Value & 1)) {
        /* Bit 0 (x87 FPU) must be 1 */
        goto InjectGp;
    }

    if ((Value & (1ULL << 2)) && !(Value & (1ULL << 1))) {
        /* AVX (bit 2) requires SSE (bit 1) */
        goto InjectGp;
    }

    /* Execute the real XSETBV via ASM wrapper (WDK 7600 has no _xsetbv intrinsic) */
    AsmXsetbv(Ecx, Value);

    VmxAdvanceGuestRip();
    return TRUE;

InjectGp:
    /* Inject #GP(0) into Guest */
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
             INTERRUPT_INFO_VALID |
             (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
             INTERRUPT_INFO_DELIVER_ERR_CODE |
             13);  /* #GP vector = 13 */
    VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, 0);
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
