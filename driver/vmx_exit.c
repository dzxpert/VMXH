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

    /*
     * DIAGNOSTIC: Per-CPU early exit counting with rapid-fire detection.
     *
     * When VM-Exits fire at extremely high frequency (e.g., millions per
     * second due to unhandled UNCONDITIONAL_IO_EXIT), the system
     * becomes unresponsive because each exit involves a VMEXIT → handler →
     * VMRESUME round-trip overhead.
     *
     * Fix: Track per-CPU exit count. If >10000 exits occur with no
     * "quiet period" (i.e., rapid-fire), forcefully shut down VMX.
     * This counter is checked BEFORE any logging to avoid recursion.
     *
     * Note: Uses static volatiles — safe because each CPU only accesses
     * its own data (partitioned by CpuIndex).
     *
     * Declared here (before any statements) for C89 compatibility
     * required by WDK 7.1 (MSVC 2008).
     */
    static volatile LONG64 s_EarlyExitCount[64] = { 0 };
    static volatile LONG64 s_LastReportedCount[64] = { 0 };

    /*
     * CRITICAL: Sync Guest RSP from VMCS into GuestContext at VM-Exit entry.
     *
     * The ASM stub saves GP registers to the stack-based GUEST_CONTEXT, but
     * RSP in that struct is a placeholder — it holds the Host stack pointer
     * at the time of the push, NOT the Guest RSP. The real Guest RSP lives
     * in VMCS_GUEST_RSP.
     *
     * By syncing it here (like HyperDbg does in VmxVmexitHandler), ALL
     * subsequent handlers can use GpRegs[4] / GuestContext->Rsp directly
     * without needing special-case code for RegIndex==4.
     *
     * On VM-Exit completion, we write back the (potentially modified) value
     * to VMCS_GUEST_RSP before VMRESUME.
     */
    GuestContext->Rsp = VmxRead(VMCS_GUEST_RSP);

    ExitReason = (ULONG)VmxRead(VMCS_EXIT_REASON);
    CpuIndex = KeGetCurrentProcessorNumber();

    /* Increment exit counter */
    if (CpuIndex < g_MaxProcessors) {
        LONG64 Count = InterlockedIncrement64(&g_VmxState.CpuContexts[CpuIndex].ExitCount);

        /*
         * HEARTBEAT DIAGNOSTIC: Log every 10000th exit per-CPU.
         * This creates a timeline showing what exit reasons appear
         * over time. When the system freezes, the last heartbeat message
         * in WinDbg tells us exactly where the system got stuck.
         *
         * Also includes rapid-fire detection at 100K intervals.
         */
        if (CpuIndex < 64) {
            s_EarlyExitCount[CpuIndex] = Count;

            /*
             * Heartbeat: Log periodically FOREVER (no upper bound).
             * - Every 100 exits for the first 5000 (detailed early diagnosis)
             * - Every 10000 exits thereafter (low-overhead long-term monitoring)
             * Uses ring buffer only — safe in VMX root mode.
             */
            if ((Count <= 5000 && (Count % 100) == 0) ||
                (Count > 5000 && (Count % 10000) == 0)) {
                VMXROOT_LOG_INFO("HEARTBEAT CPU%u: count=%lld reason=%u qual=0x%llX RIP=0x%llX",
                           CpuIndex, Count, (ULONG)(ExitReason & 0xFFFF),
                           VmxRead(VMCS_EXIT_QUALIFICATION),
                           VmxRead(VMCS_GUEST_RIP));
            }

            /* Rapid-fire detection at 1K intervals (first 10K only) */
            if (Count - s_LastReportedCount[CpuIndex] >= 1000) {
                s_LastReportedCount[CpuIndex] = Count;
                if (Count <= 10000) {
                    VMXROOT_LOG_INFO("RAPID CPU%u: count=%lld reason=%u RIP=0x%llX",
                               CpuIndex, Count, (ULONG)(ExitReason & 0xFFFF),
                               VmxRead(VMCS_GUEST_RIP));
                }
            }
        }
    }

    /* Check if Guest requested an EPT TLB flush */
    EptCheckPendingInvept();

    /*
     * AAD-BP (post-2nd-review): lazy-sync this CPU's VMCS Exception
     * Bitmap with the global desired value.  Cheap fast-path (branch on
     * generation compare); VMWRITE only on actual change.  Avoids
     * cross-CPU VMCS ownership problems by letting each CPU update its
     * OWN VMCS in its OWN exit handler.
     */
    VmxSyncExceptionBitmap();

    /* Check for VM-Entry failure (bit 31) */
    if (ExitReason & 0x80000000) {
        VMXROOT_LOG_ERROR("VM-Entry failure! Reason: %u, Qualification: 0x%llX",
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

    /*
     * EARLY DIAGNOSTIC: Log the first N VM-Exits from each CPU.
     * Uses lock-free ring buffer (VMXROOT_LOG_*) — safe in VMX root mode.
     */
    {
        static volatile LONG s_EarlyLogCountPerCpu[64] = { 0 };
        if (CpuIndex < 64) {
            LONG EarlyCount = InterlockedIncrement(&s_EarlyLogCountPerCpu[CpuIndex]);
            if (EarlyCount <= 30) {
                USHORT Reason = (USHORT)(ExitReason & 0xFFFF);
                if (Reason == EXIT_REASON_RDMSR || Reason == EXIT_REASON_WRMSR) {
                    VMXROOT_LOG_INFO("VM-Exit CPU%u #%d: reason=%u (%s) MSR=0x%08X RIP=0x%llX",
                               CpuIndex, (int)EarlyCount, (ULONG)Reason,
                               Reason == EXIT_REASON_RDMSR ? "RDMSR" : "WRMSR",
                               (ULONG)GuestContext->Rcx,
                               VmxRead(VMCS_GUEST_RIP));
                } else {
                    VMXROOT_LOG_INFO("VM-Exit CPU%u #%d: reason=%u qual=0x%llX RIP=0x%llX",
                               CpuIndex, (int)EarlyCount, (ULONG)(ExitReason & 0xFFFF),
                               VmxRead(VMCS_EXIT_QUALIFICATION),
                               VmxRead(VMCS_GUEST_RIP));
                }
            }
        }
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

    /* ===== VMX Instruction Intercepts ===== */
    /*
     * When the guest executes VMX/EPT/VPID instructions (VMXON, VMXOFF,
     * VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMREAD, VMRESUME, VMWRITE,
     * INVEPT, INVVPID), these unconditionally cause VM-Exit in VMX
     * non-root operation (Intel SDM Vol. 3C, Section 25.1.2).
     *
     * We inject #UD to the guest. The CPUID handler already hides the
     * VMX capability bit (CPUID.1:ECX[5]), so well-behaved software
     * won't attempt these. This handles malicious or VMX-probing code
     * gracefully.
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
        /*
         * HLT exit — Guest wants to sleep until an interrupt arrives.
         *
         * HLT_EXIT may be forced by must-be-1 bits, so every Guest HLT
         * causes a VM-Exit.
         *
         * IMPORTANT: We CANNOT execute native HLT in VMX root mode!
         * Doing _enable() + __halt() in VMX root would cause interrupts to
         * be delivered through the Host IDT while on the Host stack (16KB
         * ExAllocatePool buffer). This is catastrophic because:
         *   1. ISRs execute on our tiny Host stack → stack overflow risk
         *   2. ISR runs in the middle of our VM-Exit handler → corrupts
         *      local variables and call chain on the same stack
         *   3. ISR may call KeInsertQueueDpc/scheduler code that assumes
         *      a normal kernel thread stack with proper KPCR/KPRCB linkage
         *   4. IRET from ISR returns to our handler mid-execution with
         *      potentially corrupted state
         *
         * Strategy: Set Guest Activity State to "HLT" (value 1).
         * The CPU will enter Guest mode in HLT state. When an external
         * interrupt arrives, the CPU will VM-Exit with EXIT_REASON_HLT or
         * EXIT_REASON_EXTERNAL_INT (depending on PIN_BASED_EXTERNAL_INT_EXIT).
         * This achieves true CPU yielding without any VMX root mode risk.
         *
         * We do NOT advance Guest RIP — the HLT instruction is "completed"
         * by entering the HLT activity state. When the Guest wakes (via
         * interrupt injection or activity state change back to Active),
         * execution resumes at the instruction AFTER HLT automatically.
         *
         * NOTE: We advance RIP first, then set HLT state. This way, when
         * the CPU wakes from HLT (interrupt arrives → VM-Exit → we set
         * activity state back to Active → VMRESUME), Guest resumes at the
         * instruction after HLT, which is the correct behavior.
         *
         * L-8 (revised) FIX: Intel SDM Vol.3 §26.3.1.5 specifies that
         * Guest-Activity-State = HLT is valid at VM-Entry only if ALL of:
         *   (a) RFLAGS.IF = 1
         *   (b) "Blocking by STI"     (Interruptibility bit 0) is clear
         *   (c) "Blocking by MOV SS"  (Interruptibility bit 1) is clear
         *   (d) Blocking by NMI (bit 3) is ALLOWED to be either value
         *   (e) VMCS_GUEST_PENDING_DBG_EXCEPTIONS is zero
         *
         * Violating any of (a)/(b)/(c)/(e) causes the next VM-Entry to
         * fail with a VMfail reason, BSOD.  We defensively keep the
         * guest in Active state when the constraints aren't met — the
         * guest just re-executes the instruction after HLT and spins,
         * matching native CPU behaviour for "CLI; HLT" etc.
         */
        VmxAdvanceGuestRip();
        {
            ULONG64 GuestRflags      = VmxRead(VMCS_GUEST_RFLAGS);
            ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);
            ULONG64 PendingDbg       = VmxRead(VMCS_GUEST_PENDING_DBG_EXCEPTIONS);
            BOOLEAN IfOk             = (GuestRflags & (1ULL << 9)) != 0;
            BOOLEAN StiMovSsOk       = (Interruptibility & 0x3) == 0;
            BOOLEAN NoPendingDbg     = PendingDbg == 0;

            if (IfOk && StiMovSsOk && NoPendingDbg) {
                VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 1);  /* 1 = HLT */
            } else {
                VMXROOT_LOG_DEBUG("HLT skipped: IF=%u StiMovSs=0x%llX PendingDbg=0x%llX",
                                  (ULONG)IfOk, Interruptibility, PendingDbg);
            }
        }
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

    case EXIT_REASON_APIC_ACCESS:
        /*
         * APIC access VM-Exit. This can happen if must-be-1 bits force
         * "APIC-register virtualization" or "virtualize APIC accesses".
         * Just advance RIP.
         */
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_TPR_BELOW_THRESHOLD:
        /*
         * TPR below threshold - used for virtual APIC / CR8 monitoring.
         * Just resume, nothing to do.
         */
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
        VMXROOT_LOG_WARN("Task switch VM-Exit: qual=0x%llX, RIP=0x%llX",
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
         * re-executes the instruction → VM-Exit → infinite loop → system hangs.
         *
         * We emulate by executing the I/O instruction natively in host mode.
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

            /*
             * DIAGNOSTIC: Log the first few I/O exits to identify which
             * ports are causing the VM-Exit storm.
             */
            {
                static volatile LONG s_IoExitLogCount = 0;
                LONG IoCount = InterlockedIncrement(&s_IoExitLogCount);
                if (IoCount <= 5) {
                    VMXROOT_LOG_INFO("IO Exit #%d: %s port=0x%04X size=%u string=%u RIP=0x%llX",
                             (int)IoCount,
                             IsIn ? "IN" : "OUT",
                             (ULONG)Port, Size, (ULONG)IsString,
                             VmxRead(VMCS_GUEST_RIP));
                }
            }

            if (!IsString) {
                /*
                 * Simple IN/OUT (not string) — emulate by executing the
                 * I/O in VMX root mode directly, WITHOUT __try/__except.
                 *
                 * CRITICAL: __try/__except (SEH) is UNSAFE in VMX root mode!
                 * The host stack (ExAllocatePoolWithTag'd 16KB buffer) is NOT
                 * a Windows thread kernel stack. SEH relies on walking the
                 * _EXCEPTION_REGISTRATION_RECORD chain on the thread stack,
                 * and NT's exception dispatcher validates stack boundaries.
                 * When SEH triggers on our host stack, the dispatcher follows
                 * invalid/zero-filled records → jumps to a stack address →
                 * executes zeroes (add byte ptr [rax], al) → BSOD 0x0A.
                 *
                 * In VMX root mode (CPL 0, no IOPL restriction), IN/OUT
                 * instructions execute without #GP for any port. The only
                 * risk is accessing non-existent hardware, which on x86
                 * simply returns 0xFF for IN (bus float) and is a NOP for OUT.
                 */
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
                 * String I/O (INS/OUTS) - complex to emulate properly
                 * (needs RSI/RDI/RCX handling with REP prefix).
                 * For now, just advance RIP. The instruction was not executed,
                 * so guest data may be wrong, but this is better than a hang.
                 */
                /* TODO: Full string I/O emulation */
            }
            VmxAdvanceGuestRip();
        }
        break;

    case EXIT_REASON_EXTERNAL_INT:
        /*
         * On bare metal, PIN_BASED_EXTERNAL_INT_EXIT is not requested.
         * External interrupts pass directly through Guest IDT.
         * If this fires unexpectedly, just resume — the interrupt was
         * already acknowledged if ACK_INT_ON_EXIT happened to be set.
         */
        break;

    case EXIT_REASON_INT_WINDOW:
        /* Clear interrupt-window exiting bit */
        {
            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased &= ~PROC_BASED_INT_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
        }
        break;

    case EXIT_REASON_NMI_WINDOW:
        /* NMI window opened — inject the deferred NMI now */
        {
            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased &= ~PROC_BASED_NMI_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
        }
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_NMI << INTERRUPT_INFO_TYPE_SHIFT) |
                 2);  /* NMI vector */
        break;

    default:
        /*
         * BUG FIX: Unknown VM-Exit handling with AGGRESSIVE loop protection.
         *
         * If the same exit reason fires repeatedly at the same RIP, we're
         * in an infinite loop (instruction re-executes → same VM-Exit →
         * resume → repeat). This makes the system appear to "hang".
         *
         * At 3 repetitions we shut down immediately.
         */
        {
            static volatile LONG s_UnhandledCount = 0;
            static volatile ULONG64 s_LastUnhandledRip = 0;
            static volatile ULONG s_LastUnhandledReason = 0;
            ULONG64 GuestRip = VmxRead(VMCS_GUEST_RIP);
            ULONG Reason = ExitReason & 0xFFFF;

            if (Reason == s_LastUnhandledReason && GuestRip == s_LastUnhandledRip) {
                LONG Count = InterlockedIncrement(&s_UnhandledCount);
                if (Count >= 3) {
                    VMXROOT_LOG_ERROR("FATAL: Infinite VM-Exit loop! reason=%u, "
                              "qual=0x%llX, RIP=0x%llX, count=%d - SHUTTING DOWN VMX",
                              Reason, VmxRead(VMCS_EXIT_QUALIFICATION),
                              GuestRip, (int)Count);
                    Result = FALSE;
                    break;
                }
            } else {
                s_LastUnhandledReason = Reason;
                s_LastUnhandledRip = GuestRip;
                s_UnhandledCount = 1;

                /* First occurrence of a new unhandled exit: log details */
                VMXROOT_LOG_WARN("Unhandled VM-Exit: reason=%u, qual=0x%llX, RIP=0x%llX, CPU=%u",
                         Reason, VmxRead(VMCS_EXIT_QUALIFICATION),
                         GuestRip, CpuIndex);
            }

            /*
             * For the first few occurrences, try to advance RIP to avoid
             * infinite loop while we're still diagnosing.
             */
            VmxAdvanceGuestRip();
        }
        break;
    }

    /*
     * DIAGNOSTIC: Confirm handler completion for first 10 exits per CPU.
     */
    {
        static volatile LONG s_DoneLogCount[64] = { 0 };
        if (CpuIndex < 64) {
            LONG DoneCount = InterlockedIncrement(&s_DoneLogCount[CpuIndex]);
            if (DoneCount <= 10) {
                VMXROOT_LOG_INFO("DONE CPU%u #%d: reason=%u result=%d",
                           CpuIndex, (int)DoneCount,
                           (ULONG)(ExitReason & 0xFFFF), (int)Result);
            }
        }
    }

    /*
     * IDT-VECTORING EVENT RE-INJECTION
     *
     * Intel SDM Vol. 3C, Section 27.2.4:
     * When a VM-Exit occurs during delivery of an event through the IDT
     * (e.g., a page fault is being delivered but an EPT violation occurs
     * mid-delivery), the VMCS IDT-vectoring information field records
     * the interrupted event.
     *
     * If we do NOT re-inject this event, the Guest LOSES it silently:
     *   - Lost #PF → process accesses unmapped page → memory corruption
     *   - Lost #GP → Guest enters undefined state
     *   - Lost #DF → next exception becomes triple fault → CPU shutdown
     *   - Lost external interrupt → device stall, timer loss, DPC starvation
     *
     * Fix: Check IDT-vectoring info at the END of every VM-Exit handler.
     * If valid AND no other event is already being injected via
     * VMENTRY_INT_INFO, re-inject the original event.
     *
     * IMPORTANT: Only re-inject if the current handler did NOT already
     * write VMENTRY_INT_INFO (check the Valid bit). Some handlers
     * (e.g., HandleException for NMI) may have already set up an injection.
     * Double-injection is a VMCS consistency check failure → VM-Entry fail.
     */
    if (Result) {
        ULONG64 IdtVecInfo = VmxRead(VMCS_IDT_VECTORING_INFO);

        if (IdtVecInfo & INTERRUPT_INFO_VALID) {
            ULONG64 CurrentEntryInfo = VmxRead(VMCS_CTRL_VMENTRY_INT_INFO);

            if (!(CurrentEntryInfo & INTERRUPT_INFO_VALID)) {
                /* No injection pending — safe to re-inject the IDT event */
                VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, (ULONG)IdtVecInfo);

                /* Re-inject error code if the original event had one */
                if (IdtVecInfo & INTERRUPT_INFO_DELIVER_ERR_CODE) {
                    ULONG64 IdtVecErrCode = VmxRead(VMCS_IDT_VECTORING_ERRCODE);
                    VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, (ULONG)IdtVecErrCode);
                }

                /*
                 * Re-inject instruction length for software interrupts/exceptions.
                 * Intel SDM: VM-Entry instruction length is required when injecting
                 * software interrupts (INT n), software exceptions (#BP, #OF), or
                 * privileged software exceptions (INT1).
                 */
                {
                    ULONG IntType = (ULONG)((IdtVecInfo >> INTERRUPT_INFO_TYPE_SHIFT) & 0x7);
                    if (IntType == INTERRUPT_TYPE_SOFTWARE_INT ||
                        IntType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION ||
                        IntType == INTERRUPT_TYPE_PRIV_SOFTWARE_INT) {
                        VmxWrite(VMCS_CTRL_VMENTRY_INSTR_LENGTH,
                                 VmxRead(VMCS_EXIT_INSTRUCTION_LENGTH));
                    }
                }

                {
                    static volatile LONG s_IdtReinjectCount = 0;
                    LONG cnt = InterlockedIncrement(&s_IdtReinjectCount);
                    if (cnt <= 20 || (cnt % 1000 == 0)) {
                        VMXROOT_LOG_INFO("IDT-REINJECT #%d: vec=%u type=%u err=%s "
                                   "exit-reason=%u CPU=%u RIP=0x%llX",
                                   (int)cnt,
                                   (ULONG)(IdtVecInfo & INTERRUPT_INFO_VECTOR_MASK),
                                   (ULONG)((IdtVecInfo >> INTERRUPT_INFO_TYPE_SHIFT) & 0x7),
                                   (IdtVecInfo & INTERRUPT_INFO_DELIVER_ERR_CODE) ? "yes" : "no",
                                   (ULONG)(ExitReason & 0xFFFF),
                                   CpuIndex,
                                   VmxRead(VMCS_GUEST_RIP));
                    }
                }
            }
            /* else: handler already injected an event, IDT event is lost.
             * This is a known limitation — the handler's injection takes
             * priority. The Guest OS will re-trigger the original exception
             * when it re-executes the faulting instruction. */
        }
    }

    /*
     * Write back Guest RSP to VMCS before VMRESUME.
     * Any handler that modified GuestContext->Rsp (e.g., DR access with
     * GpReg==4, CR access) will have the change applied to VMCS here.
     */
    VmxWrite(VMCS_GUEST_RSP, GuestContext->Rsp);

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

    /*
     * Read VMCS fields directly WITHOUT __try/__except.
     *
     * CRITICAL: __try/__except (SEH) is UNSAFE in VMX root mode!
     * The host stack is not a thread kernel stack, so SEH's exception
     * registration chain is invalid here. If vmread fails, it simply
     * sets CF/ZF flags — it does NOT generate an x86 exception.
     * Therefore __try/__except was never needed here in the first place.
     *
     * vmread only fails if:
     *   - Not in VMX operation (impossible — we're called from VM-Exit handler)
     *   - Invalid field encoding (impossible — these are standard encodings)
     * In both cases, the values remain 0 (our initializers above).
     */
    GuestRip = VmxRead(VMCS_GUEST_RIP);
    GuestRsp = VmxRead(VMCS_GUEST_RSP);
    ExitReason = VmxRead(VMCS_EXIT_REASON);

    /*
     * This is a fatal path — we're about to vmxoff + hlt, so
     * we need maximum chance of the message reaching WinDbg.
     */
    VMXROOT_LOG_ERROR("*** VMRESUME FAILED *** VM-instruction error: %llu, "
              "Guest RIP: 0x%llX, RSP: 0x%llX, Last exit reason: %llu, CPU: %u",
              VmInstructionError, GuestRip, GuestRsp,
              ExitReason & 0xFFFF, KeGetCurrentProcessorNumber());
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

            /* Update hardware TSC Offset for the new process context */
            AadUpdateHwTscOffset(NewValue);

            /* DIAGNOSTIC: Log first few CR3 switches to confirm normal operation */
            {
                static volatile LONG s_Cr3SwitchCount = 0;
                LONG Cr3Count = InterlockedIncrement(&s_Cr3SwitchCount);
                if (Cr3Count <= 5) {
                    LOG_INFO("CR3 switch #%d: new CR3=0x%llX CPU=%u",
                             (int)Cr3Count, NewValue, KeGetCurrentProcessorNumber());
                }
            }
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

/* DR Access - delegate to anti-anti-debug.
 * NOTE: With MOV_DR_EXIT disabled in VMCS setup, this handler should
 * NOT fire. If it does fire (due to must-be-1 bits forcing DR exiting),
 * AadHandleDrAccess still handles it correctly by passing through the
 * real DR values (since no target process is set). */
static BOOLEAN HandleDrAccess(PGUEST_CONTEXT Ctx)
{
    return AadHandleDrAccess(Ctx);
}

/* Exception/NMI — bare-metal NMI reinject + anti-anti-debug delegation */
static BOOLEAN HandleException(PGUEST_CONTEXT Ctx)
{
    ULONG64 IntInfo = VmxRead(VMCS_EXIT_INTERRUPTION_INFO);
    ULONG   IntType = (ULONG)((IntInfo & INTERRUPT_INFO_TYPE_MASK) >> INTERRUPT_INFO_TYPE_SHIFT);

    if (IntType == INTERRUPT_TYPE_NMI) {
        /* Bare metal: always reinject NMI to Guest */
        ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);

        if (!(Interruptibility & (1ULL << 3))) {
            /* Not blocked by NMI — inject immediately */
            VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                     INTERRUPT_INFO_VALID |
                     (INTERRUPT_TYPE_NMI << INTERRUPT_INFO_TYPE_SHIFT) |
                     2);  /* NMI vector */
        } else {
            /* Blocked by NMI — defer via NMI-window exiting */
            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased |= PROC_BASED_NMI_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

            /* Wake from HLT if needed */
            if (VmxRead(VMCS_GUEST_ACTIVITY_STATE) == 1)
                VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 0);
        }
        return TRUE;
    }

    return AadHandleException(Ctx);
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

    /*
     * M-6 (revised): authenticate shutdown requests with a per-boot
     * nonce + full long-mode / CPL / kernel-RIP checks.  Centralised in
     * HvIsAuthenticShutdownCaller() so VMX and SVM use identical policy.
     *
     * For non-shutdown VMCALLs we still reject CPL != 0 immediately:
     * Windows kernel code never issues VMCALL in Ring 3, so any CPL-3
     * VMCALL must be an attempted attack.  Not required for security
     * (our hypervisor wouldn't do anything useful for them anyway), but
     * good defence in depth.
     */
    {
        ULONG64 GuestCsSel = VmxRead(VMCS_GUEST_CS_SEL);
        ULONG   GuestCpl   = (ULONG)(GuestCsSel & 0x3);
        if (GuestCpl != 0) {
            VMXROOT_LOG_WARN("VMCALL from CPL=%u — injecting #UD", GuestCpl);
            VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                     INTERRUPT_INFO_VALID |
                     (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                     6 /* #UD */);
            return TRUE;
        }
    }

    /*
     * Gather the full context needed to authenticate a shutdown request.
     * These reads are cheap (VMREAD) and are only done for VMCALLs,
     * which are rare.
     */
    {
        ULONG64 GuestRip   = VmxRead(VMCS_GUEST_RIP);
        ULONG64 GuestEfer  = VmxRead(VMCS_GUEST_IA32_EFER);
        ULONG64 CsAR       = VmxRead(VMCS_GUEST_CS_ACCESS_RIGHTS);
        BOOLEAN GuestCsL   = (CsAR & (1ULL << 13)) != 0;  /* bit 13 = L */
        ULONG64 CsSel      = VmxRead(VMCS_GUEST_CS_SEL);
        ULONG   GuestCpl   = (ULONG)(CsSel & 0x3);

        /* Legacy shutdown path. */
        if (Rax == VMCALL_MAGIC_SHUTDOWN) {
            if (!HvIsAuthenticShutdownCaller(Ctx->Rcx, GuestRip,
                                             GuestCpl, GuestEfer, GuestCsL)) {
                VMXROOT_LOG_WARN("VMCALL shutdown rejected: auth failed "
                                 "(RIP=0x%llX, Efer=0x%llX, CsL=%u, CPL=%u)",
                                 GuestRip, GuestEfer, (ULONG)GuestCsL, GuestCpl);
                VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                         INTERRUPT_INFO_VALID |
                         (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                         6 /* #UD */);
                return TRUE;
            }
            LOG_INFO("VMCALL shutdown request received (authenticated)");
            VmxAdvanceGuestRip();
            return FALSE;   /* Signal VMX shutdown */
        }

        /* New VMCALL dispatch: RAX high 16 bits = VMCALL_MAGIC */
        if ((Rax & VMCALL_MAGIC_MASK) == VMCALL_MAGIC) {
            SubCmd = (ULONG)(Rax & 0xFFFF);

            switch (SubCmd) {
            case VMCALL_SUBCMD_SHUTDOWN:
                if (!HvIsAuthenticShutdownCaller(Ctx->Rcx, GuestRip,
                                                 GuestCpl, GuestEfer, GuestCsL)) {
                    VMXROOT_LOG_WARN("VMCALL shutdown (new) rejected: auth failed");
                    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                             INTERRUPT_INFO_VALID |
                             (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                             6 /* #UD */);
                    return TRUE;
                }
                LOG_INFO("VMCALL shutdown request received (new, authenticated)");
                VmxAdvanceGuestRip();
                return FALSE;

            case VMCALL_SUBCMD_READ_MEMORY:
            case VMCALL_SUBCMD_WRITE_MEMORY:
                /*
                 * M-7 (revised) FIX: the hypervisor-memory VMCALL path is
                 * PERMANENTLY disabled (see hv_mem.c header comment).
                 * Injecting #UD surfaces the misuse immediately rather than
                 * silently no-oping.
                 */
                {
                    static volatile LONG s_DeprecatedMemVmcallCount = 0;
                    LONG Count = InterlockedIncrement(&s_DeprecatedMemVmcallCount);
                    if (Count <= 10) {
                        VMXROOT_LOG_WARN("Deprecated VMCALL mem-op (sub=%u) — injecting #UD",
                                         SubCmd);
                    }
                }
                VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                         INTERRUPT_INFO_VALID |
                         (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                         6 /* #UD */);
                return TRUE;

            default:
                break;
            }
        }
    }

    /*
     * Unknown VMCALL — not ours.
     * On bare metal, CPUID reports "Hv#0" (non-conformant), so Windows
     * should not issue VMCALLs for enlightenments. Inject #UD.
     */
    {
        static volatile LONG s_UnknownVmcallCount = 0;
        LONG Count = InterlockedIncrement(&s_UnknownVmcallCount);
        if (Count <= 10) {
            VMXROOT_LOG_WARN("Unknown VMCALL: RAX=0x%llX RCX=0x%llX RIP=0x%llX",
                             Rax, Ctx->Rcx, VmxRead(VMCS_GUEST_RIP));
        }
    }
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
             INTERRUPT_INFO_VALID |
             (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
             6);  /* #UD */
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

    VMXROOT_LOG_ERROR("TRIPLE FAULT! CPU=%u RIP=0x%llX RSP=0x%llX CR3=0x%llX "
              "CS=0x%llX RFLAGS=0x%llX Activity=%llu Interruptibility=0x%llX",
              KeGetCurrentProcessorNumber(),
              VmxRead(VMCS_GUEST_RIP),
              VmxRead(VMCS_GUEST_RSP),
              VmxRead(VMCS_GUEST_CR3),
              VmxRead(VMCS_GUEST_CS_SEL),
              VmxRead(VMCS_GUEST_RFLAGS),
              VmxRead(VMCS_GUEST_ACTIVITY_STATE),
              VmxRead(VMCS_GUEST_INTERRUPTIBILITY));
    VMXROOT_LOG_ERROR("TRIPLE FAULT context: IDT-vectoring=0x%llX, "
              "entry-int=0x%llX, exit-int=0x%llX, exit-reason=%llu",
              VmxRead(VMCS_IDT_VECTORING_INFO),
              VmxRead(VMCS_CTRL_VMENTRY_INT_INFO),
              VmxRead(VMCS_EXIT_INTERRUPTION_INFO),
              VmxRead(VMCS_EXIT_REASON) & 0xFFFF);
    return FALSE;
}

/* ========================================================================= */
/*  GP Register Helpers                                                      */
/* ========================================================================= */

/*
 * Map register index (from exit qualification) to GUEST_CONTEXT offset.
 * Register encoding: 0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI
 *                    8=R8,  9=R9,  10=R10, 11=R11, 12=R12, 13=R13, 14=R14, 15=R15
 *
 * NOTE: RSP (index 4) is now valid in GuestContext because VmxExitHandler()
 * syncs VMCS_GUEST_RSP → GuestContext->Rsp at entry and writes it back at exit.
 * No special-case needed for RegIndex==4 anymore.
 */
static ULONG64 GetGpRegValue(PGUEST_CONTEXT Ctx, ULONG RegIndex)
{
    ULONG64 *Regs = (ULONG64 *)Ctx;

    if (RegIndex <= 15) {
        return Regs[RegIndex];
    }

    return 0;
}

static VOID SetGpRegValue(PGUEST_CONTEXT Ctx, ULONG RegIndex, ULONG64 Value)
{
    ULONG64 *Regs = (ULONG64 *)Ctx;

    if (RegIndex <= 15) {
        Regs[RegIndex] = Value;
    }
}
