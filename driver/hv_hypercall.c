/*
 * hv_hypercall.c - VMX Anti-Anti-Debug Hypervisor
 * Hyper-V Hypercall emulation for outer-hypervisor compatibility.
 *
 * When running inside VMware Workstation, Hyper-V, or KVM, the outer
 * hypervisor sets CPUID.1:ECX[31] = 1 (Hypervisor Present).  Windows
 * caches this at boot and compiles VMCALL/VMMCALL enlightenments into
 * kernel hot paths (notably nt!SwapContext for TLB flushing).
 *
 * After our hypervisor launches, AadHandleCpuid() clears bit 31 for
 * future CPUID queries, but the kernel has ALREADY decided to use
 * VMCALL-based TLB flush.  Those VMCALLs now VM-Exit to us.
 *
 * If we return HV_STATUS_INVALID_HYPERCALL_CODE (0x0002) for these
 * TLB flush hypercalls, some callers in the Windows kernel:
 *   (a) Do not check the return value at all, OR
 *   (b) Have no fallback code path, OR
 *   (c) Assume TLB was flushed and proceed with stale TLB entries
 *
 * Any of these leads to executing from a wrong physical page → #UD
 * (illegal instruction) → BSOD at nt!SwapContext+0x100.
 *
 * SOLUTION: Identify the critical Hyper-V hypercalls and emulate them
 * by performing the equivalent hardware TLB flush (INVVPID on Intel,
 * ASID flush on AMD).  This makes the kernel happy regardless of which
 * outer hypervisor (VMware / Hyper-V / KVM) is hosting us, and is a
 * no-op on bare metal (where the kernel never issues VMCALL).
 */

#include "hv_hypercall.h"
#include "hv_ops.h"
#include "vmx.h"
#include "npt.h"
#include "log.h"

/* ========================================================================= */
/*  Global State                                                             */
/* ========================================================================= */

/*
 * These are set by HvDetectNestedMode() in hv_detect.c during DriverEntry.
 * After that they are read-only.
 */
OUTER_HYPERVISOR_TYPE g_OuterHypervisor = OUTER_HV_NONE;
BOOLEAN g_OuterHypervisorPresent = FALSE;

/* ========================================================================= */
/*  TLB Flush Implementation                                                 */
/* ========================================================================= */

/*
 * Perform a full TLB flush appropriate for the current CPU vendor.
 *
 * On Intel VMX:
 *   Use INVVPID (all-contexts) to flush all VPID-tagged TLB entries.
 *   This is the closest equivalent to HvFlushVirtualAddressSpace.
 *   We also do INVEPT (all-contexts) to flush EPT-derived entries.
 *
 * On AMD SVM:
 *   The TLB is flushed on the next VMRUN by setting TlbCtl in the VMCB.
 *   Since we're in the exit handler (about to VMRUN), we just need to
 *   set the flag. The caller (SvmExitHandler) already cleared TlbCtl
 *   to DO_NOTHING; we override it here.
 *
 * Note: This function is called from VMX root mode (Intel) or host mode
 * (AMD) — i.e., inside the VM-Exit/VMEXIT handler.  It is safe to
 * execute privileged instructions here.
 */
static VOID HvPerformTlbFlush(VOID)
{
    if (g_CpuVendor == CPU_VENDOR_INTEL) {
        INVVPID_DESCRIPTOR VpidDesc;
        INVEPT_DESCRIPTOR EptDesc;

        /*
         * INVVPID all-contexts: Flush all linear-to-physical translations
         * for all VPIDs.  This covers the guest's virtual TLB flush request.
         *
         * Also INVEPT all-contexts: Flush all EPT-derived translations.
         * Some Windows TLB flush hypercalls flush both linear and EPT
         * entries.  Better safe than sorry.
         */
        RtlZeroMemory(&VpidDesc, sizeof(VpidDesc));
        RtlZeroMemory(&EptDesc, sizeof(EptDesc));

        AsmVmxInvvpid(INVVPID_ALL_CONTEXTS, &VpidDesc);
        AsmVmxInvept(INVEPT_ALL_CONTEXTS, &EptDesc);
    }
    else if (g_CpuVendor == CPU_VENDOR_AMD) {
        /*
         * For AMD SVM, we need to set the VMCB TlbCtl field for the current
         * CPU.  NptInvalidateAll() sets TlbCtl = FLUSH_ALL_ASID on ALL CPUs'
         * VMCBs.
         *
         * Note: The SvmExitHandler dispatcher resets TlbCtl = DO_NOTHING at
         * the top of each exit.  Our flush overwrites it here, so the next
         * VMRUN on this CPU will actually flush.
         */
        NptInvalidateAll();
    }
}

/* ========================================================================= */
/*  Hypercall Emulation                                                      */
/* ========================================================================= */

/*
 * HvEmulateHypercall - Emulate a Hyper-V hypercall.
 *
 * Input layout (from Microsoft TLFS):
 *   RCX = Hypercall Input Value:
 *     Bits 15:0  = Call Code
 *     Bit  16    = Fast (1 = register-based)
 *     Bits 31:17 = Variable header size / rsvd
 *     Bits 47:32 = Rep count
 *     Bits 63:48 = Rep start index
 *   RDX = Input parameter (for fast hypercalls, GPA of input page otherwise)
 *   R8  = Input parameter 2 (fast only)
 *
 * We only need to emulate the TLB-related hypercalls that Windows uses
 * in non-optional kernel paths.  Everything else gets 0x0002.
 */
ULONG64 HvEmulateHypercall(ULONG64 Rcx, ULONG64 Rdx, ULONG64 R8)
{
    ULONG CallCode;

    UNREFERENCED_PARAMETER(Rdx);
    UNREFERENCED_PARAMETER(R8);

    CallCode = (ULONG)(Rcx & HV_HYPERCALL_CODE_MASK);

    switch (CallCode) {

    /* ----- TLB Flush Hypercalls (critical for SwapContext) ----- */

    case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE:
    case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST:
    case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX:
    case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX:
        /*
         * These are the hypercalls Windows uses in SwapContext and other
         * kernel TLB management paths.  We perform a full TLB flush.
         *
         * A more refined implementation could parse the address list
         * and do per-address INVLPG, but the full flush is safe and
         * the performance difference is negligible since these calls
         * are infrequent relative to VM-Exit cost.
         */
        HvPerformTlbFlush();
        return HV_STATUS_SUCCESS;

    /* ----- Virtual Address Space Switch ----- */

    case HVCALL_SWITCH_VIRTUAL_ADDRESS_SPACE:
        /*
         * HvSwitchVirtualAddressSpace: requests a CR3 switch + TLB flush.
         * The actual CR3 switch is done by the kernel itself; the hypercall
         * is just to give the hypervisor a heads-up for optimization.
         * Return success without doing anything special.
         */
        HvPerformTlbFlush();
        return HV_STATUS_SUCCESS;

    /* ----- IPI (Inter-Processor Interrupt) ----- */

    case HVCALL_SEND_SYNTHETIC_CLUSTER_IPI:
    case HVCALL_SEND_SYNTHETIC_CLUSTER_IPI_EX:
        /*
         * Synthetic IPI: Windows may use this for TLB shootdown IPIs.
         * We cannot easily emulate cross-CPU IPIs from a VM-Exit handler,
         * but returning SUCCESS is safe because:
         *  1. The kernel also has a fallback using real IPIs (APIC).
         *  2. The worst case is a slightly delayed TLB shootdown, which
         *     the kernel handles via its own retry logic.
         *
         * If we returned error (0x0002), the kernel might enter an
         * unexpected error path that could crash.
         */
        return HV_STATUS_SUCCESS;

    /* ----- Long Spin Wait Notification ----- */

    case HVCALL_NOTIFY_LONG_SPIN_WAIT:
        /*
         * Notification that a vCPU has been spinning on a lock.
         * This is a hint to the hypervisor for scheduling optimization.
         * We don't need to do anything — just return success so the
         * kernel doesn't think the call failed.
         */
        return HV_STATUS_SUCCESS;

    /* ----- Everything else: return SUCCESS to avoid kernel panic ----- */

    default:
        /*
         * Unknown hypercall code. Previously returned INVALID_HYPERCALL_CODE
         * (0x0002), but this caused problems:
         *
         * Windows may issue hypercalls we don't recognize (e.g., performance
         * counters, VP management, partition management). Some callers
         * DON'T check the return value and assume the call succeeded.
         * Returning an error code causes:
         *   - Stale state / missed flush → eventual crash
         *   - Unexpected error path → kernel hang or BSOD
         *
         * FIX: Return SUCCESS for ALL hypercalls. The worst case for
         * returning success on a no-op is slightly suboptimal behavior
         * (e.g., a timer hint we ignore). The worst case for returning
         * error is a kernel crash or hang.
         *
         * Log unknown codes for diagnostic purposes.
         */
        {
            static volatile LONG s_UnknownCallCount = 0;
            LONG UCount = InterlockedIncrement(&s_UnknownCallCount);
            if (UCount <= 10) {
                VMXROOT_LOG_WARN("Unknown hypercall: code=%u (0x%04X) "
                         "RCX=0x%llX RDX=0x%llX R8=0x%llX",
                         CallCode, CallCode, Rcx, Rdx, R8);
            }
        }
        return HV_STATUS_SUCCESS;
    }
}
