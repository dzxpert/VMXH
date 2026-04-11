/*
 * hv_hypercall.h - VMX Anti-Anti-Debug Hypervisor
 * Hyper-V Hypercall definitions and emulation helpers.
 *
 * When running under an outer hypervisor (VMware, Hyper-V, KVM, etc.) that
 * advertises CPUID.1:ECX[31] = 1, Windows caches the hypervisor-present bit
 * at boot and compiles VMCALL/VMMCALL enlightenments into hot kernel paths
 * such as nt!SwapContext for TLB flushing.
 *
 * Even though our CPUID handler (AadHandleCpuid) clears bit 31 after VMX
 * launch, the Windows kernel has ALREADY decided to use VMCALL-based TLB
 * flush.  If we return HV_STATUS_INVALID_HYPERCALL_CODE (0x0002), some
 * callers don't check the return value or have no fallback, causing:
 *   - Stale TLB → execute from wrong physical page → #UD / illegal insn
 *   - Or control flow error in the caller's error path
 *
 * Solution: Identify the known Hyper-V hypercalls that Windows uses in
 * non-optional hot paths and emulate them with the appropriate hardware
 * TLB flush instructions.  For all others, continue returning 0x0002.
 *
 * References:
 *   - Microsoft TLFS (Top Level Functional Specification) v6.0b
 *   - Windows Hypervisor Interface for Intel/AMD CPUs
 *   - Hyper-V CPUID leaves: 0x40000000 – 0x40000006
 */

#ifndef _HV_HYPERCALL_H_
#define _HV_HYPERCALL_H_

#include <ntddk.h>

/* ========================================================================= */
/*  Hyper-V Hypercall Input Value Layout                                     */
/* ========================================================================= */

/*
 * The Hyper-V hypercall input value is passed in RCX (fast) or via the
 * hypercall input page.  Layout:
 *
 *  Bits  63:48  = Rsvd / Rep start index
 *  Bits  47:32  = Rep count (for rep hypercalls)
 *  Bit      31  = 0 (reserved, must be zero for "fast" hypercalls)
 *  Bits  30:17  = Variable header size (for extended hypercalls)
 *  Bit      16  = Fast (1 = register-based, 0 = memory-based via GPA page)
 *  Bits  15: 0  = Call Code
 */
#define HV_HYPERCALL_CODE_MASK              0x0000FFFFULL
#define HV_HYPERCALL_FAST_BIT               (1ULL << 16)
#define HV_HYPERCALL_REP_COUNT_SHIFT        32
#define HV_HYPERCALL_REP_COUNT_MASK         0x0000FFFF00000000ULL
#define HV_HYPERCALL_REP_START_SHIFT        48
#define HV_HYPERCALL_REP_START_MASK         0x0FFF000000000000ULL

/* ========================================================================= */
/*  Hyper-V Hypercall Codes (from TLFS)                                      */
/* ========================================================================= */

/*
 * Only the hypercalls that Windows actually uses in non-optional kernel
 * hot paths are listed here.  We focus on TLB management since those are
 * the ones that cause SwapContext crashes.
 */
#define HVCALL_NOTIFY_LONG_SPIN_WAIT                0x0008
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE           0x0002
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST            0x0003
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX        0x0013
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX         0x0014
#define HVCALL_SEND_SYNTHETIC_CLUSTER_IPI            0x000B
#define HVCALL_SEND_SYNTHETIC_CLUSTER_IPI_EX         0x0015

/* Less common but may appear in some Windows versions */
#define HVCALL_SWITCH_VIRTUAL_ADDRESS_SPACE          0x0001
#define HVCALL_SIGNAL_EVENT                          0x005D
#define HVCALL_POST_MESSAGE                          0x005C
#define HVCALL_RETIRE_REGISTER_INTERCEPT_MESSAGE     0x0050

/* ========================================================================= */
/*  Hyper-V Status Codes                                                     */
/* ========================================================================= */

#define HV_STATUS_SUCCESS                           0x0000ULL
#define HV_STATUS_INVALID_HYPERCALL_CODE            0x0002ULL
#define HV_STATUS_INVALID_HYPERCALL_INPUT           0x0003ULL
#define HV_STATUS_INVALID_ALIGNMENT                 0x0004ULL
#define HV_STATUS_INVALID_PARAMETER                 0x0005ULL
#define HV_STATUS_OPERATION_DENIED                  0x0008ULL

/* ========================================================================= */
/*  Outer Hypervisor Type                                                    */
/* ========================================================================= */

typedef enum _OUTER_HYPERVISOR_TYPE {
    OUTER_HV_NONE = 0,         /* Bare metal */
    OUTER_HV_HYPERV,           /* Microsoft Hyper-V */
    OUTER_HV_VMWARE,           /* VMware (Workstation/ESXi) */
    OUTER_HV_KVM,              /* Linux KVM */
    OUTER_HV_UNKNOWN           /* Unknown hypervisor (bit 31 set) */
} OUTER_HYPERVISOR_TYPE;

/* Set during HvDetectNestedMode(), read-only after DriverEntry */
extern OUTER_HYPERVISOR_TYPE g_OuterHypervisor;

/* TRUE if any outer hypervisor is present (CPUID.1:ECX[31] = 1) */
extern BOOLEAN g_OuterHypervisorPresent;

/* ========================================================================= */
/*  Hypercall Emulation                                                      */
/* ========================================================================= */

/*
 * HvEmulateHypercall - Attempt to emulate a Hyper-V hypercall.
 *
 * Called from HandleVmcall() / SvmHandleVmmcall() when the VMCALL/VMMCALL
 * does not match our own magic values.
 *
 * Parameters:
 *   Rcx - Guest RCX at time of VMCALL (hypercall input value)
 *   Rdx - Guest RDX (input parameter for fast hypercalls)
 *   R8  - Guest R8  (input parameter for fast hypercalls)
 *
 * Returns:
 *   The value to place in Guest RAX (hypercall result).
 *   For emulated calls, returns HV_STATUS_SUCCESS (0).
 *   For unknown calls, returns HV_STATUS_INVALID_HYPERCALL_CODE (2).
 *
 * Side effects:
 *   For TLB flush hypercalls, executes the appropriate CPU TLB
 *   invalidation instructions (INVVPID/INVLPG on Intel, or TLB_CONTROL
 *   on AMD via ASID flush).
 */
ULONG64 HvEmulateHypercall(ULONG64 Rcx, ULONG64 Rdx, ULONG64 R8);

#endif /* _HV_HYPERCALL_H_ */
