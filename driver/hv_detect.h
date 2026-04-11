/*
 * hv_detect.h - VMX Anti-Anti-Debug Hypervisor
 * CPU vendor detection and virtualization capability probing
 */

#ifndef _HV_DETECT_H_
#define _HV_DETECT_H_

#include <ntddk.h>
#include "hv_ops.h"

/* ========================================================================= */
/*  CPU Detection                                                            */
/* ========================================================================= */

/*
 * Detect CPU vendor using CPUID leaf 0.
 * Returns CPU_VENDOR_INTEL, CPU_VENDOR_AMD, or CPU_VENDOR_UNKNOWN.
 */
CPU_VENDOR HvDetectCpuVendor(VOID);

/*
 * Check if Intel VT-x (VMX) is supported and enabled.
 * Checks CPUID.1:ECX[5] and IA32_FEATURE_CONTROL MSR.
 */
BOOLEAN HvCheckVmxSupport(VOID);

/*
 * Check if AMD SVM is supported and enabled.
 * Checks CPUID 0x80000001:ECX[2] and MSR_VM_CR.
 */
BOOLEAN HvCheckSvmSupport(VOID);

/*
 * Check if AMD NPT (Nested Page Tables) is supported.
 * Checks CPUID 0x8000000A:EDX[0].
 */
BOOLEAN HvCheckNptSupport(VOID);

/*
 * Get AMD SVM revision and number of ASIDs.
 * SVM CPUID function 0x8000000A.
 */
ULONG HvGetSvmRevision(VOID);
ULONG HvGetMaxAsid(VOID);

/* ========================================================================= */
/*  Hyper-V / Outer Hypervisor Detection                                     */
/* ========================================================================= */

/*
 * TRUE if running under Hyper-V as a nested hypervisor (enlightened VMCS).
 * Set once during DriverEntry and never changed.
 *
 * Note: This is TRUE only for Hyper-V (which supports Enlightened VMCS).
 * For VMware/KVM/unknown hypervisors, g_IsNestedMode = FALSE but
 * g_OuterHypervisorPresent = TRUE (see hv_hypercall.h).
 */
extern BOOLEAN g_IsNestedMode;

/*
 * Maximum CPUID leaf supported by the Hyper-V interface (0x4000000x range).
 * Only valid when g_IsNestedMode == TRUE.
 */
extern ULONG g_HypervisorMaxLeaf;

/*
 * Detect if we are running inside an outer hypervisor.
 *
 * Checks CPUID.1:ECX[31] (Hypervisor Present) and identifies the outer
 * hypervisor via the vendor string at leaf 0x40000000:
 *   - "Microsoft Hv" → Hyper-V (sets g_IsNestedMode = TRUE)
 *   - "VMwareVMware" → VMware Workstation/ESXi
 *   - "KVMKVMKVM"    → Linux KVM
 *   - Other          → Unknown hypervisor
 *
 * If ANY hypervisor is detected, sets g_OuterHypervisorPresent = TRUE
 * (in hv_hypercall.h), which triggers Hyper-V hypercall emulation in
 * the VMCALL/VMMCALL handlers.
 *
 * Returns TRUE only if Hyper-V (enlightened VMCS) is detected.
 */
BOOLEAN HvDetectNestedMode(VOID);

#endif /* _HV_DETECT_H_ */
