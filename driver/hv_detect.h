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
/*  Hyper-V Nested Virtualization Detection                                  */
/* ========================================================================= */

/*
 * TRUE if running under Hyper-V as a nested hypervisor.
 * Set once during DriverEntry and never changed.
 */
extern BOOLEAN g_IsNestedMode;

/*
 * Maximum CPUID leaf supported by the Hyper-V interface (0x4000000x range).
 * Only valid when g_IsNestedMode == TRUE.
 */
extern ULONG g_HypervisorMaxLeaf;

/*
 * Detect if we are running inside Hyper-V.
 * Checks CPUID.1:ECX[31] (Hypervisor Present) and verifies
 * the "Microsoft Hv" vendor string via leaf 0x40000000.
 * If Hyper-V is detected, sets g_IsNestedMode = TRUE.
 * Returns TRUE if Hyper-V is present, FALSE otherwise.
 */
BOOLEAN HvDetectNestedMode(VOID);

#endif /* _HV_DETECT_H_ */
