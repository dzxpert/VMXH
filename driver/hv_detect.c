/*
 * hv_detect.c - VMX Anti-Anti-Debug Hypervisor
 * CPU vendor detection and virtualization capability probing
 */

#include "hv_detect.h"
#include "hv_hypercall.h"
#include "log.h"

/* ========================================================================= */
/*  AMD MSR Definitions                                                      */
/* ========================================================================= */

#define MSR_VM_CR                   0xC0010114
#define MSR_VM_HSAVE_PA             0xC0010117

#define VM_CR_SVMDIS                (1ULL << 4)   /* SVM disabled */
#define VM_CR_LOCK                  (1ULL << 3)   /* SVM lock */

#define SVM_CPUID_FUNC              0x8000000A

/* ========================================================================= */
/*  CPU Vendor Detection                                                     */
/* ========================================================================= */

CPU_VENDOR HvDetectCpuVendor(VOID)
{
    int CpuInfo[4] = { 0 };

    /*
     * CPUID leaf 0: Vendor string is in EBX:EDX:ECX
     * Intel: "GenuineIntel" -> EBX=756E6547 EDX=49656E69 ECX=6C65746E
     * AMD:   "AuthenticAMD" -> EBX=68747541 EDX=69746E65 ECX=444D4163
     */
    __cpuid(CpuInfo, 0);

    /* Check for Intel: "Genu" "ineI" "ntel" */
    if (CpuInfo[1] == 0x756E6547 &&  /* "Genu" */
        CpuInfo[3] == 0x49656E69 &&  /* "ineI" */
        CpuInfo[2] == 0x6C65746E) {  /* "ntel" */
        LOG_INFO("CPU Vendor: Intel (GenuineIntel)");
        return CPU_VENDOR_INTEL;
    }

    /* Check for AMD: "Auth" "enti" "cAMD" */
    if (CpuInfo[1] == 0x68747541 &&  /* "Auth" */
        CpuInfo[3] == 0x69746E65 &&  /* "enti" */
        CpuInfo[2] == 0x444D4163) {  /* "cAMD" */
        LOG_INFO("CPU Vendor: AMD (AuthenticAMD)");
        return CPU_VENDOR_AMD;
    }

    LOG_WARN("CPU Vendor: Unknown (EBX=0x%08X EDX=0x%08X ECX=0x%08X)",
             CpuInfo[1], CpuInfo[3], CpuInfo[2]);
    return CPU_VENDOR_UNKNOWN;
}

/* ========================================================================= */
/*  Intel VMX Support Check                                                  */
/* ========================================================================= */

BOOLEAN HvCheckVmxSupport(VOID)
{
    int CpuInfo[4];
    ULONG64 FeatureControl;

    /* Check CPUID.1:ECX.VMX[bit 5] */
    __cpuid(CpuInfo, 1);
    if (!(CpuInfo[2] & (1 << 5))) {
        LOG_ERROR("CPU does not support VMX (CPUID.1:ECX[5] = 0)");
        return FALSE;
    }

    /* Check IA32_FEATURE_CONTROL MSR */
    FeatureControl = __readmsr(0x003A);  /* MSR_IA32_FEATURE_CONTROL */

    if (FeatureControl & (1 << 0)) {  /* Locked */
        if (!(FeatureControl & (1 << 2))) {  /* VMXON not enabled */
            LOG_ERROR("VMX is locked out in BIOS (IA32_FEATURE_CONTROL)");
            return FALSE;
        }
    } else {
        LOG_WARN("IA32_FEATURE_CONTROL not locked, BIOS may not have configured VMX");
    }

    LOG_INFO("Intel VMX support confirmed");
    return TRUE;
}

/* ========================================================================= */
/*  AMD SVM Support Check                                                    */
/* ========================================================================= */

BOOLEAN HvCheckSvmSupport(VOID)
{
    int CpuInfo[4];
    ULONG64 VmCr;

    /*
     * Check CPUID 0x80000001:ECX[2] - SVM bit
     * First verify extended CPUID is available
     */
    __cpuid(CpuInfo, 0x80000000);
    if ((ULONG)CpuInfo[0] < 0x80000001) {
        LOG_ERROR("Extended CPUID not supported");
        return FALSE;
    }

    __cpuid(CpuInfo, 0x80000001);
    if (!(CpuInfo[2] & (1 << 2))) {
        LOG_ERROR("CPU does not support SVM (CPUID 0x80000001:ECX[2] = 0)");
        return FALSE;
    }

    /*
     * Check MSR_VM_CR.SVMDIS (bit 4)
     * If SVMDIS is set AND VM_CR is locked, SVM cannot be enabled.
     * If SVMDIS is clear, SVM can be enabled via EFER.SVME.
     */
    VmCr = __readmsr(MSR_VM_CR);

    if (VmCr & VM_CR_SVMDIS) {
        /*
         * SVM is disabled. Check if it can be unlocked.
         * CPUID 0x8000000A:EDX[2] = SVM Lock
         * If lock is supported and SVM is disabled, BIOS locked it out.
         */
        __cpuid(CpuInfo, SVM_CPUID_FUNC);
        if (CpuInfo[3] & (1 << 2)) {
            LOG_ERROR("SVM is disabled and locked by BIOS (VM_CR.SVMDIS=1, SVM Lock=1)");
            return FALSE;
        }

        /* SVM disabled but not locked - might be able to enable with key */
        LOG_WARN("SVM is disabled (VM_CR.SVMDIS=1) but not locked");
        return FALSE;
    }

    LOG_INFO("AMD SVM support confirmed");
    return TRUE;
}

/* ========================================================================= */
/*  AMD NPT Support Check                                                   */
/* ========================================================================= */

BOOLEAN HvCheckNptSupport(VOID)
{
    int CpuInfo[4];

    /*
     * CPUID 0x8000000A:EDX[0] = Nested Paging
     */
    __cpuid(CpuInfo, SVM_CPUID_FUNC);

    if (CpuInfo[3] & (1 << 0)) {
        LOG_INFO("AMD NPT (Nested Page Tables) supported");
        return TRUE;
    }

    LOG_WARN("AMD NPT not supported");
    return FALSE;
}

/* ========================================================================= */
/*  SVM Feature Queries                                                      */
/* ========================================================================= */

ULONG HvGetSvmRevision(VOID)
{
    int CpuInfo[4];
    __cpuid(CpuInfo, SVM_CPUID_FUNC);
    return (ULONG)(CpuInfo[0] & 0xFF);  /* EAX[7:0] = SVM revision */
}

ULONG HvGetMaxAsid(VOID)
{
    int CpuInfo[4];
    __cpuid(CpuInfo, SVM_CPUID_FUNC);
    return (ULONG)CpuInfo[1];  /* EBX = number of ASIDs */
}

/* ========================================================================= */
/*  Hyper-V / Outer Hypervisor Detection                                     */
/* ========================================================================= */

BOOLEAN   g_IsNestedMode = FALSE;
ULONG     g_HypervisorMaxLeaf = 0;

BOOLEAN HvDetectNestedMode(VOID)
{
    int CpuInfo[4];

    /*
     * Step 1: Check CPUID.1:ECX[31] — Hypervisor Present bit.
     * If clear, we are running on bare metal (or a hypervisor that
     * doesn't set this bit). Either way, no nested mode.
     */
    __cpuid(CpuInfo, 1);
    if (!(CpuInfo[2] & (1 << 31))) {
        LOG_INFO("No hypervisor present (CPUID.1:ECX[31] = 0)");
        g_OuterHypervisor = OUTER_HV_NONE;
        g_OuterHypervisorPresent = FALSE;
        return FALSE;
    }

    /*
     * A hypervisor IS present. Record this fact immediately.
     * Windows has already seen this bit at boot and may have compiled
     * VMCALL enlightenments into kernel hot paths (SwapContext, etc.).
     */
    g_OuterHypervisorPresent = TRUE;
    LOG_INFO("Hypervisor present (CPUID.1:ECX[31] = 1)");

    /*
     * Step 2: Identify the outer hypervisor via leaf 0x40000000.
     * EAX = max hypervisor leaf
     * EBX:ECX:EDX = vendor signature string (12 bytes, little-endian)
     */
    __cpuid(CpuInfo, 0x40000000);
    g_HypervisorMaxLeaf = (ULONG)CpuInfo[0];

    /* Check for Microsoft Hyper-V: "Microsoft Hv" */
    if (CpuInfo[1] == 0x7263694D &&   /* "Micr" */
        CpuInfo[2] == 0x666F736F &&   /* "osof" */
        CpuInfo[3] == 0x76482074) {   /* "t Hv" */

        g_OuterHypervisor = OUTER_HV_HYPERV;
        g_IsNestedMode = TRUE;
        LOG_INFO("Microsoft Hyper-V detected, max leaf: 0x%08X", g_HypervisorMaxLeaf);

        /* Log nested virtualization enlightenments (informational) */
        if (g_HypervisorMaxLeaf >= 0x4000000A) {
            __cpuid(CpuInfo, 0x4000000A);
            LOG_INFO("Nested virt enlightenments (leaf 0x4000000A): EAX=0x%08X",
                     CpuInfo[0]);
            if (CpuInfo[0] & (1 << 0)) {
                LOG_INFO("  Enlightened VMCS supported");
            }
            if (CpuInfo[0] & (1 << 1)) {
                LOG_INFO("  Direct virtual flush supported");
            }
        }

        LOG_INFO("Running under Hyper-V — nested mode enabled");
        return TRUE;
    }

    /* Check for VMware: "VMwareVMware" */
    if (CpuInfo[1] == 0x61774D56 &&   /* "VMwa" */
        CpuInfo[2] == 0x4D566572 &&   /* "reVM" */
        CpuInfo[3] == 0x65726177) {   /* "ware" */

        g_OuterHypervisor = OUTER_HV_VMWARE;
        /* VMware does NOT support enlightened VMCS, so g_IsNestedMode stays FALSE.
         * But g_OuterHypervisorPresent is TRUE — this triggers hypercall emulation. */
        LOG_INFO("VMware detected (CPUID.40000000 = 'VMwareVMware'), max leaf: 0x%08X",
                 g_HypervisorMaxLeaf);
        LOG_INFO("VMware nested mode: hypercall emulation enabled, enlightened VMCS disabled");
        return FALSE;   /* No enlightened VMCS for VMware */
    }

    /* Check for KVM: "KVMKVMKVM\0\0\0" */
    if (CpuInfo[1] == 0x4B564D4B &&   /* "KVMK" */
        CpuInfo[2] == 0x564D4B56 &&   /* "VMKV" */
        (CpuInfo[3] & 0x00FFFFFF) == 0x004D564B) {  /* "KVM\0" - partial match */

        g_OuterHypervisor = OUTER_HV_KVM;
        LOG_INFO("KVM detected, max leaf: 0x%08X", g_HypervisorMaxLeaf);
        LOG_INFO("KVM nested mode: hypercall emulation enabled, enlightened VMCS disabled");
        return FALSE;   /* No enlightened VMCS for KVM */
    }

    /* Unknown hypervisor — still need hypercall emulation */
    g_OuterHypervisor = OUTER_HV_UNKNOWN;
    LOG_INFO("Unknown hypervisor present (EBX=0x%08X ECX=0x%08X EDX=0x%08X), max leaf: 0x%08X",
             CpuInfo[1], CpuInfo[2], CpuInfo[3], g_HypervisorMaxLeaf);
    LOG_INFO("Hypercall emulation enabled for unknown outer hypervisor");
    return FALSE;   /* No enlightened VMCS for unknown hypervisor */
}
