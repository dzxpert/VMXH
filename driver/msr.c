/*
 * msr.c - VMX Anti-Anti-Debug Hypervisor
 * MSR bitmap initialization and MSR read/write handling
 */

#include "vmx.h"
#include "hv_ops.h"
#include "log.h"
#include "process.h"
#include "../common/shared.h"

/* ========================================================================= */
/*  MSR Bitmap Layout                                                        */
/*                                                                           */
/*  4KB bitmap divided into 4 regions of 1KB each:                           */
/*  [0x000..0x3FF] Read bitmap for MSRs 0x00000000 - 0x00001FFF             */
/*  [0x400..0x7FF] Read bitmap for MSRs 0xC0000000 - 0xC0001FFF             */
/*  [0x800..0xBFF] Write bitmap for MSRs 0x00000000 - 0x00001FFF            */
/*  [0xC00..0xFFF] Write bitmap for MSRs 0xC0000000 - 0xC0001FFF            */
/* ========================================================================= */

/*
 * Set a bit in the MSR bitmap to intercept a specific MSR
 */
static VOID MsrBitmapSetBit(PVOID MsrBitmap, ULONG Msr, BOOLEAN Read, BOOLEAN Write)
{
    PUCHAR  Bitmap = (PUCHAR)MsrBitmap;
    ULONG   ByteOffset;
    ULONG   BitOffset;

    if (Msr <= 0x1FFF) {
        /* Low MSR range */
        ByteOffset = Msr / 8;
        BitOffset = Msr % 8;

        if (Read) {
            Bitmap[ByteOffset] |= (1 << BitOffset);
        }
        if (Write) {
            Bitmap[0x800 + ByteOffset] |= (1 << BitOffset);
        }
    }
    else if (Msr >= 0xC0000000 && Msr <= 0xC0001FFF) {
        /* High MSR range */
        ULONG Offset = Msr - 0xC0000000;
        ByteOffset = Offset / 8;
        BitOffset = Offset % 8;

        if (Read) {
            Bitmap[0x400 + ByteOffset] |= (1 << BitOffset);
        }
        if (Write) {
            Bitmap[0xC00 + ByteOffset] |= (1 << BitOffset);
        }
    }
}

/*
 * Initialize MSR bitmap for a CPU context
 * By default, all MSRs pass through (bitmap = all zeros).
 * We selectively intercept MSRs we care about.
 */
VOID MsrBitmapInitialize(PVOID MsrBitmap)
{
    /* Start with clean bitmap (all pass-through) */
    RtlZeroMemory(MsrBitmap, PAGE_SIZE_4KB);

    /*
     * Intercept debug-related MSRs for anti-anti-debug:
     *
     * IA32_DEBUGCTL: Controls debug features like LBR, BTF, etc.
     * The anti-debug code might check this to detect single-stepping.
     */
    MsrBitmapSetBit(MsrBitmap, MSR_IA32_DEBUGCTL, TRUE, TRUE);

    /*
     * NESTED VIRTUALIZATION: Intercept VMX capability MSRs.
     *
     * Guest software (or a nested hypervisor) may probe VMX capability MSRs
     * (IA32_VMX_BASIC through IA32_VMX_VMFUNC, MSR range 0x480-0x491) to
     * discover VMX features before attempting VMXON. We intercept these and
     * return zero to indicate VMX is not available, consistent with the CPUID
     * hiding of VMX capability bit (CPUID.1:ECX[5]).
     *
     * Also intercept IA32_FEATURE_CONTROL (0x3A) to hide the VMXON-enabled
     * bit and prevent the guest from attempting to enable VMX.
     */
    MsrBitmapSetBit(MsrBitmap, 0x003A, TRUE, TRUE);   /* IA32_FEATURE_CONTROL */
    {
        ULONG VmxMsr;
        for (VmxMsr = 0x0480; VmxMsr <= 0x0491; VmxMsr++) {
            MsrBitmapSetBit(MsrBitmap, VmxMsr, TRUE, TRUE);
        }
    }

    LOG_DEBUG("MSR bitmap initialized with debug + VMX MSR interceptions");
}

/* ========================================================================= */
/*  MSR Read Handler                                                         */
/* ========================================================================= */

BOOLEAN HandleRdmsrImpl(PGUEST_CONTEXT GuestContext)
{
    ULONG       Msr = (ULONG)GuestContext->Rcx;
    ULONG64     Value;
    ULONG64     GuestCr3;

    GuestCr3 = HvReadGuestCr3();

    /*
     * NESTED VIRTUALIZATION: Intercept VMX/SVM capability MSRs.
     *
     * Return zero for all VMX capability MSRs (0x480-0x491) and hide the
     * VMXON-enabled bit in IA32_FEATURE_CONTROL. Also handle SVM-related
     * MSRs (VM_CR, VM_HSAVE_PA) if running on AMD.
     *
     * This prevents guest software from discovering virtualization capabilities,
     * consistent with the CPUID hiding of VMX/SVM bits.
     */
    if (Msr >= 0x0480 && Msr <= 0x0491) {
        /* VMX capability MSRs: return 0 (VMX not available) */
        GuestContext->Rax = 0;
        GuestContext->Rdx = 0;
        HvAdvanceGuestRip();
        return TRUE;
    }

    if (Msr == 0x003A) {
        /*
         * IA32_FEATURE_CONTROL: return locked with VMXON disabled.
         * Bit 0 (Lock) = 1, Bit 2 (VMXON outside SMX) = 0
         * This tells the guest VMX is locked out in BIOS.
         */
        GuestContext->Rax = 1;  /* Locked, VMXON disabled */
        GuestContext->Rdx = 0;
        HvAdvanceGuestRip();
        return TRUE;
    }

    if (Msr == 0xC0010114) {
        /*
         * MSR_VM_CR (AMD): Hide SVM capability.
         * Set SVMDIS bit (bit 4) to indicate SVM is disabled.
         * Set LOCK bit (bit 3) to indicate it's locked by BIOS.
         */
        Value = __readmsr(Msr);
        Value |= (1ULL << 4);  /* SVMDIS = 1 */
        Value |= (1ULL << 3);  /* LOCK = 1 */
        GuestContext->Rax = (Value & 0xFFFFFFFF);
        GuestContext->Rdx = (Value >> 32);
        HvAdvanceGuestRip();
        return TRUE;
    }

    if (Msr == 0xC0010117) {
        /*
         * MSR_VM_HSAVE_PA (AMD): Return 0 to hide SVM host save area.
         */
        GuestContext->Rax = 0;
        GuestContext->Rdx = 0;
        HvAdvanceGuestRip();
        return TRUE;
    }

    /* Read the actual MSR value */
    __try {
        Value = __readmsr(Msr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* MSR doesn't exist - inject #GP(0) to guest */
        LOG_WARN("RDMSR: Invalid MSR 0x%08X, injecting #GP", Msr);

        HvInjectException(13, INTERRUPT_TYPE_HARDWARE_EXCEPTION, TRUE, 0);
        HvSetEntryInstructionLength(HvReadExitInstructionLength());
        return TRUE;
    }

    /* Anti-anti-debug: spoof MSR values for target process */
    if (IsTargetProcess(GuestCr3)) {
        switch (Msr) {
        case MSR_IA32_DEBUGCTL:
            if (IsFeatureEnabled(GuestCr3, AAD_HIDE_DEBUGGER)) {
                /*
                 * Clear debug-related bits that indicate debugging:
                 * Bit 0 (LBR): Last Branch Record
                 * Bit 1 (BTF): Single-Step on Branches
                 * Bit 6 (TR): Trace messages enable
                 */
                Value &= ~0x43ULL;
                LOG_DEBUG_PID(0, "RDMSR: Spoofed IA32_DEBUGCTL = 0x%llX", Value);
            }
            break;
        }
    }

    /* Return value in EDX:EAX */
    GuestContext->Rax = (Value & 0xFFFFFFFF);
    GuestContext->Rdx = (Value >> 32);

    HvAdvanceGuestRip();
    return TRUE;
}

/* ========================================================================= */
/*  MSR Write Handler                                                        */
/* ========================================================================= */

BOOLEAN HandleWrmsrImpl(PGUEST_CONTEXT GuestContext)
{
    ULONG       Msr = (ULONG)GuestContext->Rcx;
    ULONG64     Value = (GuestContext->Rax & 0xFFFFFFFF) |
                        ((GuestContext->Rdx & 0xFFFFFFFF) << 32);

    /*
     * NESTED VIRTUALIZATION: Block writes to VMX/SVM capability MSRs.
     *
     * VMX MSRs (0x480-0x491) are read-only; writes should #GP.
     * IA32_FEATURE_CONTROL (0x3A) writes could enable VMXON; block them.
     * MSR_VM_HSAVE_PA (0xC0010117) writes would set the SVM host save area; block.
     * MSR_VM_CR (0xC0010114) writes could enable SVM; block.
     *
     * Inject #GP(0) for all of these to match bare-metal behavior when
     * VMX/SVM is disabled.
     */
    if ((Msr >= 0x0480 && Msr <= 0x0491) ||
        Msr == 0x003A ||
        Msr == 0xC0010114 ||
        Msr == 0xC0010117) {
        HvInjectException(13, INTERRUPT_TYPE_HARDWARE_EXCEPTION, TRUE, 0);
        HvSetEntryInstructionLength(HvReadExitInstructionLength());
        return TRUE;
    }

    /* Write the MSR */
    __try {
        __writemsr(Msr, Value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* MSR doesn't exist or invalid value - inject #GP(0) */
        LOG_WARN("WRMSR: Failed MSR 0x%08X = 0x%llX, injecting #GP", Msr, Value);

        HvInjectException(13, INTERRUPT_TYPE_HARDWARE_EXCEPTION, TRUE, 0);
        HvSetEntryInstructionLength(HvReadExitInstructionLength());
        return TRUE;
    }

    HvAdvanceGuestRip();
    return TRUE;
}
