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

    LOG_DEBUG("MSR bitmap initialized with debug MSR interceptions");
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
