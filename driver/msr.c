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
/*  Invalid MSR Pre-Probing Bitmap                                           */
/*                                                                           */
/*  Probes MSRs in the low range (0x0-0x1FFF) and high range                */
/*  (0xC0000000-0xC0001FFF) BEFORE entering VMX/SVM root mode, while        */
/*  __try/__except still works reliably. MSRs that cause #GP are marked     */
/*  as invalid. In VM-Exit handlers, the bitmap is checked BEFORE           */
/*  executing __readmsr()/__writemsr(), avoiding reliance on SEH in         */
/*  VMX root mode where exception handling is unreliable.                    */
/*                                                                           */
/*  Bitmap layout (1 bit per MSR):                                          */
/*  [0x000..0x3FF] MSRs 0x00000000 - 0x00001FFF  (1024 bytes = 8192 bits)  */
/*  [0x400..0x7FF] MSRs 0xC0000000 - 0xC0001FFF  (1024 bytes = 8192 bits)  */
/*  Total: 2048 bytes (2KB)                                                  */
/* ========================================================================= */

#define INVALID_MSR_BITMAP_SIZE  2048   /* 2KB: 0x1FFF+1 bits * 2 ranges / 8 */
#define INVALID_MSR_LOW_OFFSET   0      /* Offset for MSR range 0x0-0x1FFF */
#define INVALID_MSR_HIGH_OFFSET  0x400  /* Offset for MSR range 0xC0000000-0xC0001FFF */

/*
 * Global invalid MSR bitmap. Allocated once before VMX/SVM initialization.
 * NULL means probing hasn't been done yet (unknown MSRs will be executed directly).
 */
static PUCHAR g_InvalidMsrBitmap = NULL;

/*
 * Check if an MSR is known-invalid (causes #GP on real hardware).
 * Returns TRUE if the MSR is in the bitmap and marked as invalid.
 * Returns FALSE if the MSR is not covered by the bitmap or is valid.
 */
static BOOLEAN MsrIsKnownInvalid(ULONG Msr)
{
    ULONG ByteOffset;
    ULONG BitOffset;

    if (!g_InvalidMsrBitmap) {
        return FALSE;  /* Probing not done, can't determine */
    }

    if (Msr <= 0x1FFF) {
        ByteOffset = INVALID_MSR_LOW_OFFSET + (Msr / 8);
        BitOffset = Msr % 8;
    } else if (Msr >= 0xC0000000 && Msr <= 0xC0001FFF) {
        ULONG Index = Msr - 0xC0000000;
        ByteOffset = INVALID_MSR_HIGH_OFFSET + (Index / 8);
        BitOffset = Index % 8;
    } else {
        return FALSE;  /* MSR not in bitmap-covered range */
    }

    return (g_InvalidMsrBitmap[ByteOffset] & (1 << BitOffset)) != 0;
}

/*
 * Mark an MSR as invalid in the bitmap.
 */
static VOID MsrSetInvalid(ULONG Msr)
{
    ULONG ByteOffset;
    ULONG BitOffset;

    if (!g_InvalidMsrBitmap) return;

    if (Msr <= 0x1FFF) {
        ByteOffset = INVALID_MSR_LOW_OFFSET + (Msr / 8);
        BitOffset = Msr % 8;
    } else if (Msr >= 0xC0000000 && Msr <= 0xC0001FFF) {
        ULONG Index = Msr - 0xC0000000;
        ByteOffset = INVALID_MSR_HIGH_OFFSET + (Index / 8);
        BitOffset = Index % 8;
    } else {
        return;
    }

    g_InvalidMsrBitmap[ByteOffset] |= (1 << BitOffset);
}

/*
 * MsrProbeInvalidMsrs - Pre-probe MSRs to discover which ones cause #GP.
 *
 * MUST be called BEFORE VMXON/VMRUN, while running in normal kernel mode
 * where __try/__except (SEH) works reliably. After VMX/SVM is enabled,
 * SEH is unreliable in root mode because the code runs outside the
 * thread stack region Windows requires for structured exception handling.
 *
 * We probe MSRs in two ranges:
 *   Low:  0x0000 - 0x1FFF  (Intel/AMD MSR bitmap range 1)
 *   High: 0xC0000000 - 0xC0001FFF  (Intel/AMD MSR bitmap range 2)
 *
 * MSRs outside these ranges (e.g., 0x4000xxxx Hyper-V Synthetic MSRs)
 * always cause VM-Exit regardless of bitmap settings and are handled
 * by dedicated logic in HandleRdmsrImpl/HandleWrmsrImpl.
 *
 * NOTE: We only probe RDMSR (read), not WRMSR (write). A write-probe
 * could alter system state or cause unintended side effects. If RDMSR
 * causes #GP, the MSR doesn't exist, so WRMSR will also #GP.
 *
 * Returns STATUS_SUCCESS on successful probe completion.
 */
NTSTATUS MsrProbeInvalidMsrs(VOID)
{
    ULONG Msr;
    ULONG InvalidCountLow = 0;
    ULONG InvalidCountHigh = 0;

    /* Allocate the bitmap if not already done */
    if (!g_InvalidMsrBitmap) {
        g_InvalidMsrBitmap = (PUCHAR)ExAllocatePoolWithTag(
            NonPagedPool, INVALID_MSR_BITMAP_SIZE, 'rsmI');
        if (!g_InvalidMsrBitmap) {
            LOG_ERROR("Failed to allocate invalid MSR bitmap (%u bytes)",
                      INVALID_MSR_BITMAP_SIZE);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(g_InvalidMsrBitmap, INVALID_MSR_BITMAP_SIZE);
    }

    LOG_INFO("Starting MSR pre-probe (low range 0x0-0x1FFF)...");

    /* Probe low range: 0x0 - 0x1FFF */
    for (Msr = 0; Msr <= 0x1FFF; Msr++) {
        __try {
            (void)__readmsr(Msr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            MsrSetInvalid(Msr);
            InvalidCountLow++;
        }
    }

    LOG_INFO("Low range probe complete: %u/%u MSRs invalid",
             InvalidCountLow, 0x2000);

    LOG_INFO("Starting MSR pre-probe (high range 0xC0000000-0xC0001FFF)...");

    /* Probe high range: 0xC0000000 - 0xC0001FFF */
    for (Msr = 0xC0000000; Msr <= 0xC0001FFF; Msr++) {
        __try {
            (void)__readmsr(Msr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            MsrSetInvalid(Msr);
            InvalidCountHigh++;
        }
    }

    LOG_INFO("High range probe complete: %u/%u MSRs invalid",
             InvalidCountHigh, 0x2000);
    LOG_INFO("MSR pre-probe done: total %u invalid MSRs discovered",
             InvalidCountLow + InvalidCountHigh);

    return STATUS_SUCCESS;
}

/*
 * MsrCleanupInvalidBitmap - Free the invalid MSR bitmap.
 * Called during driver termination.
 */
VOID MsrCleanupInvalidBitmap(VOID)
{
    if (g_InvalidMsrBitmap) {
        ExFreePoolWithTag(g_InvalidMsrBitmap, 'rsmI');
        g_InvalidMsrBitmap = NULL;
    }
}

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

    /*
     * HYPER-V SYNTHETIC MSR EMULATION (0x40000000 - 0x400000FF)
     *
     * When we advertise "Microsoft Hv" in CPUID leaf 0x40000000, Windows
     * will read Hyper-V synthetic MSRs during initialization. These MSRs
     * don't exist on real hardware — executing __readmsr() on them causes
     * #GP in VMX root mode.
     *
     * These MSRs are also OUTSIDE the MSR bitmap coverage ranges
     * (0x00000000-0x00001FFF and 0xC0000000-0xC0001FFF), so they ALWAYS
     * cause VM-Exit regardless of bitmap settings.
     *
     * We must emulate them by returning sensible values.
     *
     * Key MSRs:
     *   0x40000000 = HV_X64_MSR_GUEST_OS_ID
     *   0x40000001 = HV_X64_MSR_HYPERCALL (hypercall page setup)
     *   0x40000002 = HV_X64_MSR_VP_INDEX
     *   0x40000003 = HV_X64_MSR_RESET
     *   0x40000070 = HV_X64_MSR_REFERENCE_TSC
     *   0x40000073 = HV_X64_MSR_VP_ASSIST_PAGE
     *   0x40000100 = HV_X64_MSR_SCONTROL (Synic control)
     *   0x40000101 = HV_X64_MSR_SVERSION (Synic version)
     *   0x40000102 = HV_X64_MSR_SIEFP (Synic event flags page)
     *   0x40000103 = HV_X64_MSR_SIMP (Synic message page)
     *   0x40000104 = HV_X64_MSR_EOM (End of message)
     *   0x40000105 = HV_X64_MSR_SINT0 (Synthetic interrupt source 0)
     *   0x40000106-0x4000010F = HV_X64_MSR_SINT1-SINT15
     */
    if (Msr >= 0x40000000 && Msr <= 0x400000FF) {
        GuestContext->Rax = 0;
        GuestContext->Rdx = 0;
        HvAdvanceGuestRip();
        return TRUE;
    }

    /*
     * INVALID MSR PRE-PROBE CHECK
     *
     * Before executing __readmsr(), check the pre-probed invalid MSR bitmap.
     * If the MSR was discovered to cause #GP during pre-probing (done before
     * VMX/SVM init, when SEH was reliable), inject #GP immediately without
     * executing the real instruction.
     *
     * This eliminates reliance on __try/__except in VMX/SVM root mode,
     * where SEH is unreliable because the host stack is outside the
     * thread stack region Windows requires for structured exception handling.
     *
     * For MSRs outside the pre-probe range (0x2000-0x3FFFFFFF, 0x40000100+,
     * 0xC0002000+), we execute __readmsr() directly WITHOUT __try/__except.
     * These MSRs only reach this handler if intercepted by the MSR bitmap,
     * and the bitmap is configured to only intercept known-valid MSRs
     * (IA32_DEBUGCTL, VMX capability MSRs 0x480-0x491, IA32_FEATURE_CONTROL).
     *
     * CRITICAL: __try/__except (SEH) is UNSAFE in VMX root mode!
     * The host stack is ExAllocatePoolWithTag'd memory, not a thread kernel
     * stack. SEH's exception registration chain is invalid → attempting SEH
     * causes the exception dispatcher to follow corrupt records → jumps to
     * zero-filled stack memory → BSOD 0x0A (IRQL_NOT_LESS_OR_EQUAL).
     */
    if (MsrIsKnownInvalid(Msr)) {
        LOG_DEBUG("RDMSR: MSR 0x%08X known-invalid (pre-probed), injecting #GP", Msr);
        HvInjectException(13, INTERRUPT_TYPE_HARDWARE_EXCEPTION, TRUE, 0);
        HvSetEntryInstructionLength(HvReadExitInstructionLength());
        return TRUE;
    }

    /*
     * Read the actual MSR value.
     *
     * This MSR passed the pre-probe check (it's either known-valid in the
     * probed ranges, or it's outside the probed ranges but was explicitly
     * intercepted by the MSR bitmap). In either case, __readmsr() should
     * succeed. If it doesn't (extremely unlikely edge case), the #GP in
     * VMX root mode is unrecoverable regardless — SEH wouldn't help anyway
     * because it's broken on our host stack.
     */
    Value = __readmsr(Msr);

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

    /*
     * HYPER-V SYNTHETIC MSR EMULATION (0x40000000 - 0x400000FF)
     *
     * Windows writes to these MSRs to configure Hyper-V synthetic devices
     * (SynIC, hypercall page, reference TSC, etc.) when it detects a Hyper-V
     * compatible hypervisor via CPUID.
     *
     * These MSRs don't exist on real hardware. Executing __writemsr() on
     * them causes #GP in VMX root mode. The __try/__except MAY catch it,
     * but the injected #GP into the Guest causes BSOD 0x1AA because Windows
     * kernel doesn't expect #GP when writing Hyper-V MSRs.
     *
     * FIX: Silently absorb the writes. Windows will think the MSR was
     * written successfully. Since we don't actually implement SynIC or
     * reference TSC, the features simply won't work, but that's safe —
     * Windows falls back to non-enlightened paths.
     */
    if (Msr >= 0x40000000 && Msr <= 0x400000FF) {
        HvAdvanceGuestRip();
        return TRUE;
    }

    /*
     * INVALID MSR PRE-PROBE CHECK (same rationale as HandleRdmsrImpl)
     *
     * If the MSR is known-invalid from pre-probing, inject #GP immediately
     * without executing __writemsr().
     *
     * CRITICAL: __try/__except (SEH) is UNSAFE in VMX root mode!
     * See HandleRdmsrImpl comments for the full explanation.
     */
    if (MsrIsKnownInvalid(Msr)) {
        VMXROOT_LOG_DEBUG("WRMSR: MSR 0x%08X known-invalid (pre-probed), injecting #GP", Msr);
        HvInjectException(13, INTERRUPT_TYPE_HARDWARE_EXCEPTION, TRUE, 0);
        HvSetEntryInstructionLength(HvReadExitInstructionLength());
        return TRUE;
    }

    /*
     * Write the MSR directly, without SEH.
     *
     * Same rationale as HandleRdmsrImpl: MSRs reaching here are either
     * known-valid (passed pre-probe) or explicitly intercepted by the MSR
     * bitmap (which only intercepts known MSRs). SEH is broken on our
     * host stack anyway, so it would cause BSOD instead of catching #GP.
     */
    __writemsr(Msr, Value);

    HvAdvanceGuestRip();
    return TRUE;
}
