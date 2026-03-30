/*
 * vmx_enlightened.h - VMX Anti-Anti-Debug Hypervisor
 * Hyper-V Enlightened VMCS structure, field mapping, clean bits,
 * VP Assist Page, and EvmcsRead/EvmcsWrite helpers.
 *
 * Used when running nested under Hyper-V to avoid costly VMREAD/VMWRITE
 * emulation. Instead, VMCS fields are accessed via direct struct member
 * reads/writes, and Hyper-V uses clean field bits to skip re-validation
 * of unchanged fields on VMRESUME.
 *
 * Reference: Microsoft Hypervisor Top-Level Functional Specification (TLFS)
 */

#ifndef _VMX_ENLIGHTENED_H_
#define _VMX_ENLIGHTENED_H_

#include <ntddk.h>

/* ========================================================================= */
/*  Hyper-V MSR Definitions                                                  */
/* ========================================================================= */

#define HV_X64_MSR_VP_ASSIST_PAGE       0x40000073
#define HV_VP_ASSIST_PAGE_ENABLE        (1ULL << 0)

/* ========================================================================= */
/*  Enlightened VMCS Clean Field Bitmasks                                     */
/* ========================================================================= */

#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE                  0x0000
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP             0x0001
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP            0x0002
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2          0x0004
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1          0x0008
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_PROC          0x0010
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT         0x0020
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_ENTRY         0x0040
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN         0x0080
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR                  0x0100
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT          0x0200
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC           0x0400
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1            0x0800
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2            0x1000
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER          0x2000
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1             0x4000
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_ENLIGHTENMENTSCONTROL 0x8000
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL                   0xFFFF

/* ========================================================================= */
/*  VP Assist Page                                                           */
/* ========================================================================= */

/*
 * The VP Assist Page is a 4KB page shared between L1 and L0 Hyper-V.
 * Writing its PA to MSR 0x40000073 with bit 0 set activates it.
 * Setting EnlightenedVmcsEnabled=1 tells L0 to use Enlightened VMCS.
 * CurrentEnlightenedVmcs points to the physical address of the active eVMCS.
 */
typedef struct _HV_VP_ASSIST_PAGE {
    /* APIC assist (not used by us) */
    ULONG       ApicAssist;                 /* 0x000 */
    ULONG       Reserved1;                  /* 0x004 */

    /* Enlightened VMCS control */
    ULONG       EnlightenedVmcsEnabled;     /* 0x008: 1 = use eVMCS */
    ULONG       Reserved2;                  /* 0x00C */
    ULONG64     CurrentEnlightenedVmcs;     /* 0x010: PA of active eVMCS */

    UCHAR       Reserved3[PAGE_SIZE - 0x18]; /* Pad to 4KB */
} HV_VP_ASSIST_PAGE, *PHV_VP_ASSIST_PAGE;

C_ASSERT(sizeof(HV_VP_ASSIST_PAGE) == PAGE_SIZE);

/* ========================================================================= */
/*  Enlightened VMCS Structure                                               */
/*                                                                           */
/*  This is a 4KB page that maps every VMCS field to a struct member.        */
/*  L0 Hyper-V reads/writes these fields directly instead of interpreting    */
/*  VMREAD/VMWRITE instructions.                                             */
/*                                                                           */
/*  Layout per Microsoft TLFS (Hypervisor Top-Level Functional Spec).        */
/* ========================================================================= */

#pragma pack(push, 1)

typedef struct _HV_VMX_ENLIGHTENED_VMCS {

    /* ===== Version and Abort ===== */
    ULONG       VersionNumber;              /* 0x000: Must be 1 */
    ULONG       AbortIndicator;             /* 0x004 */

    /* ===== 16-Bit Host State ===== */
    USHORT      HostEsSel;                  /* 0x008 */
    USHORT      HostCsSel;                  /* 0x00A */
    USHORT      HostSsSel;                  /* 0x00C */
    USHORT      HostDsSel;                  /* 0x00E */
    USHORT      HostFsSel;                  /* 0x010 */
    USHORT      HostGsSel;                  /* 0x012 */
    USHORT      HostTrSel;                  /* 0x014 */

    /* ===== 64-Bit Host State ===== */
    ULONG64     HostIa32Pat;                /* 0x016 */
    ULONG64     HostIa32Efer;               /* 0x01E */
    ULONG64     HostCr0;                    /* 0x026 */
    ULONG64     HostCr3;                    /* 0x02E */
    ULONG64     HostCr4;                    /* 0x036 */
    ULONG64     HostIa32SysenterEsp;        /* 0x03E */
    ULONG64     HostIa32SysenterEip;        /* 0x046 */
    ULONG64     HostRip;                    /* 0x04E */
    ULONG       HostIa32SysenterCs;         /* 0x056 */

    /* ===== 32-Bit VM-Execution Controls ===== */
    ULONG       PinBasedVmExecControl;      /* 0x05A */
    ULONG       VmExitControls;             /* 0x05E */
    ULONG       SecondaryVmExecControl;     /* 0x062 */

    /* ===== 64-Bit Host Descriptor-Table ===== */
    ULONG64     HostIa32PerfGlobalCtrl;     /* 0x066: padding per TLFS */

    /* Padding / alignment area */
    ULONG64     Reserved0;                  /* 0x06E */

    /* ===== 64-Bit Control Fields ===== */
    ULONG64     IoBitmapA;                  /* 0x076 */
    ULONG64     IoBitmapB;                  /* 0x07E */
    ULONG64     MsrBitmap;                  /* 0x086 */

    /* ===== 16-Bit Guest State ===== */
    USHORT      GuestEsSel;                 /* 0x08E */
    USHORT      GuestCsSel;                 /* 0x090 */
    USHORT      GuestSsSel;                 /* 0x092 */
    USHORT      GuestDsSel;                 /* 0x094 */
    USHORT      GuestFsSel;                 /* 0x096 */
    USHORT      GuestGsSel;                 /* 0x098 */
    USHORT      GuestLdtrSel;              /* 0x09A */
    USHORT      GuestTrSel;                 /* 0x09C */

    /* ===== 32-Bit VM-Entry / VM-Exit Controls ===== */
    ULONG       VmEntryControls;            /* 0x09E */
    ULONG       VmEntryMsrLoadCount;        /* 0x0A2 */
    ULONG       VmEntryIntrInfoField;       /* 0x0A6 */
    ULONG       VmEntryExceptionErrCode;    /* 0x0AA */
    ULONG       VmEntryInstrLen;            /* 0x0AE */
    ULONG       TprThreshold;               /* 0x0B2 */

    /* ===== 64-Bit Guest State ===== */
    ULONG64     GuestIa32Pat;               /* 0x0B6 */
    ULONG64     GuestIa32Efer;              /* 0x0BE */
    ULONG64     GuestIa32PerfGlobalCtrl;    /* 0x0C6: unused by us */

    /* ===== 64-Bit Control Fields (cont.) ===== */
    ULONG64     VmcsLinkPointer;            /* 0x0CE */
    ULONG64     GuestIa32Debugctl;          /* 0x0D6 */

    /* ===== 32-Bit Guest State ===== */
    ULONG       GuestEsLimit;               /* 0x0DE */
    ULONG       GuestCsLimit;               /* 0x0E2 */
    ULONG       GuestSsLimit;               /* 0x0E6 */
    ULONG       GuestDsLimit;               /* 0x0EA */
    ULONG       GuestFsLimit;               /* 0x0EE */
    ULONG       GuestGsLimit;               /* 0x0F2 */
    ULONG       GuestLdtrLimit;             /* 0x0F6 */
    ULONG       GuestTrLimit;               /* 0x0FA */
    ULONG       GuestGdtrLimit;             /* 0x0FE */
    ULONG       GuestIdtrLimit;             /* 0x102 */

    ULONG       GuestEsArBytes;             /* 0x106 */
    ULONG       GuestCsArBytes;             /* 0x10A */
    ULONG       GuestSsArBytes;             /* 0x10E */
    ULONG       GuestDsArBytes;             /* 0x112 */
    ULONG       GuestFsArBytes;             /* 0x116 */
    ULONG       GuestGsArBytes;             /* 0x11A */
    ULONG       GuestLdtrArBytes;           /* 0x11E */
    ULONG       GuestTrArBytes;             /* 0x122 */

    ULONG64     GuestEsBase;                /* 0x126 */
    ULONG64     GuestCsBase;                /* 0x12E */
    ULONG64     GuestSsBase;                /* 0x136 */
    ULONG64     GuestDsBase;                /* 0x13E */
    ULONG64     GuestFsBase;                /* 0x146 */
    ULONG64     GuestGsBase;                /* 0x14E */
    ULONG64     GuestLdtrBase;              /* 0x156 */
    ULONG64     GuestTrBase;                /* 0x15E */
    ULONG64     GuestGdtrBase;              /* 0x166 */
    ULONG64     GuestIdtrBase;              /* 0x16E */

    /* ===== Natural-Width Guest State ===== */
    ULONG64     GuestRsp;                   /* 0x176 */
    ULONG64     GuestRip;                   /* 0x17E */
    ULONG64     GuestRflags;                /* 0x186 */

    /* ===== Natural-Width Guest Control Registers ===== */
    ULONG64     GuestCr0;                   /* 0x18E */
    ULONG64     GuestCr3;                   /* 0x196 */
    ULONG64     GuestCr4;                   /* 0x19E */
    ULONG64     GuestDr7;                   /* 0x1A6 */

    /* ===== Natural-Width Host State ===== */
    ULONG64     HostFsBase;                 /* 0x1AE */
    ULONG64     HostGsBase;                 /* 0x1B6 */
    ULONG64     HostTrBase;                 /* 0x1BE */
    ULONG64     HostGdtrBase;               /* 0x1C6 */
    ULONG64     HostIdtrBase;               /* 0x1CE */
    ULONG64     HostRsp;                    /* 0x1D6 */

    /* ===== 32-Bit Guest MSRs ===== */
    ULONG64     GuestIa32SysenterEsp;       /* 0x1DE */
    ULONG64     GuestIa32SysenterEip;       /* 0x1E6 */
    ULONG       GuestIa32SysenterCs;        /* 0x1EE */

    /* ===== 32-Bit Control Fields ===== */
    ULONG       CpuBasedVmExecControl;      /* 0x1F2 */
    ULONG       ExceptionBitmap;            /* 0x1F6 */
    ULONG       PageFaultErrorCodeMask;     /* 0x1FA */
    ULONG       PageFaultErrorCodeMatch;    /* 0x1FE */
    ULONG       Cr3TargetCount;             /* 0x202 */
    ULONG       VmExitMsrStoreCount;        /* 0x206 */
    ULONG       VmExitMsrLoadCount;         /* 0x20A */

    /* ===== 64-Bit Control Fields (cont.) ===== */
    ULONG64     VmExitMsrStoreAddr;         /* 0x20E */
    ULONG64     VmExitMsrLoadAddr;          /* 0x216 */
    ULONG64     VmEntryMsrLoadAddr;         /* 0x21E */

    /* ===== Natural-Width Control Fields ===== */
    ULONG64     Cr0GuestHostMask;           /* 0x226 */
    ULONG64     Cr4GuestHostMask;           /* 0x22E */
    ULONG64     Cr0ReadShadow;              /* 0x236 */
    ULONG64     Cr4ReadShadow;              /* 0x23E */

    /* ===== EPT / VPID ===== */
    ULONG64     EptPointer;                 /* 0x246 */
    USHORT      VirtualProcessorId;         /* 0x24E */

    /* ===== 64-Bit Control Fields (cont.) ===== */
    ULONG64     TscOffset;                  /* 0x250 */

    /* ===== 32-Bit Read-Only Data Fields ===== */
    ULONG       ExitReason;                 /* 0x258 */
    ULONG       VmExitIntrInfo;             /* 0x25C */
    ULONG       VmExitIntrErrorCode;        /* 0x260 */
    ULONG       IdtVectoringInfoField;      /* 0x264 */
    ULONG       IdtVectoringErrorCode;      /* 0x268 */
    ULONG       VmExitInstructionLen;       /* 0x26C */
    ULONG       VmExitInstructionInfo;      /* 0x270 */

    /* ===== Natural-Width Read-Only Data Fields ===== */
    ULONG64     ExitQualification;          /* 0x274 */
    ULONG64     IoRcx;                      /* 0x27C */
    ULONG64     IoRsi;                      /* 0x284 */
    ULONG64     IoRdi;                      /* 0x28C */
    ULONG64     IoRip;                      /* 0x294 */
    ULONG64     GuestLinearAddress;         /* 0x29C */

    /* ===== 64-Bit Read-Only Data Fields ===== */
    ULONG64     GuestPhysicalAddress;       /* 0x2A4 */

    /* ===== Guest State (cont.) ===== */
    ULONG       GuestActivityState;         /* 0x2AC */
    ULONG       GuestInterruptibilityInfo;  /* 0x2B0 */
    ULONG64     GuestPendingDbgExceptions;  /* 0x2B4 */
    ULONG       GuestSmbase;                /* 0x2BC: padding for alignment */

    /* ===== Guest PDPTE (for 32-bit PAE paging) ===== */
    ULONG64     GuestPdpte0;                /* 0x2C0 */
    ULONG64     GuestPdpte1;                /* 0x2C8 */
    ULONG64     GuestPdpte2;                /* 0x2D0 */
    ULONG64     GuestPdpte3;                /* 0x2D8 */

    /* ===== Preemption Timer ===== */
    ULONG       GuestPreemptionTimerValue;  /* 0x2E0 */

    /* ===== Enlightened-specific fields ===== */
    ULONG       CleanFields;                /* 0x2E4: bitmask of unchanged field groups */
    ULONG       Padding0;                   /* 0x2E8 */

    /* Synthetic fields added by Hyper-V */
    ULONG       SyntheticControls;          /* 0x2EC */
    ULONG       EnlightenmentsControl;      /* 0x2F0 */
    ULONG       VpId;                       /* 0x2F4 */
    ULONG64     VmId;                       /* 0x2F8 */
    ULONG64     PartitionAssistPage;        /* 0x300 */

    /* Pad remainder to 4KB */
    UCHAR       Padding1[PAGE_SIZE - 0x308];

} HV_VMX_ENLIGHTENED_VMCS, *PHV_VMX_ENLIGHTENED_VMCS;

#pragma pack(pop)

C_ASSERT(sizeof(HV_VMX_ENLIGHTENED_VMCS) == PAGE_SIZE);

/* ========================================================================= */
/*  VMCS Field Encoding Constants (matching vmx.h defines)                   */
/*  Used by the field-to-offset lookup table                                 */
/* ========================================================================= */

/*
 * Field encoding → struct offset mapping entry.
 * Used by EvmcsFieldOffset() to translate a VMCS field encoding
 * to the byte offset within HV_VMX_ENLIGHTENED_VMCS.
 */
typedef struct _EVMCS_FIELD_ENTRY {
    ULONG   FieldEncoding;
    USHORT  Offset;         /* offsetof(HV_VMX_ENLIGHTENED_VMCS, member) */
    USHORT  CleanBit;       /* Which clean field group this belongs to */
} EVMCS_FIELD_ENTRY;

/*
 * Master lookup table: VMCS field encoding → eVMCS struct offset + clean bit.
 *
 * The field encodings match the VMCS_* defines in vmx.h.
 * This table is searched linearly; since it's only used when g_IsNestedMode
 * is TRUE, and VmxRead/VmxWrite are called at IRQL <= DISPATCH, the cost
 * is acceptable compared to emulated VMREAD/VMWRITE.
 */
static const EVMCS_FIELD_ENTRY g_EvmcsFieldTable[] = {

    /* === 16-Bit Control Fields === */
    { 0x0000 /* VPID */,                    (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VirtualProcessorId),       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT },

    /* === 16-Bit Guest-State Fields === */
    { 0x0800 /* GUEST_ES_SEL */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestEsSel),              HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x0802 /* GUEST_CS_SEL */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestCsSel),              HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x0804 /* GUEST_SS_SEL */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestSsSel),              HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x0806 /* GUEST_DS_SEL */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestDsSel),              HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x0808 /* GUEST_FS_SEL */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestFsSel),              HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x080A /* GUEST_GS_SEL */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestGsSel),              HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x080C /* GUEST_LDTR_SEL */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestLdtrSel),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x080E /* GUEST_TR_SEL */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestTrSel),              HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },

    /* === 16-Bit Host-State Fields === */
    { 0x0C00 /* HOST_ES_SEL */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostEsSel),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x0C02 /* HOST_CS_SEL */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostCsSel),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x0C04 /* HOST_SS_SEL */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostSsSel),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x0C06 /* HOST_DS_SEL */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostDsSel),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x0C08 /* HOST_FS_SEL */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostFsSel),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x0C0A /* HOST_GS_SEL */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostGsSel),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x0C0C /* HOST_TR_SEL */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostTrSel),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },

    /* === 64-Bit Control Fields === */
    { 0x2000 /* IO_BITMAP_A */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, IoBitmapA),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP },
    { 0x2002 /* IO_BITMAP_B */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, IoBitmapB),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP },
    { 0x2004 /* MSR_BITMAP */,              (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, MsrBitmap),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP },
    { 0x2006 /* VMEXIT_MSR_STORE_ADDR */,   (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmExitMsrStoreAddr),     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 },
    { 0x2008 /* VMEXIT_MSR_LOAD_ADDR */,    (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmExitMsrLoadAddr),      HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 },
    { 0x200A /* VMENTRY_MSR_LOAD_ADDR */,   (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmEntryMsrLoadAddr),     HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 },
    { 0x2010 /* TSC_OFFSET */,              (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, TscOffset),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2 },
    { 0x201A /* EPT_POINTER */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, EptPointer),              HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT },

    /* === 64-Bit Read-Only Data Fields === */
    { 0x2400 /* GUEST_PHYSICAL_ADDRESS */,  (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestPhysicalAddress),    HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },

    /* === 64-Bit Guest-State Fields === */
    { 0x2800 /* GUEST_VMCS_LINK_PTR */,     (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmcsLinkPointer),        HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },
    { 0x2802 /* GUEST_IA32_DEBUGCTL */,     (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestIa32Debugctl),      HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },
    { 0x2804 /* GUEST_IA32_PAT */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestIa32Pat),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },
    { 0x2806 /* GUEST_IA32_EFER */,         (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestIa32Efer),          HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },
    { 0x280A /* GUEST_PDPTE0 */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestPdpte0),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },
    { 0x280C /* GUEST_PDPTE1 */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestPdpte1),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },
    { 0x280E /* GUEST_PDPTE2 */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestPdpte2),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },
    { 0x2810 /* GUEST_PDPTE3 */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestPdpte3),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },

    /* === 64-Bit Host-State Fields === */
    { 0x2C00 /* HOST_IA32_PAT */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostIa32Pat),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x2C02 /* HOST_IA32_EFER */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostIa32Efer),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },

    /* === 32-Bit Control Fields === */
    { 0x4000 /* PIN_BASED_VM_EXEC */,       (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, PinBasedVmExecControl),  HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 },
    { 0x4002 /* PROC_BASED_VM_EXEC */,      (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, CpuBasedVmExecControl),  HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_PROC },
    { 0x4004 /* EXCEPTION_BITMAP */,        (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, ExceptionBitmap),        HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN },
    { 0x4006 /* PAGE_FAULT_ERROR_MASK */,   (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, PageFaultErrorCodeMask), HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN },
    { 0x4008 /* PAGE_FAULT_ERROR_MATCH */,  (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, PageFaultErrorCodeMatch),HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN },
    { 0x400A /* CR3_TARGET_COUNT */,        (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, Cr3TargetCount),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 },
    { 0x400C /* VMEXIT_CONTROLS */,         (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmExitControls),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 },
    { 0x400E /* VMEXIT_MSR_STORE_COUNT */,  (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmExitMsrStoreCount),   HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 },
    { 0x4010 /* VMEXIT_MSR_LOAD_COUNT */,   (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmExitMsrLoadCount),    HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 },
    { 0x4012 /* VMENTRY_CONTROLS */,        (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmEntryControls),        HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_ENTRY },
    { 0x4014 /* VMENTRY_MSR_LOAD_COUNT */,  (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmEntryMsrLoadCount),   HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_ENTRY },
    { 0x4016 /* VMENTRY_INT_INFO */,        (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmEntryIntrInfoField),   HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT },
    { 0x4018 /* VMENTRY_EXCEPTION_ERRCODE */,(USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmEntryExceptionErrCode),HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT },
    { 0x401A /* VMENTRY_INSTR_LENGTH */,    (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmEntryInstrLen),        HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT },
    { 0x401C /* TPR_THRESHOLD */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, TprThreshold),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 },
    { 0x401E /* SECONDARY_VM_EXEC */,       (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, SecondaryVmExecControl), HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 },

    /* === 32-Bit Read-Only Data Fields === */
    { 0x4400 /* EXIT_REASON */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, ExitReason),             HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },
    { 0x4402 /* EXIT_INT_INFO */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmExitIntrInfo),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },
    { 0x4404 /* EXIT_INT_ERRCODE */,        (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmExitIntrErrorCode),    HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },
    { 0x4406 /* IDT_VECTORING_INFO */,      (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, IdtVectoringInfoField),  HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },
    { 0x4408 /* IDT_VECTORING_ERRCODE */,   (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, IdtVectoringErrorCode),  HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },
    { 0x440C /* EXIT_INSTRUCTION_LEN */,    (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmExitInstructionLen),   HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },
    { 0x440E /* EXIT_INSTRUCTION_INFO */,   (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, VmExitInstructionInfo),  HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },

    /* === 32-Bit Guest-State Fields === */
    { 0x4800 /* GUEST_ES_LIMIT */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestEsLimit),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4802 /* GUEST_CS_LIMIT */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestCsLimit),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4804 /* GUEST_SS_LIMIT */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestSsLimit),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4806 /* GUEST_DS_LIMIT */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestDsLimit),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4808 /* GUEST_FS_LIMIT */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestFsLimit),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x480A /* GUEST_GS_LIMIT */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestGsLimit),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x480C /* GUEST_LDTR_LIMIT */,        (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestLdtrLimit),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x480E /* GUEST_TR_LIMIT */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestTrLimit),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4810 /* GUEST_GDTR_LIMIT */,        (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestGdtrLimit),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4812 /* GUEST_IDTR_LIMIT */,        (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestIdtrLimit),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4814 /* GUEST_ES_AR */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestEsArBytes),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4816 /* GUEST_CS_AR */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestCsArBytes),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4818 /* GUEST_SS_AR */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestSsArBytes),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x481A /* GUEST_DS_AR */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestDsArBytes),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x481C /* GUEST_FS_AR */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestFsArBytes),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x481E /* GUEST_GS_AR */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestGsArBytes),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4820 /* GUEST_LDTR_AR */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestLdtrArBytes),       HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4822 /* GUEST_TR_AR */,             (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestTrArBytes),         HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x4824 /* GUEST_INTERRUPTIBILITY */,  (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestInterruptibilityInfo), HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC },
    { 0x4826 /* GUEST_ACTIVITY_STATE */,    (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestActivityState),     HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC },
    { 0x482A /* GUEST_SYSENTER_CS */,       (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestIa32SysenterCs),    HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },
    { 0x482E /* PREEMPT_TIMER */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestPreemptionTimerValue), HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },

    /* === 32-Bit Host-State Fields === */
    { 0x4C00 /* HOST_SYSENTER_CS */,        (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostIa32SysenterCs),     HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },

    /* === Natural-Width Control Fields === */
    { 0x6000 /* CR0_GUEST_HOST_MASK */,     (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, Cr0GuestHostMask),       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR },
    { 0x6002 /* CR4_GUEST_HOST_MASK */,     (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, Cr4GuestHostMask),       HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR },
    { 0x6004 /* CR0_READ_SHADOW */,         (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, Cr0ReadShadow),          HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR },
    { 0x6006 /* CR4_READ_SHADOW */,         (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, Cr4ReadShadow),          HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR },

    /* === Natural-Width Read-Only Data Fields === */
    { 0x6400 /* EXIT_QUALIFICATION */,      (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, ExitQualification),      HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },
    { 0x640A /* EXIT_GUEST_LINEAR_ADDR */,  (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestLinearAddress),     HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE },

    /* === Natural-Width Guest-State Fields === */
    { 0x6800 /* GUEST_CR0 */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestCr0),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR },
    { 0x6802 /* GUEST_CR3 */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestCr3),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR },
    { 0x6804 /* GUEST_CR4 */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestCr4),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR },
    { 0x6806 /* GUEST_ES_BASE */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestEsBase),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x6808 /* GUEST_CS_BASE */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestCsBase),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x680A /* GUEST_SS_BASE */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestSsBase),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x680C /* GUEST_DS_BASE */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestDsBase),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x680E /* GUEST_FS_BASE */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestFsBase),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x6810 /* GUEST_GS_BASE */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestGsBase),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x6812 /* GUEST_LDTR_BASE */,         (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestLdtrBase),          HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x6814 /* GUEST_TR_BASE */,           (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestTrBase),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x6816 /* GUEST_GDTR_BASE */,         (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestGdtrBase),          HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x6818 /* GUEST_IDTR_BASE */,         (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestIdtrBase),          HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 },
    { 0x681A /* GUEST_DR7 */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestDr7),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR },
    { 0x681C /* GUEST_RSP */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestRsp),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC },
    { 0x681E /* GUEST_RIP */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestRip),               HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC },
    { 0x6820 /* GUEST_RFLAGS */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestRflags),            HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC },
    { 0x6822 /* GUEST_PENDING_DBG_EXCPN */, (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestPendingDbgExceptions), HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC },
    { 0x6824 /* GUEST_SYSENTER_ESP */,      (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestIa32SysenterEsp),  HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },
    { 0x6826 /* GUEST_SYSENTER_EIP */,      (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, GuestIa32SysenterEip),  HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 },

    /* === Natural-Width Host-State Fields === */
    { 0x6C00 /* HOST_CR0 */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostCr0),                HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x6C02 /* HOST_CR3 */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostCr3),                HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x6C04 /* HOST_CR4 */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostCr4),                HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x6C06 /* HOST_FS_BASE */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostFsBase),             HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER },
    { 0x6C08 /* HOST_GS_BASE */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostGsBase),             HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER },
    { 0x6C0A /* HOST_TR_BASE */,            (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostTrBase),             HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER },
    { 0x6C0C /* HOST_GDTR_BASE */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostGdtrBase),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER },
    { 0x6C0E /* HOST_IDTR_BASE */,          (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostIdtrBase),           HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER },
    { 0x6C10 /* HOST_SYSENTER_ESP */,       (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostIa32SysenterEsp),   HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x6C12 /* HOST_SYSENTER_EIP */,       (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostIa32SysenterEip),   HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 },
    { 0x6C14 /* HOST_RSP */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostRsp),                HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER },
    { 0x6C16 /* HOST_RIP */,               (USHORT)FIELD_OFFSET(HV_VMX_ENLIGHTENED_VMCS, HostRip),                HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER },
};

#define EVMCS_FIELD_TABLE_SIZE  (sizeof(g_EvmcsFieldTable) / sizeof(g_EvmcsFieldTable[0]))

/* ========================================================================= */
/*  Enlightened VMCS Field Access Helpers                                     */
/* ========================================================================= */

/*
 * Look up the byte offset within HV_VMX_ENLIGHTENED_VMCS for a given
 * VMCS field encoding. Returns (USHORT)-1 if not found.
 */
FORCEINLINE USHORT EvmcsFieldOffset(ULONG VmcsField)
{
    ULONG i;
    for (i = 0; i < EVMCS_FIELD_TABLE_SIZE; i++) {
        if (g_EvmcsFieldTable[i].FieldEncoding == VmcsField) {
            return g_EvmcsFieldTable[i].Offset;
        }
    }
    return (USHORT)-1;  /* Not mapped in eVMCS */
}

/*
 * Look up the clean field bitmask for a given VMCS field encoding.
 * Returns 0 (NONE) if not found.
 */
FORCEINLINE USHORT EvmcsFieldCleanBit(ULONG VmcsField)
{
    ULONG i;
    for (i = 0; i < EVMCS_FIELD_TABLE_SIZE; i++) {
        if (g_EvmcsFieldTable[i].FieldEncoding == VmcsField) {
            return g_EvmcsFieldTable[i].CleanBit;
        }
    }
    return HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
}

/*
 * Read a VMCS field from the Enlightened VMCS structure.
 * The field size is determined by the field encoding:
 *   - 0x0xxx: 16-bit field  → read as USHORT, zero-extend to ULONG64
 *   - 0x2xxx: 64-bit field  → read as ULONG64
 *   - 0x4xxx: 32-bit field  → read as ULONG, zero-extend to ULONG64
 *   - 0x6xxx: natural-width → read as ULONG64 (we're always 64-bit)
 */
FORCEINLINE ULONG64 EvmcsRead(PHV_VMX_ENLIGHTENED_VMCS Evmcs, ULONG Field)
{
    USHORT Offset = EvmcsFieldOffset(Field);
    PUCHAR Base;

    if (Offset == (USHORT)-1) {
        /* Field not mapped — fall through to VMREAD */
        SIZE_T Value = 0;
        __vmx_vmread(Field, &Value);
        return (ULONG64)Value;
    }

    Base = (PUCHAR)Evmcs;

    switch ((Field >> 13) & 0x3) {
    case 0: /* 16-bit */
        return (ULONG64)(*(PUSHORT)(Base + Offset));
    case 1: /* 64-bit */
        return *(PULONG64)(Base + Offset);
    case 2: /* 32-bit */
        return (ULONG64)(*(PULONG)(Base + Offset));
    case 3: /* natural-width (64-bit on x64) */
        return *(PULONG64)(Base + Offset);
    }

    return 0;
}

/*
 * Write a VMCS field into the Enlightened VMCS structure
 * and clear the corresponding clean field bit so L0 re-validates it.
 */
FORCEINLINE VOID EvmcsWrite(PHV_VMX_ENLIGHTENED_VMCS Evmcs, ULONG Field, ULONG64 Value)
{
    USHORT Offset = EvmcsFieldOffset(Field);
    USHORT CleanBit;
    PUCHAR Base;

    if (Offset == (USHORT)-1) {
        /* Field not mapped — fall through to VMWRITE */
        __vmx_vmwrite(Field, Value);
        return;
    }

    Base = (PUCHAR)Evmcs;

    switch ((Field >> 13) & 0x3) {
    case 0: /* 16-bit */
        *(PUSHORT)(Base + Offset) = (USHORT)Value;
        break;
    case 1: /* 64-bit */
        *(PULONG64)(Base + Offset) = Value;
        break;
    case 2: /* 32-bit */
        *(PULONG)(Base + Offset) = (ULONG)Value;
        break;
    case 3: /* natural-width (64-bit on x64) */
        *(PULONG64)(Base + Offset) = Value;
        break;
    }

    /* Mark the corresponding clean field group as dirty */
    CleanBit = EvmcsFieldCleanBit(Field);
    if (CleanBit != HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE) {
        Evmcs->CleanFields &= ~(ULONG)CleanBit;
    }
}

#endif /* _VMX_ENLIGHTENED_H_ */
