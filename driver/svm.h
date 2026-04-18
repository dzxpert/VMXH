/*
 * svm.h - VMX Anti-Anti-Debug Hypervisor
 * AMD SVM (Secure Virtual Machine) definitions:
 *   VMCB structures, SVM exit codes, intercept bits, MSR definitions
 *
 * References:
 *   AMD64 Architecture Programmer's Manual, Volume 2 (System Programming)
 *   AEHD svm.h / svm_def.h / uapi/asm/svm.h
 */

#ifndef _SVM_H_
#define _SVM_H_

#include <ntddk.h>
#include "hv_ops.h"

/* ========================================================================= */
/*  SVM Pool Tag                                                             */
/* ========================================================================= */

#define SVM_TAG     'mvSD'

/* ========================================================================= */
/*  AMD MSR Definitions                                                      */
/* ========================================================================= */

#define MSR_EFER                    0xC0000080
#define MSR_STAR                    0xC0000081
#define MSR_LSTAR                   0xC0000082
#define MSR_CSTAR                   0xC0000083
#define MSR_SFMASK                  0xC0000084
#define MSR_FS_BASE                 0xC0000100
#define MSR_GS_BASE                 0xC0000101
#define MSR_KERNEL_GS_BASE          0xC0000102
#define MSR_TSC_AUX                 0xC0000103

#define MSR_AMD_VM_CR               0xC0010114
#define MSR_AMD_VM_HSAVE_PA         0xC0010117

/* EFER bits */
#define EFER_SVME                   (1ULL << 12)    /* SVM Enable */
#define EFER_LME                    (1ULL << 8)     /* Long Mode Enable */
#define EFER_LMA                    (1ULL << 10)    /* Long Mode Active */
#define EFER_NXE                    (1ULL << 11)    /* No-Execute Enable */
#define EFER_SCE                    (1ULL << 0)     /* System Call Enable */

/* VM_CR bits */
#define VM_CR_DPD                   (1ULL << 0)
#define VM_CR_R_INIT                (1ULL << 1)
#define VM_CR_DIS_A20M              (1ULL << 2)
#define VM_CR_LOCK                  (1ULL << 3)
#define VM_CR_SVMDIS                (1ULL << 4)

/* ========================================================================= */
/*  SVM CPUID Function                                                       */
/* ========================================================================= */

#define SVM_CPUID_FUNC              0x8000000A

/* EDX feature bits from CPUID 0x8000000A */
#define SVM_FEATURE_NPT             (1 << 0)    /* Nested Paging */
#define SVM_FEATURE_LBRV            (1 << 1)    /* LBR Virtualization */
#define SVM_FEATURE_SVM_LOCK        (1 << 2)    /* SVM Lock */
#define SVM_FEATURE_NRIP_SAVE       (1 << 3)    /* Next RIP Save */
#define SVM_FEATURE_TSC_RATE        (1 << 4)    /* TSC Rate Control */
#define SVM_FEATURE_VMCB_CLEAN      (1 << 5)    /* VMCB Clean Bits */
#define SVM_FEATURE_FLUSH_ASID      (1 << 6)    /* Flush by ASID */
#define SVM_FEATURE_DECODE_ASSIST   (1 << 7)    /* Decode Assists */
#define SVM_FEATURE_PAUSE_FILTER    (1 << 10)   /* Pause Intercept Filter */

/* ========================================================================= */
/*  SVM Exit Codes                                                           */
/* ========================================================================= */

#define SVM_EXIT_READ_CR0           0x000
#define SVM_EXIT_READ_CR2           0x002
#define SVM_EXIT_READ_CR3           0x003
#define SVM_EXIT_READ_CR4           0x004
#define SVM_EXIT_READ_CR8           0x008
#define SVM_EXIT_WRITE_CR0          0x010
#define SVM_EXIT_WRITE_CR2          0x012
#define SVM_EXIT_WRITE_CR3          0x013
#define SVM_EXIT_WRITE_CR4          0x014
#define SVM_EXIT_WRITE_CR8          0x018

#define SVM_EXIT_READ_DR0           0x020
#define SVM_EXIT_READ_DR1           0x021
#define SVM_EXIT_READ_DR2           0x022
#define SVM_EXIT_READ_DR3           0x023
#define SVM_EXIT_READ_DR4           0x024
#define SVM_EXIT_READ_DR5           0x025
#define SVM_EXIT_READ_DR6           0x026
#define SVM_EXIT_READ_DR7           0x027
#define SVM_EXIT_WRITE_DR0          0x030
#define SVM_EXIT_WRITE_DR1          0x031
#define SVM_EXIT_WRITE_DR2          0x032
#define SVM_EXIT_WRITE_DR3          0x033
#define SVM_EXIT_WRITE_DR4          0x034
#define SVM_EXIT_WRITE_DR5          0x035
#define SVM_EXIT_WRITE_DR6          0x036
#define SVM_EXIT_WRITE_DR7          0x037

#define SVM_EXIT_EXCP_BASE          0x040
/* Individual exception exits: SVM_EXIT_EXCP_BASE + vector */
#define SVM_EXIT_EXCP_DB            (SVM_EXIT_EXCP_BASE + 1)   /* #DB */
#define SVM_EXIT_EXCP_BP            (SVM_EXIT_EXCP_BASE + 3)   /* #BP */
#define SVM_EXIT_EXCP_UD            (SVM_EXIT_EXCP_BASE + 6)   /* #UD */
#define SVM_EXIT_EXCP_PF            (SVM_EXIT_EXCP_BASE + 14)  /* #PF */
#define SVM_EXIT_EXCP_GP            (SVM_EXIT_EXCP_BASE + 13)  /* #GP */

#define SVM_EXIT_INTR               0x060
#define SVM_EXIT_NMI                0x061
#define SVM_EXIT_SMI                0x062
#define SVM_EXIT_INIT               0x063
#define SVM_EXIT_VINTR              0x064
#define SVM_EXIT_CR0_SEL_WRITE      0x065
#define SVM_EXIT_IDTR_READ          0x066
#define SVM_EXIT_GDTR_READ          0x067
#define SVM_EXIT_LDTR_READ          0x068
#define SVM_EXIT_TR_READ            0x069
#define SVM_EXIT_IDTR_WRITE         0x06A
#define SVM_EXIT_GDTR_WRITE         0x06B
#define SVM_EXIT_LDTR_WRITE         0x06C
#define SVM_EXIT_TR_WRITE           0x06D
#define SVM_EXIT_RDTSC              0x06E
#define SVM_EXIT_RDPMC              0x06F
#define SVM_EXIT_PUSHF              0x070
#define SVM_EXIT_POPF               0x071
#define SVM_EXIT_CPUID              0x072
#define SVM_EXIT_RSM                0x073
#define SVM_EXIT_IRET               0x074
#define SVM_EXIT_SWINT              0x075
#define SVM_EXIT_INVD               0x076
#define SVM_EXIT_PAUSE              0x077
#define SVM_EXIT_HLT                0x078
#define SVM_EXIT_INVLPG             0x079
#define SVM_EXIT_INVLPGA            0x07A
#define SVM_EXIT_IOIO               0x07B
#define SVM_EXIT_MSR                0x07C
#define SVM_EXIT_TASK_SWITCH        0x07D
#define SVM_EXIT_FERR_FREEZE        0x07E
#define SVM_EXIT_SHUTDOWN           0x07F
#define SVM_EXIT_VMRUN              0x080
#define SVM_EXIT_VMMCALL            0x081
#define SVM_EXIT_VMLOAD             0x082
#define SVM_EXIT_VMSAVE             0x083
#define SVM_EXIT_STGI               0x084
#define SVM_EXIT_CLGI               0x085
#define SVM_EXIT_SKINIT             0x086
#define SVM_EXIT_RDTSCP             0x087
#define SVM_EXIT_ICEBP              0x088
#define SVM_EXIT_WBINVD             0x089
#define SVM_EXIT_MONITOR            0x08A
#define SVM_EXIT_MWAIT              0x08B
#define SVM_EXIT_MWAIT_COND         0x08C
#define SVM_EXIT_XSETBV             0x08D
#define SVM_EXIT_NPF                0x400

#define SVM_EXIT_ERR                ((ULONG)-1)

/* ========================================================================= */
/*  SVM Intercept Bit Positions (for VMCB.control.intercept)                 */
/* ========================================================================= */

/* These are bit positions in the 64-bit intercept field */
#define SVM_INTERCEPT_INTR              0
#define SVM_INTERCEPT_NMI               1
#define SVM_INTERCEPT_SMI               2
#define SVM_INTERCEPT_INIT              3
#define SVM_INTERCEPT_VINTR             4
#define SVM_INTERCEPT_SELECTIVE_CR0     5
#define SVM_INTERCEPT_STORE_IDTR        6
#define SVM_INTERCEPT_STORE_GDTR        7
#define SVM_INTERCEPT_STORE_LDTR        8
#define SVM_INTERCEPT_STORE_TR          9
#define SVM_INTERCEPT_LOAD_IDTR         10
#define SVM_INTERCEPT_LOAD_GDTR         11
#define SVM_INTERCEPT_LOAD_LDTR         12
#define SVM_INTERCEPT_LOAD_TR           13
#define SVM_INTERCEPT_RDTSC             14
#define SVM_INTERCEPT_RDPMC             15
#define SVM_INTERCEPT_PUSHF             16
#define SVM_INTERCEPT_POPF              17
#define SVM_INTERCEPT_CPUID             18
#define SVM_INTERCEPT_RSM               19
#define SVM_INTERCEPT_IRET              20
#define SVM_INTERCEPT_INTn              21
#define SVM_INTERCEPT_INVD              22
#define SVM_INTERCEPT_PAUSE             23
#define SVM_INTERCEPT_HLT               24
#define SVM_INTERCEPT_INVLPG            25
#define SVM_INTERCEPT_INVLPGA           26
#define SVM_INTERCEPT_IOIO_PROT         27
#define SVM_INTERCEPT_MSR_PROT          28
#define SVM_INTERCEPT_TASK_SWITCH       29
#define SVM_INTERCEPT_FERR_FREEZE       30
#define SVM_INTERCEPT_SHUTDOWN          31
/* Second dword (bits 32+) */
#define SVM_INTERCEPT_VMRUN             32
#define SVM_INTERCEPT_VMMCALL           33
#define SVM_INTERCEPT_VMLOAD            34
#define SVM_INTERCEPT_VMSAVE            35
#define SVM_INTERCEPT_STGI              36
#define SVM_INTERCEPT_CLGI              37
#define SVM_INTERCEPT_SKINIT            38
#define SVM_INTERCEPT_RDTSCP            39
#define SVM_INTERCEPT_ICEBP             40
#define SVM_INTERCEPT_WBINVD            41
#define SVM_INTERCEPT_MONITOR           42
#define SVM_INTERCEPT_MWAIT             43
#define SVM_INTERCEPT_MWAIT_COND        44
#define SVM_INTERCEPT_XSETBV            45

/* ========================================================================= */
/*  CR/DR Intercept Bit Positions                                            */
/* ========================================================================= */

/* intercept_cr: bits 0-15 = read CRn, bits 16-31 = write CRn */
#define SVM_INTERCEPT_CR0_READ      0
#define SVM_INTERCEPT_CR3_READ      3
#define SVM_INTERCEPT_CR4_READ      4
#define SVM_INTERCEPT_CR8_READ      8
#define SVM_INTERCEPT_CR0_WRITE     (16 + 0)
#define SVM_INTERCEPT_CR3_WRITE     (16 + 3)
#define SVM_INTERCEPT_CR4_WRITE     (16 + 4)
#define SVM_INTERCEPT_CR8_WRITE     (16 + 8)

/* intercept_dr: bits 0-15 = read DRn, bits 16-31 = write DRn */
#define SVM_INTERCEPT_DR0_READ      0
#define SVM_INTERCEPT_DR1_READ      1
#define SVM_INTERCEPT_DR2_READ      2
#define SVM_INTERCEPT_DR3_READ      3
#define SVM_INTERCEPT_DR6_READ      6
#define SVM_INTERCEPT_DR7_READ      7
#define SVM_INTERCEPT_DR0_WRITE     (16 + 0)
#define SVM_INTERCEPT_DR1_WRITE     (16 + 1)
#define SVM_INTERCEPT_DR2_WRITE     (16 + 2)
#define SVM_INTERCEPT_DR3_WRITE     (16 + 3)
#define SVM_INTERCEPT_DR6_WRITE     (16 + 6)
#define SVM_INTERCEPT_DR7_WRITE     (16 + 7)

/* ========================================================================= */
/*  TLB Control                                                              */
/* ========================================================================= */

#define TLB_CONTROL_DO_NOTHING      0
#define TLB_CONTROL_FLUSH_ALL_ASID  1
#define TLB_CONTROL_FLUSH_ASID      3
#define TLB_CONTROL_FLUSH_ASID_LOCAL 7

/* ========================================================================= */
/*  Interrupt Control (int_ctl)                                              */
/* ========================================================================= */

#define V_TPR_MASK                  0x0F
#define V_IRQ_SHIFT                 8
#define V_IRQ_MASK                  (1 << V_IRQ_SHIFT)
#define V_INTR_PRIO_SHIFT           16
#define V_INTR_PRIO_MASK            (0x0F << V_INTR_PRIO_SHIFT)
#define V_IGN_TPR_SHIFT             20
#define V_IGN_TPR_MASK              (1 << V_IGN_TPR_SHIFT)
#define V_INTR_MASKING_SHIFT        24
#define V_INTR_MASKING_MASK         (1 << V_INTR_MASKING_SHIFT)

/* ========================================================================= */
/*  Interrupt State (int_state at offset 0x068)                              */
/* ========================================================================= */

#define SVM_INTSTATE_SHADOW         (1 << 0)    /* Blocking by STI/MOV SS */
#define SVM_INTSTATE_NMI_MASK       (1 << 2)    /* Blocking by NMI (NMI mask) */

/* ========================================================================= */
/*  Nested Paging Control                                                    */
/* ========================================================================= */

#define SVM_NESTED_CTL_NP_ENABLE    (1ULL << 0)

/* ========================================================================= */
/*  Event Injection (event_inj)                                              */
/* ========================================================================= */

#define SVM_EVTINJ_VEC_MASK         0xFF
#define SVM_EVTINJ_TYPE_SHIFT       8
#define SVM_EVTINJ_TYPE_MASK        (7 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_INTR        (0 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_NMI         (2 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_EXEPT       (3 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_SOFT        (4 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_VALID            (1U << 31)
#define SVM_EVTINJ_VALID_ERR        (1 << 11)

/* Exit interrupt info has same layout */
#define SVM_EXITINTINFO_VEC_MASK    SVM_EVTINJ_VEC_MASK
#define SVM_EXITINTINFO_TYPE_MASK   SVM_EVTINJ_TYPE_MASK
#define SVM_EXITINTINFO_VALID       SVM_EVTINJ_VALID
#define SVM_EXITINTINFO_VALID_ERR   SVM_EVTINJ_VALID_ERR

/* ========================================================================= */
/*  NPT Exit Information (exit_info_1 for NPF)                              */
/* ========================================================================= */

#define SVM_NPF_P                   (1ULL << 0)   /* Present */
#define SVM_NPF_W                   (1ULL << 1)   /* Write access */
#define SVM_NPF_U                   (1ULL << 2)   /* User access */
#define SVM_NPF_RSV                 (1ULL << 3)   /* Reserved bit set */
#define SVM_NPF_ID                  (1ULL << 4)   /* Instruction fetch */
/* AMD specific: bit 32 = 1 if the fault is caused by guest page tables */
#define SVM_NPF_GUEST_PAGE_FAULT    (1ULL << 32)

/* ========================================================================= */
/*  VMCB Structures                                                          */
/* ========================================================================= */

#pragma pack(push, 1)

/*
 * VMCB Segment Register (used in save area)
 */
typedef struct _VMCB_SEG {
    USHORT  Selector;
    USHORT  Attrib;
    ULONG   Limit;
    ULONG64 Base;
} VMCB_SEG, *PVMCB_SEG;

/*
 * VMCB Control Area (offset 0x000 - 0x3FF in VMCB)
 */
typedef struct _VMCB_CONTROL_AREA {
    ULONG       InterceptCr;            /* 0x000: CR read/write intercepts */
    ULONG       InterceptDr;            /* 0x004: DR read/write intercepts */
    ULONG       InterceptExceptions;    /* 0x008: Exception intercepts */
    ULONG64     Intercept;              /* 0x00C: Instruction intercepts */
    UCHAR       Reserved1[40];          /* 0x014 */
    USHORT      PauseFilterThreshold;   /* 0x03C */
    USHORT      PauseFilterCount;       /* 0x03E */
    ULONG64     IopmBasePa;             /* 0x040: I/O Permission Map PA */
    ULONG64     MsrpmBasePa;            /* 0x048: MSR Permission Map PA */
    ULONG64     TscOffset;              /* 0x050: TSC Offset */
    ULONG       Asid;                   /* 0x058: Address Space ID */
    UCHAR       TlbCtl;                 /* 0x05C: TLB Control */
    UCHAR       Reserved2[3];           /* 0x05D */
    ULONG       IntCtl;                 /* 0x060: Interrupt Control */
    ULONG       IntVector;              /* 0x064: Interrupt Vector */
    ULONG       IntState;               /* 0x068: Interrupt State */
    UCHAR       Reserved3[4];           /* 0x06C */
    ULONG       ExitCode;               /* 0x070: Exit Code */
    ULONG       ExitCodeHi;             /* 0x074: Exit Code High */
    ULONG64     ExitInfo1;              /* 0x078: Exit Info 1 */
    ULONG64     ExitInfo2;              /* 0x080: Exit Info 2 */
    ULONG       ExitIntInfo;            /* 0x088: Exit Interrupt Info */
    ULONG       ExitIntInfoErr;         /* 0x08C: Exit Interrupt Error Code */
    ULONG64     NestedCtl;              /* 0x090: Nested Paging Control */
    ULONG64     AvicVapicBar;           /* 0x098: AVIC VAPIC BAR */
    UCHAR       Reserved4[8];           /* 0x0A0 */
    ULONG       EventInj;              /* 0x0A8: Event Injection */
    ULONG       EventInjErr;           /* 0x0AC: Event Injection Error Code */
    ULONG64     NestedCr3;              /* 0x0B0: Nested CR3 (NPT root) */
    ULONG64     LbrCtl;                 /* 0x0B8: LBR Virtualization */
    ULONG       CleanBits;              /* 0x0C0: VMCB Clean Bits */
    ULONG       Reserved5;              /* 0x0C4 */
    ULONG64     NextRip;                /* 0x0C8: Next Sequential RIP (NRIP) */
    UCHAR       InsnLen;                /* 0x0D0: Instruction Length */
    UCHAR       InsnBytes[15];          /* 0x0D1: Instruction Bytes */
    ULONG64     AvicBackingPage;        /* 0x0E0 */
    UCHAR       Reserved6[8];           /* 0x0E8 */
    ULONG64     AvicLogicalId;          /* 0x0F0 */
    ULONG64     AvicPhysicalId;         /* 0x0F8 */
    UCHAR       Reserved7[768];         /* 0x100 - 0x3FF */
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;

/*
 * VMCB Save Area (offset 0x400 - 0xFFF in VMCB)
 */
typedef struct _VMCB_SAVE_AREA {
    VMCB_SEG    Es;                     /* 0x400 */
    VMCB_SEG    Cs;                     /* 0x410 */
    VMCB_SEG    Ss;                     /* 0x420 */
    VMCB_SEG    Ds;                     /* 0x430 */
    VMCB_SEG    Fs;                     /* 0x440 */
    VMCB_SEG    Gs;                     /* 0x450 */
    VMCB_SEG    Gdtr;                   /* 0x460 */
    VMCB_SEG    Ldtr;                   /* 0x470 */
    VMCB_SEG    Idtr;                   /* 0x480 */
    VMCB_SEG    Tr;                     /* 0x490 */
    UCHAR       Reserved1[43];          /* 0x4A0 */
    UCHAR       Cpl;                    /* 0x4CB */
    UCHAR       Reserved2[4];           /* 0x4CC */
    ULONG64     Efer;                   /* 0x4D0 */
    UCHAR       Reserved3[112];         /* 0x4D8 */
    ULONG64     Cr4;                    /* 0x548 */
    ULONG64     Cr3;                    /* 0x550 */
    ULONG64     Cr0;                    /* 0x558 */
    ULONG64     Dr7;                    /* 0x560 */
    ULONG64     Dr6;                    /* 0x568 */
    ULONG64     Rflags;                 /* 0x570 */
    ULONG64     Rip;                    /* 0x578 */
    UCHAR       Reserved4[88];          /* 0x580 */
    ULONG64     Rsp;                    /* 0x5D8 */
    UCHAR       Reserved5[24];          /* 0x5E0 */
    ULONG64     Rax;                    /* 0x5F8 */
    ULONG64     Star;                   /* 0x600 */
    ULONG64     Lstar;                  /* 0x608 */
    ULONG64     Cstar;                  /* 0x610 */
    ULONG64     Sfmask;                 /* 0x618 */
    ULONG64     KernelGsBase;           /* 0x620 */
    ULONG64     SysenterCs;             /* 0x628 */
    ULONG64     SysenterEsp;            /* 0x630 */
    ULONG64     SysenterEip;            /* 0x638 */
    ULONG64     Cr2;                    /* 0x640 */
    UCHAR       Reserved6[32];          /* 0x648 */
    ULONG64     GPat;                   /* 0x668 */
    ULONG64     Dbgctl;                 /* 0x670 */
    ULONG64     BrFrom;                 /* 0x678 */
    ULONG64     BrTo;                   /* 0x680 */
    ULONG64     LastExcpFrom;           /* 0x688 */
    ULONG64     LastExcpTo;             /* 0x690 */
} VMCB_SAVE_AREA, *PVMCB_SAVE_AREA;

/*
 * Complete VMCB (4KB page: 1KB control + 3KB save area)
 */
typedef struct _VMCB {
    VMCB_CONTROL_AREA   Control;        /* 0x000 - 0x3FF */
    VMCB_SAVE_AREA      Save;           /* 0x400 - 0xFFF */
} VMCB, *PVMCB;

#pragma pack(pop)

/* Verify VMCB size - must fit in a 4KB page */
C_ASSERT(sizeof(VMCB) <= 0x1000);

/* ========================================================================= */
/*  SVM Per-CPU Context                                                      */
/* ========================================================================= */

typedef struct _SVM_CPU_CONTEXT {
    /* Common HV context (must be first for casting) */
    HV_CPU_CONTEXT  Common;

    /* VMCB */
    PVMCB           VmcbVa;             /* Virtual address of VMCB */
    ULONG64         VmcbPa;             /* Physical address of VMCB */

    /*
     * Hardware-managed Host Save Area — pointed to by MSR_VM_HSAVE_PA.
     * The CPU implicitly saves a *subset* of host state here on VMRUN
     * (CR3, RFLAGS, RAX, RSP, RIP, CS, SS, DS, ES — per AMD APM Vol.2
     * §15.5.1).  Additional host state (FS/GS/TR/LDTR bases,
     * KernelGsBase, LSTAR, STAR, CSTAR, SFMASK, SYSENTER_*, Efer) is NOT
     * touched by the CPU here — the hypervisor is responsible for it.
     */
    PVOID           HostSaveAreaVa;
    ULONG64         HostSaveAreaPa;

    /*
     * Software-managed Host VMCB — used as the target of the explicit
     * VMSAVE / VMLOAD instructions executed in the VMRUN loop.  VMSAVE
     * saves FS/GS/TR/LDTR base + the syscall/sysret MSRs; VMLOAD reloads
     * them.
     *
     * CRITICAL FIX (post-2nd-review): without this, the symmetric VMLOAD
     * that our launch loop runs just before every VMRUN would OVERWRITE
     * the host's FS/GS/TR/LSTAR/... with GUEST values coming from VMCB.Save,
     * and when we VMEXIT back into host mode we'd never restore the host
     * versions — Windows' GS_BASE (KPCR), TR.base (TSS), LSTAR (syscall
     * entry), etc. would stay poisoned, BSOD guaranteed.
     *
     * The VMRUN loop therefore looks like:
     *    first time only:           VMSAVE HostVmcbPa   (capture real host)
     *    every VMEXIT:              VMLOAD HostVmcbPa   (restore host)
     *    every VMRUN (non-first):   VMLOAD VmcbPa       (load guest extra)
     *                               VMRUN
     *
     * This VMCB is the same 4KB layout as the normal VMCB but only the
     * Save-area fields touched by VMSAVE/VMLOAD are meaningful; the
     * Control area is unused.
     */
    PVMCB           HostVmcbVa;
    ULONG64         HostVmcbPa;

    /* MSRPM (MSR Permission Map, 8KB = 2 pages) */
    PVOID           MsrpmVa;
    ULONG64         MsrpmPa;

    /* Host stack for #VMEXIT handler */
    PVOID           HostStackBase;
    SIZE_T          HostStackSize;

    /* ASID assigned to this vCPU */
    ULONG           Asid;

    /* Original EFER value (for restoration) */
    ULONG64         OriginalEfer;

} SVM_CPU_CONTEXT, *PSVM_CPU_CONTEXT;

/* ========================================================================= */
/*  SVM Global State                                                         */
/* ========================================================================= */

typedef struct _SVM_STATE {
    PSVM_CPU_CONTEXT CpuContexts;   /* dynamically allocated array [g_MaxProcessors] */
    ULONG           CpuCount;
    BOOLEAN         Initialized;

    /* Global IOPM (I/O Permission Map, 12KB = 3 pages) */
    PVOID           IopmVa;
    ULONG64         IopmPa;

    /* SVM capabilities from CPUID 0x8000000A */
    ULONG           SvmRevision;
    ULONG           MaxAsid;
    BOOLEAN         NptSupported;
    BOOLEAN         NripSaveSupported;
    BOOLEAN         VmcbCleanSupported;
    BOOLEAN         FlushByAsidSupported;
    BOOLEAN         DecodeAssistSupported;

} SVM_STATE, *PSVM_STATE;

/* ========================================================================= */
/*  MSRPM Layout                                                             */
/*                                                                           */
/*  8KB bitmap, 2 bits per MSR (read + write):                               */
/*  [0x0000..0x07FF] MSRs 0x00000000 - 0x00001FFF                           */
/*  [0x0800..0x0FFF] MSRs 0xC0000000 - 0xC0001FFF                           */
/*  [0x1000..0x17FF] MSRs 0xC0010000 - 0xC0011FFF                           */
/* ========================================================================= */

#define SVM_MSRPM_SIZE      (8192)      /* 8KB = 2 pages */
#define SVM_IOPM_SIZE       (12288)     /* 12KB = 3 pages */

/* ========================================================================= */
/*  Segment Attribute Conversion                                             */
/* ========================================================================= */

/*
 * SVM segment attributes are a 16-bit compact form:
 *   [3:0]   Type
 *   [4]     S (descriptor type)
 *   [6:5]   DPL
 *   [7]     P (present)
 *   [8]     AVL
 *   [9]     L (long mode)
 *   [10]    D/B
 *   [11]    G (granularity)
 */
#define SVM_SELECTOR_S_SHIFT        4
#define SVM_SELECTOR_DPL_SHIFT      5
#define SVM_SELECTOR_P_SHIFT        7
#define SVM_SELECTOR_AVL_SHIFT      8
#define SVM_SELECTOR_L_SHIFT        9
#define SVM_SELECTOR_DB_SHIFT       10
#define SVM_SELECTOR_G_SHIFT        11

/* ========================================================================= */
/*  Function Declarations                                                    */
/* ========================================================================= */

/* svm_init.c */
NTSTATUS    SvmInitialize(VOID);
VOID        SvmTerminate(VOID);
BOOLEAN     SvmIsSupported(VOID);

/*
 * C-3: dynamically enable / disable #DB / #BP intercepts across all CPUs.
 *
 * Each sub-feature owns a single bit:
 *   - SvmSetExceptionInterceptDb() is called by the NPT hook engine
 *     (hook count > 0 ⇒ TRUE, count == 0 ⇒ FALSE).
 *   - SvmSetExceptionInterceptBp() is called by the anti-anti-debug
 *     subsystem when AAD_HIDE_EXCEPTIONS is toggled.
 *
 * Internally the two bits are ORed into VMCB.Control.InterceptExceptions,
 * so they can be toggled independently without interfering with each
 * other.  The change takes effect on each CPU's next VMEXIT → VMRUN.
 */
VOID        SvmSetExceptionInterceptDb(BOOLEAN Enable);
VOID        SvmSetExceptionInterceptBp(BOOLEAN Enable);

/*
 * One-time init for the intercept-flag lock.  Called from SvmInitialize()
 * before any Set*ExceptionIntercept* call can happen — removes the race
 * in the old lazy-init pattern.
 */
VOID        SvmInterceptLockInitialize(VOID);

/* svm_exit.c */
BOOLEAN     SvmExitHandler(struct _GUEST_CONTEXT *GuestContext);

/* svm_asm.asm */
extern VOID  AsmSvmVmrun(ULONG64 VmcbPa, struct _GUEST_CONTEXT *GuestContext);
extern UCHAR AsmSvmLaunch(ULONG64 VmcbPa, PVOID VmcbVa, ULONG64 HostVmcbPa);
extern VOID  AsmSvmVmmcall(ULONG64 HypercallValue);
extern VOID  AsmSvmVmmcall2(ULONG64 HypercallValue, ULONG64 Arg1);
extern VOID  AsmClgi(VOID);
extern VOID  AsmStgi(VOID);
extern VOID  AsmSvmExitHandler(VOID);

/* SVM HV_OPS backend (registered in svm_init.c) */
extern HV_OPS g_SvmOps;

/* Global SVM state */
extern SVM_STATE g_SvmState;

#endif /* _SVM_H_ */
