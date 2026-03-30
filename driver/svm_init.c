/*
 * svm_init.c - VMX Anti-Anti-Debug Hypervisor
 * AMD SVM initialization: VMCB configuration, per-CPU enable/disable,
 * and HV_OPS backend registration.
 *
 * References: AEHD svm.c, AMD64 APM Vol. 2
 */

#include "svm.h"
#include "npt.h"
#include "hv_detect.h"
#include "vmx.h"        /* For AsmGet* segment/register accessor declarations */
#include "log.h"
#include "ept.h"
#include "svm_enlightened.h"

/* ========================================================================= */
/*  Globals                                                                  */
/* ========================================================================= */

SVM_STATE g_SvmState = { 0 };

/* ========================================================================= */
/*  Forward Declarations                                                     */
/* ========================================================================= */

static BOOLEAN  SvmCheckCapabilities(VOID);
static NTSTATUS SvmAllocateCpuContext(PSVM_CPU_CONTEXT CpuCtx);
static VOID     SvmFreeCpuContext(PSVM_CPU_CONTEXT CpuCtx);
static NTSTATUS SvmEnableOnCpu(PSVM_CPU_CONTEXT CpuCtx);
static VOID     SvmDisableOnCpu(PSVM_CPU_CONTEXT CpuCtx);
static VOID     SvmInitVmcb(PSVM_CPU_CONTEXT CpuCtx);
static NTSTATUS SvmAllocateGlobalResources(VOID);
static VOID     SvmFreeGlobalResources(VOID);

/* MSRPM helpers */
static VOID     SvmMsrpmSetBit(PVOID Msrpm, ULONG Msr, BOOLEAN Read, BOOLEAN Write);
static VOID     SvmInitMsrpm(PVOID Msrpm);

/* Segment descriptor parsing helpers (reuse from vmx_init.c concepts) */
static USHORT   SvmGetSegmentAttrib(ULONG64 GdtBase, USHORT Selector);

/* DPC context for per-CPU init */
typedef struct _SVM_DPC_CONTEXT {
    NTSTATUS    Status;
    KEVENT      Event;
} SVM_DPC_CONTEXT, *PSVM_DPC_CONTEXT;

/* ========================================================================= */
/*  Aligned Memory Allocation                                                */
/* ========================================================================= */

static PVOID SvmAllocateContiguous(SIZE_T Size, ULONG64 *PhysicalAddress)
{
    PHYSICAL_ADDRESS HighAddr, LowAddr, BoundaryAddr;
    PVOID VirtualAddr;

    LowAddr.QuadPart = 0;
    HighAddr.QuadPart = ~0ULL;
    BoundaryAddr.QuadPart = PAGE_SIZE;

    VirtualAddr = MmAllocateContiguousMemorySpecifyCache(
        Size, LowAddr, HighAddr, BoundaryAddr, MmCached);

    if (VirtualAddr) {
        PHYSICAL_ADDRESS PhysAddr;
        RtlZeroMemory(VirtualAddr, Size);
        PhysAddr = MmGetPhysicalAddress(VirtualAddr);
        *PhysicalAddress = PhysAddr.QuadPart;
    }

    return VirtualAddr;
}

/* ========================================================================= */
/*  SVM Support Detection                                                    */
/* ========================================================================= */

BOOLEAN SvmIsSupported(VOID)
{
    return HvCheckSvmSupport();
}

/* ========================================================================= */
/*  Capability Check                                                         */
/* ========================================================================= */

static BOOLEAN SvmCheckCapabilities(VOID)
{
    int CpuInfo[4];

    __cpuid(CpuInfo, SVM_CPUID_FUNC);

    g_SvmState.SvmRevision = (ULONG)(CpuInfo[0] & 0xFF);
    g_SvmState.MaxAsid = (ULONG)CpuInfo[1];

    /* Feature flags from EDX */
    g_SvmState.NptSupported          = (CpuInfo[3] & SVM_FEATURE_NPT) != 0;
    g_SvmState.NripSaveSupported     = (CpuInfo[3] & SVM_FEATURE_NRIP_SAVE) != 0;
    g_SvmState.VmcbCleanSupported    = (CpuInfo[3] & SVM_FEATURE_VMCB_CLEAN) != 0;
    g_SvmState.FlushByAsidSupported  = (CpuInfo[3] & SVM_FEATURE_FLUSH_ASID) != 0;
    g_SvmState.DecodeAssistSupported = (CpuInfo[3] & SVM_FEATURE_DECODE_ASSIST) != 0;

    LOG_INFO("SVM Revision: %u, Max ASID: %u", g_SvmState.SvmRevision, g_SvmState.MaxAsid);
    LOG_INFO("NPT: %s, NRIP Save: %s, VMCB Clean: %s, Flush-by-ASID: %s",
             g_SvmState.NptSupported ? "YES" : "NO",
             g_SvmState.NripSaveSupported ? "YES" : "NO",
             g_SvmState.VmcbCleanSupported ? "YES" : "NO",
             g_SvmState.FlushByAsidSupported ? "YES" : "NO");

    if (g_SvmState.MaxAsid == 0) {
        LOG_ERROR("SVM reports 0 ASIDs available");
        return FALSE;
    }

    if (!g_SvmState.NptSupported) {
        LOG_ERROR("NPT not supported - required for EPT-equivalent functionality");
        return FALSE;
    }

    return TRUE;
}

/* ========================================================================= */
/*  Global Resource Allocation                                               */
/* ========================================================================= */

static NTSTATUS SvmAllocateGlobalResources(VOID)
{
    /* IOPM: 12KB I/O Permission Map - all zeros = don't intercept I/O */
    g_SvmState.IopmVa = SvmAllocateContiguous(SVM_IOPM_SIZE, &g_SvmState.IopmPa);
    if (!g_SvmState.IopmVa) {
        LOG_ERROR("Failed to allocate IOPM");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* All zeros = pass-through all I/O ports */

    return STATUS_SUCCESS;
}

static VOID SvmFreeGlobalResources(VOID)
{
    if (g_SvmState.IopmVa) {
        MmFreeContiguousMemory(g_SvmState.IopmVa);
        g_SvmState.IopmVa = NULL;
    }
}

/* ========================================================================= */
/*  Per-CPU Context Allocation                                               */
/* ========================================================================= */

static NTSTATUS SvmAllocateCpuContext(PSVM_CPU_CONTEXT CpuCtx)
{
    /* VMCB (4KB, page-aligned) */
    CpuCtx->VmcbVa = (PVMCB)SvmAllocateContiguous(PAGE_SIZE, &CpuCtx->VmcbPa);
    if (!CpuCtx->VmcbVa) {
        LOG_ERROR("Failed to allocate VMCB for CPU %u", CpuCtx->Common.ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Host Save Area (4KB, page-aligned) */
    CpuCtx->HostSaveAreaVa = SvmAllocateContiguous(PAGE_SIZE, &CpuCtx->HostSaveAreaPa);
    if (!CpuCtx->HostSaveAreaVa) {
        LOG_ERROR("Failed to allocate host save area for CPU %u",
                  CpuCtx->Common.ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Per-CPU MSRPM (8KB) */
    CpuCtx->MsrpmVa = SvmAllocateContiguous(SVM_MSRPM_SIZE, &CpuCtx->MsrpmPa);
    if (!CpuCtx->MsrpmVa) {
        LOG_ERROR("Failed to allocate MSRPM for CPU %u", CpuCtx->Common.ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SvmInitMsrpm(CpuCtx->MsrpmVa);

    /* Host Stack (16KB) */
    CpuCtx->HostStackSize = 4 * PAGE_SIZE;
    CpuCtx->HostStackBase = ExAllocatePoolWithTag(
        NonPagedPool, CpuCtx->HostStackSize, SVM_TAG);
    if (!CpuCtx->HostStackBase) {
        LOG_ERROR("Failed to allocate host stack for CPU %u",
                  CpuCtx->Common.ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(CpuCtx->HostStackBase, CpuCtx->HostStackSize);

    /* Assign ASID (simple: CPU number + 1, ASID 0 is reserved for host) */
    CpuCtx->Asid = CpuCtx->Common.ProcessorNumber + 1;
    if (CpuCtx->Asid >= g_SvmState.MaxAsid) {
        CpuCtx->Asid = 1;  /* Wrap to 1 if too many CPUs */
    }

    /* Partition Assist Page (nested mode only) */
    if (g_IsNestedMode) {
        CpuCtx->PartitionAssistPageVa = SvmAllocateContiguous(
            PAGE_SIZE, &CpuCtx->PartitionAssistPagePa);
        if (!CpuCtx->PartitionAssistPageVa) {
            LOG_ERROR("Failed to allocate Partition Assist Page for CPU %u",
                      CpuCtx->Common.ProcessorNumber);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        LOG_INFO("Partition Assist Page allocated for CPU %u: PA=0x%llX",
                 CpuCtx->Common.ProcessorNumber, CpuCtx->PartitionAssistPagePa);
    }

    return STATUS_SUCCESS;
}

static VOID SvmFreeCpuContext(PSVM_CPU_CONTEXT CpuCtx)
{
    if (CpuCtx->VmcbVa) {
        MmFreeContiguousMemory(CpuCtx->VmcbVa);
        CpuCtx->VmcbVa = NULL;
    }
    if (CpuCtx->HostSaveAreaVa) {
        MmFreeContiguousMemory(CpuCtx->HostSaveAreaVa);
        CpuCtx->HostSaveAreaVa = NULL;
    }
    if (CpuCtx->MsrpmVa) {
        MmFreeContiguousMemory(CpuCtx->MsrpmVa);
        CpuCtx->MsrpmVa = NULL;
    }
    if (CpuCtx->HostStackBase) {
        ExFreePoolWithTag(CpuCtx->HostStackBase, SVM_TAG);
        CpuCtx->HostStackBase = NULL;
    }
    /* Partition Assist Page (nested mode) */
    if (CpuCtx->PartitionAssistPageVa) {
        MmFreeContiguousMemory(CpuCtx->PartitionAssistPageVa);
        CpuCtx->PartitionAssistPageVa = NULL;
    }
}

/* ========================================================================= */
/*  MSRPM Initialization                                                     */
/* ========================================================================= */

/*
 * SVM MSRPM layout: 8KB total, 2 bits per MSR (bit 0 = read intercept, bit 1 = write)
 * Range 0: MSRs 0x00000000 - 0x00001FFF (offset 0x0000, 4KB)
 * Range 1: MSRs 0xC0000000 - 0xC0001FFF (offset 0x0800, 4KB)
 * Range 2: MSRs 0xC0010000 - 0xC0011FFF (offset 0x1000, 4KB)
 */
static VOID SvmMsrpmSetBit(PVOID Msrpm, ULONG Msr, BOOLEAN Read, BOOLEAN Write)
{
    PUCHAR Bitmap = (PUCHAR)Msrpm;
    ULONG  Offset;
    ULONG  BitBase;
    ULONG  ByteOffset;
    ULONG  BitOffset;

    if (Msr <= 0x1FFF) {
        Offset = 0x0000;
        BitBase = Msr;
    } else if (Msr >= 0xC0000000 && Msr <= 0xC0001FFF) {
        Offset = 0x0800;
        BitBase = Msr - 0xC0000000;
    } else if (Msr >= 0xC0010000 && Msr <= 0xC0011FFF) {
        Offset = 0x1000;
        BitBase = Msr - 0xC0010000;
    } else {
        return;  /* MSR not in any MSRPM range */
    }

    /* Each MSR gets 2 bits: bit 0 = read, bit 1 = write */
    ByteOffset = Offset + (BitBase * 2) / 8;
    BitOffset = (BitBase * 2) % 8;

    if (Read && ByteOffset < SVM_MSRPM_SIZE) {
        Bitmap[ByteOffset] |= (1 << BitOffset);
    }
    if (Write && ByteOffset < SVM_MSRPM_SIZE) {
        Bitmap[ByteOffset] |= (1 << (BitOffset + 1));
    }
}

static VOID SvmInitMsrpm(PVOID Msrpm)
{
    /* Start clean: all MSRs pass-through */
    RtlZeroMemory(Msrpm, SVM_MSRPM_SIZE);

    /* Intercept debug-related MSRs */
    SvmMsrpmSetBit(Msrpm, 0x01D9, TRUE, TRUE);   /* IA32_DEBUGCTL */

    LOG_DEBUG("SVM MSRPM initialized");
}

/* ========================================================================= */
/*  Segment Attribute Helper                                                 */
/* ========================================================================= */

/*
 * Convert GDT entry to SVM segment attribute format (16-bit)
 */
static USHORT SvmGetSegmentAttrib(ULONG64 GdtBase, USHORT Selector)
{
    typedef struct {
        USHORT  LimitLow;
        USHORT  BaseLow;
        UCHAR   BaseMid;
        UCHAR   Access;
        UCHAR   LimitHighAndFlags;
        UCHAR   BaseHigh;
    } GDT_RAW_ENTRY;

    GDT_RAW_ENTRY  *Entry;
    USHORT          Attrib;

    if (Selector == 0 || (Selector & 0xFFF8) == 0) {
        return 0;  /* Null selector */
    }

    Entry = (GDT_RAW_ENTRY *)(GdtBase + (Selector >> 3) * 8);

    /*
     * SVM attribute format:
     * [3:0]  Type
     * [4]    S
     * [6:5]  DPL
     * [7]    P
     * [8]    AVL
     * [9]    L
     * [10]   D/B
     * [11]   G
     */
    Attrib = (USHORT)(Entry->Access & 0xFF);                    /* Type, S, DPL, P */
    Attrib |= (USHORT)((Entry->LimitHighAndFlags >> 4) & 0xF) << 8;  /* AVL, L, D/B, G */

    return Attrib;
}

/* ========================================================================= */
/*  VMCB Configuration                                                       */
/* ========================================================================= */

static VOID SvmInitVmcb(PSVM_CPU_CONTEXT CpuCtx)
{
    PVMCB       Vmcb = CpuCtx->VmcbVa;
    ULONG64     GdtBase;
    USHORT      GdtLimit, IdtLimit;
    ULONG64     IdtBase;
    USHORT      Cs, Ss, Ds, Es, Fs, Gs, Tr, Ldtr;

    RtlZeroMemory(Vmcb, PAGE_SIZE);

    /* ===== Control Area ===== */

    /*
     * CR intercepts:
     * For anti-anti-debug, we intercept CR3 writes (process switch detection).
     * With NPT enabled, we don't need CR3 read/write intercepts for address translation.
     */
    Vmcb->Control.InterceptCr =
        (1 << SVM_INTERCEPT_CR0_WRITE) |
        (1 << SVM_INTERCEPT_CR4_WRITE);

    /*
     * DR intercepts:
     * Intercept all DR reads and writes for anti-anti-debug DR spoofing.
     */
    Vmcb->Control.InterceptDr =
        (1 << SVM_INTERCEPT_DR0_READ) | (1 << SVM_INTERCEPT_DR1_READ) |
        (1 << SVM_INTERCEPT_DR2_READ) | (1 << SVM_INTERCEPT_DR3_READ) |
        (1 << SVM_INTERCEPT_DR6_READ) | (1 << SVM_INTERCEPT_DR7_READ) |
        (1 << SVM_INTERCEPT_DR0_WRITE) | (1 << SVM_INTERCEPT_DR1_WRITE) |
        (1 << SVM_INTERCEPT_DR2_WRITE) | (1 << SVM_INTERCEPT_DR3_WRITE) |
        (1 << SVM_INTERCEPT_DR6_WRITE) | (1 << SVM_INTERCEPT_DR7_WRITE);

    /*
     * Exception intercepts:
     * #DB (1) and #BP (3) for anti-anti-debug exception handling
     */
    Vmcb->Control.InterceptExceptions =
        (1 << 1) |     /* #DB */
        (1 << 3);      /* #BP */

    /*
     * Instruction intercepts (64-bit):
     * CPUID, RDTSC/RDTSCP, MSR, VMMCALL, HLT, INVD, WBINVD, XSETBV, VMRUN
     */
    Vmcb->Control.Intercept =
        (1ULL << SVM_INTERCEPT_CPUID) |
        (1ULL << SVM_INTERCEPT_RDTSC) |
        (1ULL << SVM_INTERCEPT_RDTSCP) |
        (1ULL << SVM_INTERCEPT_MSR_PROT) |
        (1ULL << SVM_INTERCEPT_VMMCALL) |
        (1ULL << SVM_INTERCEPT_HLT) |
        (1ULL << SVM_INTERCEPT_INVD) |
        (1ULL << SVM_INTERCEPT_WBINVD) |
        (1ULL << SVM_INTERCEPT_XSETBV) |
        (1ULL << SVM_INTERCEPT_VMRUN) |     /* Required: must intercept VMRUN */
        (1ULL << SVM_INTERCEPT_VMLOAD) |
        (1ULL << SVM_INTERCEPT_VMSAVE) |
        (1ULL << SVM_INTERCEPT_STGI) |
        (1ULL << SVM_INTERCEPT_CLGI) |
        (1ULL << SVM_INTERCEPT_SKINIT) |
        (1ULL << SVM_INTERCEPT_INTR) |      /* Intercept physical interrupts */
        (1ULL << SVM_INTERCEPT_NMI);

    /* IOPM and MSRPM base addresses */
    Vmcb->Control.IopmBasePa = g_SvmState.IopmPa;
    Vmcb->Control.MsrpmBasePa = CpuCtx->MsrpmPa;

    /* TSC Offset (0 initially, adjusted for anti-timing) */
    Vmcb->Control.TscOffset = 0;

    /* ASID */
    Vmcb->Control.Asid = CpuCtx->Asid;

    /* TLB control: flush all on first entry */
    Vmcb->Control.TlbCtl = TLB_CONTROL_FLUSH_ALL_ASID;

    /* Interrupt control: enable virtual interrupt masking */
    Vmcb->Control.IntCtl = V_INTR_MASKING_MASK;

    /* Nested Paging (NPT) */
    if (g_SvmState.NptSupported) {
        Vmcb->Control.NestedCtl = SVM_NESTED_CTL_NP_ENABLE;
        Vmcb->Control.NestedCr3 = NptGetRootPageTablePa();

        /*
         * With NPT enabled, CR3 interception for paging is not needed.
         * We still intercept CR0/CR4 writes to maintain consistency.
         */
        LOG_INFO("NPT enabled for CPU %u, nested_cr3=0x%llX",
                 CpuCtx->Common.ProcessorNumber, Vmcb->Control.NestedCr3);
    }

    /* ===== Save Area - Mirror Current CPU State ===== */

    /* Read current descriptor tables */
    GdtBase = AsmGetGdtBase();
    GdtLimit = AsmGetGdtLimit();
    IdtBase = AsmGetIdtBase();
    IdtLimit = AsmGetIdtLimit();

    /* Read current segment selectors */
    Cs = AsmGetCs();
    Ss = AsmGetSs();
    Ds = AsmGetDs();
    Es = AsmGetEs();
    Fs = AsmGetFs();
    Gs = AsmGetGs();
    Tr = AsmGetTr();
    Ldtr = AsmGetLdtr();

    /* Segment registers */
    Vmcb->Save.Cs.Selector = Cs;
    Vmcb->Save.Cs.Attrib = SvmGetSegmentAttrib(GdtBase, Cs);
    Vmcb->Save.Cs.Limit = 0xFFFFFFFF;
    Vmcb->Save.Cs.Base = 0;

    Vmcb->Save.Ss.Selector = Ss;
    Vmcb->Save.Ss.Attrib = SvmGetSegmentAttrib(GdtBase, Ss);
    Vmcb->Save.Ss.Limit = 0xFFFFFFFF;
    Vmcb->Save.Ss.Base = 0;

    Vmcb->Save.Ds.Selector = Ds;
    Vmcb->Save.Ds.Attrib = SvmGetSegmentAttrib(GdtBase, Ds);
    Vmcb->Save.Ds.Limit = 0xFFFFFFFF;
    Vmcb->Save.Ds.Base = 0;

    Vmcb->Save.Es.Selector = Es;
    Vmcb->Save.Es.Attrib = SvmGetSegmentAttrib(GdtBase, Es);
    Vmcb->Save.Es.Limit = 0xFFFFFFFF;
    Vmcb->Save.Es.Base = 0;

    Vmcb->Save.Fs.Selector = Fs;
    Vmcb->Save.Fs.Attrib = SvmGetSegmentAttrib(GdtBase, Fs);
    Vmcb->Save.Fs.Limit = 0xFFFFFFFF;
    Vmcb->Save.Fs.Base = __readmsr(MSR_FS_BASE);

    Vmcb->Save.Gs.Selector = Gs;
    Vmcb->Save.Gs.Attrib = SvmGetSegmentAttrib(GdtBase, Gs);
    Vmcb->Save.Gs.Limit = 0xFFFFFFFF;
    Vmcb->Save.Gs.Base = __readmsr(MSR_GS_BASE);

    /* GDTR / IDTR (these use the VMCB_SEG format but only Base and Limit matter) */
    Vmcb->Save.Gdtr.Base = GdtBase;
    Vmcb->Save.Gdtr.Limit = GdtLimit;

    Vmcb->Save.Idtr.Base = IdtBase;
    Vmcb->Save.Idtr.Limit = IdtLimit;

    /* TR */
    {
        typedef struct {
            USHORT LimitLow; USHORT BaseLow; UCHAR BaseMid; UCHAR Access;
            UCHAR LimitHighAndFlags; UCHAR BaseHigh; ULONG BaseUpper; ULONG Reserved;
        } GDT_ENTRY64_RAW;

        GDT_ENTRY64_RAW *TrEntry;
        ULONG64 TrBase;
        ULONG TrLimit;

        TrEntry = (GDT_ENTRY64_RAW *)(GdtBase + (Tr >> 3) * 8);
        TrBase = TrEntry->BaseLow | ((ULONG64)TrEntry->BaseMid << 16) |
                 ((ULONG64)TrEntry->BaseHigh << 24) | ((ULONG64)TrEntry->BaseUpper << 32);
        TrLimit = TrEntry->LimitLow | ((ULONG)(TrEntry->LimitHighAndFlags & 0x0F) << 16);
        if (TrEntry->LimitHighAndFlags & 0x80) {
            TrLimit = (TrLimit << 12) | 0xFFF;
        }

        Vmcb->Save.Tr.Selector = Tr;
        Vmcb->Save.Tr.Attrib = SvmGetSegmentAttrib(GdtBase, Tr);
        Vmcb->Save.Tr.Base = TrBase;
        Vmcb->Save.Tr.Limit = TrLimit;
    }

    /* LDTR */
    Vmcb->Save.Ldtr.Selector = Ldtr;
    Vmcb->Save.Ldtr.Attrib = SvmGetSegmentAttrib(GdtBase, Ldtr);
    Vmcb->Save.Ldtr.Base = 0;
    Vmcb->Save.Ldtr.Limit = 0;

    /* Control registers */
    Vmcb->Save.Cr0 = __readcr0();
    Vmcb->Save.Cr3 = __readcr3();
    Vmcb->Save.Cr4 = __readcr4();
    Vmcb->Save.Cr2 = __readcr2();

    /* Debug registers */
    Vmcb->Save.Dr7 = __readdr(7);
    Vmcb->Save.Dr6 = __readdr(6);

    /* RFLAGS */
    Vmcb->Save.Rflags = AsmGetRflags();

    /* EFER - must have SVME set in guest */
    Vmcb->Save.Efer = __readmsr(MSR_EFER) | EFER_SVME;

    /* MSRs */
    Vmcb->Save.Star = __readmsr(MSR_STAR);
    Vmcb->Save.Lstar = __readmsr(MSR_LSTAR);
    Vmcb->Save.Cstar = __readmsr(MSR_CSTAR);
    Vmcb->Save.Sfmask = __readmsr(MSR_SFMASK);
    Vmcb->Save.KernelGsBase = __readmsr(MSR_KERNEL_GS_BASE);
    Vmcb->Save.SysenterCs = __readmsr(0x174);   /* IA32_SYSENTER_CS */
    Vmcb->Save.SysenterEsp = __readmsr(0x175);  /* IA32_SYSENTER_ESP */
    Vmcb->Save.SysenterEip = __readmsr(0x176);  /* IA32_SYSENTER_EIP */
    Vmcb->Save.GPat = __readmsr(0x277);          /* IA32_PAT */
    Vmcb->Save.Dbgctl = __readmsr(0x1D9);        /* IA32_DEBUGCTL */

    /* RSP and RIP will be set just before VMRUN */
    Vmcb->Save.Cpl = 0;    /* Ring 0 */

    /*
     * Enlightened VMCB fields (nested mode only).
     * Overlay the HV_SVM_ENLIGHTENED_VMCB_FIELDS at VMCB offset 0x3E0
     * (within the control area reserved region).
     */
    if (g_IsNestedMode) {
        PHV_SVM_ENLIGHTENED_VMCB_FIELDS Enl =
            (PHV_SVM_ENLIGHTENED_VMCB_FIELDS)((PUCHAR)Vmcb + VMCB_ENLIGHTENED_OFFSET);

        Enl->EnlightenedVmcbVersion = 1;
        Enl->EnableEnlightenedNptTlb = 1;
        Enl->EnableEnlightenedMsrBitmap = 1;
        Enl->VpId = CpuCtx->Common.ProcessorNumber + 1;
        Enl->VmId = 1;  /* Single VM */

        if (CpuCtx->PartitionAssistPageVa) {
            Enl->PartitionAssistPagePa = CpuCtx->PartitionAssistPagePa;
        }

        /* Mark enlightened fields as dirty on first setup */
        Vmcb->Control.CleanBits &= ~VMCB_CLEAN_BIT_ENLIGHTENED;

        LOG_INFO("Enlightened VMCB fields configured for CPU %u (VpId=%u)",
                 CpuCtx->Common.ProcessorNumber, Enl->VpId);
    }

    LOG_INFO("VMCB initialized for CPU %u", CpuCtx->Common.ProcessorNumber);
}

/* ========================================================================= */
/*  Per-CPU SVM Enable/Disable                                               */
/* ========================================================================= */

static NTSTATUS SvmEnableOnCpu(PSVM_CPU_CONTEXT CpuCtx)
{
    ULONG64 Efer;

    /* Save original EFER */
    CpuCtx->OriginalEfer = __readmsr(MSR_EFER);

    /* Set EFER.SVME (bit 12) to enable SVM */
    Efer = CpuCtx->OriginalEfer | EFER_SVME;
    __writemsr(MSR_EFER, Efer);

    /* Set MSR_VM_HSAVE_PA to point to our host save area */
    __writemsr(MSR_AMD_VM_HSAVE_PA, CpuCtx->HostSaveAreaPa);

    CpuCtx->Common.HvEnabled = TRUE;
    LOG_INFO("SVM enabled on CPU %u (EFER.SVME=1, HSAVE_PA=0x%llX)",
             CpuCtx->Common.ProcessorNumber, CpuCtx->HostSaveAreaPa);

    return STATUS_SUCCESS;
}

static VOID SvmDisableOnCpu(PSVM_CPU_CONTEXT CpuCtx)
{
    if (CpuCtx->Common.HvEnabled) {
        /* Clear EFER.SVME */
        __writemsr(MSR_EFER, CpuCtx->OriginalEfer);

        /* Clear host save area */
        __writemsr(MSR_AMD_VM_HSAVE_PA, 0);

        CpuCtx->Common.HvEnabled = FALSE;
        CpuCtx->Common.GuestLaunched = FALSE;
        LOG_INFO("SVM disabled on CPU %u", CpuCtx->Common.ProcessorNumber);
    }
}

/* ========================================================================= */
/*  Public Interface                                                         */
/* ========================================================================= */

NTSTATUS SvmInitialize(VOID)
{
    NTSTATUS Status;
    ULONG i, j;
    ULONG CpuCount;

    if (g_SvmState.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_SvmState, sizeof(SVM_STATE));
    CpuCount = KeQueryActiveProcessorCount(NULL);
    g_SvmState.CpuCount = CpuCount;

    LOG_INFO("Initializing SVM on %u processors", CpuCount);

    /* Check capabilities */
    if (!SvmCheckCapabilities()) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Allocate global resources (IOPM) */
    Status = SvmAllocateGlobalResources();
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /* Initialize NPT globally (AMD equivalent of EPT) */
    Status = NptInitialize();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("NPT initialization failed: 0x%08X", Status);
        SvmFreeGlobalResources();
        return Status;
    }

    /* Allocate per-CPU structures */
    for (i = 0; i < CpuCount; i++) {
        g_SvmState.CpuContexts[i].Common.ProcessorNumber = i;
        Status = SvmAllocateCpuContext(&g_SvmState.CpuContexts[i]);
        if (!NT_SUCCESS(Status)) {
            for (j = 0; j < i; j++) {
                SvmFreeCpuContext(&g_SvmState.CpuContexts[j]);
            }
            NptCleanup();
            SvmFreeGlobalResources();
            return Status;
        }

        /* Initialize VMCB for this CPU */
        SvmInitVmcb(&g_SvmState.CpuContexts[i]);
    }

    g_SvmState.Initialized = TRUE;
    LOG_INFO("SVM initialization complete");

    return STATUS_SUCCESS;
}

VOID SvmTerminate(VOID)
{
    ULONG i;

    if (!g_SvmState.Initialized) {
        return;
    }

    LOG_INFO("Terminating SVM...");

    /* Cleanup NPT */
    NptCleanup();

    /* Free per-CPU resources */
    for (i = 0; i < g_SvmState.CpuCount; i++) {
        SvmDisableOnCpu(&g_SvmState.CpuContexts[i]);
        SvmFreeCpuContext(&g_SvmState.CpuContexts[i]);
    }

    SvmFreeGlobalResources();

    g_SvmState.Initialized = FALSE;
    LOG_INFO("SVM terminated");
}

/* ========================================================================= */
/*  HV_OPS Backend Implementation (SVM)                                      */
/* ========================================================================= */

/* Helper to get current CPU's SVM context */
static PSVM_CPU_CONTEXT SvmGetCurrentCpu(VOID)
{
    ULONG CpuNum = KeGetCurrentProcessorNumber();
    if (CpuNum < MAX_PROCESSORS) {
        return &g_SvmState.CpuContexts[CpuNum];
    }
    return NULL;
}

/* Helper to get current CPU's VMCB */
static PVMCB SvmGetCurrentVmcb(VOID)
{
    PSVM_CPU_CONTEXT Ctx = SvmGetCurrentCpu();
    return Ctx ? Ctx->VmcbVa : NULL;
}

static BOOLEAN SvmOpsIsSupported(VOID)
{
    return SvmIsSupported();
}

static NTSTATUS SvmOpsInitialize(VOID)
{
    return SvmInitialize();
}

static VOID SvmOpsTerminate(VOID)
{
    SvmTerminate();
}

static ULONG64 SvmOpsReadGuestRip(VOID)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    return Vmcb ? Vmcb->Save.Rip : 0;
}

static VOID SvmOpsWriteGuestRip(ULONG64 Value)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb) Vmcb->Save.Rip = Value;
}

static ULONG64 SvmOpsReadGuestRsp(VOID)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    return Vmcb ? Vmcb->Save.Rsp : 0;
}

static VOID SvmOpsWriteGuestRsp(ULONG64 Value)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb) Vmcb->Save.Rsp = Value;
}

static ULONG64 SvmOpsReadGuestCr3(VOID)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    return Vmcb ? Vmcb->Save.Cr3 : 0;
}

static VOID SvmOpsWriteGuestCr3(ULONG64 Value)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb) Vmcb->Save.Cr3 = Value;
}

static ULONG64 SvmOpsReadGuestRflags(VOID)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    return Vmcb ? Vmcb->Save.Rflags : 0;
}

static VOID SvmOpsWriteGuestRflags(ULONG64 Value)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb) Vmcb->Save.Rflags = Value;
}

static ULONG64 SvmOpsReadExitReason(VOID)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    return Vmcb ? (ULONG64)Vmcb->Control.ExitCode : 0;
}

static ULONG64 SvmOpsReadExitQualification(VOID)
{
    /* SVM uses exit_info_1 as the primary exit qualification */
    PVMCB Vmcb = SvmGetCurrentVmcb();
    return Vmcb ? Vmcb->Control.ExitInfo1 : 0;
}

static ULONG64 SvmOpsReadExitInterruptionInfo(VOID)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    return Vmcb ? (ULONG64)Vmcb->Control.ExitIntInfo : 0;
}

static ULONG64 SvmOpsReadExitInterruptionErrorCode(VOID)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    return Vmcb ? (ULONG64)Vmcb->Control.ExitIntInfoErr : 0;
}

static ULONG SvmOpsReadExitInstructionLength(VOID)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb && g_SvmState.NripSaveSupported) {
        /* NRIP Save: NextRip - CurrentRip = instruction length */
        if (Vmcb->Control.NextRip > Vmcb->Save.Rip) {
            return (ULONG)(Vmcb->Control.NextRip - Vmcb->Save.Rip);
        }
    }
    /* Fallback: use the InsnLen field if available (decode assist) */
    if (Vmcb && Vmcb->Control.InsnLen > 0) {
        return (ULONG)Vmcb->Control.InsnLen;
    }
    /* Last resort: assume common instruction lengths */
    return 0;
}

static ULONG64 SvmOpsReadGuestPhysicalAddress(VOID)
{
    /* For NPF, exit_info_2 contains the faulting guest physical address */
    PVMCB Vmcb = SvmGetCurrentVmcb();
    return Vmcb ? Vmcb->Control.ExitInfo2 : 0;
}

static VOID SvmOpsAdvanceGuestRip(VOID)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (!Vmcb) return;

    if (g_SvmState.NripSaveSupported && Vmcb->Control.NextRip != 0) {
        /* Use NRIP Save for precise RIP advancement */
        Vmcb->Save.Rip = Vmcb->Control.NextRip;
    } else {
        /* Fallback: use instruction length from decode assist */
        ULONG Len = SvmOpsReadExitInstructionLength();
        if (Len > 0) {
            Vmcb->Save.Rip += Len;
        }
    }
}

static VOID SvmOpsInjectException(ULONG Vector, ULONG Type, BOOLEAN HasErrorCode, ULONG ErrorCode)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    ULONG EventInj;

    if (!Vmcb) return;

    EventInj = SVM_EVTINJ_VALID;
    EventInj |= (Vector & SVM_EVTINJ_VEC_MASK);
    EventInj |= (Type << SVM_EVTINJ_TYPE_SHIFT);

    if (HasErrorCode) {
        EventInj |= SVM_EVTINJ_VALID_ERR;
        Vmcb->Control.EventInjErr = ErrorCode;
    }

    Vmcb->Control.EventInj = EventInj;
}

static VOID SvmOpsInjectInterruptInfo(ULONG InfoField)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb) Vmcb->Control.EventInj = InfoField;
}

static VOID SvmOpsSetEntryInterruptionInfo(ULONG Info)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb) Vmcb->Control.EventInj = Info;
}

static VOID SvmOpsSetEntryExceptionErrorCode(ULONG ErrorCode)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb) Vmcb->Control.EventInjErr = ErrorCode;
}

static VOID SvmOpsSetEntryInstructionLength(ULONG Length)
{
    /* SVM doesn't have a separate instruction length field for entry */
    /* The NRIP save field handles this automatically */
    UNREFERENCED_PARAMETER(Length);
}

static NTSTATUS SvmOpsSetupPageTables(VOID)
{
    return NptInitialize();
}

static VOID SvmOpsCleanupPageTables(VOID)
{
    NptCleanup();
}

static VOID SvmOpsInvalidatePageTables(VOID)
{
    NptInvalidateAll();
}

static NTSTATUS SvmOpsHookFunction(ULONG64 TargetVa, PVOID HookFunc, PVOID *OrigFunc)
{
    return NptHookFunction(TargetVa, HookFunc, OrigFunc);
}

static NTSTATUS SvmOpsUnhookFunction(ULONG64 TargetVa)
{
    return NptUnhookFunction(TargetVa);
}

static VOID SvmOpsUnhookAll(VOID)
{
    NptUnhookAll();
}

static VOID SvmOpsEnableSingleStep(VOID)
{
    /*
     * AMD SVM doesn't have a direct MTF equivalent.
     * We simulate single-step by setting RFLAGS.TF and intercepting #DB.
     * The #DB exception is already intercepted for anti-anti-debug.
     */
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb) {
        Vmcb->Save.Rflags |= (1ULL << 8);  /* Set TF (Trap Flag) */
    }
}

static VOID SvmOpsDisableSingleStep(VOID)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb) {
        Vmcb->Save.Rflags &= ~(1ULL << 8);  /* Clear TF */
    }
}

static ULONG64 SvmOpsReadPrimaryProcControls(VOID)
{
    /* SVM doesn't have exact equivalent of primary proc controls.
     * Return the intercept field which serves a similar purpose. */
    PVMCB Vmcb = SvmGetCurrentVmcb();
    return Vmcb ? Vmcb->Control.Intercept : 0;
}

static VOID SvmOpsWritePrimaryProcControls(ULONG64 Value)
{
    PVMCB Vmcb = SvmGetCurrentVmcb();
    if (Vmcb) Vmcb->Control.Intercept = Value;
}

static PHV_CPU_CONTEXT SvmOpsGetCurrentCpuContext(VOID)
{
    PSVM_CPU_CONTEXT Ctx = SvmGetCurrentCpu();
    return Ctx ? &Ctx->Common : NULL;
}

/* ========================================================================= */
/*  HV_OPS Structure Registration                                            */
/* ========================================================================= */

HV_OPS g_SvmOps = {
    "AMD SVM",                              /* Name */
    CPU_VENDOR_AMD,                         /* Vendor */
    SvmOpsIsSupported,                      /* IsSupported */
    SvmOpsInitialize,                       /* Initialize */
    SvmOpsTerminate,                        /* Terminate */
    SvmOpsReadGuestRip,                     /* ReadGuestRip */
    SvmOpsWriteGuestRip,                    /* WriteGuestRip */
    SvmOpsReadGuestRsp,                     /* ReadGuestRsp */
    SvmOpsWriteGuestRsp,                    /* WriteGuestRsp */
    SvmOpsReadGuestCr3,                     /* ReadGuestCr3 */
    SvmOpsWriteGuestCr3,                    /* WriteGuestCr3 */
    SvmOpsReadGuestRflags,                  /* ReadGuestRflags */
    SvmOpsWriteGuestRflags,                 /* WriteGuestRflags */
    SvmOpsReadExitReason,                   /* ReadExitReason */
    SvmOpsReadExitQualification,            /* ReadExitQualification */
    SvmOpsReadExitInterruptionInfo,         /* ReadExitInterruptionInfo */
    SvmOpsReadExitInterruptionErrorCode,    /* ReadExitInterruptionErrorCode */
    SvmOpsReadExitInstructionLength,        /* ReadExitInstructionLength */
    SvmOpsReadGuestPhysicalAddress,         /* ReadGuestPhysicalAddress */
    SvmOpsAdvanceGuestRip,                  /* AdvanceGuestRip */
    SvmOpsInjectException,                  /* InjectException */
    SvmOpsInjectInterruptInfo,              /* InjectInterruptInfo */
    SvmOpsSetEntryInterruptionInfo,         /* SetEntryInterruptionInfo */
    SvmOpsSetEntryExceptionErrorCode,       /* SetEntryExceptionErrorCode */
    SvmOpsSetEntryInstructionLength,        /* SetEntryInstructionLength */
    SvmOpsSetupPageTables,                  /* SetupPageTables */
    SvmOpsCleanupPageTables,                /* CleanupPageTables */
    SvmOpsInvalidatePageTables,             /* InvalidatePageTables */
    SvmOpsHookFunction,                     /* HookFunction */
    SvmOpsUnhookFunction,                   /* UnhookFunction */
    SvmOpsUnhookAll,                        /* UnhookAll */
    SvmOpsEnableSingleStep,                 /* EnableSingleStep */
    SvmOpsDisableSingleStep,                /* DisableSingleStep */
    SvmOpsReadPrimaryProcControls,          /* ReadPrimaryProcControls */
    SvmOpsWritePrimaryProcControls,         /* WritePrimaryProcControls */
    SvmOpsGetCurrentCpuContext,             /* GetCurrentCpuContext */
};
