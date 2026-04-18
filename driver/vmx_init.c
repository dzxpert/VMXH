/*
 * vmx_init.c - VMX Anti-Anti-Debug Hypervisor
 * VMX initialization: VMXON, VMCS setup, per-CPU virtualization
 */

#include "vmx.h"
#include "ept.h"
#include "log.h"
#include "hv_ops.h"
#include "hv_detect.h"
#include "process.h"   /* AAD-BP: ProcessRegisterExceptionHideToggle */

/* ========================================================================= */
/*  Forward Declarations                                                     */
/* ========================================================================= */

static BOOLEAN  VmxCheckCapabilities(PVMX_STATE State);
static NTSTATUS VmxAllocateCpuContext(PVMX_CPU_CONTEXT CpuCtx, ULONG VmcsRevision);
static VOID     VmxFreeCpuContext(PVMX_CPU_CONTEXT CpuCtx);
static NTSTATUS VmxEnableOnCpu(PVMX_CPU_CONTEXT CpuCtx, PVMX_STATE State);
static VOID     VmxDisableOnCpu(PVMX_CPU_CONTEXT CpuCtx);
static ULONG    VmxAdjustControls(ULONG RequestedControls, ULONG64 Capability);

/* Segment descriptor parsing helpers */
static ULONG64  VmxGetSegmentBase(ULONG64 GdtBase, USHORT Selector);
static ULONG    VmxGetSegmentAccessRights(ULONG64 GdtBase, USHORT Selector);
static ULONG    VmxGetSegmentLimit(ULONG64 GdtBase, USHORT Selector);

/* DPC for per-CPU initialization */
typedef struct _VMX_DPC_CONTEXT {
    PVMX_STATE  State;
    NTSTATUS    Status;
    KEVENT      Event;
} VMX_DPC_CONTEXT, *PVMX_DPC_CONTEXT;

static VOID VmxInitDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2);
static VOID VmxTerminateDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2);

/* Per-CPU HV_CPU_CONTEXT array for VmxOpsGetCurrentCpuContext() */
static PHV_CPU_CONTEXT g_VmxHvCtx = NULL;

/* ========================================================================= */
/*  VMX Support Detection                                                    */
/* ========================================================================= */

BOOLEAN VmxIsSupported(VOID)
{
    int CpuInfo[4];
    ULONG64 FeatureControl;

    /* Check CPUID.1:ECX.VMX[bit 5] */
    __cpuid(CpuInfo, 1);
    if (!(CpuInfo[2] & (1 << CPUID_VMX_BIT))) {
        LOG_ERROR("CPU does not support VMX (CPUID.1:ECX[5] = 0)");
        return FALSE;
    }

    /* Check IA32_FEATURE_CONTROL MSR */
    FeatureControl = __readmsr(MSR_IA32_FEATURE_CONTROL);

    if (FeatureControl & FEATURE_CONTROL_LOCKED) {
        if (!(FeatureControl & FEATURE_CONTROL_VMXON_ENABLED)) {
            LOG_ERROR("VMX is locked out in BIOS (IA32_FEATURE_CONTROL)");
            return FALSE;
        }
    } else {
        /*
         * MSR not locked - we could lock it with VMXON enabled,
         * but it's better to require BIOS configuration
         */
        LOG_WARN("IA32_FEATURE_CONTROL not locked, BIOS may not have configured VMX");
    }

    return TRUE;
}

/* ========================================================================= */
/*  Capability Check                                                         */
/* ========================================================================= */

static BOOLEAN VmxCheckCapabilities(PVMX_STATE State)
{
    State->VmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
    State->VmcsRevisionId = (ULONG)(State->VmxBasic & 0x7FFFFFFF);
    State->TrueControlsSupported = (State->VmxBasic >> 55) & 1;

    LOG_INFO("VMCS Revision ID: 0x%08X", State->VmcsRevisionId);
    LOG_INFO("True controls supported: %s", State->TrueControlsSupported ? "YES" : "NO");

    /* Read capability MSRs */
    if (State->TrueControlsSupported) {
        State->TruePinBasedCap  = __readmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS);
        State->TrueProcBasedCap = __readmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
        State->TrueExitCap      = __readmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS);
        State->TrueEntryCap     = __readmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
    }

    State->PinBasedCap  = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
    State->ProcBasedCap = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
    State->ExitCap      = __readmsr(MSR_IA32_VMX_EXIT_CTLS);
    State->EntryCap     = __readmsr(MSR_IA32_VMX_ENTRY_CTLS);

    /* Check secondary controls support */
    if (VmxAdjustControls(PROC_BASED_SECONDARY_CONTROLS, State->ProcBasedCap)
        & PROC_BASED_SECONDARY_CONTROLS) {
        State->ProcBased2Cap = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
    }

    /* Check EPT/VPID support */
    State->EptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

    /* Verify required features */
    {
    ULONG SecondaryAdj = VmxAdjustControls(
        PROC_BASED2_ENABLE_EPT | PROC_BASED2_ENABLE_RDTSCP | PROC_BASED2_ENABLE_VPID,
        State->ProcBased2Cap
    );

    if (!(SecondaryAdj & PROC_BASED2_ENABLE_EPT)) {
        LOG_ERROR("EPT not supported - cannot continue");
        return FALSE;
    }

    LOG_INFO("EPT support: YES, VPID support: %s",
             (SecondaryAdj & PROC_BASED2_ENABLE_VPID) ? "YES" : "NO");
    }

    return TRUE;
}

/* ========================================================================= */
/*  Control Field Adjustment                                                 */
/* ========================================================================= */

/*
 * Adjust control fields per Intel SDM Vol. 3C, Section 31.5.1
 * Low 32 bits = allowed 0-settings (must-be-1)
 * High 32 bits = allowed 1-settings (can-be-1)
 */
static ULONG VmxAdjustControls(ULONG RequestedControls, ULONG64 Capability)
{
    ULONG Low  = (ULONG)(Capability & 0xFFFFFFFF);
    ULONG High = (ULONG)(Capability >> 32);

    RequestedControls |= Low;   /* Set required bits */
    RequestedControls &= High;  /* Clear unsupported bits */

    return RequestedControls;
}

/* ========================================================================= */
/*  Memory Allocation                                                        */
/* ========================================================================= */

static PVOID VmxAllocateAlignedMemory(SIZE_T Size, ULONG64 *PhysicalAddress)
{
    PHYSICAL_ADDRESS HighAddr, LowAddr, BoundaryAddr;
    PVOID VirtualAddr;

    LowAddr.QuadPart = 0;
    HighAddr.QuadPart = ~0ULL;
    BoundaryAddr.QuadPart = PAGE_SIZE_4KB;

    VirtualAddr = MmAllocateContiguousMemorySpecifyCache(
        Size,
        LowAddr,
        HighAddr,
        BoundaryAddr,
        MmCached
    );

    if (VirtualAddr) {
        PHYSICAL_ADDRESS PhysAddr;
        RtlZeroMemory(VirtualAddr, Size);
        PhysAddr = MmGetPhysicalAddress(VirtualAddr);
        *PhysicalAddress = PhysAddr.QuadPart;
    }

    return VirtualAddr;
}

static NTSTATUS VmxAllocateCpuContext(PVMX_CPU_CONTEXT CpuCtx, ULONG VmcsRevision)
{
    /* VMXON Region */
    CpuCtx->VmxonRegionVa = VmxAllocateAlignedMemory(PAGE_SIZE_4KB, &CpuCtx->VmxonRegionPa);
    if (!CpuCtx->VmxonRegionVa) {
        LOG_ERROR("Failed to allocate VMXON region for CPU %u", CpuCtx->ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    *(PULONG)CpuCtx->VmxonRegionVa = VmcsRevision;

    /* VMCS Region */
    CpuCtx->VmcsRegionVa = VmxAllocateAlignedMemory(PAGE_SIZE_4KB, &CpuCtx->VmcsRegionPa);
    if (!CpuCtx->VmcsRegionVa) {
        LOG_ERROR("Failed to allocate VMCS region for CPU %u", CpuCtx->ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    *(PULONG)CpuCtx->VmcsRegionVa = VmcsRevision;

    /* MSR Bitmap */
    CpuCtx->MsrBitmapVa = VmxAllocateAlignedMemory(PAGE_SIZE_4KB, &CpuCtx->MsrBitmapPa);
    if (!CpuCtx->MsrBitmapVa) {
        LOG_ERROR("Failed to allocate MSR bitmap for CPU %u", CpuCtx->ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* I/O Bitmaps A and B (4KB each, initialized to all zeros = no I/O VM-Exit).
     * When USE_IO_BITMAPS is enabled together with UNCONDITIONAL_IO_EXIT,
     * the bitmap takes precedence: only ports with bit=1 cause VM-Exit.
     * All zeros = no I/O exits. */
    CpuCtx->IoBitmapAVa = VmxAllocateAlignedMemory(PAGE_SIZE_4KB, &CpuCtx->IoBitmapAPa);
    if (!CpuCtx->IoBitmapAVa) {
        LOG_ERROR("Failed to allocate I/O bitmap A for CPU %u", CpuCtx->ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    CpuCtx->IoBitmapBVa = VmxAllocateAlignedMemory(PAGE_SIZE_4KB, &CpuCtx->IoBitmapBPa);
    if (!CpuCtx->IoBitmapBVa) {
        LOG_ERROR("Failed to allocate I/O bitmap B for CPU %u", CpuCtx->ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Host Stack (32KB) — increased from 16KB for safety margin.
     * Normal VM-Exit handler uses ~2-4KB, but deep call chains (EPT violation →
     * hook lookup → logging) and unoptimized builds can use significantly more.
     * NBP uses 64KB; 32KB is a conservative middle ground.
     * Cost: 16KB extra per CPU (e.g., 2 CPUs = 32KB total increase). */
    CpuCtx->HostStackSize = 8 * PAGE_SIZE_4KB;
    CpuCtx->HostStackBase = ExAllocatePoolWithTag(
        NonPagedPool,
        CpuCtx->HostStackSize,
        VMX_TAG
    );
    if (!CpuCtx->HostStackBase) {
        LOG_ERROR("Failed to allocate host stack for CPU %u", CpuCtx->ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(CpuCtx->HostStackBase, CpuCtx->HostStackSize);

    return STATUS_SUCCESS;
}

static VOID VmxFreeCpuContext(PVMX_CPU_CONTEXT CpuCtx)
{
    if (CpuCtx->VmxonRegionVa) {
        MmFreeContiguousMemory(CpuCtx->VmxonRegionVa);
        CpuCtx->VmxonRegionVa = NULL;
    }
    if (CpuCtx->VmcsRegionVa) {
        MmFreeContiguousMemory(CpuCtx->VmcsRegionVa);
        CpuCtx->VmcsRegionVa = NULL;
    }
    if (CpuCtx->MsrBitmapVa) {
        MmFreeContiguousMemory(CpuCtx->MsrBitmapVa);
        CpuCtx->MsrBitmapVa = NULL;
    }
    if (CpuCtx->HostStackBase) {
        ExFreePoolWithTag(CpuCtx->HostStackBase, VMX_TAG);
        CpuCtx->HostStackBase = NULL;
    }
}

/* ========================================================================= */
/*  Segment Descriptor Parsing                                               */
/* ========================================================================= */

static ULONG64 VmxGetSegmentBase(ULONG64 GdtBase, USHORT Selector)
{
    PGDT_ENTRY  Entry;
    ULONG64     Base;
    USHORT      Index;

    if (Selector == 0 || (Selector & 0xFFF8) == 0) {
        return 0;
    }

    Index = (Selector >> 3);
    Entry = (PGDT_ENTRY)(GdtBase + Index * 8);

    Base = Entry->BaseLow | ((ULONG64)Entry->BaseMid << 16) | ((ULONG64)Entry->BaseHigh << 24);

    /* System segment (TSS, LDT) in 64-bit mode uses 16-byte descriptor */
    if (!(Entry->Access & 0x10)) {  /* S bit = 0 means system descriptor */
        PGDT_ENTRY64 Entry64 = (PGDT_ENTRY64)Entry;
        Base |= ((ULONG64)Entry64->BaseUpper << 32);
    }

    return Base;
}

static ULONG VmxGetSegmentAccessRights(ULONG64 GdtBase, USHORT Selector)
{
    PGDT_ENTRY  Entry;
    ULONG       AccessRights;
    USHORT      Index;

    if (Selector == 0 || (Selector & 0xFFF8) == 0) {
        return 0x10000;  /* Unusable segment */
    }

    Index = (Selector >> 3);
    Entry = (PGDT_ENTRY)(GdtBase + Index * 8);

    /*
     * VMCS access rights format (Intel SDM Vol. 3C, Table 24-2):
     * Bits 3:0   = Type
     * Bit 4      = S (descriptor type)
     * Bits 6:5   = DPL
     * Bit 7      = P (present)
     * Bits 11:8  = reserved (0)
     * Bit 12     = AVL
     * Bit 13     = L (64-bit mode)
     * Bit 14     = D/B
     * Bit 15     = G (granularity)
     * Bit 16     = Unusable
     */
    AccessRights = Entry->Access & 0xFF;                          /* Type, S, DPL, P */
    AccessRights |= ((Entry->LimitHighAndFlags >> 4) & 0xF) << 12; /* AVL, L, D/B, G */

    return AccessRights;
}

static ULONG VmxGetSegmentLimit(ULONG64 GdtBase, USHORT Selector)
{
    PGDT_ENTRY  Entry;
    ULONG       Limit;
    USHORT      Index;

    if (Selector == 0 || (Selector & 0xFFF8) == 0) {
        return 0;
    }

    Index = (Selector >> 3);
    Entry = (PGDT_ENTRY)(GdtBase + Index * 8);

    Limit = Entry->LimitLow | ((ULONG)(Entry->LimitHighAndFlags & 0x0F) << 16);

    /* If granularity bit is set, limit is in 4KB pages */
    if (Entry->LimitHighAndFlags & 0x80) {
        Limit = (Limit << 12) | 0xFFF;
    }

    return Limit;
}

/* ========================================================================= */
/*  VMCS Setup                                                               */
/* ========================================================================= */

NTSTATUS VmxSetupVmcs(PVMX_CPU_CONTEXT CpuCtx, PVMX_STATE State)
{
    ULONG       PinBased, ProcBased, ProcBased2, ExitCtls, EntryCtls;
    ULONG64     GdtBase, IdtBase;
    USHORT      Cs, Ss, Ds, Es, Fs, Gs, Tr, Ldtr;
    ULONG64     Cr0, Cr3, Cr4;
    ULONG64     Rflags;
    NTSTATUS    Status;

    /* Clear VMCS */
    if (__vmx_vmclear(&CpuCtx->VmcsRegionPa) != 0) {
        LOG_ERROR("VMCLEAR failed for CPU %u", CpuCtx->ProcessorNumber);
        return STATUS_UNSUCCESSFUL;
    }

    /* Load VMCS */
    if (__vmx_vmptrld(&CpuCtx->VmcsRegionPa) != 0) {
        LOG_ERROR("VMPTRLD failed for CPU %u", CpuCtx->ProcessorNumber);
        return STATUS_UNSUCCESSFUL;
    }

    LOG_INFO("VmxSetupVmcs: starting on CPU %u", CpuCtx->ProcessorNumber);

    /* ===== Read current CPU state ===== */
    GdtBase = AsmGetGdtBase();
    IdtBase = AsmGetIdtBase();
    Cs = AsmGetCs();
    Ss = AsmGetSs();
    Ds = AsmGetDs();
    Es = AsmGetEs();
    Fs = AsmGetFs();
    Gs = AsmGetGs();
    Tr = AsmGetTr();
    Ldtr = AsmGetLdtr();
    Cr0 = __readcr0();
    Cr3 = __readcr3();
    Cr4 = __readcr4();
    Rflags = AsmGetRflags();

    /* ===== VM-Execution Controls ===== */

    /* Pin-Based Controls
     *
     * We do NOT request PIN_BASED_EXTERNAL_INT_EXIT — in a Blue Pill hypervisor,
     * external interrupts should be delivered directly to the Guest via Guest IDT.
     *
     * NMI_EXIT: Requested for WinDbg Ctrl+Break support and proper NMI
     * blocking semantics.
     */
    PinBased = VmxAdjustControls(
        PIN_BASED_NMI_EXIT,
        State->TrueControlsSupported ? State->TruePinBasedCap : State->PinBasedCap
    );

    VmxWrite(VMCS_CTRL_PIN_BASED_VM_EXEC, PinBased);

    /* Primary Processor-Based Controls */
    {
        ULONG RequestedProcBased =
            PROC_BASED_USE_MSR_BITMAPS |
            PROC_BASED_USE_IO_BITMAPS |         /* I/O bitmap controls which ports trigger VM-Exit.
                                                 * All zeros = no I/O exits. */
            PROC_BASED_SECONDARY_CONTROLS |
            PROC_BASED_CR3_LOAD_EXIT |           /* Needed for process switch tracking */
            PROC_BASED_MOV_DR_EXIT |             /* Needed for anti-debug DR spoofing */
            PROC_BASED_USE_TSC_OFFSETTING;      /* Use hardware TSC Offset (no VM-Exit) */

        ProcBased = VmxAdjustControls(
            RequestedProcBased,
            State->TrueControlsSupported ? State->TrueProcBasedCap : State->ProcBasedCap
        );

        /*
         * DIAGNOSTIC: Log which bits were force-enabled by must-be-1 bits.
         */
        {
            ULONG ForcedBits = ProcBased & ~RequestedProcBased;
            if (ForcedBits) {
                LOG_WARN("CPU %u: Primary ProcBased forced bits: 0x%08X (final: 0x%08X)",
                         CpuCtx->ProcessorNumber, ForcedBits, ProcBased);
                if (ForcedBits & PROC_BASED_UNCONDITIONAL_IO_EXIT)
                    LOG_WARN("  -> UNCONDITIONAL_IO_EXIT forced ON");
                if (ForcedBits & PROC_BASED_HLT_EXIT)
                    LOG_WARN("  -> HLT_EXIT forced ON");
                if (ForcedBits & PROC_BASED_MWAIT_EXIT)
                    LOG_WARN("  -> MWAIT_EXIT forced ON");
                if (ForcedBits & PROC_BASED_MONITOR_EXIT)
                    LOG_WARN("  -> MONITOR_EXIT forced ON");
                if (ForcedBits & PROC_BASED_PAUSE_EXIT)
                    LOG_WARN("  -> PAUSE_EXIT forced ON");
                if (ForcedBits & PROC_BASED_RDPMC_EXIT)
                    LOG_WARN("  -> RDPMC_EXIT forced ON");
                if (ForcedBits & PROC_BASED_INVLPG_EXIT)
                    LOG_WARN("  -> INVLPG_EXIT forced ON");
                if (ForcedBits & PROC_BASED_MOV_DR_EXIT)
                    LOG_WARN("  -> MOV_DR_EXIT forced ON (will cause DR access VM-Exit storm!)");
                if (ForcedBits & PROC_BASED_CR3_STORE_EXIT)
                    LOG_WARN("  -> CR3_STORE_EXIT forced ON");
            }
        }
    }
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: ProcBased written\n",
               CpuCtx->ProcessorNumber);

    /* Secondary Processor-Based Controls */
    {
        ULONG RequestedProcBased2 =
            PROC_BASED2_ENABLE_EPT |
            PROC_BASED2_ENABLE_RDTSCP |
            PROC_BASED2_ENABLE_VPID |
            PROC_BASED2_ENABLE_INVPCID |
            PROC_BASED2_ENABLE_XSAVES;      /* Allow guest XSAVES/XRSTORS (used by SwapContext) */

        ProcBased2 = VmxAdjustControls(
            RequestedProcBased2,
            State->ProcBased2Cap
        );

        /*
         * DIAGNOSTIC: Log forced secondary proc-based bits.
         */
        {
            ULONG ForcedBits2 = ProcBased2 & ~RequestedProcBased2;
            if (ForcedBits2) {
                LOG_WARN("CPU %u: Secondary ProcBased2 forced bits: 0x%08X (final: 0x%08X)",
                         CpuCtx->ProcessorNumber, ForcedBits2, ProcBased2);
                if (ForcedBits2 & PROC_BASED2_DESC_TABLE_EXIT)
                    LOG_WARN("  -> DESC_TABLE_EXIT forced ON (LGDT/LIDT/LLDT/LTR will VM-Exit!)");
                if (ForcedBits2 & PROC_BASED2_WBINVD_EXIT)
                    LOG_WARN("  -> WBINVD_EXIT forced ON");
                if (ForcedBits2 & PROC_BASED2_VIRT_APIC_ACCESS)
                    LOG_WARN("  -> VIRT_APIC_ACCESS forced ON");
                if (ForcedBits2 & PROC_BASED2_RDRAND_EXIT)
                    LOG_WARN("  -> RDRAND_EXIT forced ON");
                if (ForcedBits2 & PROC_BASED2_RDSEED_EXIT)
                    LOG_WARN("  -> RDSEED_EXIT forced ON");
            }
        }
    }
    VmxWrite(VMCS_CTRL_SECONDARY_VM_EXEC, ProcBased2);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: Secondary written (0x%08X)\n",
               CpuCtx->ProcessorNumber, ProcBased2);

    if (!(ProcBased2 & PROC_BASED2_ENABLE_XSAVES)) {
        LOG_WARN("ENABLE_XSAVES not supported - guest XSAVES/XRSTORS may #UD");
    }

    /* Exception Bitmap: no exceptions intercepted for now.
     *
     * #DB and #BP interception is only needed for anti-anti-debug exception
     * normalization (AadHandleException). Enable (EXCEPTION_BITMAP_DB |
     * EXCEPTION_BITMAP_BP) when anti-debug features are being tested.
     */
    VmxWrite(VMCS_CTRL_EXCEPTION_BITMAP, 0);

    /* MSR Bitmap — initialize interception bits then write the PA */
    {
        extern VOID MsrBitmapInitialize(PVOID MsrBitmap);
        MsrBitmapInitialize(CpuCtx->MsrBitmapVa);
    }
    VmxWrite(VMCS_CTRL_MSR_BITMAP, CpuCtx->MsrBitmapPa);

    /* I/O Bitmaps A and B — physical addresses of the 4KB pages.
     * Both bitmaps are all zeros (set during allocation by VmxAllocateAlignedMemory),
     * meaning no I/O port will trigger a VM-Exit. */
    VmxWrite(VMCS_CTRL_IO_BITMAP_A, CpuCtx->IoBitmapAPa);
    VmxWrite(VMCS_CTRL_IO_BITMAP_B, CpuCtx->IoBitmapBPa);
    LOG_INFO("CPU %u: I/O bitmaps configured (A PA=0x%llX, B PA=0x%llX) - all zeros, no I/O exits",
             CpuCtx->ProcessorNumber, CpuCtx->IoBitmapAPa, CpuCtx->IoBitmapBPa);

    /* VPID - use processor number + 1 (VPID 0 is reserved for host) */
    VmxWrite(VMCS_CTRL_VPID, CpuCtx->ProcessorNumber + 1);

    /* XSS-Exiting Bitmap: 0 = don't intercept any XSAVES/XRSTORS components */
    if (ProcBased2 & PROC_BASED2_ENABLE_XSAVES) {
        VmxWrite(VMCS_CTRL_XSS_EXITING_BITMAP, 0);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: Bitmaps+VPID+XSS done\n",
               CpuCtx->ProcessorNumber);

    /* EPT Pointer - will be set when EPT is initialized */
    /* For now, set up identity-mapped EPT */
    Status = EptSetupIdentityMap(CpuCtx, State);
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("EPT setup failed for CPU %u", CpuCtx->ProcessorNumber);
        return Status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: EPT identity map done\n",
               CpuCtx->ProcessorNumber);

    LOG_INFO("CPU %u: VMCS controls + EPT done", CpuCtx->ProcessorNumber);

    /* CR0/CR4 guest/host masks and read shadows */

    /*
     * CR0 Guest-Host Mask: intercept writes to VMX-restricted bits.
     *
     * VMX requires certain CR0 bits to match MSR_IA32_VMX_CR0_FIXED0/FIXED1.
     * If the Guest directly modifies these bits (MOV CR0) without going through
     * our handler, the value may violate Fixed Bit constraints, causing the
     * next VM-Entry to fail.
     *
     * By setting the Mask to CR0_FIXED0 (bits that must be 1), any Guest write
     * that touches these bits triggers a VM-Exit → HandleCrAccess applies
     * Fixed0/Fixed1 adjustment before writing to VMCS Guest CR0.
     *
     * ReadShadow stores the Guest's view of the masked bits so that MOV-from-CR0
     * returns the value the Guest expects (before VMX adjustment).
     */
    {
        ULONG64 Cr0Fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
        VmxWrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, Cr0Fixed0);
        VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, Cr0 & Cr0Fixed0);
    }
    VmxWrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMXE);  /* Hide VMXE from guest */
    VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, Cr4 & ~CR4_VMXE);

    /* TSC Offset */
    VmxWrite(VMCS_CTRL_TSC_OFFSET, 0);

    /* ===== VM-Exit Controls ===== */
    ExitCtls = VmxAdjustControls(
        VMEXIT_HOST_ADDR_SPACE_SIZE | VMEXIT_SAVE_IA32_EFER | VMEXIT_LOAD_IA32_EFER,
        State->TrueControlsSupported ? State->TrueExitCap : State->ExitCap
    );
    VmxWrite(VMCS_CTRL_VMEXIT_CONTROLS, ExitCtls);
    VmxWrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    VmxWrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);

    /* ===== VM-Entry Controls ===== */
    EntryCtls = VmxAdjustControls(
        VMENTRY_IA32E_MODE_GUEST |          /* 64-bit guest */
        VMENTRY_LOAD_IA32_EFER,
        State->TrueControlsSupported ? State->TrueEntryCap : State->EntryCap
    );
    VmxWrite(VMCS_CTRL_VMENTRY_CONTROLS, EntryCtls);
    VmxWrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: Exit+Entry controls done\n",
               CpuCtx->ProcessorNumber);

    /* ===== Guest State ===== */

    /* Segment registers */
    VmxWrite(VMCS_GUEST_CS_SEL, Cs);
    VmxWrite(VMCS_GUEST_CS_BASE, VmxGetSegmentBase(GdtBase, Cs));
    VmxWrite(VMCS_GUEST_CS_LIMIT, VmxGetSegmentLimit(GdtBase, Cs));
    VmxWrite(VMCS_GUEST_CS_ACCESS_RIGHTS, VmxGetSegmentAccessRights(GdtBase, Cs));

    VmxWrite(VMCS_GUEST_SS_SEL, Ss);
    VmxWrite(VMCS_GUEST_SS_BASE, VmxGetSegmentBase(GdtBase, Ss));
    VmxWrite(VMCS_GUEST_SS_LIMIT, VmxGetSegmentLimit(GdtBase, Ss));
    VmxWrite(VMCS_GUEST_SS_ACCESS_RIGHTS, VmxGetSegmentAccessRights(GdtBase, Ss));

    VmxWrite(VMCS_GUEST_DS_SEL, Ds);
    VmxWrite(VMCS_GUEST_DS_BASE, VmxGetSegmentBase(GdtBase, Ds));
    VmxWrite(VMCS_GUEST_DS_LIMIT, VmxGetSegmentLimit(GdtBase, Ds));
    VmxWrite(VMCS_GUEST_DS_ACCESS_RIGHTS, VmxGetSegmentAccessRights(GdtBase, Ds));

    VmxWrite(VMCS_GUEST_ES_SEL, Es);
    VmxWrite(VMCS_GUEST_ES_BASE, VmxGetSegmentBase(GdtBase, Es));
    VmxWrite(VMCS_GUEST_ES_LIMIT, VmxGetSegmentLimit(GdtBase, Es));
    VmxWrite(VMCS_GUEST_ES_ACCESS_RIGHTS, VmxGetSegmentAccessRights(GdtBase, Es));

    VmxWrite(VMCS_GUEST_FS_SEL, Fs);
    VmxWrite(VMCS_GUEST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
    VmxWrite(VMCS_GUEST_FS_LIMIT, VmxGetSegmentLimit(GdtBase, Fs));
    VmxWrite(VMCS_GUEST_FS_ACCESS_RIGHTS, VmxGetSegmentAccessRights(GdtBase, Fs));

    VmxWrite(VMCS_GUEST_GS_SEL, Gs);
    VmxWrite(VMCS_GUEST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
    VmxWrite(VMCS_GUEST_GS_LIMIT, VmxGetSegmentLimit(GdtBase, Gs));
    VmxWrite(VMCS_GUEST_GS_ACCESS_RIGHTS, VmxGetSegmentAccessRights(GdtBase, Gs));

    VmxWrite(VMCS_GUEST_TR_SEL, Tr);
    VmxWrite(VMCS_GUEST_TR_BASE, VmxGetSegmentBase(GdtBase, Tr));
    VmxWrite(VMCS_GUEST_TR_LIMIT, VmxGetSegmentLimit(GdtBase, Tr));
    VmxWrite(VMCS_GUEST_TR_ACCESS_RIGHTS, VmxGetSegmentAccessRights(GdtBase, Tr));

    VmxWrite(VMCS_GUEST_LDTR_SEL, Ldtr);
    VmxWrite(VMCS_GUEST_LDTR_BASE, VmxGetSegmentBase(GdtBase, Ldtr));
    VmxWrite(VMCS_GUEST_LDTR_LIMIT, VmxGetSegmentLimit(GdtBase, Ldtr));
    VmxWrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, VmxGetSegmentAccessRights(GdtBase, Ldtr));

    /* Control registers */
    VmxWrite(VMCS_GUEST_CR0, Cr0);
    VmxWrite(VMCS_GUEST_CR3, Cr3);
    VmxWrite(VMCS_GUEST_CR4, Cr4);

    /* Descriptor tables */
    VmxWrite(VMCS_GUEST_GDTR_BASE, GdtBase);
    VmxWrite(VMCS_GUEST_GDTR_LIMIT, AsmGetGdtLimit());
    VmxWrite(VMCS_GUEST_IDTR_BASE, IdtBase);
    VmxWrite(VMCS_GUEST_IDTR_LIMIT, AsmGetIdtLimit());

    /* Debug registers */
    VmxWrite(VMCS_GUEST_DR7, __readdr(7));

    /* RSP and RIP will be set just before VMLAUNCH */
    VmxWrite(VMCS_GUEST_RFLAGS, Rflags);

    /* MSRs */
    VmxWrite(VMCS_GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL));
    VmxWrite(VMCS_GUEST_IA32_EFER, __readmsr(MSR_IA32_EFER));
    VmxWrite(VMCS_GUEST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    VmxWrite(VMCS_GUEST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    VmxWrite(VMCS_GUEST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    /* IA32_XSS: required when ENABLE_XSAVES is set in secondary controls */
    if (ProcBased2 & PROC_BASED2_ENABLE_XSAVES) {
        VmxWrite(VMCS_GUEST_IA32_XSS, __readmsr(MSR_IA32_XSS));
    }

    /* Other guest state */
    VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 0);     /* Active */
    VmxWrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
    VmxWrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, 0);
    VmxWrite(VMCS_GUEST_VMCS_LINK_PTR, 0xFFFFFFFFFFFFFFFF);

    LOG_INFO("CPU %u: Guest state done", CpuCtx->ProcessorNumber);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: Guest state done\n",
               CpuCtx->ProcessorNumber);

    /* ===== Host State ===== */

    VmxWrite(VMCS_HOST_CR0, Cr0);
    VmxWrite(VMCS_HOST_CR3, Cr3);
    VmxWrite(VMCS_HOST_CR4, Cr4);

    /* Host segments (RPL must be 0) */
    VmxWrite(VMCS_HOST_CS_SEL, Cs & 0xFFF8);
    VmxWrite(VMCS_HOST_SS_SEL, Ss & 0xFFF8);
    VmxWrite(VMCS_HOST_DS_SEL, Ds & 0xFFF8);
    VmxWrite(VMCS_HOST_ES_SEL, Es & 0xFFF8);
    VmxWrite(VMCS_HOST_FS_SEL, Fs & 0xFFF8);
    VmxWrite(VMCS_HOST_GS_SEL, Gs & 0xFFF8);
    VmxWrite(VMCS_HOST_TR_SEL, Tr & 0xFFF8);

    /* Host base addresses */
    VmxWrite(VMCS_HOST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
    VmxWrite(VMCS_HOST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
    VmxWrite(VMCS_HOST_TR_BASE, VmxGetSegmentBase(GdtBase, Tr));
    VmxWrite(VMCS_HOST_GDTR_BASE, GdtBase);
    VmxWrite(VMCS_HOST_IDTR_BASE, IdtBase);

    /* Host MSRs */
    VmxWrite(VMCS_HOST_IA32_EFER, __readmsr(MSR_IA32_EFER));
    VmxWrite(VMCS_HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    VmxWrite(VMCS_HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    VmxWrite(VMCS_HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    /* Host IA32_XSS: required when ENABLE_XSAVES is set */
    if (ProcBased2 & PROC_BASED2_ENABLE_XSAVES) {
        VmxWrite(VMCS_HOST_IA32_XSS, __readmsr(MSR_IA32_XSS));
    }

    /* Host RSP: top of the host stack, 16-byte aligned.
     * x64 ABI requires RSP % 16 == 0 before CALL. VM-Exit delivers RSP directly,
     * so we must ensure it's properly aligned from the start. The -8 simulates
     * a "return address push" so that after sub rsp,N in the handler, the
     * CALL VmxExitHandler has RSP % 16 == 0.
     */
    {
        ULONG64 StackTop = (ULONG64)CpuCtx->HostStackBase + CpuCtx->HostStackSize;
        StackTop &= ~0xFULL;   /* Align down to 16 bytes */
        StackTop -= 8;         /* Simulate pushed return address (mod 16 = 8) */
        VmxWrite(VMCS_HOST_RSP, StackTop);
    }

    /* Host RIP: VM-Exit handler entry point */
    VmxWrite(VMCS_HOST_RIP, (ULONG64)AsmVmxExitHandler);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: Host state done, VMCS complete\n",
               CpuCtx->ProcessorNumber);

    LOG_INFO("VMCS setup complete for CPU %u", CpuCtx->ProcessorNumber);
    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  Per-CPU VMX Enable/Disable                                               */
/* ========================================================================= */

static NTSTATUS VmxEnableOnCpu(PVMX_CPU_CONTEXT CpuCtx, PVMX_STATE State)
{
    ULONG64 Cr4;
    ULONG64 VmxonPa;
    ULONG64 Cr0;

    /* Set CR4.VMXE */
    CpuCtx->OriginalCr4 = __readcr4();
    Cr4 = CpuCtx->OriginalCr4 | CR4_VMXE;
    __writecr4(Cr4);

    /* Adjust CR0 to satisfy VMX fixed bits */
    Cr0 = __readcr0();
    Cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    Cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    __writecr0(Cr0);

    /* VMXON */
    VmxonPa = CpuCtx->VmxonRegionPa;
    if (__vmx_on(&VmxonPa) != 0) {
        LOG_ERROR("VMXON failed on CPU %u", CpuCtx->ProcessorNumber);
        __writecr4(CpuCtx->OriginalCr4);
        return STATUS_UNSUCCESSFUL;
    }

    CpuCtx->VmxEnabled = TRUE;
    LOG_INFO("VMXON succeeded on CPU %u", CpuCtx->ProcessorNumber);

    return STATUS_SUCCESS;
}

static VOID VmxDisableOnCpu(PVMX_CPU_CONTEXT CpuCtx)
{
    if (CpuCtx->VmxEnabled) {
        /*
         * Only execute vmxoff if the guest was never fully launched
         * (VMXON succeeded but VMLAUNCH wasn't done or failed).
         * If VmcsLaunched was TRUE, vmxoff was already executed by the
         * VmxShutdown ASM path during VMCALL-based termination.
         */
        if (!CpuCtx->VmcsLaunched) {
            __vmx_off();
        }
        __writecr4(CpuCtx->OriginalCr4);
        CpuCtx->VmxEnabled = FALSE;
        CpuCtx->VmcsLaunched = FALSE;
        LOG_INFO("VMX disabled on CPU %u", CpuCtx->ProcessorNumber);
    }
}

/* ========================================================================= */
/*  DPC Routines for Per-CPU Execution                                       */
/* ========================================================================= */

static VOID VmxInitDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    PVMX_DPC_CONTEXT    DpcCtx = (PVMX_DPC_CONTEXT)Context;
    ULONG               CpuNum = KeGetCurrentProcessorNumber();
    PVMX_CPU_CONTEXT    CpuCtx;
    NTSTATUS            Status;
    UCHAR               VmLaunchResult;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    CpuCtx = &DpcCtx->State->CpuContexts[CpuNum];

    /* Enable VMX */
    Status = VmxEnableOnCpu(CpuCtx, DpcCtx->State);
    if (!NT_SUCCESS(Status)) {
        DpcCtx->Status = Status;
        KeSetEvent(&DpcCtx->Event, IO_NO_INCREMENT, FALSE);
        return;
    }

    /* Setup VMCS */
    Status = VmxSetupVmcs(CpuCtx, DpcCtx->State);
    if (!NT_SUCCESS(Status)) {
        VmxDisableOnCpu(CpuCtx);
        DpcCtx->Status = Status;
        KeSetEvent(&DpcCtx->Event, IO_NO_INCREMENT, FALSE);
        return;
    }

    /*
     * VMLAUNCH via assembly helper.
     *
     * AsmVmxLaunch will:
     *   1. Save non-volatile registers
     *   2. Write Guest RSP = current RSP, Guest RIP = success label address
     *   3. Execute VMLAUNCH
     *   4. If successful, CPU enters guest mode and resumes from success label
     *   5. Returns 0 on success, 1 on failure
     *
     * On success, execution continues at the next line after AsmVmxLaunch()
     * because AsmVmxLaunch sets Guest RIP to the return-success path.
     */
    LOG_INFO("CPU %u: About to VMLAUNCH...", CpuNum);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: >>> VMLAUNCH NOW <<<\n", CpuNum);
    VmLaunchResult = AsmVmxLaunch();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: <<< VMLAUNCH returned %u >>>\n",
               CpuNum, (ULONG)VmLaunchResult);
    LOG_INFO("CPU %u: VMLAUNCH returned %u", CpuNum, (ULONG)VmLaunchResult);

    if (VmLaunchResult != 0) {
        /* VMLAUNCH failed */
        LOG_ERROR("VMLAUNCH failed on CPU %u, result=%u", CpuNum, (ULONG)VmLaunchResult);
        VmxDisableOnCpu(CpuCtx);
        DpcCtx->Status = STATUS_UNSUCCESSFUL;
        KeSetEvent(&DpcCtx->Event, IO_NO_INCREMENT, FALSE);
        return;
    }

    /* Success - we're now running as a guest! */
    CpuCtx->VmcsLaunched = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: DPC signaling Event (SUCCESS)\n", CpuNum);
    DpcCtx->Status = STATUS_SUCCESS;
    KeSetEvent(&DpcCtx->Event, IO_NO_INCREMENT, FALSE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[VMXToolbox] CHECKPOINT CPU %u: DPC KeSetEvent DONE, DPC returning\n", CpuNum);
}

static VOID VmxTerminateDpcRoutine(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    PVMX_DPC_CONTEXT    DpcCtx = (PVMX_DPC_CONTEXT)Context;
    ULONG               CpuNum = KeGetCurrentProcessorNumber();
    PVMX_CPU_CONTEXT    CpuCtx;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    CpuCtx = &DpcCtx->State->CpuContexts[CpuNum];

    /*
     * Issue VMCALL to request VMX shutdown.
     * HandleVmcall returns FALSE → AsmVmxExitHandler's VmxShutdown path
     * executes vmxoff and restores guest state, returning here.
     *
     * After VmxShutdown: CPU is no longer in VMX operation (vmxoff done).
     * We must NOT call VmxDisableOnCpu which would try __vmx_off() again
     * (causing #UD). Just restore CR4 to clear VMXE and update flags.
     */
    if (CpuCtx->VmcsLaunched) {
        /* M-6: pass the per-boot nonce in RCX so the handler can auth us. */
        AsmVmxVmcall2(VMCALL_MAGIC_SHUTDOWN, g_VmcallShutdownNonce);

        /* vmxoff already executed by VmxShutdown ASM path.
         * Just restore original CR4 (clears VMXE) and update flags. */
        __writecr4(CpuCtx->OriginalCr4);
        CpuCtx->VmxEnabled = FALSE;
        CpuCtx->VmcsLaunched = FALSE;
        LOG_INFO("VMX shutdown complete on CPU %u", CpuNum);
    } else {
        /* CPU was never launched or already exited VMX (VM-Entry failure).
         * Still need to clean up VMXON state if VmxEnabled. */
        VmxDisableOnCpu(CpuCtx);
    }

    KeSetEvent(&DpcCtx->Event, IO_NO_INCREMENT, FALSE);
}

/* ========================================================================= */
/*  Public Interface                                                         */
/* ========================================================================= */

NTSTATUS VmxInitialize(PVMX_STATE State)
{
    NTSTATUS    Status;
    ULONG       i, j;
    ULONG       CpuCount;

    if (State->Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(State, sizeof(VMX_STATE));
    CpuCount = KeQueryActiveProcessorCount(NULL);
    State->CpuCount = CpuCount;

    /* Set the global processor count (used for bounds checks everywhere) */
    g_MaxProcessors = CpuCount;

    LOG_INFO("Initializing VMX on %u processors", CpuCount);

    /* Dynamically allocate per-CPU context array */
    State->CpuContexts = (PVMX_CPU_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool,
        CpuCount * sizeof(VMX_CPU_CONTEXT),
        'xmvC');
    if (!State->CpuContexts) {
        LOG_ERROR("Failed to allocate VMX CPU contexts for %u CPUs", CpuCount);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(State->CpuContexts, CpuCount * sizeof(VMX_CPU_CONTEXT));

    /* Check capabilities */
    if (!VmxCheckCapabilities(State)) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Allocate per-CPU structures */
    for (i = 0; i < CpuCount; i++) {
        State->CpuContexts[i].ProcessorNumber = i;
        Status = VmxAllocateCpuContext(&State->CpuContexts[i], State->VmcsRevisionId);
        if (!NT_SUCCESS(Status)) {
            /* Cleanup already allocated */
            for (j = 0; j < i; j++) {
                VmxFreeCpuContext(&State->CpuContexts[j]);
            }
            return Status;
        }
    }

    /*
     * PRE-PROBE INVALID MSRs (before VMXON)
     *
     * This MUST happen before any CPU enters VMX root mode (VMXON).
     * In normal kernel mode, __try/__except works reliably and we can
     * safely probe each MSR to discover which ones cause #GP.
     *
     * After VMXON, SEH is unreliable in VMX root mode because the host
     * stack is outside the thread stack region Windows requires for
     * structured exception handling. The pre-probed bitmap eliminates
     * the need for SEH when handling RDMSR/WRMSR VM-Exits.
     *
     * Note: The probe only needs to run once globally (not per-CPU)
     * because MSR existence is a CPU model property, not per-core.
     */
    {
        extern NTSTATUS MsrProbeInvalidMsrs(VOID);
        Status = MsrProbeInvalidMsrs();
        if (!NT_SUCCESS(Status)) {
            LOG_WARN("MSR pre-probe failed: 0x%08X (unknown MSRs will execute directly)", Status);
            /* Non-fatal but risky: without the bitmap, unknown MSRs may #GP in root mode */
        }
    }

    /* Initialize EPT globally */
    Status = EptInitialize();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("EPT initialization failed: 0x%08X", Status);
        for (i = 0; i < CpuCount; i++) {
            VmxFreeCpuContext(&State->CpuContexts[i]);
        }
        if (State->CpuContexts) {
            ExFreePoolWithTag(State->CpuContexts, 'xmvC');
            State->CpuContexts = NULL;
        }
        return Status;
    }

    /*
     * BUG FIX (Issue #1): Pre-allocate the per-CPU HV_CPU_CONTEXT array here
     * instead of lazy allocation in VmxOpsGetCurrentCpuContext().
     *
     * The original lazy allocation was unsafe: multiple CPUs could see
     * g_VmxHvCtx == NULL simultaneously during the first VM-Exit and race
     * to allocate, causing double-allocation and memory leaks.
     *
     * Pre-allocating here (single-threaded, before any CPU enters VMX)
     * eliminates the race condition entirely.
     */
    if (!g_VmxHvCtx && CpuCount > 0) {
        g_VmxHvCtx = (PHV_CPU_CONTEXT)ExAllocatePoolWithTag(
            NonPagedPool,
            CpuCount * sizeof(HV_CPU_CONTEXT),
            'xvhC');
        if (!g_VmxHvCtx) {
            LOG_ERROR("Failed to pre-allocate HV_CPU_CONTEXT array for %u CPUs", CpuCount);
            for (i = 0; i < CpuCount; i++) {
                VmxFreeCpuContext(&State->CpuContexts[i]);
            }
            if (State->CpuContexts) {
                ExFreePoolWithTag(State->CpuContexts, 'xmvC');
                State->CpuContexts = NULL;
            }
            EptCleanup();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(g_VmxHvCtx, CpuCount * sizeof(HV_CPU_CONTEXT));
    }

    /* Initialize per-CPU EPT structures (hook page isolation) */
    Status = EptInitPerCpu();
    if (!NT_SUCCESS(Status)) {
        LOG_WARN("Per-CPU EPT init failed: 0x%08X (falling back to shared EPT)", Status);
        /* Non-fatal: hooks still work but without per-CPU isolation */
    }

    /*
     * Enable VMX on each CPU via DPC.
     * HvSetTargetProcessorDpc + KeInsertQueueDpc ensures the DPC runs on
     * the target processor.  We wait for completion via KEVENT before
     * proceeding to the next CPU (serialized launch).
     *
     * BUG FIX (Issue #8): Uses dynamically resolved KeSetTargetProcessorDpcEx
     * (PROCESSOR_NUMBER-based) for >127 CPU support, falling back to
     * KeSetTargetProcessorDpc (CCHAR-based) on older systems.
     *
     * IMPORTANT (Problem E safety note): Dpc and DpcCtx are stack-allocated
     * inside this loop. This is ONLY safe because KeWaitForSingleObject()
     * blocks until the DPC completes and signals the Event. Do NOT remove
     * or defer the wait — the KDPC object must remain valid while queued,
     * and DpcCtx must remain valid while the DPC routine accesses it.
     * If parallel CPU launch is needed in the future, allocate Dpc/DpcCtx
     * from NonPagedPool instead of the stack.
     */
    for (i = 0; i < CpuCount; i++) {
        KDPC            Dpc;
        VMX_DPC_CONTEXT DpcCtx;

        DpcCtx.State  = State;
        DpcCtx.Status = STATUS_UNSUCCESSFUL;
        KeInitializeEvent(&DpcCtx.Event, NotificationEvent, FALSE);

        KeInitializeDpc(&Dpc, VmxInitDpcRoutine, &DpcCtx);
        KeSetImportanceDpc(&Dpc, HighImportance);

        /*
         * BUG FIX (Issue #8): Use HvSetTargetProcessorDpc which dynamically
         * resolves KeSetTargetProcessorDpcEx (supports >127 CPUs) and falls
         * back to KeSetTargetProcessorDpc (CCHAR) on older systems.
         */
        {
            NTSTATUS DpcTargetStatus = HvSetTargetProcessorDpc(&Dpc, i);
            if (!NT_SUCCESS(DpcTargetStatus)) {
                LOG_ERROR("Failed to target DPC to CPU %u: 0x%08X", i, DpcTargetStatus);
                Status = DpcTargetStatus;
                goto InitFailed;
            }
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[VMXToolbox] Main thread: About to queue DPC for CPU %u\n", i);

        if (!KeInsertQueueDpc(&Dpc, NULL, NULL)) {
            LOG_ERROR("Failed to queue init DPC for CPU %u", i);
            Status = STATUS_UNSUCCESSFUL;
            goto InitFailed;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[VMXToolbox] Main thread: DPC queued, now waiting for CPU %u...\n", i);

        /*
         * Wait with periodic timeout diagnostics.
         * Use 1-second polling to distinguish
         * "slow" from "stuck" in WinDbg output.
         *
         * Also monitor VM-Exit counts for already-launched CPUs to detect
         * VM-Exit storms that prevent DPC completion.
         */
        {
            LARGE_INTEGER Timeout;
            NTSTATUS WaitStatus;
            ULONG WaitCount = 0;

            Timeout.QuadPart = -10000000LL;  /* 1 second (negative = relative) */
            for (;;) {
                WaitStatus = KeWaitForSingleObject(
                    &DpcCtx.Event, Executive, KernelMode, FALSE, &Timeout);
                if (WaitStatus == STATUS_SUCCESS) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[VMXToolbox] Main thread: CPU %u Event signaled after %u sec\n",
                               i, WaitCount);
                    break;  /* Event signaled */
                }
                WaitCount++;

                /* Report VM-Exit counts for all CPUs (including already-launched ones) */
                {
                    ULONG k;
                    for (k = 0; k <= i && k < CpuCount; k++) {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                                   "[VMXToolbox] Main thread: Still waiting for CPU %u DPC... "
                                   "(%u seconds elapsed) CPU%u exits=%lld\n",
                                   i, WaitCount, k,
                                   State->CpuContexts[k].ExitCount);
                    }
                }
                if (WaitCount >= 60) {  /* 60 second timeout */
                    LOG_ERROR("CPU %u DPC timed out after 60 seconds!", i);

                    /*
                     * H-6 FIX: Dpc and DpcCtx live on this stack frame.
                     * If we goto InitFailed while the DPC is still queued
                     * or in-progress on the target CPU, the DPC routine
                     * would later dereference freed stack memory and
                     * probably BSOD.
                     *
                     * Proper teardown sequence:
                     *   1. Try KeRemoveQueueDpc — succeeds if the DPC was
                     *      still queued (not yet executed) and removes it
                     *      from the queue.  In that case, we can safely
                     *      unwind.
                     *   2. If KeRemoveQueueDpc returns FALSE, the DPC has
                     *      already started running on the target CPU but
                     *      is hung for some reason.  We CANNOT unwind
                     *      this stack without corrupting DpcCtx.  We wait
                     *      forever for Event — there's no recovery path
                     *      other than a manual bugcheck, which is better
                     *      than silent memory corruption.
                     */
                    if (KeRemoveQueueDpc(&Dpc)) {
                        LOG_WARN("CPU %u DPC removed from queue; safe to unwind", i);
                    } else {
                        LOG_ERROR("CPU %u DPC has started — waiting indefinitely "
                                  "to avoid stack corruption", i);
                        KeWaitForSingleObject(&DpcCtx.Event, Executive, KernelMode,
                                              FALSE, NULL);
                        LOG_ERROR("CPU %u DPC finally completed after timeout", i);
                    }

                    Status = STATUS_TIMEOUT;
                    goto InitFailed;
                }
            }
        }
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[VMXToolbox] Main thread: CPU %u DPC completed, status=0x%08X\n",
                   i, DpcCtx.Status);

        if (!NT_SUCCESS(DpcCtx.Status)) {
            LOG_ERROR("VMX init failed on CPU %u: 0x%08X", i, DpcCtx.Status);
            Status = DpcCtx.Status;
            goto InitFailed;
        }

        LOG_INFO("CPU %u: VMX guest mode active", i);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[VMXToolbox] Main thread: CPU %u VMX guest mode active\n", i);
    }

    State->Initialized = TRUE;

    /*
     * AAD-BP (post-2nd-review): register exception-intercept toggle
     * callback with the process-tracking subsystem.  See svm_init.c for
     * the same pattern on the SVM side.
     */
    ProcessRegisterExceptionHideToggle(VmxSetExceptionInterceptBp);

    LOG_INFO("VMX initialization complete: %u CPUs virtualized", CpuCount);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               "[VMXToolbox] Main thread: VMX initialization COMPLETE (%u CPUs)\n", CpuCount);

    return STATUS_SUCCESS;

InitFailed:
    /* Teardown any CPUs that were already launched */
    for (j = 0; j < i; j++) {
        if (State->CpuContexts[j].VmcsLaunched) {
            KDPC            Dpc;
            VMX_DPC_CONTEXT DpcCtx;
            DpcCtx.State  = State;
            DpcCtx.Status = STATUS_UNSUCCESSFUL;
            KeInitializeEvent(&DpcCtx.Event, NotificationEvent, FALSE);
            KeInitializeDpc(&Dpc, VmxTerminateDpcRoutine, &DpcCtx);
            KeSetImportanceDpc(&Dpc, HighImportance);
            if (NT_SUCCESS(HvSetTargetProcessorDpc(&Dpc, j)) &&
                KeInsertQueueDpc(&Dpc, NULL, NULL)) {
                KeWaitForSingleObject(&DpcCtx.Event, Executive, KernelMode, FALSE, NULL);
            }
        }
        VmxFreeCpuContext(&State->CpuContexts[j]);
    }
    /* Free remaining un-launched CPU contexts */
    for (j = i; j < CpuCount; j++) {
        VmxFreeCpuContext(&State->CpuContexts[j]);
    }
    EptCleanupPerCpu();
    EptCleanup();
    if (g_VmxHvCtx) {
        ExFreePoolWithTag(g_VmxHvCtx, 'xvhC');
        g_VmxHvCtx = NULL;
    }
    {
        extern VOID MsrCleanupInvalidBitmap(VOID);
        MsrCleanupInvalidBitmap();
    }
    if (State->CpuContexts) {
        ExFreePoolWithTag(State->CpuContexts, 'xmvC');
        State->CpuContexts = NULL;
    }
    return Status;
}

/* ========================================================================= */
/*  AAD-BP: Dynamic Exception Bitmap (Intel VMX)                             */
/* ========================================================================= */

/*
 * See vmx.h for the rationale — exception bitmap is maintained as a
 * global "desired" value plus a per-CPU "last applied" generation.
 *
 * g_VmxDesiredExceptionBitmap contains the OR of every feature-flag:
 *   bit 1 = #DB wanted (set by NPT/EPT hook subsystem once on its side,
 *                       TODO: wire up when EPT-side #DB single-step is
 *                       added — currently unused on Intel because EPT
 *                       uses MTF, not TF, for single-step)
 *   bit 3 = #BP wanted (set when any target process has AAD_HIDE_EXCEPTIONS)
 *
 * Generation counter: incremented on every change to the desired value.
 * Each CPU stores its last-applied generation in g_VmxExcBmpCpuGen[cpu].
 * VmxSyncExceptionBitmap (called from the exit handler) compares and,
 * if behind, VMWRITEs the new value.  Because the VMCS is loaded on the
 * current CPU (we're in its exit handler), the VMWRITE always targets
 * the right VMCS — no VMPTRLD dance needed.
 */
static volatile ULONG  g_VmxDesiredExceptionBitmap = 0;
static volatile LONG   g_VmxExcBmpGeneration       = 0;
static volatile LONG  *g_VmxExcBmpCpuGen           = NULL;  /* [g_MaxProcessors] */
static KSPIN_LOCK      g_VmxExcBmpLock;
static BOOLEAN         g_VmxExcBmpInited           = FALSE;

static VOID VmxExcBmpEnsureInit(VOID)
{
    /*
     * Called from SvmInitialize-analogue / VmxInitialize path.  We run
     * under PASSIVE_LEVEL exactly once, before any per-CPU state could
     * race — but we use InterlockedCompareExchange out of paranoia.
     */
    if (InterlockedCompareExchange((LONG *)&g_VmxExcBmpInited, TRUE, FALSE) == FALSE) {
        KeInitializeSpinLock(&g_VmxExcBmpLock);
        if (g_MaxProcessors > 0) {
            g_VmxExcBmpCpuGen = (volatile LONG *)ExAllocatePoolWithTag(
                NonPagedPool, g_MaxProcessors * sizeof(LONG), 'xmvG');
            if (g_VmxExcBmpCpuGen) {
                RtlZeroMemory((PVOID)g_VmxExcBmpCpuGen,
                              g_MaxProcessors * sizeof(LONG));
            }
        }
    }
}

static VOID VmxExcBmpSet(ULONG BitMask, BOOLEAN Enable)
{
    KIRQL OldIrql;
    ULONG Old, New;

    VmxExcBmpEnsureInit();

    KeAcquireSpinLock(&g_VmxExcBmpLock, &OldIrql);
    Old = g_VmxDesiredExceptionBitmap;
    New = Enable ? (Old | BitMask) : (Old & ~BitMask);
    if (New != Old) {
        g_VmxDesiredExceptionBitmap = New;
        InterlockedIncrement(&g_VmxExcBmpGeneration);
    }
    KeReleaseSpinLock(&g_VmxExcBmpLock, OldIrql);
}

VOID VmxSetExceptionInterceptDb(BOOLEAN Enable)
{
    VmxExcBmpSet(EXCEPTION_BITMAP_DB, Enable);
}

VOID VmxSetExceptionInterceptBp(BOOLEAN Enable)
{
    VmxExcBmpSet(EXCEPTION_BITMAP_BP, Enable);
}

VOID VmxSyncExceptionBitmap(VOID)
{
    ULONG CpuIndex;
    LONG  CurGen;

    /*
     * Called at the top of the VMX exit handler.  If init never ran
     * (called before VmxInitialize fully completed?), g_VmxExcBmpCpuGen
     * will be NULL — bail safely.
     */
    if (!g_VmxExcBmpCpuGen) return;

    CpuIndex = KeGetCurrentProcessorNumber();
    if (CpuIndex >= g_MaxProcessors) return;

    CurGen = g_VmxExcBmpGeneration;
    if (g_VmxExcBmpCpuGen[CpuIndex] == CurGen) {
        /* Already in sync on this CPU — fast path, no VMWRITE. */
        return;
    }

    /*
     * Apply the current desired mask.  VMWRITE implicitly targets the
     * VMCS that is LOAD'd on the current CPU — which is THIS CPU's
     * VMCS (we are in its exit handler, VMPTRLD was done at VMENTRY).
     */
    VmxWrite(VMCS_CTRL_EXCEPTION_BITMAP, g_VmxDesiredExceptionBitmap);
    g_VmxExcBmpCpuGen[CpuIndex] = CurGen;
}

VOID VmxTerminate(PVMX_STATE State)
{
    ULONG i;

    if (!State->Initialized) {
        return;
    }

    LOG_INFO("Terminating VMX...");

    /*
     * First, exit VMX guest mode on each CPU via DPC.
     * VmxTerminateDpcRoutine issues VMCALL(VMCALL_MAGIC_SHUTDOWN)
     * which triggers HandleVmcall -> returns FALSE -> AsmVmxExitHandler
     * executes VMXOFF, returning the CPU to normal (non-root) operation.
     * We must do this BEFORE cleaning up EPT / freeing VMCS regions.
     */
    for (i = 0; i < State->CpuCount; i++) {
        if (State->CpuContexts[i].VmcsLaunched) {
            KDPC            Dpc;
            VMX_DPC_CONTEXT DpcCtx;

            DpcCtx.State  = State;
            DpcCtx.Status = STATUS_UNSUCCESSFUL;
            KeInitializeEvent(&DpcCtx.Event, NotificationEvent, FALSE);

            KeInitializeDpc(&Dpc, VmxTerminateDpcRoutine, &DpcCtx);
            KeSetImportanceDpc(&Dpc, HighImportance);

            if (NT_SUCCESS(HvSetTargetProcessorDpc(&Dpc, i)) &&
                KeInsertQueueDpc(&Dpc, NULL, NULL)) {
                KeWaitForSingleObject(&DpcCtx.Event, Executive, KernelMode, FALSE, NULL);
            }

            LOG_INFO("CPU %u: VMX guest mode exited", i);
        }
    }

    /* Now safe to clean up EPT (no CPU is using it anymore) */
    EptCleanupPerCpu();
    EptCleanup();

    /* Free per-CPU resources */
    for (i = 0; i < State->CpuCount; i++) {
        VmxFreeCpuContext(&State->CpuContexts[i]);
    }

    /* Free the dynamically allocated CpuContexts array */
    if (State->CpuContexts) {
        ExFreePoolWithTag(State->CpuContexts, 'xmvC');
        State->CpuContexts = NULL;
    }

    /* Free the per-CPU HV_CPU_CONTEXT array used by VmxOpsGetCurrentCpuContext */
    if (g_VmxHvCtx) {
        ExFreePoolWithTag(g_VmxHvCtx, 'xvhC');
        g_VmxHvCtx = NULL;
    }

    /* Free the invalid MSR pre-probe bitmap */
    {
        extern VOID MsrCleanupInvalidBitmap(VOID);
        MsrCleanupInvalidBitmap();
    }

    /* AAD-BP: free per-CPU generation counter for Exception Bitmap sync. */
    if (g_VmxExcBmpCpuGen) {
        ExFreePoolWithTag((PVOID)g_VmxExcBmpCpuGen, 'xmvG');
        g_VmxExcBmpCpuGen = NULL;
    }
    /*
     * Leave g_VmxExcBmpInited TRUE so a second Init in the same driver
     * lifecycle won't re-init the lock out from under us.  The lock is
     * idempotent and the desired-bitmap global is reset explicitly by
     * the next VmxSetException* call anyway.
     */
    g_VmxDesiredExceptionBitmap = 0;
    g_VmxExcBmpGeneration       = 0;

    State->Initialized = FALSE;
    LOG_INFO("VMX terminated");
}

/* ========================================================================= */
/*  HV_OPS Backend Implementation (Intel VMX)                                */
/* ========================================================================= */

static BOOLEAN VmxOpsIsSupported(VOID) { return VmxIsSupported(); }
static NTSTATUS VmxOpsInitialize(VOID) { return VmxInitialize(&g_VmxState); }
static VOID VmxOpsTerminate(VOID) { VmxTerminate(&g_VmxState); }

static ULONG64 VmxOpsReadGuestRip(VOID) { return VmxRead(VMCS_GUEST_RIP); }
static VOID VmxOpsWriteGuestRip(ULONG64 V) { VmxWrite(VMCS_GUEST_RIP, V); }
static ULONG64 VmxOpsReadGuestRsp(VOID) { return VmxRead(VMCS_GUEST_RSP); }
static VOID VmxOpsWriteGuestRsp(ULONG64 V) { VmxWrite(VMCS_GUEST_RSP, V); }
static ULONG64 VmxOpsReadGuestCr3(VOID) { return VmxRead(VMCS_GUEST_CR3); }
static VOID VmxOpsWriteGuestCr3(ULONG64 V) { VmxWrite(VMCS_GUEST_CR3, V); }
static ULONG64 VmxOpsReadGuestRflags(VOID) { return VmxRead(VMCS_GUEST_RFLAGS); }
static VOID VmxOpsWriteGuestRflags(ULONG64 V) { VmxWrite(VMCS_GUEST_RFLAGS, V); }

static ULONG64 VmxOpsReadExitReason(VOID) { return VmxRead(VMCS_EXIT_REASON); }
static ULONG64 VmxOpsReadExitQualification(VOID) { return VmxRead(VMCS_EXIT_QUALIFICATION); }
static ULONG64 VmxOpsReadExitInterruptionInfo(VOID) { return VmxRead(VMCS_EXIT_INTERRUPTION_INFO); }
static ULONG64 VmxOpsReadExitInterruptionErrorCode(VOID) { return VmxRead(VMCS_EXIT_INTERRUPTION_ERRCODE); }
static ULONG VmxOpsReadExitInstructionLength(VOID) { return (ULONG)VmxRead(VMCS_EXIT_INSTRUCTION_LENGTH); }
static ULONG64 VmxOpsReadGuestPhysicalAddress(VOID) { return VmxRead(VMCS_GUEST_PHYSICAL_ADDRESS); }

static VOID VmxOpsAdvanceGuestRip(VOID) { VmxAdvanceGuestRip(); }

static VOID VmxOpsInjectException(ULONG Vector, ULONG Type, BOOLEAN HasErrorCode, ULONG ErrorCode)
{
    ULONG Info = INTERRUPT_INFO_VALID;
    Info |= (Vector & INTERRUPT_INFO_VECTOR_MASK);
    Info |= (Type << INTERRUPT_INFO_TYPE_SHIFT);
    if (HasErrorCode) {
        Info |= INTERRUPT_INFO_DELIVER_ERR_CODE;
        VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, ErrorCode);
    }
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, Info);
}

static VOID VmxOpsInjectInterruptInfo(ULONG InfoField)
{
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, InfoField);
}

static VOID VmxOpsSetEntryInterruptionInfo(ULONG Info)
{
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, Info);
}

static VOID VmxOpsSetEntryExceptionErrorCode(ULONG ErrorCode)
{
    VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, ErrorCode);
}

static VOID VmxOpsSetEntryInstructionLength(ULONG Length)
{
    VmxWrite(VMCS_CTRL_VMENTRY_INSTR_LENGTH, Length);
}

static NTSTATUS VmxOpsSetupPageTables(VOID) { return EptInitialize(); }
static VOID VmxOpsCleanupPageTables(VOID) { EptCleanup(); }
static VOID VmxOpsInvalidatePageTables(VOID) { EptInvalidateFromGuest(); }

static NTSTATUS VmxOpsHookFunction(ULONG64 TargetVa, PVOID HookFunc, PVOID *OrigFunc)
{
    return EptHookFunction(TargetVa, HookFunc, OrigFunc);
}

static NTSTATUS VmxOpsUnhookFunction(ULONG64 TargetVa)
{
    return EptUnhookFunction(TargetVa);
}

static VOID VmxOpsUnhookAll(VOID)
{
    EptUnhookAll();
}

static VOID VmxOpsEnableSingleStep(VOID)
{
    ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
    ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
}

static VOID VmxOpsDisableSingleStep(VOID)
{
    ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
    ProcBased &= ~PROC_BASED_MONITOR_TRAP_FLAG;
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
}

static ULONG64 VmxOpsReadPrimaryProcControls(VOID)
{
    return VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
}

static VOID VmxOpsWritePrimaryProcControls(ULONG64 Value)
{
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, Value);
}

static VOID VmxOpsWriteTscOffset(LONG64 Offset)
{
    /*
     * Write the hardware TSC Offset to VMCS.
     * When PROC_BASED_USE_TSC_OFFSETTING is enabled, the CPU automatically
     * adds this value to the TSC seen by the guest on RDTSC/RDTSCP.
     * A negative offset effectively subtracts time from the guest's view.
     */
    VmxWrite(VMCS_CTRL_TSC_OFFSET, (ULONG64)(-Offset));
}

static PHV_CPU_CONTEXT VmxOpsGetCurrentCpuContext(VOID)
{
    /*
     * BUG FIX (Issue #1): g_VmxHvCtx is now pre-allocated in VmxInitialize()
     * before any CPU enters VMX operation, eliminating the lazy allocation
     * race condition where multiple CPUs could double-allocate.
     */
    ULONG Cpu = KeGetCurrentProcessorNumber();

    if (g_VmxHvCtx && Cpu < g_MaxProcessors) {
        g_VmxHvCtx[Cpu].ProcessorNumber = g_VmxState.CpuContexts[Cpu].ProcessorNumber;
        g_VmxHvCtx[Cpu].HvEnabled = g_VmxState.CpuContexts[Cpu].VmxEnabled;
        g_VmxHvCtx[Cpu].GuestLaunched = g_VmxState.CpuContexts[Cpu].VmcsLaunched;
        g_VmxHvCtx[Cpu].TscOffset = g_VmxState.CpuContexts[Cpu].TscOffset;
        g_VmxHvCtx[Cpu].LastDebugPauseTsc = g_VmxState.CpuContexts[Cpu].LastDebugPauseTsc;
        g_VmxHvCtx[Cpu].InDebugPause = g_VmxState.CpuContexts[Cpu].InDebugPause;
        g_VmxHvCtx[Cpu].ExitCount = g_VmxState.CpuContexts[Cpu].ExitCount;
        return &g_VmxHvCtx[Cpu];
    }
    return NULL;
}

HV_OPS g_VmxOps = {
    "Intel VMX",                            /* Name */
    CPU_VENDOR_INTEL,                       /* Vendor */
    VmxOpsIsSupported,                      /* IsSupported */
    VmxOpsInitialize,                       /* Initialize */
    VmxOpsTerminate,                        /* Terminate */
    VmxOpsReadGuestRip,                     /* ReadGuestRip */
    VmxOpsWriteGuestRip,                    /* WriteGuestRip */
    VmxOpsReadGuestRsp,                     /* ReadGuestRsp */
    VmxOpsWriteGuestRsp,                    /* WriteGuestRsp */
    VmxOpsReadGuestCr3,                     /* ReadGuestCr3 */
    VmxOpsWriteGuestCr3,                    /* WriteGuestCr3 */
    VmxOpsReadGuestRflags,                  /* ReadGuestRflags */
    VmxOpsWriteGuestRflags,                 /* WriteGuestRflags */
    VmxOpsReadExitReason,                   /* ReadExitReason */
    VmxOpsReadExitQualification,            /* ReadExitQualification */
    VmxOpsReadExitInterruptionInfo,         /* ReadExitInterruptionInfo */
    VmxOpsReadExitInterruptionErrorCode,    /* ReadExitInterruptionErrorCode */
    VmxOpsReadExitInstructionLength,        /* ReadExitInstructionLength */
    VmxOpsReadGuestPhysicalAddress,         /* ReadGuestPhysicalAddress */
    VmxOpsAdvanceGuestRip,                  /* AdvanceGuestRip */
    VmxOpsInjectException,                  /* InjectException */
    VmxOpsInjectInterruptInfo,              /* InjectInterruptInfo */
    VmxOpsSetEntryInterruptionInfo,         /* SetEntryInterruptionInfo */
    VmxOpsSetEntryExceptionErrorCode,       /* SetEntryExceptionErrorCode */
    VmxOpsSetEntryInstructionLength,        /* SetEntryInstructionLength */
    VmxOpsSetupPageTables,                  /* SetupPageTables */
    VmxOpsCleanupPageTables,                /* CleanupPageTables */
    VmxOpsInvalidatePageTables,             /* InvalidatePageTables */
    VmxOpsHookFunction,                     /* HookFunction */
    VmxOpsUnhookFunction,                   /* UnhookFunction */
    VmxOpsUnhookAll,                        /* UnhookAll */
    VmxOpsEnableSingleStep,                 /* EnableSingleStep */
    VmxOpsDisableSingleStep,                /* DisableSingleStep */
    VmxOpsReadPrimaryProcControls,          /* ReadPrimaryProcControls */
    VmxOpsWritePrimaryProcControls,         /* WritePrimaryProcControls */
    VmxOpsWriteTscOffset,                   /* WriteTscOffset */
    VmxOpsGetCurrentCpuContext,             /* GetCurrentCpuContext */
};
