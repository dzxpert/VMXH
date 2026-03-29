/*
 * vmx_init.c - VMX Anti-Anti-Debug Hypervisor
 * VMX initialization: VMXON, VMCS setup, per-CPU virtualization
 */

#include "vmx.h"
#include "ept.h"
#include "log.h"
#include "hv_ops.h"

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

    /* Host Stack (16KB) */
    CpuCtx->HostStackSize = 4 * PAGE_SIZE_4KB;
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

    /* Pin-Based Controls */
    PinBased = VmxAdjustControls(
        PIN_BASED_NMI_EXIT,
        State->TrueControlsSupported ? State->TruePinBasedCap : State->PinBasedCap
    );
    VmxWrite(VMCS_CTRL_PIN_BASED_VM_EXEC, PinBased);

    /* Primary Processor-Based Controls */
    ProcBased = VmxAdjustControls(
        PROC_BASED_USE_MSR_BITMAPS |
        PROC_BASED_SECONDARY_CONTROLS |
        PROC_BASED_CR3_LOAD_EXIT |          /* Monitor process switching */
        PROC_BASED_MOV_DR_EXIT |            /* Intercept DR access */
        PROC_BASED_RDTSC_EXIT,              /* Intercept RDTSC */
        State->TrueControlsSupported ? State->TrueProcBasedCap : State->ProcBasedCap
    );
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

    /* Secondary Processor-Based Controls */
    ProcBased2 = VmxAdjustControls(
        PROC_BASED2_ENABLE_EPT |
        PROC_BASED2_ENABLE_RDTSCP |
        PROC_BASED2_ENABLE_VPID |
        PROC_BASED2_ENABLE_INVPCID,
        State->ProcBased2Cap
    );
    VmxWrite(VMCS_CTRL_SECONDARY_VM_EXEC, ProcBased2);

    /* Exception Bitmap: intercept #DB and #BP */
    VmxWrite(VMCS_CTRL_EXCEPTION_BITMAP,
             EXCEPTION_BITMAP_DB | EXCEPTION_BITMAP_BP);

    /* MSR Bitmap */
    VmxWrite(VMCS_CTRL_MSR_BITMAP, CpuCtx->MsrBitmapPa);

    /* VPID - use processor number + 1 (VPID 0 is reserved for host) */
    VmxWrite(VMCS_CTRL_VPID, CpuCtx->ProcessorNumber + 1);

    /* EPT Pointer - will be set when EPT is initialized */
    /* For now, set up identity-mapped EPT */
    Status = EptSetupIdentityMap(CpuCtx, State);
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("EPT setup failed for CPU %u", CpuCtx->ProcessorNumber);
        return Status;
    }

    /* CR0/CR4 guest/host masks and read shadows */
    VmxWrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);    /* Don't intercept CR0 */
    VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, Cr0);
    VmxWrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMXE);  /* Hide VMXE from guest */
    VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, Cr4 & ~CR4_VMXE);

    /* TSC Offset */
    VmxWrite(VMCS_CTRL_TSC_OFFSET, 0);

    /* ===== VM-Exit Controls ===== */
    ExitCtls = VmxAdjustControls(
        VMEXIT_HOST_ADDR_SPACE_SIZE |       /* 64-bit host */
        VMEXIT_SAVE_IA32_EFER |
        VMEXIT_LOAD_IA32_EFER |
        VMEXIT_ACK_INT_ON_EXIT,
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

    /* Other guest state */
    VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 0);     /* Active */
    VmxWrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
    VmxWrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, 0);
    VmxWrite(VMCS_GUEST_VMCS_LINK_PTR, 0xFFFFFFFFFFFFFFFF);

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

    /* Host RSP: top of the host stack (stack grows down) */
    VmxWrite(VMCS_HOST_RSP,
             (ULONG64)CpuCtx->HostStackBase + CpuCtx->HostStackSize - 8);

    /* Host RIP: VM-Exit handler entry point */
    VmxWrite(VMCS_HOST_RIP, (ULONG64)AsmVmxExitHandler);

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
        __vmx_off();
        __writecr4(CpuCtx->OriginalCr4);
        CpuCtx->VmxEnabled = FALSE;
        CpuCtx->VmcsLaunched = FALSE;
        LOG_INFO("VMXOFF executed on CPU %u", CpuCtx->ProcessorNumber);
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
     *   1. Save current RSP/RIP context
     *   2. Write Guest RSP = current RSP, Guest RIP = return address
     *   3. Execute VMLAUNCH
     *   4. If successful, CPU enters guest mode and resumes from return address
     *   5. If failed, returns non-zero
     *
     * On success, execution continues at the next line after AsmVmxLaunch()
     * because AsmVmxLaunch sets Guest RIP to the return address on the stack.
     */
    VmLaunchResult = __vmx_vmlaunch();

    if (VmLaunchResult != 0) {
        /* VMLAUNCH failed */
        LOG_ERROR("VMLAUNCH failed on CPU %u, result=%u",
                  CpuNum, (ULONG)VmLaunchResult);
        VmxDisableOnCpu(CpuCtx);
        DpcCtx->Status = STATUS_UNSUCCESSFUL;
        KeSetEvent(&DpcCtx->Event, IO_NO_INCREMENT, FALSE);
        return;
    }

    /* Success - we're now running as a guest! */
    CpuCtx->VmcsLaunched = TRUE;
    DpcCtx->Status = STATUS_SUCCESS;
    KeSetEvent(&DpcCtx->Event, IO_NO_INCREMENT, FALSE);
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
     * The VM-Exit handler will execute VMXOFF.
     */
    if (CpuCtx->VmcsLaunched) {
        /* Magic VMCALL to signal shutdown */
        AsmVmxVmcall();
    }

    VmxDisableOnCpu(CpuCtx);

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

    LOG_INFO("Initializing VMX on %u processors", CpuCount);

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

    /* Initialize EPT globally */
    Status = EptInitialize();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("EPT initialization failed: 0x%08X", Status);
        for (i = 0; i < CpuCount; i++) {
            VmxFreeCpuContext(&State->CpuContexts[i]);
        }
        return Status;
    }

    /*
     * TODO: Enable VMX on each CPU via DPC.
     * For now, mark as initialized after allocation succeeds.
     * The actual VMLAUNCH will be done when the first target is set.
     *
     * In a full implementation, we would use KeSetTargetProcessorDpc
     * to run VmxInitDpcRoutine on each CPU.
     */

    State->Initialized = TRUE;
    LOG_INFO("VMX initialization complete");

    return STATUS_SUCCESS;
}

VOID VmxTerminate(PVMX_STATE State)
{
    ULONG i;

    if (!State->Initialized) {
        return;
    }

    LOG_INFO("Terminating VMX...");

    /*
     * TODO: Execute VMXOFF on each CPU via DPC.
     * For now, just clean up resources.
     */

    /* Cleanup EPT */
    EptCleanup();

    /* Free per-CPU resources */
    for (i = 0; i < State->CpuCount; i++) {
        VmxDisableOnCpu(&State->CpuContexts[i]);
        VmxFreeCpuContext(&State->CpuContexts[i]);
    }

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
static VOID VmxOpsInvalidatePageTables(VOID) { EptInvalidateAllContexts(); }

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

static PHV_CPU_CONTEXT VmxOpsGetCurrentCpuContext(VOID)
{
    /* VMX_CPU_CONTEXT doesn't embed HV_CPU_CONTEXT at start,
     * so we return a static adapter. For VMX, callers use
     * g_VmxState.CpuContexts directly for TSC offset etc.
     * This provides a minimal interface for the abstraction layer. */
    static HV_CPU_CONTEXT VmxHvCtx;
    ULONG Cpu = KeGetCurrentProcessorNumber();
    if (Cpu < MAX_PROCESSORS) {
        VmxHvCtx.ProcessorNumber = g_VmxState.CpuContexts[Cpu].ProcessorNumber;
        VmxHvCtx.HvEnabled = g_VmxState.CpuContexts[Cpu].VmxEnabled;
        VmxHvCtx.GuestLaunched = g_VmxState.CpuContexts[Cpu].VmcsLaunched;
        VmxHvCtx.TscOffset = g_VmxState.CpuContexts[Cpu].TscOffset;
        VmxHvCtx.LastDebugPauseTsc = g_VmxState.CpuContexts[Cpu].LastDebugPauseTsc;
        VmxHvCtx.InDebugPause = g_VmxState.CpuContexts[Cpu].InDebugPause;
        VmxHvCtx.ExitCount = g_VmxState.CpuContexts[Cpu].ExitCount;
    }
    return &VmxHvCtx;
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
    VmxOpsGetCurrentCpuContext,             /* GetCurrentCpuContext */
};
