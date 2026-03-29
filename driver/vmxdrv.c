/*
 * vmxdrv.c - VMX Anti-Anti-Debug Hypervisor
 * Kernel driver entry point, IRP dispatch, IOCTL handling
 */

#include "vmx.h"
#include "svm.h"
#include "hv_ops.h"
#include "hv_detect.h"
#include "hv_mem.h"
#include "hv_hook.h"
#include "log.h"
#include "process.h"
#include "../common/shared.h"

/* ========================================================================= */
/*  Globals                                                                  */
/* ========================================================================= */

VMX_STATE   g_VmxState = { 0 };
PDEVICE_OBJECT  g_DeviceObject = NULL;

/* Hypervisor abstraction layer globals */
PHV_OPS     g_HvOps = NULL;
CPU_VENDOR  g_CpuVendor = CPU_VENDOR_UNKNOWN;

/* ========================================================================= */
/*  Forward Declarations                                                     */
/* ========================================================================= */

DRIVER_INITIALIZE           DriverEntry;
DRIVER_UNLOAD               DriverUnload;

DRIVER_DISPATCH             DispatchCreateClose;

DRIVER_DISPATCH             DispatchDeviceControl;

static NTSTATUS HandleIoctlInit(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlSetTarget(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlRemoveTarget(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlSetConfig(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlGetLog(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlStop(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlQueryStatus(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlReadMemory(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlWriteMemory(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlInstallHook(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlRemoveHook(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlListHooks(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS HandleIoctlGetHookEvents(PIRP Irp, PIO_STACK_LOCATION IoStack);

/* ========================================================================= */
/*  Driver Entry / Unload                                                    */
/* ========================================================================= */

NTSTATUS DriverEntry(
    PDRIVER_OBJECT     DriverObject,
    PUNICODE_STRING    RegistryPath
)
{
    NTSTATUS        Status;
    UNICODE_STRING  DeviceName;
    UNICODE_STRING  SymLinkName;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* Initialize logging first */
    LogInitialize();
    LOG_INFO("VMX Anti-Anti-Debug Driver loading...");

    /* Detect CPU vendor and select hypervisor backend */
    g_CpuVendor = HvDetectCpuVendor();

    switch (g_CpuVendor) {
    case CPU_VENDOR_INTEL:
        if (!HvCheckVmxSupport()) {
            LOG_ERROR("Intel VMX is not supported or disabled on this CPU");
            LogTerminate();
            return STATUS_NOT_SUPPORTED;
        }
        g_HvOps = &g_VmxOps;
        LOG_INFO("Selected backend: Intel VMX");
        break;

    case CPU_VENDOR_AMD:
        if (!HvCheckSvmSupport()) {
            LOG_ERROR("AMD SVM is not supported or disabled on this CPU");
            LogTerminate();
            return STATUS_NOT_SUPPORTED;
        }
        g_HvOps = &g_SvmOps;
        LOG_INFO("Selected backend: AMD SVM");
        break;

    default:
        LOG_ERROR("Unsupported CPU vendor - neither Intel nor AMD detected");
        LogTerminate();
        return STATUS_NOT_SUPPORTED;
    }

    LOG_INFO("Hypervisor backend: %s", g_HvOps->Name);

    /* Create device object */
    RtlInitUnicodeString(&DeviceName, VMX_DEVICE_NAME);
    Status = IoCreateDevice(
        DriverObject,
        0,                          /* DeviceExtension size */
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                      /* Not exclusive */
        &g_DeviceObject
    );

    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("IoCreateDevice failed: 0x%08X", Status);
        LogTerminate();
        return Status;
    }

    /* Create symbolic link for user-mode access */
    RtlInitUnicodeString(&SymLinkName, VMX_SYMLINK_NAME);
    Status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);

    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("IoCreateSymbolicLink failed: 0x%08X", Status);
        IoDeleteDevice(g_DeviceObject);
        LogTerminate();
        return Status;
    }

    /* Register IRP dispatch routines */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload                          = DriverUnload;

    /* Initialize process tracking */
    ProcessTrackingInit();

    /* Initialize generic hook framework */
    GenericHookInit();

    LOG_INFO("Driver loaded successfully. Device: %wZ", &DeviceName);
    return STATUS_SUCCESS;
}

VOID DriverUnload(
    PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING SymLinkName;

    UNREFERENCED_PARAMETER(DriverObject);

    LOG_INFO("Driver unloading...");

    /* Cleanup generic hooks before terminating hypervisor */
    GenericHookCleanup();

    /* Terminate hypervisor on all processors */
    if (g_HvOps) {
        if (g_CpuVendor == CPU_VENDOR_INTEL && g_VmxState.Initialized) {
            g_HvOps->Terminate();
        } else if (g_CpuVendor == CPU_VENDOR_AMD && g_SvmState.Initialized) {
            g_HvOps->Terminate();
        }
    }

    /* Cleanup process tracking */
    ProcessTrackingCleanup();

    /* Delete symbolic link and device */
    RtlInitUnicodeString(&SymLinkName, VMX_SYMLINK_NAME);
    IoDeleteSymbolicLink(&SymLinkName);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    LOG_INFO("Driver unloaded");
    LogTerminate();
}

/* ========================================================================= */
/*  IRP Dispatch: Create / Close                                             */
/* ========================================================================= */

NTSTATUS DispatchCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  IRP Dispatch: Device Control (IOCTL)                                     */
/* ========================================================================= */

NTSTATUS DispatchDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS            Status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION  IoStack;
    ULONG               IoControlCode;

    UNREFERENCED_PARAMETER(DeviceObject);

    IoStack = IoGetCurrentIrpStackLocation(Irp);
    IoControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;

    switch (IoControlCode) {
    case IOCTL_VMX_INIT:
        Status = HandleIoctlInit(Irp, IoStack);
        break;

    case IOCTL_VMX_SET_TARGET:
        Status = HandleIoctlSetTarget(Irp, IoStack);
        break;

    case IOCTL_VMX_REMOVE_TARGET:
        Status = HandleIoctlRemoveTarget(Irp, IoStack);
        break;

    case IOCTL_VMX_SET_CONFIG:
        Status = HandleIoctlSetConfig(Irp, IoStack);
        break;

    case IOCTL_VMX_GET_LOG:
        Status = HandleIoctlGetLog(Irp, IoStack);
        break;

    case IOCTL_VMX_STOP:
        Status = HandleIoctlStop(Irp, IoStack);
        break;

    case IOCTL_VMX_QUERY_STATUS:
        Status = HandleIoctlQueryStatus(Irp, IoStack);
        break;

    case IOCTL_VMX_READ_MEMORY:
        Status = HandleIoctlReadMemory(Irp, IoStack);
        break;

    case IOCTL_VMX_WRITE_MEMORY:
        Status = HandleIoctlWriteMemory(Irp, IoStack);
        break;

    case IOCTL_VMX_INSTALL_HOOK:
        Status = HandleIoctlInstallHook(Irp, IoStack);
        break;

    case IOCTL_VMX_REMOVE_HOOK:
        Status = HandleIoctlRemoveHook(Irp, IoStack);
        break;

    case IOCTL_VMX_LIST_HOOKS:
        Status = HandleIoctlListHooks(Irp, IoStack);
        break;

    case IOCTL_VMX_GET_HOOK_EVENTS:
        Status = HandleIoctlGetHookEvents(Irp, IoStack);
        break;

    default:
        LOG_WARN("Unknown IOCTL code: 0x%08X", IoControlCode);
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

/* ========================================================================= */
/*  IOCTL Handlers                                                           */
/* ========================================================================= */

static NTSTATUS HandleIoctlInit(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStack);

    if (!g_HvOps) {
        LOG_ERROR("No hypervisor backend selected");
        return STATUS_NOT_SUPPORTED;
    }

    /* Check if already initialized based on backend */
    if ((g_CpuVendor == CPU_VENDOR_INTEL && g_VmxState.Initialized) ||
        (g_CpuVendor == CPU_VENDOR_AMD && g_SvmState.Initialized)) {
        LOG_WARN("Hypervisor already initialized");
        return STATUS_ALREADY_REGISTERED;
    }

    LOG_INFO("Initializing %s on all processors...", g_HvOps->Name);
    return g_HvOps->Initialize();
}

static NTSTATUS HandleIoctlSetTarget(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_TARGET_INFO Input;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(VMX_TARGET_INFO)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Input = (PVMX_TARGET_INFO)Irp->AssociatedIrp.SystemBuffer;
    if (!Input) {
        return STATUS_INVALID_PARAMETER;
    }

    LOG_INFO("Setting target process: PID=%u, Flags=0x%08X", Input->Pid, Input->Flags);
    return ProcessAddTarget(Input->Pid, Input->Flags);
}

static NTSTATUS HandleIoctlRemoveTarget(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_REMOVE_TARGET Input;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(VMX_REMOVE_TARGET)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Input = (PVMX_REMOVE_TARGET)Irp->AssociatedIrp.SystemBuffer;
    if (!Input) {
        return STATUS_INVALID_PARAMETER;
    }

    LOG_INFO("Removing target process: PID=%u", Input->Pid);
    return ProcessRemoveTarget(Input->Pid);
}

static NTSTATUS HandleIoctlSetConfig(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_CONFIG_INFO Input;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(VMX_CONFIG_INFO)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Input = (PVMX_CONFIG_INFO)Irp->AssociatedIrp.SystemBuffer;
    if (!Input) {
        return STATUS_INVALID_PARAMETER;
    }

    LOG_INFO("Updating config for PID=%u, NewFlags=0x%08X", Input->Pid, Input->Flags);
    return ProcessUpdateConfig(Input->Pid, Input->Flags);
}

static NTSTATUS HandleIoctlGetLog(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_LOG_BUFFER Output;
    ULONG           OutputSize;
    ULONG           MaxEntries;
    ULONG           Copied;

    OutputSize = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (OutputSize < sizeof(VMX_LOG_BUFFER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Output = (PVMX_LOG_BUFFER)Irp->AssociatedIrp.SystemBuffer;
    if (!Output) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Calculate how many entries fit in the output buffer */
    MaxEntries = (OutputSize - FIELD_OFFSET(VMX_LOG_BUFFER, Entries)) / sizeof(VMX_LOG_ENTRY);
    if (MaxEntries == 0) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Copied = LogRead(Output->Entries, MaxEntries);
    Output->Count = Copied;

    Irp->IoStatus.Information = FIELD_OFFSET(VMX_LOG_BUFFER, Entries) +
                                 (Copied * sizeof(VMX_LOG_ENTRY));
    return STATUS_SUCCESS;
}

static NTSTATUS HandleIoctlStop(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    BOOLEAN IsInitialized;

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStack);

    IsInitialized = (g_CpuVendor == CPU_VENDOR_INTEL && g_VmxState.Initialized) ||
                    (g_CpuVendor == CPU_VENDOR_AMD && g_SvmState.Initialized);

    if (!IsInitialized) {
        LOG_WARN("Hypervisor not initialized, nothing to stop");
        return STATUS_NOT_FOUND;
    }

    LOG_INFO("Stopping %s on all processors...", g_HvOps ? g_HvOps->Name : "HV");
    if (g_HvOps) {
        g_HvOps->Terminate();
    }

    return STATUS_SUCCESS;
}

static NTSTATUS HandleIoctlQueryStatus(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_STATUS Output;
    ULONG       i;
    ULONG       TotalExits = 0;
    BOOLEAN     IsActive;
    ULONG       CpuCount;

    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(VMX_STATUS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Output = (PVMX_STATUS)Irp->AssociatedIrp.SystemBuffer;
    if (!Output) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Determine active state based on backend */
    if (g_CpuVendor == CPU_VENDOR_INTEL) {
        IsActive = g_VmxState.Initialized;
        CpuCount = g_VmxState.CpuCount;
        for (i = 0; i < CpuCount; i++) {
            TotalExits += (ULONG)g_VmxState.CpuContexts[i].ExitCount;
        }
    } else if (g_CpuVendor == CPU_VENDOR_AMD) {
        IsActive = g_SvmState.Initialized;
        CpuCount = g_SvmState.CpuCount;
        for (i = 0; i < CpuCount; i++) {
            TotalExits += (ULONG)g_SvmState.CpuContexts[i].Common.ExitCount;
        }
    } else {
        IsActive = FALSE;
        CpuCount = 0;
    }

    Output->VmxActive = IsActive;
    Output->ActiveTargets = ProcessGetActiveCount();
    Output->CpuCount = CpuCount;
    Output->TotalExits = TotalExits;

    Irp->IoStatus.Information = sizeof(VMX_STATUS);
    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  Hypervisor Memory Read/Write IOCTL Handlers                              */
/* ========================================================================= */

/*
 * Helper: resolve PID to CR3 using existing process tracking infrastructure.
 * Must be called at PASSIVE_LEVEL.
 */
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);

static NTSTATUS ResolvePidToCr3(ULONG Pid, PULONG64 OutCr3)
{
    NTSTATUS    Status;
    PEPROCESS   Process = NULL;
    ULONG64     Cr3;

    if (!g_EprocessOffsets.Resolved) {
        return STATUS_NOT_SUPPORTED;
    }

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Cr3 = *(PULONG64)((PUCHAR)Process + g_EprocessOffsets.DirectoryTableBase);
    ObDereferenceObject(Process);

    if (Cr3 == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    *OutCr3 = Cr3;
    return STATUS_SUCCESS;
}

/*
 * Issue a VMCALL from the kernel driver to the Hypervisor.
 * On Intel: VMCALL instruction
 * On AMD:   VMMCALL instruction
 *
 * RAX = VMCALL_MAGIC | SubCommand
 * RDX = pointer to VMCALL_MEM_PARAMS
 *
 * The Hypervisor exit handler will pick this up and execute the operation
 * entirely in Ring -1, bypassing all Guest protections.
 */
extern void AsmVmxVmcall(void);

static NTSTATUS IssueMemoryVmcall(ULONG SubCommand, PVMCALL_MEM_PARAMS Params)
{
    /*
     * We use inline assembly approach: set RAX and RDX, then issue vmcall/vmmcall.
     * Since WDK 7600 for x64 doesn't support inline asm, we pass params through
     * a kernel-visible memory location and use existing VMCALL mechanism.
     *
     * Simpler approach: since we're in the kernel driver (Ring 0, Guest),
     * we can directly call the HvReadGuestMemory / HvWriteGuestMemory
     * functions IF we're not in VMX non-root. But since these functions
     * access physical memory via identity map, and we ARE running in Guest
     * (VMX non-root), we need the Hypervisor to do it.
     *
     * However, the identity map means Guest physical == Host virtual.
     * In our setup, the kernel driver runs in Guest mode, but the
     * identity-mapped physical memory is accessible from kernel VA
     * through MmMapIoSpace or similar. But the cleanest path is VMCALL.
     *
     * For simplicity and correctness, we'll do the page table walk and
     * physical memory access directly from the kernel driver, since
     * the EPT/NPT identity map means any Guest physical address is
     * accessible as a Host virtual address, and from the Guest kernel's
     * perspective, we can use MmGetVirtualForPhysical or similar.
     *
     * Actually, the simplest correct approach: just do it directly in
     * the IOCTL handler using MmMapIoSpace for the physical addresses.
     * This avoids VMCALL complexity entirely while still being invisible
     * to anti-cheat (no NtReadVirtualMemory, no KeStackAttachProcess).
     */

    /*
     * Direct physical memory approach (no VMCALL needed):
     * Walk target's page tables from kernel mode, then map and copy
     * the physical pages. Anti-cheat can't intercept this because
     * we never call any memory-access APIs on the target process.
     */
    UNREFERENCED_PARAMETER(SubCommand);
    UNREFERENCED_PARAMETER(Params);

    /* This is handled inline in the IOCTL handlers below */
    return STATUS_SUCCESS;
}

/*
 * Walk Guest page tables from kernel mode.
 * Since we're in kernel (Ring 0), we can use MmGetPhysicalAddress and
 * MmMapIoSpace to access physical memory directly.
 *
 * This is essentially the same page table walk as HvGuestVaToPa,
 * but done from Guest kernel mode using MmMapIoSpace for each level.
 */
static ULONG64 KernelGuestVaToPa(ULONG64 GuestCr3, ULONG64 VirtualAddress)
{
    PHYSICAL_ADDRESS PhysAddr;
    PVOID MappedPage;
    ULONG64 Entry;
    ULONG64 TableBase;

    /* Level 4: PML4 */
    TableBase = GuestCr3 & 0x000FFFFFFFFFF000ULL;
    PhysAddr.QuadPart = (LONGLONG)(TableBase + (((VirtualAddress >> 39) & 0x1FF) * 8));
    MappedPage = MmMapIoSpace(PhysAddr, sizeof(ULONG64), MmNonCached);
    if (!MappedPage) return 0;
    Entry = *(PULONG64)MappedPage;
    MmUnmapIoSpace(MappedPage, sizeof(ULONG64));
    if (!(Entry & 1)) return 0;

    /* Level 3: PDPT */
    TableBase = Entry & 0x000FFFFFFFFFF000ULL;
    PhysAddr.QuadPart = (LONGLONG)(TableBase + (((VirtualAddress >> 30) & 0x1FF) * 8));
    MappedPage = MmMapIoSpace(PhysAddr, sizeof(ULONG64), MmNonCached);
    if (!MappedPage) return 0;
    Entry = *(PULONG64)MappedPage;
    MmUnmapIoSpace(MappedPage, sizeof(ULONG64));
    if (!(Entry & 1)) return 0;
    if (Entry & (1ULL << 7))  /* 1GB page */
        return (Entry & 0x000FFFFFC0000000ULL) | (VirtualAddress & 0x3FFFFFFF);

    /* Level 2: PD */
    TableBase = Entry & 0x000FFFFFFFFFF000ULL;
    PhysAddr.QuadPart = (LONGLONG)(TableBase + (((VirtualAddress >> 21) & 0x1FF) * 8));
    MappedPage = MmMapIoSpace(PhysAddr, sizeof(ULONG64), MmNonCached);
    if (!MappedPage) return 0;
    Entry = *(PULONG64)MappedPage;
    MmUnmapIoSpace(MappedPage, sizeof(ULONG64));
    if (!(Entry & 1)) return 0;
    if (Entry & (1ULL << 7))  /* 2MB page */
        return (Entry & 0x000FFFFFFFE00000ULL) | (VirtualAddress & 0x1FFFFF);

    /* Level 1: PT */
    TableBase = Entry & 0x000FFFFFFFFFF000ULL;
    PhysAddr.QuadPart = (LONGLONG)(TableBase + (((VirtualAddress >> 12) & 0x1FF) * 8));
    MappedPage = MmMapIoSpace(PhysAddr, sizeof(ULONG64), MmNonCached);
    if (!MappedPage) return 0;
    Entry = *(PULONG64)MappedPage;
    MmUnmapIoSpace(MappedPage, sizeof(ULONG64));
    if (!(Entry & 1)) return 0;

    return (Entry & 0x000FFFFFFFFFF000ULL) | (VirtualAddress & 0xFFF);
}

/*
 * Copy memory between kernel buffer and target process physical memory.
 * Walks target CR3 page tables, maps physical pages, copies data.
 * Handles page boundary crossing.
 */
static NTSTATUS KernelCopyProcessMemory(
    ULONG64     TargetCr3,
    ULONG64     TargetVa,
    PVOID       KernelBuffer,
    ULONG       Size,
    BOOLEAN     IsRead     /* TRUE=read from target, FALSE=write to target */
)
{
    ULONG       BytesDone = 0;
    PUCHAR      Buffer = (PUCHAR)KernelBuffer;

    while (BytesDone < Size) {
        ULONG64             TargetPa;
        ULONG               PageOffset;
        ULONG               ChunkSize;
        PHYSICAL_ADDRESS    PhysAddr;
        PVOID               MappedPage;

        TargetPa = KernelGuestVaToPa(TargetCr3, TargetVa + BytesDone);
        if (TargetPa == 0) {
            LOG_DEBUG("KernelCopyProcessMemory: VA 0x%llX not present", TargetVa + BytesDone);
            return STATUS_INVALID_ADDRESS;
        }

        PageOffset = (ULONG)(TargetPa & 0xFFF);
        ChunkSize = 0x1000 - PageOffset;
        if (ChunkSize > (Size - BytesDone)) {
            ChunkSize = Size - BytesDone;
        }

        /* Map the physical page */
        PhysAddr.QuadPart = (LONGLONG)(TargetPa & ~0xFFFULL);
        MappedPage = MmMapIoSpace(PhysAddr, 0x1000, MmNonCached);
        if (!MappedPage) {
            LOG_DEBUG("KernelCopyProcessMemory: MmMapIoSpace failed for PA 0x%llX", TargetPa);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        __try {
            if (IsRead) {
                RtlCopyMemory(Buffer + BytesDone, (PUCHAR)MappedPage + PageOffset, ChunkSize);
            } else {
                RtlCopyMemory((PUCHAR)MappedPage + PageOffset, Buffer + BytesDone, ChunkSize);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            MmUnmapIoSpace(MappedPage, 0x1000);
            return STATUS_ACCESS_VIOLATION;
        }

        MmUnmapIoSpace(MappedPage, 0x1000);
        BytesDone += ChunkSize;
    }

    return STATUS_SUCCESS;
}

/*
 * IOCTL_VMX_READ_MEMORY handler
 *
 * Input:  VMX_MEMORY_REQUEST (Pid, VirtualAddress, Size)
 * Output: Raw bytes (Size bytes)
 *
 * Flow:
 *   1. Resolve PID -> CR3 (via EPROCESS)
 *   2. Walk target's CR3 page tables to find physical pages
 *   3. Map physical pages and copy data to output buffer
 *
 * Invisible to anti-cheat because:
 *   - No OpenProcess / handle creation
 *   - No NtReadVirtualMemory / MmCopyVirtualMemory
 *   - No KeStackAttachProcess
 *   - Direct physical memory access via MmMapIoSpace
 */
static NTSTATUS HandleIoctlReadMemory(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_MEMORY_REQUEST Input;
    PVOID               OutputBuffer;
    ULONG               OutputSize;
    ULONG64             TargetCr3 = 0;
    NTSTATUS            Status;

    /* Validate input */
    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(VMX_MEMORY_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Input = (PVMX_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    if (!Input) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Input->Size == 0 || Input->Size > VMX_MEM_MAX_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Input->VirtualAddress == 0) {
        return STATUS_INVALID_ADDRESS;
    }

    /* Validate output buffer */
    OutputSize = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (OutputSize < Input->Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    OutputBuffer = Irp->AssociatedIrp.SystemBuffer;

    /* Resolve PID -> CR3 */
    Status = ResolvePidToCr3(Input->Pid, &TargetCr3);
    if (!NT_SUCCESS(Status)) {
        LOG_DEBUG("ReadMemory: Failed to resolve CR3 for PID %u: 0x%08X", Input->Pid, Status);
        return Status;
    }

    /* Read via physical memory access */
    Status = KernelCopyProcessMemory(TargetCr3, Input->VirtualAddress,
                                      OutputBuffer, Input->Size, TRUE);
    if (NT_SUCCESS(Status)) {
        Irp->IoStatus.Information = Input->Size;
    }

    return Status;
}

/*
 * IOCTL_VMX_WRITE_MEMORY handler
 *
 * Input layout: [VMX_MEMORY_REQUEST header][payload bytes...]
 * Total InputBufferLength = sizeof(VMX_MEMORY_REQUEST) + Size
 */
static NTSTATUS HandleIoctlWriteMemory(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_MEMORY_REQUEST Input;
    PVOID               PayloadData;
    ULONG               InputSize;
    ULONG64             TargetCr3 = 0;
    NTSTATUS            Status;

    InputSize = IoStack->Parameters.DeviceIoControl.InputBufferLength;

    /* Need at least the header */
    if (InputSize < sizeof(VMX_MEMORY_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    Input = (PVMX_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    if (!Input) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Input->Size == 0 || Input->Size > VMX_MEM_MAX_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Input->VirtualAddress == 0) {
        return STATUS_INVALID_ADDRESS;
    }

    /* Validate that payload is present */
    if (InputSize < sizeof(VMX_MEMORY_REQUEST) + Input->Size) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Payload immediately follows the header */
    PayloadData = (PUCHAR)Input + sizeof(VMX_MEMORY_REQUEST);

    /* Resolve PID -> CR3 */
    Status = ResolvePidToCr3(Input->Pid, &TargetCr3);
    if (!NT_SUCCESS(Status)) {
        LOG_DEBUG("WriteMemory: Failed to resolve CR3 for PID %u: 0x%08X", Input->Pid, Status);
        return Status;
    }

    /* Write via physical memory access */
    Status = KernelCopyProcessMemory(TargetCr3, Input->VirtualAddress,
                                      PayloadData, Input->Size, FALSE);

    return Status;
}

/* ========================================================================= */
/*  Universal Hook Framework IOCTL Handlers                                  */
/* ========================================================================= */

static NTSTATUS HandleIoctlInstallHook(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_HOOK_REQUEST   Input;
    PVMX_HOOK_RESPONSE  Output;
    ULONG64             TargetVa = 0;
    ULONG               HookId = 0;
    NTSTATUS            Status;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(VMX_HOOK_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(VMX_HOOK_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    Input = (PVMX_HOOK_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    Output = (PVMX_HOOK_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    if (!Input) return STATUS_INVALID_PARAMETER;

    /* Resolve target address */
    if (Input->ByName) {
        UNICODE_STRING FuncName;
        PVOID Addr;
        RtlInitUnicodeString(&FuncName, Input->FunctionName);
        Addr = MmGetSystemRoutineAddress(&FuncName);
        if (!Addr) {
            LOG_WARN("InstallHook: Cannot resolve '%wZ'", &FuncName);
            return STATUS_NOT_FOUND;
        }
        TargetVa = (ULONG64)Addr;
    } else {
        if (Input->TargetAddress == 0) return STATUS_INVALID_PARAMETER;
        TargetVa = Input->TargetAddress;
    }

    Status = GenericHookInstall(
        TargetVa,
        Input->ProcessId,
        Input->ByName ? Input->FunctionName : NULL,
        &Input->Rule,
        &HookId
    );

    if (NT_SUCCESS(Status)) {
        Output->HookId = HookId;
        Output->ResolvedAddress = TargetVa;
        Irp->IoStatus.Information = sizeof(VMX_HOOK_RESPONSE);
    }

    return Status;
}

static NTSTATUS HandleIoctlRemoveHook(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_UNHOOK_REQUEST Input;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(VMX_UNHOOK_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    Input = (PVMX_UNHOOK_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    if (!Input) return STATUS_INVALID_PARAMETER;

    return GenericHookRemove(Input->HookId);
}

static NTSTATUS HandleIoctlListHooks(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_HOOK_LIST      Output;
    ULONG               OutputSize, MaxEntries, Count;
    PGENERIC_HOOK_ENTRY Entry;

    OutputSize = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (OutputSize < sizeof(VMX_HOOK_LIST))
        return STATUS_BUFFER_TOO_SMALL;

    Output = (PVMX_HOOK_LIST)Irp->AssociatedIrp.SystemBuffer;
    if (!Output) return STATUS_INVALID_PARAMETER;

    MaxEntries = (OutputSize - FIELD_OFFSET(VMX_HOOK_LIST, Hooks)) / sizeof(VMX_HOOK_INFO);
    Count = 0;

    Entry = g_GenericHookState.HookListHead;
    while (Entry && Count < MaxEntries) {
        if (Entry->Active) {
            GenericHookGetInfo(Entry->HookId, &Output->Hooks[Count]);
            Count++;
        }
        Entry = Entry->Next;
    }

    Output->Count = Count;
    Irp->IoStatus.Information = FIELD_OFFSET(VMX_HOOK_LIST, Hooks) +
                                 Count * sizeof(VMX_HOOK_INFO);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleIoctlGetHookEvents(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PVMX_HOOK_EVENT_BUFFER  Output;
    ULONG                   OutputSize, MaxEntries, Copied;

    OutputSize = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (OutputSize < sizeof(VMX_HOOK_EVENT_BUFFER))
        return STATUS_BUFFER_TOO_SMALL;

    Output = (PVMX_HOOK_EVENT_BUFFER)Irp->AssociatedIrp.SystemBuffer;
    if (!Output) return STATUS_INVALID_PARAMETER;

    MaxEntries = (OutputSize - FIELD_OFFSET(VMX_HOOK_EVENT_BUFFER, Events)) / sizeof(HOOK_EVENT);

    Copied = HookLogRead(Output->Events, MaxEntries);
    Output->Count = Copied;

    Irp->IoStatus.Information = FIELD_OFFSET(VMX_HOOK_EVENT_BUFFER, Events) +
                                 Copied * sizeof(HOOK_EVENT);
    return STATUS_SUCCESS;
}
