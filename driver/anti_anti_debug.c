/*
 * anti_anti_debug.c - VMX Anti-Anti-Debug Hypervisor
 * Core anti-anti-debug engine: DR spoofing, TSC compensation,
 * CPUID hiding, EPT hooks on Nt* APIs, exception normalization
 */

#include "anti_anti_debug.h"
#include "ept.h"
#include "hv_ops.h"
#include "hv_detect.h"
#include "hv_hypercall.h"
#include "log.h"
#include "../common/shared.h"
#include <ntstrsafe.h>

/* ========================================================================= */
/*  Global State                                                             */
/* ========================================================================= */

AAD_STATE g_AadState = { 0 };

/* ========================================================================= */
/*  Kernel Address Resolution                                                */
/* ========================================================================= */

/*
 * Resolve ntoskrnl export by name using MmGetSystemRoutineAddress
 */
static ULONG64 ResolveKernelExport(const WCHAR *FunctionName)
{
    UNICODE_STRING Name;
    PVOID Addr;
    RtlInitUnicodeString(&Name, FunctionName);
    Addr = MmGetSystemRoutineAddress(&Name);
    return (ULONG64)Addr;
}

/* ========================================================================= */
/*  EPT Hook Handlers (replacement functions)                                */
/* ========================================================================= */

/*
 * Hooked NtQueryInformationProcess
 * Spoofs debug-related information classes for target processes
 */
static NTSTATUS NTAPI HookNtQueryInformationProcess(
    HANDLE  ProcessHandle,
    ULONG   ProcessInformationClass,
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength,
    PULONG  ReturnLength
)
{
    NTSTATUS Status;
    PEPROCESS CurrentProcess;
    ULONG CurrentPid;
    ULONG64 CurrentCr3;
    PTARGET_PROCESS Target;

    /* Call original function first */
    Status = g_AadState.OrigNtQueryInformationProcess(
        ProcessHandle,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationLength,
        ReturnLength
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /* Check if current process is a target */
    CurrentProcess = PsGetCurrentProcess();
    CurrentPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    /*
     * We check by PID here since we're in the context of the calling process.
     * For a more robust check, we could look up CR3.
     */
    CurrentCr3 = __readcr3();
    Target = ProcessFindByCr3(CurrentCr3);

    if (!Target || !(Target->Flags & AAD_HIDE_DEBUGGER)) {
        return Status;
    }

    /* Spoof debug information */
    __try {
        switch (ProcessInformationClass) {
        case ProcessDebugPort:
            /*
             * ProcessDebugPort (7): Returns debug port.
             * Non-zero means being debugged.
             * Spoof: set to 0 (not being debugged)
             */
            if (ProcessInformation && ProcessInformationLength >= sizeof(ULONG_PTR)) {
                *(PULONG_PTR)ProcessInformation = 0;
                LOG_DEBUG_PID(CurrentPid, "Spoofed ProcessDebugPort = 0");
            }
            break;

        case ProcessDebugObjectHandle:
            /*
             * ProcessDebugObjectHandle (0x1E): Returns debug object handle.
             * Success means being debugged.
             * Spoof: return STATUS_PORT_NOT_SET
             */
            if (ProcessInformation && ProcessInformationLength >= sizeof(HANDLE)) {
                *(PHANDLE)ProcessInformation = NULL;
                Status = (NTSTATUS)0xC0000353L;  /* STATUS_PORT_NOT_SET */
                LOG_DEBUG_PID(CurrentPid, "Spoofed ProcessDebugObjectHandle = STATUS_PORT_NOT_SET");
            }
            break;

        case ProcessDebugFlags:
            /*
             * ProcessDebugFlags (0x1F): Returns NoDebugInherit flag.
             * 0 means being debugged, 1 means not.
             * Spoof: set to 1 (not being debugged)
             */
            if (ProcessInformation && ProcessInformationLength >= sizeof(ULONG)) {
                *(PULONG)ProcessInformation = 1;
                LOG_DEBUG_PID(CurrentPid, "Spoofed ProcessDebugFlags = 1");
            }
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Invalid user buffer - just return original status */
    }

    return Status;
}

/*
 * Hooked NtQuerySystemInformation
 * Spoofs SystemKernelDebuggerInformation
 */
static NTSTATUS NTAPI HookNtQuerySystemInformation(
    ULONG   SystemInformationClass,
    PVOID   SystemInformation,
    ULONG   SystemInformationLength,
    PULONG  ReturnLength
)
{
    NTSTATUS Status;
    ULONG64 CurrentCr3;

    /* Call original */
    Status = g_AadState.OrigNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /* Check if caller is a target process */
    CurrentCr3 = __readcr3();
    if (!IsFeatureEnabled(CurrentCr3, AAD_HIDE_SYSINFO)) {
        return Status;
    }

    __try {
        if (SystemInformationClass == SystemKernelDebuggerInformation) {
            PSYSTEM_KERNEL_DEBUGGER_INFORMATION Info =
                (PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;

            if (SystemInformationLength >= sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION)) {
                Info->KernelDebuggerEnabled = FALSE;
                Info->KernelDebuggerNotPresent = TRUE;
                LOG_DEBUG("Spoofed SystemKernelDebuggerInformation");
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Invalid buffer */
    }

    return Status;
}

/*
 * Hooked NtSetInformationThread
 * Blocks ThreadHideFromDebugger (0x11)
 */
static NTSTATUS NTAPI HookNtSetInformationThread(
    HANDLE  ThreadHandle,
    ULONG   ThreadInformationClass,
    PVOID   ThreadInformation,
    ULONG   ThreadInformationLength
)
{
    ULONG64 CurrentCr3 = __readcr3();

    /*
     * ThreadHideFromDebugger (0x11): Hides thread from debugger.
     * If target process calls this, we block it by returning success
     * without actually calling the original function.
     */
    if (ThreadInformationClass == 0x11 &&
        IsFeatureEnabled(CurrentCr3, AAD_HIDE_THREADINFO)) {
        LOG_DEBUG("Blocked NtSetInformationThread(ThreadHideFromDebugger)");
        return STATUS_SUCCESS;  /* Pretend it succeeded */
    }

    return g_AadState.OrigNtSetInformationThread(
        ThreadHandle,
        ThreadInformationClass,
        ThreadInformation,
        ThreadInformationLength
    );
}

/*
 * Hooked NtClose
 * Prevents NtClose with invalid handle from triggering exception
 * (anti-debug trick: debugger catches the exception, non-debugged app doesn't)
 */
static NTSTATUS NTAPI HookNtClose(HANDLE Handle)
{
    ULONG64 CurrentCr3 = __readcr3();

    if (IsFeatureEnabled(CurrentCr3, AAD_HIDE_NTCLOSE)) {
        /*
         * Instead of letting NtClose potentially raise an exception
         * (STATUS_HANDLE_NOT_CLOSABLE or STATUS_INVALID_HANDLE),
         * we wrap the call and suppress exceptions.
         */
        NTSTATUS Status;

        __try {
            Status = g_AadState.OrigNtClose(Handle);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
            LOG_DEBUG("Suppressed NtClose exception: 0x%08X", Status);
        }

        return Status;
    }

    return g_AadState.OrigNtClose(Handle);
}

/* ========================================================================= */
/*  Initialization                                                           */
/* ========================================================================= */

NTSTATUS AadInitialize(VOID)
{
    RtlZeroMemory(&g_AadState, sizeof(AAD_STATE));

    /* Resolve kernel function addresses */
    g_AadState.NtQueryInformationProcessAddr =
        ResolveKernelExport(L"NtQueryInformationProcess");
    g_AadState.NtQuerySystemInformationAddr =
        ResolveKernelExport(L"NtQuerySystemInformation");
    g_AadState.NtSetInformationThreadAddr =
        ResolveKernelExport(L"NtSetInformationThread");
    g_AadState.NtCloseAddr =
        ResolveKernelExport(L"NtClose");

    if (!g_AadState.NtQueryInformationProcessAddr) {
        LOG_ERROR("Failed to resolve NtQueryInformationProcess");
        return STATUS_NOT_FOUND;
    }

    LOG_INFO("Resolved NtQueryInformationProcess: 0x%llX", g_AadState.NtQueryInformationProcessAddr);
    LOG_INFO("Resolved NtQuerySystemInformation:  0x%llX", g_AadState.NtQuerySystemInformationAddr);
    LOG_INFO("Resolved NtSetInformationThread:    0x%llX", g_AadState.NtSetInformationThreadAddr);
    LOG_INFO("Resolved NtClose:                   0x%llX", g_AadState.NtCloseAddr);

    g_AadState.Initialized = TRUE;
    return STATUS_SUCCESS;
}

VOID AadCleanup(VOID)
{
    AadRemoveHooks();
    g_AadState.Initialized = FALSE;
}

/* ========================================================================= */
/*  EPT Hook Installation                                                    */
/* ========================================================================= */

NTSTATUS AadInstallHooks(VOID)
{
    NTSTATUS Status;

    if (!g_AadState.Initialized) {
        Status = AadInitialize();
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    /* Hook NtQueryInformationProcess */
    if (g_AadState.NtQueryInformationProcessAddr) {
        Status = HvHookFunction(
            g_AadState.NtQueryInformationProcessAddr,
            (PVOID)HookNtQueryInformationProcess,
            (PVOID *)&g_AadState.OrigNtQueryInformationProcess
        );
        if (NT_SUCCESS(Status)) {
            LOG_INFO("Hook installed: NtQueryInformationProcess");
        } else {
            LOG_WARN("Failed to hook NtQueryInformationProcess: 0x%08X", Status);
        }
    }

    /* Hook NtQuerySystemInformation */
    if (g_AadState.NtQuerySystemInformationAddr) {
        Status = HvHookFunction(
            g_AadState.NtQuerySystemInformationAddr,
            (PVOID)HookNtQuerySystemInformation,
            (PVOID *)&g_AadState.OrigNtQuerySystemInformation
        );
        if (NT_SUCCESS(Status)) {
            LOG_INFO("Hook installed: NtQuerySystemInformation");
        } else {
            LOG_WARN("Failed to hook NtQuerySystemInformation: 0x%08X", Status);
        }
    }

    /* Hook NtSetInformationThread */
    if (g_AadState.NtSetInformationThreadAddr) {
        Status = HvHookFunction(
            g_AadState.NtSetInformationThreadAddr,
            (PVOID)HookNtSetInformationThread,
            (PVOID *)&g_AadState.OrigNtSetInformationThread
        );
        if (NT_SUCCESS(Status)) {
            LOG_INFO("Hook installed: NtSetInformationThread");
        } else {
            LOG_WARN("Failed to hook NtSetInformationThread: 0x%08X", Status);
        }
    }

    /* Hook NtClose */
    if (g_AadState.NtCloseAddr) {
        Status = HvHookFunction(
            g_AadState.NtCloseAddr,
            (PVOID)HookNtClose,
            (PVOID *)&g_AadState.OrigNtClose
        );
        if (NT_SUCCESS(Status)) {
            LOG_INFO("Hook installed: NtClose");
        } else {
            LOG_WARN("Failed to hook NtClose: 0x%08X", Status);
        }
    }

    return STATUS_SUCCESS;
}

VOID AadRemoveHooks(VOID)
{
    if (g_AadState.NtQueryInformationProcessAddr)
        HvUnhookFunction(g_AadState.NtQueryInformationProcessAddr);
    if (g_AadState.NtQuerySystemInformationAddr)
        HvUnhookFunction(g_AadState.NtQuerySystemInformationAddr);
    if (g_AadState.NtSetInformationThreadAddr)
        HvUnhookFunction(g_AadState.NtSetInformationThreadAddr);
    if (g_AadState.NtCloseAddr)
        HvUnhookFunction(g_AadState.NtCloseAddr);

    LOG_INFO("All anti-anti-debug hooks removed");
}

/* ========================================================================= */
/*  Debug Register Access Handler                                            */
/* ========================================================================= */

/*
 * Handle MOV-DR exit for target processes.
 * Spoofs DR0-DR7 to hide hardware breakpoints.
 */
BOOLEAN AadHandleDrAccess(PGUEST_CONTEXT GuestContext)
{
    ULONG64     ExitQual;
    ULONG       DrNumber;
    ULONG       Direction;
    ULONG       GpReg;
    ULONG64     GuestCr3;
    PULONG64    RegPtr;
    ULONG64     *GpRegs;

    ExitQual = HvReadExitQualification();
    DrNumber  = (ULONG)(ExitQual & DR_ACCESS_REG_MASK);
    Direction = (ULONG)((ExitQual >> DR_ACCESS_DIRECTION_BIT) & 1);
    GpReg     = (ULONG)((ExitQual >> DR_ACCESS_GP_REG_SHIFT) & DR_ACCESS_GP_REG_MASK);

    GuestCr3 = HvReadGuestCr3();

    /* Map GP register number to GUEST_CONTEXT field */
    GpRegs = (ULONG64 *)GuestContext;  /* RAX=0, RCX=1, RDX=2, ... */
    if (GpReg > 15) {
        /* Invalid register - shouldn't happen */
        HvAdvanceGuestRip();
        return TRUE;
    }

    /*
     * BUG FIX: GpReg=4 means RSP. The GUEST_CONTEXT.Rsp field is just a
     * placeholder — the actual Guest RSP lives in the VMCS. We must use
     * the VMCS read/write path for RSP, same as the CR access handler does.
     * Using the placeholder would read/write garbage and corrupt guest state.
     */
    /*
     * RSP handling: With the unified RSP sync at VM-Exit entry
     * (VmxExitHandler/SvmExitHandler reads VMCS/VMCB Guest RSP into
     * GuestContext->Rsp), GpRegs[4] is now always valid. No special
     * case needed for GpReg==4 anymore. The write-back to VMCS/VMCB
     * happens at VM-Exit exit.
     */
    RegPtr = &GpRegs[GpReg];

    if (!IsFeatureEnabled(GuestCr3, AAD_HIDE_HWBP)) {
        /* Not a target - execute the instruction normally */
        if (Direction == DR_ACCESS_DIRECTION_READ) {
            /*
             * MOV FROM DR (read): Read real DR value and write to guest GP register.
             *
             * VERIFIED CORRECT: The value is written back via `*RegPtr = DrValue`
             * which writes directly into GpRegs[GpReg] (the GUEST_CONTEXT array).
             * This correctly updates the guest register state.
             *
             * HyperDbg had a bug where MOV FROM DR used a local variable without
             * writing the result back to the guest register. VMXToolbox does NOT
             * have this bug — `RegPtr` points directly into the GUEST_CONTEXT,
             * and with unified RSP sync at VM-Exit entry, GpRegs[4] (RSP) is
             * also valid, so no special case is needed for any register index.
             */
            ULONG64 DrValue = 0;
            switch (DrNumber) {
                case 0: DrValue = __readdr(0); break;
                case 1: DrValue = __readdr(1); break;
                case 2: DrValue = __readdr(2); break;
                case 3: DrValue = __readdr(3); break;
                case 6: DrValue = __readdr(6); break;
                case 7: DrValue = __readdr(7); break;
            }
            *RegPtr = DrValue;
        } else {
            /* MOV to DR from GP - write real DR value */
            ULONG64 Value = *RegPtr;
            switch (DrNumber) {
                case 0: __writedr(0, Value); break;
                case 1: __writedr(1, Value); break;
                case 2: __writedr(2, Value); break;
                case 3: __writedr(3, Value); break;
                case 6: __writedr(6, Value); break;
                case 7: __writedr(7, Value); break;
            }
        }
        HvAdvanceGuestRip();
        return TRUE;
    }

    /* === Target process: spoof DR values === */

    if (Direction == DR_ACCESS_DIRECTION_READ) {
        /*
         * Reading DR - return fake (spoofed) values.
         * VERIFIED CORRECT: FakeValue is written back via `*RegPtr = FakeValue`
         * which correctly updates the guest register in GUEST_CONTEXT.
         */
        ULONG64 FakeValue = 0;

        switch (DrNumber) {
        case 0: case 1: case 2: case 3:
            /* DR0-DR3: Hardware breakpoint addresses - return 0 */
            FakeValue = 0;
            break;

        case 6:
            /* DR6: Debug status - return clean value */
            FakeValue = DR6_DEFAULT_VALUE;
            break;

        case 7:
            /* DR7: Debug control - return default (no BPs active) */
            FakeValue = DR7_DEFAULT_VALUE;
            break;

        default:
            FakeValue = 0;
            break;
        }

        *RegPtr = FakeValue;
        VMXROOT_LOG_DEBUG("DR%u read spoofed: returned 0x%llX", DrNumber, FakeValue);

    } else {
        /* Writing DR - allow but silently consume for DR0-3 visibility */
        ULONG64 Value = *RegPtr;

        /*
         * We still write the real DR values so hardware breakpoints work,
         * but we hide them from reads.
         */
        switch (DrNumber) {
            case 0: __writedr(0, Value); break;
            case 1: __writedr(1, Value); break;
            case 2: __writedr(2, Value); break;
            case 3: __writedr(3, Value); break;
            case 6: __writedr(6, Value); break;
            case 7: __writedr(7, Value); break;
        }
    }

    HvAdvanceGuestRip();
    return TRUE;
}

/* ========================================================================= */
/*  TSC Offset Management (Hardware TSC Offsetting)                          */
/* ========================================================================= */

/*
 * Update the hardware TSC Offset (VMCS/VMCB) based on the current process.
 *
 * Called on CR3 load (process context switch) to apply or clear the TSC
 * compensation. For target processes with AAD_HIDE_TIMING, we write the
 * accumulated TscOffset as a negative hardware offset so that RDTSC/RDTSCP
 * automatically returns adjusted values without VM-Exit.
 *
 * For non-target processes, we reset the hardware offset to 0.
 */
VOID AadUpdateHwTscOffset(ULONG64 NewCr3)
{
    PHV_CPU_CONTEXT HvCtx;

    if (!g_HvOps) return;

    HvCtx = g_HvOps->GetCurrentCpuContext();
    if (!HvCtx) return;

    if (IsFeatureEnabled(NewCr3, AAD_HIDE_TIMING)) {
        /* Target process: apply accumulated debug-pause offset */
        HvWriteTscOffset(HvCtx->TscOffset);
    } else {
        /* Non-target process: no TSC adjustment */
        HvWriteTscOffset(0);
    }
}

/*
 * Notify that debugging has paused execution (e.g., breakpoint hit)
 * Called when we detect the debugger has taken control
 */
VOID AadNotifyDebugPause(ULONG CpuIndex)
{
    if (CpuIndex < g_MaxProcessors && g_HvOps) {
        PHV_CPU_CONTEXT HvCtx = g_HvOps->GetCurrentCpuContext();
        if (HvCtx && !HvCtx->InDebugPause) {
            HvCtx->LastDebugPauseTsc = __rdtsc();
            HvCtx->InDebugPause = TRUE;
        }
    }
}

/*
 * Notify that debugging has resumed execution
 * Accumulate the paused time into TscOffset
 */
VOID AadNotifyDebugResume(ULONG CpuIndex)
{
    if (CpuIndex < g_MaxProcessors && g_HvOps) {
        PHV_CPU_CONTEXT HvCtx = g_HvOps->GetCurrentCpuContext();
        if (HvCtx && HvCtx->InDebugPause) {
            ULONG64 Now = __rdtsc();
            ULONG64 PauseDuration = Now - HvCtx->LastDebugPauseTsc;
            HvCtx->TscOffset += (LONG64)PauseDuration;
            HvCtx->InDebugPause = FALSE;

            /*
             * Immediately update the hardware TSC Offset so the resumed
             * guest process sees compensated TSC values right away.
             * Only apply if the current process is a target with timing hide.
             */
            {
                ULONG64 GuestCr3 = HvReadGuestCr3();
                if (IsFeatureEnabled(GuestCr3, AAD_HIDE_TIMING)) {
                    HvWriteTscOffset(HvCtx->TscOffset);
                }
            }
        }
    }
}

/* ========================================================================= */
/*  CPUID Handler                                                            */
/* ========================================================================= */

/*
 * Handle CPUID to hide hypervisor presence from target processes.
 */
BOOLEAN AadHandleCpuid(PGUEST_CONTEXT GuestContext)
{
    int         CpuInfo[4] = { 0 };
    ULONG       Leaf = (ULONG)GuestContext->Rax;
    ULONG       SubLeaf = (ULONG)GuestContext->Rcx;
    ULONG64     GuestCr3;

    GuestCr3 = HvReadGuestCr3();

    /* Execute real CPUID */
    __cpuidex(CpuInfo, Leaf, SubLeaf);

    /*
     * CPUID Leaf 1 (ECX): Hypervisor Presence and VMX capability.
     *
     * CRITICAL DESIGN DECISION for nested virtualization (VMware L0):
     *
     * Windows already decided at boot time to use VMCALL enlightenments
     * because VMware (L0) advertised CPUID.1:ECX[31]=1. That decision
     * is CACHED and cannot be un-done by clearing the bit later.
     *
     * Previous approach: Clear bit 31 → Windows "thinks" no hypervisor,
     * but STILL uses cached VMCALL paths → contradictory state.
     *
     * New approach: KEEP bit 31 set (hypervisor present), and provide
     * minimal compatible hypervisor CPUID leaves (0x40000000+) that
     * tell Windows we support the enlightenments it's already using.
     * This way Windows's cached decision is consistent with what
     * CPUID reports.
     *
     * We still hide VMX (bit 5) to prevent nested VM creation.
     */
    if (Leaf == 1) {
        /* KEEP hypervisor present bit (bit 31) — Windows already cached it */
        /* CpuInfo[2] &= ~(1 << CPUID_HYPERVISOR_BIT); -- REMOVED */
        CpuInfo[2] &= ~(1 << 5);                       /* Hide VMX (Intel VT-x) */
    }
    else if (Leaf == 0x80000001) {
        /*
         * AMD extended features: hide SVM capability (ECX bit 2).
         * This prevents guest OS / nested hypervisors from detecting
         * SVM support and attempting VMRUN, which we intercept as #UD.
         */
        CpuInfo[2] &= ~(1 << 2);                       /* Hide SVM (AMD-V) */
    }
    else if (Leaf == 0x8000000A) {
        /*
         * AMD SVM features leaf: zero out entirely.
         * This leaf reports SVM revision, number of ASIDs, and NPT support.
         * Returning zeros prevents nested SVM detection at any depth.
         */
        CpuInfo[0] = 0;
        CpuInfo[1] = 0;
        CpuInfo[2] = 0;
        CpuInfo[3] = 0;
    }
    else if (Leaf == 0x40000000) {
        /*
         * Hypervisor identification leaf.
         *
         * EAX = Maximum hypervisor CPUID leaf
         * EBX/ECX/EDX = Hypervisor vendor signature.
         *
         * CRITICAL DESIGN: Split behavior based on outer hypervisor presence.
         *
         * NESTED MODE (g_OuterHypervisorPresent == TRUE):
         *   Windows already saw CPUID.1:ECX[31]=1 at boot and cached the
         *   decision to use VMCALL enlightenments (SwapContext TLB flush, etc.).
         *   We MUST report "Microsoft Hv" + "Hv#1" so Windows's cached decision
         *   remains consistent. The hypercalls are emulated in hv_hypercall.c.
         *
         * BARE METAL (g_OuterHypervisorPresent == FALSE):
         *   Windows booted without seeing any hypervisor. It never cached
         *   VMCALL enlightenment decisions. We return "Hv#0" (non-conformant)
         *   to prevent Windows from trying to use Hyper-V Synthetic MSRs
         *   (0x40000100+) which don't exist on real hardware and would cause
         *   #GP in VMX root mode.
         *
         * This dual-mode approach is the safest:
         * - Nested: maintains compatibility with already-cached VMCALL paths
         * - Bare metal: prevents BSOD 0x1AA from Synthetic MSR writes
         */
        if (g_OuterHypervisorPresent) {
            /* Nested mode: maintain Microsoft Hv compatibility */
            CpuInfo[0] = 0x40000006;   /* Max leaf = 0x40000006 (standard range) */
            CpuInfo[1] = 0x7263694D;   /* "Micr" */
            CpuInfo[2] = 0x666F736F;   /* "osof" */
            CpuInfo[3] = 0x76482074;   /* "t Hv" */
        } else {
            /* Bare metal: don't claim Microsoft Hv conformance */
            CpuInfo[0] = 0x40000001;   /* Max leaf = 0x40000001 (minimal) */
            CpuInfo[1] = 0x7263694D;   /* "Micr" */
            CpuInfo[2] = 0x666F736F;   /* "osof" */
            CpuInfo[3] = 0x76482074;   /* "t Hv" */
        }
    }
    else if (Leaf == 0x40000001) {
        /*
         * Hypervisor interface identification.
         *
         * NESTED MODE: "Hv#1" = standard Hyper-V interface.
         *   Windows uses the standard VMCALL-based hypercall ABI, which we
         *   emulate in hv_hypercall.c. This is required because Windows has
         *   already compiled VMCALL into kernel hot paths.
         *
         * BARE METAL: "Hv#0" = non-conformant interface.
         *   Tells Windows we do NOT conform to the Microsoft Hv interface.
         *   Windows will NOT attempt to use Hyper-V Synthetic MSRs or SynIC,
         *   preventing BSOD from writes to non-existent MSRs 0x40000100+.
         *   Similar to HyperDbg's approach ("Hv#0").
         */
        if (g_OuterHypervisorPresent) {
            CpuInfo[0] = 0x31237648;   /* "Hv#1" — Microsoft Hv conformant */
        } else {
            CpuInfo[0] = 0x30237648;   /* "Hv#0" — NOT conformant */
        }
        CpuInfo[1] = 0;
        CpuInfo[2] = 0;
        CpuInfo[3] = 0;
    }
    else if (Leaf == 0x40000002) {
        /*
         * Leaf 0x40000002: Build version info.
         * Return zeros — no specific build version to report.
         */
        CpuInfo[0] = 0;
        CpuInfo[1] = 0;
        CpuInfo[2] = 0;
        CpuInfo[3] = 0;
    }
    else if (Leaf == 0x40000003) {
        /*
         * Leaf 0x40000003: HV_X64_CPUID_FEATURES (Partition Privilege Flags).
         *
         * This tells Windows which Hyper-V enlightenments we support.
         * In nested mode (g_OuterHypervisorPresent), we MUST advertise
         * the features that Windows already cached at boot time, otherwise
         * Windows may hang when it re-queries features and finds them
         * missing (inconsistent with cached decisions).
         *
         * EAX = Partition Privileges (low 32 bits):
         *   Bit 0:  AccessVpRunTimeReg       — VP runtime MSR
         *   Bit 1:  AccessPartitionReferenceCounter — reference TSC
         *   Bit 2:  AccessSynicRegs          — SynIC MSRs (SCONTROL, SIEFP, etc.)
         *   Bit 3:  AccessSyntheticTimerRegs — Synthetic Timer MSRs (0x400000B0+)
         *   Bit 4:  AccessIntrCtrlRegs       — APIC MSRs
         *   Bit 5:  AccessHypercallMsrs      — Hypercall page MSR
         *   Bit 9:  AccessVpIndex            — VP_INDEX MSR
         *
         * EDX = Miscellaneous features:
         *   Bit 3:  available (AccessFrequencyRegs)
         *
         * We advertise ONLY the minimal set that Windows requires for
         * the enlightenments it already uses. All the corresponding
         * MSR reads/writes are absorbed in msr.c (silently return 0
         * or absorb writes).
         */
        if (g_OuterHypervisorPresent) {
            CpuInfo[0] = (1 << 0)   /* AccessVpRunTimeReg */
                       | (1 << 1)   /* AccessPartitionReferenceCounter */
                       | (1 << 2)   /* AccessSynicRegs */
                       | (1 << 3)   /* AccessSyntheticTimerRegs */
                       | (1 << 5)   /* AccessHypercallMsrs */
                       | (1 << 9);  /* AccessVpIndex */
        } else {
            CpuInfo[0] = 0;   /* Bare metal: no enlightenments */
        }
        CpuInfo[1] = 0;
        CpuInfo[2] = 0;
        CpuInfo[3] = 0;
    }
    else if (Leaf == 0x40000004) {
        /*
         * Leaf 0x40000004: Implementation Recommendations.
         *
         * Bit 0: HvRecommendRelaxedTiming — recommend relaxed timing
         * Bit 1: HvRecommendDmaRemapping — recommend DMA remapping
         * Bit 3: HvRecommendUsingHypercallsForTlbFlush
         * Bit 6: HvRecommendUsingHypercallsForLocalTlbFlush
         * Bit 7: HvRecommendUsingHypercallsForRemoteTlbFlush
         * Bit 11: HvRecommendUsingSpinlockAwarenessInterface
         *
         * We recommend TLB flush via hypercalls (which we emulate in
         * hv_hypercall.c) to keep Windows using the paths it cached.
         */
        if (g_OuterHypervisorPresent) {
            CpuInfo[0] = (1 << 0)    /* RelaxedTiming */
                       | (1 << 3)    /* TlbFlushHypercalls */
                       | (1 << 6)    /* LocalTlbFlushHypercalls */
                       | (1 << 7);   /* RemoteTlbFlushHypercalls */
        } else {
            CpuInfo[0] = 0;
        }
        CpuInfo[1] = 0;
        CpuInfo[2] = 0;
        CpuInfo[3] = 0;
    }
    else if (Leaf >= 0x40000005 && Leaf <= 0x40000006) {
        /*
         * Leaves 0x40000005-0x40000006: Implementation Limits + HW features.
         * Return zeros — no special limits or hardware features to report.
         */
        CpuInfo[0] = 0;
        CpuInfo[1] = 0;
        CpuInfo[2] = 0;
        CpuInfo[3] = 0;
    }

    /* Additional spoofing for target processes with anti-anti-debug enabled.
     * In nested mode, skip to avoid interfering with Hyper-V's own leaves. */
    if (!g_IsNestedMode && IsFeatureEnabled(GuestCr3, AAD_HIDE_CPUID)) {
        /* Leaf 1 and 0x40000000+ already handled above for all processes.
         * Additional per-target spoofing can go here if needed. */
    }

    /* Return CPUID results */
    GuestContext->Rax = (ULONG64)(ULONG)CpuInfo[0];
    GuestContext->Rbx = (ULONG64)(ULONG)CpuInfo[1];
    GuestContext->Rcx = (ULONG64)(ULONG)CpuInfo[2];
    GuestContext->Rdx = (ULONG64)(ULONG)CpuInfo[3];

    HvAdvanceGuestRip();
    return TRUE;
}

/* ========================================================================= */
/*  Exception Handler                                                        */
/* ========================================================================= */

/*
 * Handle intercepted exceptions (#DB, #BP) for anti-anti-debug.
 *
 * Anti-debug tricks using exceptions:
 * - INT 2D: Debugger skips the byte after INT 2D, non-debugged app doesn't
 * - INT 3: Debugger catches it, non-debugged app's SEH handles it
 * - Single step (#DB): Debugger intercepts, behavior differs
 */
BOOLEAN AadHandleException(PGUEST_CONTEXT GuestContext)
{
    ULONG64     IntInfo;
    ULONG       Vector;
    ULONG       IntType;
    ULONG64     GuestCr3;
    ULONG64     ErrorCode;
    BOOLEAN     HasErrorCode;
    ULONG       InjectInfo;

    UNREFERENCED_PARAMETER(GuestContext);

    IntInfo = HvReadExitInterruptionInfo();

    if (!(IntInfo & INTERRUPT_INFO_VALID)) {
        return FALSE;
    }

    Vector = (ULONG)(IntInfo & INTERRUPT_INFO_VECTOR_MASK);
    IntType = (ULONG)((IntInfo & INTERRUPT_INFO_TYPE_MASK) >> INTERRUPT_INFO_TYPE_SHIFT);
    HasErrorCode = (IntInfo & INTERRUPT_INFO_DELIVER_ERR_CODE) != 0;
    ErrorCode = HasErrorCode ? HvReadExitInterruptionErrorCode() : 0;

    GuestCr3 = HvReadGuestCr3();

    /*
     * For target processes with exception hiding enabled:
     * Re-inject the exception to the guest OS so that the application's
     * SEH handler processes it, just like on a non-debugged system.
     *
     * For non-target processes or non-hidden exceptions:
     * Re-inject normally.
     */
    if (IsFeatureEnabled(GuestCr3, AAD_HIDE_EXCEPTIONS)) {
        switch (Vector) {
        case 1: /* #DB - Debug Exception */
            /*
             * Clear single-step flag in RFLAGS to prevent the debugger
             * from seeing repeated single-step events.
             * The guest's SEH will handle it naturally.
             */
            LOG_DEBUG("Re-injecting #DB to guest SEH");
            break;

        case 3: /* #BP - Breakpoint */
            /*
             * Re-inject INT 3 to guest.
             * The guest's VEH/SEH handler will process it.
             */
            LOG_DEBUG("Re-injecting #BP to guest SEH");
            break;
        }
    }

    /*
     * Re-inject the exception into the guest.
     * Use VM-Entry interruption-information field.
     */
    InjectInfo = INTERRUPT_INFO_VALID;
    InjectInfo |= (Vector & INTERRUPT_INFO_VECTOR_MASK);
    InjectInfo |= (IntType << INTERRUPT_INFO_TYPE_SHIFT);

    if (HasErrorCode) {
        InjectInfo |= INTERRUPT_INFO_DELIVER_ERR_CODE;
        HvSetEntryExceptionErrorCode((ULONG)ErrorCode);
    }

    HvSetEntryInterruptionInfo(InjectInfo);

    /* For software exceptions/interrupts, set instruction length */
    if (IntType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION ||
        IntType == INTERRUPT_TYPE_SOFTWARE_INT) {
        HvSetEntryInstructionLength(HvReadExitInstructionLength());
    }

    /* Don't advance RIP - the exception handler will take care of it */
    return TRUE;
}
