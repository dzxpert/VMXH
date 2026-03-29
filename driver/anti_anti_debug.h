/*
 * anti_anti_debug.h - VMX Anti-Anti-Debug Hypervisor
 * Anti-anti-debug engine: definitions and function declarations
 */

#ifndef _VMX_ANTI_ANTI_DEBUG_H_
#define _VMX_ANTI_ANTI_DEBUG_H_

#include <ntddk.h>
#include "vmx.h"
#include "hv_ops.h"
#include "process.h"

/* ========================================================================= */
/*  NtQueryInformationProcess Classes                                        */
/* ========================================================================= */

#define ProcessDebugPort                0x07
#define ProcessDebugObjectHandle        0x1E
#define ProcessDebugFlags               0x1F

/* ========================================================================= */
/*  NtQuerySystemInformation Classes                                         */
/* ========================================================================= */

#define SystemKernelDebuggerInformation     0x23

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

/* ========================================================================= */
/*  Debug Register Fake Values                                               */
/* ========================================================================= */

#define DR7_DEFAULT_VALUE               0x400ULL    /* Default: no BPs enabled */
#define DR6_DEFAULT_VALUE               0xFFFF0FF0ULL

/* ========================================================================= */
/*  NT API typedefs for EPT hooks                                            */
/* ========================================================================= */

typedef NTSTATUS (*PFN_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (*PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (*PFN_NtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

typedef NTSTATUS (*PFN_NtClose)(
    HANDLE Handle
);

/* ========================================================================= */
/*  Anti-Anti-Debug State                                                    */
/* ========================================================================= */

typedef struct _AAD_STATE {
    BOOLEAN Initialized;

    /* Original function pointers (trampolines) */
    PFN_NtQueryInformationProcess   OrigNtQueryInformationProcess;
    PFN_NtQuerySystemInformation    OrigNtQuerySystemInformation;
    PFN_NtSetInformationThread      OrigNtSetInformationThread;
    PFN_NtClose                     OrigNtClose;

    /* Resolved kernel addresses */
    ULONG64     NtQueryInformationProcessAddr;
    ULONG64     NtQuerySystemInformationAddr;
    ULONG64     NtSetInformationThreadAddr;
    ULONG64     NtCloseAddr;

} AAD_STATE, *PAAD_STATE;

/* ========================================================================= */
/*  Function Declarations                                                    */
/* ========================================================================= */

/* Initialization */
NTSTATUS    AadInitialize(VOID);
VOID        AadCleanup(VOID);

/* Install/remove hooks */
NTSTATUS    AadInstallHooks(VOID);
VOID        AadRemoveHooks(VOID);

/* VM-Exit handlers for anti-anti-debug */
BOOLEAN     AadHandleDrAccess(PGUEST_CONTEXT GuestContext);
BOOLEAN     AadHandleRdtsc(PGUEST_CONTEXT GuestContext);
BOOLEAN     AadHandleCpuid(PGUEST_CONTEXT GuestContext);
BOOLEAN     AadHandleException(PGUEST_CONTEXT GuestContext);

/* TSC management */
VOID        AadNotifyDebugPause(ULONG CpuIndex);
VOID        AadNotifyDebugResume(ULONG CpuIndex);

/* Global state */
extern AAD_STATE g_AadState;

#endif /* _VMX_ANTI_ANTI_DEBUG_H_ */
