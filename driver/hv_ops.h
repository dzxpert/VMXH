/*
 * hv_ops.h - VMX Anti-Anti-Debug Hypervisor
 * Hypervisor abstraction layer: unified interface for Intel VMX and AMD SVM
 *
 * Both backends (VMX and SVM) register an implementation of HV_OPS.
 * The global pointer g_HvOps is set at driver init based on CPU vendor.
 */

#ifndef _HV_OPS_H_
#define _HV_OPS_H_

#include <ntddk.h>

/* Forward declarations */
struct _GUEST_CONTEXT;

/* ========================================================================= */
/*  CPU Vendor Enumeration                                                   */
/* ========================================================================= */

typedef enum _CPU_VENDOR {
    CPU_VENDOR_UNKNOWN = 0,
    CPU_VENDOR_INTEL,
    CPU_VENDOR_AMD
} CPU_VENDOR;

/* ========================================================================= */
/*  Per-CPU Context (generic)                                                */
/* ========================================================================= */

/*
 * Generic per-CPU hypervisor context.
 * Each backend stores its own specific data (VMX_CPU_CONTEXT or SVM_CPU_CONTEXT)
 * but shares these common fields for the abstraction layer.
 */
typedef struct _HV_CPU_CONTEXT {
    ULONG       ProcessorNumber;
    BOOLEAN     HvEnabled;          /* VMX/SVM enabled on this CPU */
    BOOLEAN     GuestLaunched;      /* Guest is running */

    /* TSC compensation for anti-timing */
    LONG64      TscOffset;
    ULONG64     LastDebugPauseTsc;
    BOOLEAN     InDebugPause;

    /* Statistics */
    volatile LONG64 ExitCount;

} HV_CPU_CONTEXT, *PHV_CPU_CONTEXT;

/* ========================================================================= */
/*  Hypervisor Operations Interface                                          */
/* ========================================================================= */

#define MAX_PROCESSORS  64

typedef struct _HV_OPS {

    /* ===== Identity ===== */
    const char  *Name;                  /* "Intel VMX" or "AMD SVM" */
    CPU_VENDOR  Vendor;

    /* ===== Lifecycle ===== */

    /* Check if this hypervisor technology is supported on current CPU */
    BOOLEAN     (*IsSupported)(VOID);

    /* Global initialization / termination */
    NTSTATUS    (*Initialize)(VOID);
    VOID        (*Terminate)(VOID);

    /* ===== Guest State Access ===== */

    /* Read guest register values (from VMCS or VMCB) */
    ULONG64     (*ReadGuestRip)(VOID);
    VOID        (*WriteGuestRip)(ULONG64 Value);
    ULONG64     (*ReadGuestRsp)(VOID);
    VOID        (*WriteGuestRsp)(ULONG64 Value);
    ULONG64     (*ReadGuestCr3)(VOID);
    VOID        (*WriteGuestCr3)(ULONG64 Value);
    ULONG64     (*ReadGuestRflags)(VOID);
    VOID        (*WriteGuestRflags)(ULONG64 Value);

    /* ===== Exit Information ===== */

    ULONG64     (*ReadExitReason)(VOID);
    ULONG64     (*ReadExitQualification)(VOID);
    ULONG64     (*ReadExitInterruptionInfo)(VOID);
    ULONG64     (*ReadExitInterruptionErrorCode)(VOID);
    ULONG       (*ReadExitInstructionLength)(VOID);
    ULONG64     (*ReadGuestPhysicalAddress)(VOID);

    /* ===== Guest RIP Advancement ===== */

    VOID        (*AdvanceGuestRip)(VOID);

    /* ===== Exception / Interrupt Injection ===== */

    VOID        (*InjectException)(ULONG Vector, ULONG Type,
                                   BOOLEAN HasErrorCode, ULONG ErrorCode);
    VOID        (*InjectInterruptInfo)(ULONG InfoField);

    /* ===== VM-Execution Control Manipulation ===== */

    /* Set VM-Entry interruption-information for re-injection */
    VOID        (*SetEntryInterruptionInfo)(ULONG Info);
    VOID        (*SetEntryExceptionErrorCode)(ULONG ErrorCode);
    VOID        (*SetEntryInstructionLength)(ULONG Length);

    /* ===== Second-Level Page Tables (EPT / NPT) ===== */

    NTSTATUS    (*SetupPageTables)(VOID);
    VOID        (*CleanupPageTables)(VOID);
    VOID        (*InvalidatePageTables)(VOID);

    /* Hook/unhook via EPT or NPT */
    NTSTATUS    (*HookFunction)(ULONG64 TargetVa, PVOID HookFunc, PVOID *OrigFunc);
    NTSTATUS    (*UnhookFunction)(ULONG64 TargetVa);
    VOID        (*UnhookAll)(VOID);

    /* ===== Monitor Trap Flag / Single-Step ===== */

    VOID        (*EnableSingleStep)(VOID);
    VOID        (*DisableSingleStep)(VOID);

    /* ===== Primary Execution Control ===== */

    /* Read/modify primary execution controls (for interrupt window, etc.) */
    ULONG64     (*ReadPrimaryProcControls)(VOID);
    VOID        (*WritePrimaryProcControls)(ULONG64 Value);

    /* ===== Per-CPU Context Access ===== */

    /* Get generic per-CPU context for current processor */
    PHV_CPU_CONTEXT (*GetCurrentCpuContext)(VOID);

} HV_OPS, *PHV_OPS;

/* ========================================================================= */
/*  Global State                                                             */
/* ========================================================================= */

/*
 * Global pointer to the active hypervisor backend.
 * Set once during DriverEntry based on CPU vendor detection.
 * All modules use this to call hypervisor operations.
 */
extern PHV_OPS g_HvOps;

/*
 * Detected CPU vendor (set during detection phase)
 */
extern CPU_VENDOR g_CpuVendor;

/* ========================================================================= */
/*  Convenience Macros                                                       */
/* ========================================================================= */

/* These provide quick access without going through the pointer */
#define HvReadGuestRip()                g_HvOps->ReadGuestRip()
#define HvWriteGuestRip(v)              g_HvOps->WriteGuestRip(v)
#define HvReadGuestRsp()                g_HvOps->ReadGuestRsp()
#define HvWriteGuestRsp(v)              g_HvOps->WriteGuestRsp(v)
#define HvReadGuestCr3()                g_HvOps->ReadGuestCr3()
#define HvWriteGuestCr3(v)              g_HvOps->WriteGuestCr3(v)
#define HvReadExitReason()              g_HvOps->ReadExitReason()
#define HvReadExitQualification()       g_HvOps->ReadExitQualification()
#define HvReadExitInterruptionInfo()    g_HvOps->ReadExitInterruptionInfo()
#define HvReadExitInterruptionErrorCode() g_HvOps->ReadExitInterruptionErrorCode()
#define HvReadExitInstructionLength()   g_HvOps->ReadExitInstructionLength()
#define HvReadGuestPhysicalAddress()    g_HvOps->ReadGuestPhysicalAddress()
#define HvAdvanceGuestRip()             g_HvOps->AdvanceGuestRip()
#define HvInjectException(v,t,h,e)      g_HvOps->InjectException(v,t,h,e)
#define HvSetEntryInterruptionInfo(i)   g_HvOps->SetEntryInterruptionInfo(i)
#define HvSetEntryExceptionErrorCode(e) g_HvOps->SetEntryExceptionErrorCode(e)
#define HvSetEntryInstructionLength(l)  g_HvOps->SetEntryInstructionLength(l)
#define HvEnableSingleStep()            g_HvOps->EnableSingleStep()
#define HvDisableSingleStep()           g_HvOps->DisableSingleStep()
#define HvInvalidatePageTables()        g_HvOps->InvalidatePageTables()
#define HvHookFunction(t,h,o)           g_HvOps->HookFunction(t,h,o)
#define HvUnhookFunction(t)             g_HvOps->UnhookFunction(t)
#define HvUnhookAll()                   g_HvOps->UnhookAll()

#endif /* _HV_OPS_H_ */
