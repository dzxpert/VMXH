/*
 * process.h - VMX Anti-Anti-Debug Hypervisor
 * Process tracking and target identification
 */

#ifndef _VMX_PROCESS_H_
#define _VMX_PROCESS_H_

#include <ntddk.h>

/* ========================================================================= */
/*  Configuration                                                            */
/* ========================================================================= */

#define MAX_TARGET_PROCESSES    16

/* ========================================================================= */
/*  Target Process Structure                                                 */
/* ========================================================================= */

typedef struct _TARGET_PROCESS {
    ULONG64     Cr3;            /* DirectoryTableBase for CR3 matching */
    ULONG       Pid;            /* Process ID */
    ULONG       Flags;          /* AAD_HIDE_* bitmask */
    BOOLEAN     Active;         /* Slot in use */
} TARGET_PROCESS, *PTARGET_PROCESS;

typedef struct _PROCESS_TRACKING {
    TARGET_PROCESS  Targets[MAX_TARGET_PROCESSES];
    KSPIN_LOCK      Lock;
    ULONG           ActiveCount;
    BOOLEAN         Initialized;
} PROCESS_TRACKING, *PPROCESS_TRACKING;

/* ========================================================================= */
/*  Dynamic EPROCESS Offset Discovery                                        */
/* ========================================================================= */

/*
 * Dynamically resolved offset of DirectoryTableBase within EPROCESS.
 * Determined at init time by scanning the current process's EPROCESS
 * for a value matching the known CR3.
 */
typedef struct _EPROCESS_OFFSETS {
    ULONG   DirectoryTableBase;     /* Offset of CR3 in EPROCESS */
    BOOLEAN Resolved;               /* TRUE if offsets were successfully found */
} EPROCESS_OFFSETS, *PEPROCESS_OFFSETS;

extern EPROCESS_OFFSETS g_EprocessOffsets;

/* ========================================================================= */
/*  Functions                                                                */
/* ========================================================================= */

NTSTATUS    ProcessResolveOffsets(VOID);
VOID        ProcessTrackingInit(VOID);
VOID        ProcessTrackingCleanup(VOID);

NTSTATUS    ProcessAddTarget(ULONG Pid, ULONG Flags);
NTSTATUS    ProcessRemoveTarget(ULONG Pid);
NTSTATUS    ProcessUpdateConfig(ULONG Pid, ULONG NewFlags);
ULONG       ProcessGetActiveCount(VOID);

/*
 * Fast lookup by CR3 - called from VM-Exit handler (high IRQL)
 * Returns pointer to target or NULL if not tracked
 */
PTARGET_PROCESS ProcessFindByCr3(ULONG64 Cr3);

/*
 * Check if a given CR3 belongs to a target process
 */
FORCEINLINE BOOLEAN IsTargetProcess(ULONG64 Cr3)
{
    return ProcessFindByCr3(Cr3) != NULL;
}

/*
 * Check if specific feature is enabled for a CR3
 */
FORCEINLINE BOOLEAN IsFeatureEnabled(ULONG64 Cr3, ULONG FeatureFlag)
{
    PTARGET_PROCESS Target = ProcessFindByCr3(Cr3);
    if (Target) {
        return (Target->Flags & FeatureFlag) != 0;
    }
    return FALSE;
}

/* Global process tracking state */
extern PROCESS_TRACKING g_ProcessTracking;

/*
 * AAD-BP (post-2nd-review): helpers exposed to the hypervisor backends.
 *
 * ProcessAnyTargetHasExceptionHiding():
 *   Returns TRUE if at least one active target has AAD_HIDE_EXCEPTIONS
 *   set.  Used by a backend on startup to initialise its exception
 *   intercept state correctly if targets were pre-added (edge case,
 *   but possible via IOCTL sequence).
 *
 * ProcessRegisterExceptionHideToggle(Callback):
 *   Installs a callback invoked on every Add/Remove/UpdateConfig of a
 *   target whose flag set affects AAD_HIDE_EXCEPTIONS.  The callback
 *   receives TRUE if any target still has the flag, FALSE otherwise,
 *   and is expected to toggle the backend's #BP intercept accordingly.
 *
 *   Registration is one-shot (per boot).  Each backend (SVM or VMX)
 *   registers its own hook during initialisation; the OTHER backend's
 *   init never runs so there is no collision.
 */
BOOLEAN ProcessAnyTargetHasExceptionHiding(VOID);

typedef VOID (*PFN_EXCEPTION_HIDE_TOGGLE)(BOOLEAN Enable);
VOID    ProcessRegisterExceptionHideToggle(PFN_EXCEPTION_HIDE_TOGGLE Callback);

#endif /* _VMX_PROCESS_H_ */
