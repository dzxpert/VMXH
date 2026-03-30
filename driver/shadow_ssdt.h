/*
 * shadow_ssdt.h - VMX Hypervisor Toolbox
 * Shadow SSDT (Win32k) Monitoring & Hook Framework
 *
 * Extends the SSDT module architecture to the Win32k Shadow SSDT
 * (KeServiceDescriptorTableShadow), covering NtUser/NtGdi syscalls.
 *
 * Key challenges handled:
 *   - KeServiceDescriptorTableShadow is not exported; discovered via KTHREAD
 *   - KTHREAD.ServiceTable offset varies by Windows version; found dynamically
 *   - win32k.sys is per-Session mapped; KeStackAttachProcess used for access
 *   - Win10+ splits win32k into three modules; all are enumerated
 *
 * All hook mechanics delegate to GenericHookInstall() / GenericHookRemove().
 */

#ifndef _SHADOW_SSDT_H_
#define _SHADOW_SSDT_H_

#include <ntddk.h>
#include "../common/shared.h"
#include "ssdt.h"          /* Reuses SSDT_HOOK_MAPPING, KSERVICE_TABLE_DESCRIPTOR */

/* ========================================================================= */
/*  KTHREAD Offset Discovery                                                 */
/* ========================================================================= */

/*
 * KTHREAD_OFFSETS - Result of scanning KTHREAD for ServiceTable field.
 * The ServiceTable field offset varies across Windows builds.
 */
typedef struct _KTHREAD_OFFSETS {
    BOOLEAN Resolved;
    ULONG   ServiceTableOffset;     /* KTHREAD.ServiceTable byte offset */
} KTHREAD_OFFSETS;

/* ========================================================================= */
/*  Win32k Module Information                                                */
/* ========================================================================= */

/*
 * Win10+ splits win32k into three modules:
 *   - win32kbase.sys
 *   - win32kfull.sys
 *   - win32k.sys (stub)
 * All three may contain NtUser/NtGdi exports.
 */
#define MAX_WIN32K_MODULES  4

typedef struct _WIN32K_MODULE_INFO {
    ULONG64 Base;
    ULONG   Size;
    CHAR    Name[64];               /* Short name for logging */
    WCHAR   Path[260];              /* NT path for file mapping */
} WIN32K_MODULE_INFO;

/* ========================================================================= */
/*  Shadow SSDT Global State                                                 */
/* ========================================================================= */

typedef struct _SHADOW_SSDT_STATE {
    BOOLEAN     Initialized;

    /* KTHREAD offset discovery */
    KTHREAD_OFFSETS KthreadOffsets;

    /* Discovery results */
    ULONG64     KeServiceDescriptorTableShadowVa;
    ULONG64     W32pServiceTableVa;     /* Shadow[1].Base */
    ULONG       ServiceCount;           /* Shadow[1].Limit */

    /* GUI process context (held with reference count for KeStackAttachProcess) */
    PEPROCESS   GuiProcess;

    /* Address cache: pre-resolved function VAs (indexed by Shadow syscall index) */
    ULONG64     ResolvedAddresses[SHADOW_SSDT_MAX_SERVICES];

    /* Name cache: NtUser/NtGdi names */
    WCHAR       NameCache[SHADOW_SSDT_MAX_SERVICES][SSDT_MAX_NAME_LEN];
    BOOLEAN     NamesPopulated;

    /* win32k module info (supports Win10+ split modules) */
    ULONG               Win32kModuleCount;
    WIN32K_MODULE_INFO   Win32kModules[MAX_WIN32K_MODULES];

    /* Hook mapping linked list (reuses SSDT_HOOK_MAPPING from ssdt.h) */
    PSSDT_HOOK_MAPPING  HookListHead;
    ULONG               HookCount;
    KSPIN_LOCK          HookLock;

    /* Monitor mode state */
    ULONG       MonitorMode;            /* SSDT_MONITOR_OFF/ALL/FILTERED */
    ULONG       MonitorPid;

} SHADOW_SSDT_STATE, *PSHADOW_SSDT_STATE;

extern SHADOW_SSDT_STATE g_ShadowSsdtState;

/* ========================================================================= */
/*  Public API                                                               */
/* ========================================================================= */

/* Lifecycle */
NTSTATUS    ShadowSsdtInitialize(VOID);
VOID        ShadowSsdtCleanup(VOID);

/* Table query */
NTSTATUS    ShadowSsdtGetEntryInfo(ULONG Index, PSSDT_ENTRY_INFO Out);
NTSTATUS    ShadowSsdtDumpTable(ULONG Start, ULONG Count,
                                 PSSDT_ENTRY_INFO Out, PULONG OutCount);
NTSTATUS    ShadowSsdtFindIndexByName(const WCHAR *Name, PULONG OutIndex);

/* Hook operations (delegate to GenericHookInstall/Remove) */
NTSTATUS    ShadowSsdtHookByIndex(ULONG Index, PHOOK_RULE Rule, PULONG OutHookId);
NTSTATUS    ShadowSsdtHookByName(const WCHAR *Name, PHOOK_RULE Rule,
                                  PULONG OutIndex, PULONG OutHookId);
NTSTATUS    ShadowSsdtUnhookByIndex(ULONG Index);
NTSTATUS    ShadowSsdtUnhookByHookId(ULONG HookId);
VOID        ShadowSsdtUnhookAll(VOID);

/* Monitor mode */
NTSTATUS    ShadowSsdtSetMonitorMode(PVMX_SHADOW_SSDT_MONITOR_REQUEST Req);
VOID        ShadowSsdtStopMonitoring(VOID);

#endif /* _SHADOW_SSDT_H_ */
