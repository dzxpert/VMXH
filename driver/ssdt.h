/*
 * ssdt.h - VMX Hypervisor Toolbox
 * SSDT (System Service Descriptor Table) Monitoring & Hook Framework
 *
 * Provides SSDT discovery, parsing, name resolution, and per-syscall
 * hooking via the existing GenericHook EPT/NPT framework.
 *
 * This module is a thin coordination layer: all actual hook mechanics
 * (thunk generation, EPT split pages, decision logic, event logging)
 * are delegated to GenericHookInstall() / GenericHookRemove().
 */

#ifndef _SSDT_H_
#define _SSDT_H_

#include <ntddk.h>
#include "../common/shared.h"

/* ========================================================================= */
/*  Internal Structures                                                      */
/* ========================================================================= */

/*
 * SSDT_HOOK_MAPPING - tracks the relationship between a syscall index
 * and the generic hook framework's hookId.  Linked list node.
 */
typedef struct _SSDT_HOOK_MAPPING {
    struct _SSDT_HOOK_MAPPING  *Next;
    ULONG       SyscallIndex;       /* SSDT index (0..ServiceCount-1) */
    ULONG       GenericHookId;      /* ID returned by GenericHookInstall */
    BOOLEAN     IsMonitorHook;      /* TRUE if created by monitor mode */
} SSDT_HOOK_MAPPING, *PSSDT_HOOK_MAPPING;

/*
 * SSDT_STATE - global state for the SSDT subsystem
 */
typedef struct _SSDT_STATE {
    /* Discovery results */
    BOOLEAN     Initialized;
    ULONG64     KiSystemCall64Va;       /* IA32_LSTAR value (informational) */
    ULONG64     KiServiceTableVa;       /* nt!KiServiceTable base (live memory) */
    ULONG       ServiceCount;           /* Number of syscall entries */

    /* Address cache: pre-resolved function VAs (indexed by syscall#) */
    ULONG64     ResolvedAddresses[SSDT_MAX_SERVICES];

    /* File-mapped ntoskrnl image for clean SSDT resolution */
    PVOID       FileImageBase;          /* SEC_IMAGE mapped view, NULL if unavailable */
    SIZE_T      FileImageViewSize;      /* Size of mapped view */
    HANDLE      FileImageSection;       /* Section handle (for cleanup) */

    /* Name cache: resolved Nt* export names */
    WCHAR       NameCache[SSDT_MAX_SERVICES][SSDT_MAX_NAME_LEN];
    BOOLEAN     NamesPopulated;

    /* ntoskrnl base for PE export walk (live in-memory) */
    ULONG64     NtoskrnlBase;
    ULONG       NtoskrnlSize;

    /* Full path of ntoskrnl on disk (for file mapping) */
    WCHAR       NtoskrnlPath[260];

    /* SSDT hook mapping list */
    PSSDT_HOOK_MAPPING  HookListHead;
    ULONG               HookCount;
    KSPIN_LOCK          HookLock;

    /* Monitor mode state */
    ULONG       MonitorMode;            /* SSDT_MONITOR_OFF/ALL/FILTERED */
    ULONG       MonitorPid;

} SSDT_STATE, *PSSDT_STATE;

extern SSDT_STATE g_SsdtState;

/* ========================================================================= */
/*  Public API                                                               */
/* ========================================================================= */

/* Lifecycle */
NTSTATUS    SsdtInitialize(VOID);
VOID        SsdtCleanup(VOID);

/* Table query */
NTSTATUS    SsdtGetEntryInfo(ULONG Index, PSSDT_ENTRY_INFO Out);
NTSTATUS    SsdtDumpTable(ULONG Start, ULONG Count,
                          PSSDT_ENTRY_INFO Out, PULONG OutCount);
ULONG64     SsdtResolveAddress(ULONG Index);
NTSTATUS    SsdtPopulateNames(VOID);
NTSTATUS    SsdtFindIndexByName(const WCHAR *Name, PULONG OutIndex);

/* Hook operations (delegate to GenericHookInstall/Remove) */
NTSTATUS    SsdtHookByIndex(ULONG Index, PHOOK_RULE Rule, PULONG OutHookId);
NTSTATUS    SsdtHookByName(const WCHAR *Name, PHOOK_RULE Rule,
                           PULONG OutIndex, PULONG OutHookId);
NTSTATUS    SsdtUnhookByIndex(ULONG Index);
NTSTATUS    SsdtUnhookByHookId(ULONG HookId);
VOID        SsdtUnhookAll(VOID);

/* Monitor mode */
NTSTATUS    SsdtSetMonitorMode(PVMX_SSDT_MONITOR_REQUEST Req);
VOID        SsdtStopMonitoring(VOID);

#endif /* _SSDT_H_ */
