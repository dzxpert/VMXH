/*
 * shared.h - VMX Hypervisor Toolbox
 * Shared definitions between kernel driver and user-mode client
 */

#ifndef _VMX_SHARED_H_
#define _VMX_SHARED_H_

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

/* ========================================================================= */
/*  Device & Symbolic Link Names                                             */
/* ========================================================================= */

#define VMX_DEVICE_NAME     L"\\Device\\VMXToolbox"
#define VMX_SYMLINK_NAME    L"\\DosDevices\\VMXToolbox"
#define VMX_USERMODE_PATH   "\\\\.\\VMXToolbox"

/* ========================================================================= */
/*  IOCTL Codes                                                              */
/* ========================================================================= */

#define IOCTL_VMX_INIT              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SET_TARGET        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_REMOVE_TARGET     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SET_CONFIG        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_GET_LOG           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_STOP              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_QUERY_STATUS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_READ_MEMORY       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_WRITE_MEMORY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_INSTALL_HOOK      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_REMOVE_HOOK       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_LIST_HOOKS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_GET_HOOK_EVENTS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ========================================================================= */
/*  Anti-Anti-Debug Feature Flags                                            */
/* ========================================================================= */

#define AAD_HIDE_DEBUGGER       (1 << 0)    /* PEB.BeingDebugged, NtQueryInformationProcess */
#define AAD_HIDE_HWBP           (1 << 1)    /* DR0-DR7 register concealment */
#define AAD_HIDE_TIMING         (1 << 2)    /* RDTSC/RDTSCP offset compensation */
#define AAD_HIDE_CPUID          (1 << 3)    /* Hide hypervisor from CPUID */
#define AAD_HIDE_SYSINFO        (1 << 4)    /* NtQuerySystemInformation spoofing */
#define AAD_HIDE_EXCEPTIONS     (1 << 5)    /* INT 2D / INT 3 behavior normalization */
#define AAD_HIDE_NTCLOSE        (1 << 6)    /* NtClose invalid handle exception */
#define AAD_HIDE_THREADINFO     (1 << 7)    /* NtSetInformationThread HideFromDebugger */
#define AAD_HIDE_HEAP           (1 << 8)    /* Heap flags concealment */
#define AAD_HIDE_PARENT         (1 << 9)    /* Parent process spoofing */

#define AAD_HIDE_ALL            (0xFFFFFFFF)

/* ========================================================================= */
/*  Shared Data Structures                                                   */
/* ========================================================================= */

/*
 * IOCTL_VMX_SET_TARGET input
 * Specifies a target process and what to hide
 */
typedef struct _VMX_TARGET_INFO {
    ULONG   Pid;            /* Target process ID */
    ULONG   Flags;          /* Bitmask of AAD_HIDE_* flags */
} VMX_TARGET_INFO, *PVMX_TARGET_INFO;

/*
 * IOCTL_VMX_REMOVE_TARGET input
 */
typedef struct _VMX_REMOVE_TARGET {
    ULONG   Pid;            /* Process ID to stop protecting */
} VMX_REMOVE_TARGET, *PVMX_REMOVE_TARGET;

/*
 * IOCTL_VMX_SET_CONFIG input
 * Update flags for an already-tracked process
 */
typedef struct _VMX_CONFIG_INFO {
    ULONG   Pid;            /* Target process ID */
    ULONG   Flags;          /* New bitmask of AAD_HIDE_* flags */
} VMX_CONFIG_INFO, *PVMX_CONFIG_INFO;

/*
 * IOCTL_VMX_QUERY_STATUS output
 */
typedef struct _VMX_STATUS {
    BOOLEAN VmxActive;          /* VMX is initialized and running */
    ULONG   ActiveTargets;      /* Number of actively protected processes */
    ULONG   TotalExits;         /* Total VM-Exits handled (low 32 bits) */
    ULONG   CpuCount;          /* Number of logical CPUs virtualized */
} VMX_STATUS, *PVMX_STATUS;

/*
 * Log entry for IOCTL_VMX_GET_LOG
 */
#define VMX_LOG_MAX_MSG     256
#define VMX_LOG_BUFFER_SIZE 4096

typedef struct _VMX_LOG_ENTRY {
    ULONG       Level;          /* 0=Error, 1=Warn, 2=Info, 3=Debug */
    ULONG       Pid;            /* Source process ID (0 = system) */
    LARGE_INTEGER Timestamp;    /* KeQuerySystemTimePrecise */
    CHAR        Message[VMX_LOG_MAX_MSG];
} VMX_LOG_ENTRY, *PVMX_LOG_ENTRY;

typedef struct _VMX_LOG_BUFFER {
    ULONG           Count;      /* Number of entries returned */
    VMX_LOG_ENTRY   Entries[1]; /* Variable length array */
} VMX_LOG_BUFFER, *PVMX_LOG_BUFFER;

/* ========================================================================= */
/*  Hypervisor Memory Read/Write (bypasses all Guest protections)            */
/* ========================================================================= */

/*
 * Maximum bytes per single read/write request.
 * Larger transfers should be split into multiple IOCTLs.
 * Kept small to fit in METHOD_BUFFERED system buffer.
 */
#define VMX_MEM_MAX_SIZE    (64 * 1024)     /* 64 KB per request */

/*
 * IOCTL_VMX_READ_MEMORY input
 * Reads memory from a target process via Hypervisor (EPT/NPT physical access).
 *
 * The driver resolves target PID -> CR3, then walks the Guest page tables
 * to translate VirtualAddress -> physical address, and copies directly
 * from physical memory. No Windows API is called, so no kernel callback
 * or anti-cheat hook can intercept this.
 *
 * Input:  VMX_MEMORY_REQUEST (Pid, VirtualAddress, Size)
 * Output: Raw bytes (Size bytes written to output buffer)
 */
typedef struct _VMX_MEMORY_REQUEST {
    ULONG       Pid;                /* Target process ID */
    ULONG       Size;               /* Bytes to read/write (max VMX_MEM_MAX_SIZE) */
    ULONG64     VirtualAddress;     /* Target virtual address in the process */
} VMX_MEMORY_REQUEST, *PVMX_MEMORY_REQUEST;

/*
 * IOCTL_VMX_WRITE_MEMORY input
 * Writes memory to a target process via Hypervisor.
 *
 * Input layout (in SystemBuffer):
 *   [VMX_MEMORY_REQUEST header][payload bytes...]
 *
 * The payload immediately follows the header in the buffer.
 * Total InputBufferLength = sizeof(VMX_MEMORY_REQUEST) + Size
 */

/* ========================================================================= */
/*  Universal Hook Framework (EPT/NPT invisible hooks)                       */
/* ========================================================================= */

/*
 * Hook action: what to do when a hooked function is called
 */
#define HOOK_ACTION_PASSTHROUGH     0   /* Call original, count only */
#define HOOK_ACTION_LOG_ONLY        1   /* Call original, log each call */
#define HOOK_ACTION_BLOCK           2   /* Skip original, return BlockReturnValue */
#define HOOK_ACTION_MODIFY_RETVAL   3   /* Call original, overwrite return value */

/*
 * Hook rule: controls hook behavior
 */
typedef struct _HOOK_RULE {
    ULONG       Action;             /* HOOK_ACTION_* */
    ULONG       TargetPid;          /* 0 = global (all processes), >0 = specific PID */
    ULONG64     BlockReturnValue;   /* Return value when BLOCK */
    ULONG64     NewReturnValue;     /* Return value when MODIFY_RETVAL */
    BOOLEAN     LogEnabled;         /* Write to event log regardless of action */
} HOOK_RULE, *PHOOK_RULE;

/*
 * Maximum function name length for name-based hooks
 */
#define HOOK_MAX_NAME_LEN   128

/*
 * IOCTL_VMX_INSTALL_HOOK input
 */
typedef struct _VMX_HOOK_REQUEST {
    BOOLEAN     ByName;                          /* TRUE = resolve FunctionName */
    WCHAR       FunctionName[HOOK_MAX_NAME_LEN]; /* Kernel export name (ByName=TRUE) */
    ULONG64     TargetAddress;                   /* Direct VA (ByName=FALSE) */
    ULONG       ProcessId;                       /* 0 = kernel hook */
    HOOK_RULE   Rule;
} VMX_HOOK_REQUEST, *PVMX_HOOK_REQUEST;

/*
 * IOCTL_VMX_INSTALL_HOOK output
 */
typedef struct _VMX_HOOK_RESPONSE {
    ULONG       HookId;             /* Unique ID for remove/query */
    ULONG64     ResolvedAddress;    /* Actual VA that was hooked */
} VMX_HOOK_RESPONSE, *PVMX_HOOK_RESPONSE;

/*
 * IOCTL_VMX_REMOVE_HOOK input
 */
typedef struct _VMX_UNHOOK_REQUEST {
    ULONG       HookId;
} VMX_UNHOOK_REQUEST, *PVMX_UNHOOK_REQUEST;

/*
 * Hook info entry (for LIST_HOOKS query)
 */
typedef struct _VMX_HOOK_INFO {
    ULONG       HookId;
    BOOLEAN     Active;
    ULONG64     TargetAddress;
    ULONG       ProcessId;
    HOOK_RULE   Rule;
    ULONG64     HitCount;
    WCHAR       FunctionName[HOOK_MAX_NAME_LEN];
} VMX_HOOK_INFO, *PVMX_HOOK_INFO;

/*
 * IOCTL_VMX_LIST_HOOKS output
 */
typedef struct _VMX_HOOK_LIST {
    ULONG           Count;
    VMX_HOOK_INFO   Hooks[1];      /* Variable length */
} VMX_HOOK_LIST, *PVMX_HOOK_LIST;

/*
 * Hook event log entry
 */
typedef struct _HOOK_EVENT {
    ULONG       HookId;
    ULONG       ProcessId;
    ULONG64     Timestamp;
    ULONG64     ReturnAddress;      /* Caller's return address */
    ULONG64     FinalRetVal;        /* Return value sent to caller */
    ULONG       ActionTaken;        /* HOOK_ACTION_* */
} HOOK_EVENT, *PHOOK_EVENT;

#define HOOK_EVENT_RING_SIZE    512

/*
 * IOCTL_VMX_GET_HOOK_EVENTS output
 */
typedef struct _VMX_HOOK_EVENT_BUFFER {
    ULONG       Count;
    HOOK_EVENT  Events[1];          /* Variable length */
} VMX_HOOK_EVENT_BUFFER, *PVMX_HOOK_EVENT_BUFFER;

/* ========================================================================= */
/*  Log Levels                                                               */
/* ========================================================================= */

#define VMX_LOG_ERROR   0
#define VMX_LOG_WARN    1
#define VMX_LOG_INFO    2
#define VMX_LOG_DEBUG   3

/* ========================================================================= */
/*  SSDT Monitoring & Hook Framework                                         */
/* ========================================================================= */

/*
 * IOCTL codes for SSDT operations (0x80D–0x813)
 */
#define IOCTL_VMX_SSDT_INIT         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SSDT_DUMP         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SSDT_HOOK         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SSDT_UNHOOK       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SSDT_UNHOOK_ALL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SSDT_LIST_HOOKS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SSDT_MONITOR      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*
 * SSDT constants
 */
#define SSDT_MAX_SERVICES       512
#define SSDT_MAX_NAME_LEN       128
#define SSDT_MONITOR_OFF        0
#define SSDT_MONITOR_ALL        1
#define SSDT_MONITOR_FILTERED   2

/*
 * SSDT_ENTRY_INFO — single SSDT entry information
 */
typedef struct _SSDT_ENTRY_INFO {
    ULONG       SyscallIndex;                   /* Syscall number */
    ULONG       ArgCount;                       /* Number of arguments (entry & 0xF) */
    LONG        RawOffset;                      /* Raw SSDT table entry (before >> 4) */
    ULONG64     FunctionVa;                     /* Resolved virtual address */
    WCHAR       FunctionName[SSDT_MAX_NAME_LEN]; /* Resolved name (may be empty) */
} SSDT_ENTRY_INFO, *PSSDT_ENTRY_INFO;

/*
 * IOCTL_VMX_SSDT_INIT output
 */
typedef struct _VMX_SSDT_INIT_RESPONSE {
    BOOLEAN     Success;
    ULONG       ServiceCount;                   /* Number of SSDT entries discovered */
    ULONG64     KiServiceTableVa;               /* VA of nt!KiServiceTable */
    ULONG64     KiSystemCall64Va;               /* VA of nt!KiSystemCall64 */
} VMX_SSDT_INIT_RESPONSE, *PVMX_SSDT_INIT_RESPONSE;

/*
 * IOCTL_VMX_SSDT_DUMP input
 */
typedef struct _VMX_SSDT_DUMP_REQUEST {
    ULONG       StartIndex;                     /* First syscall index to dump */
    ULONG       Count;                          /* Number of entries requested (0 = all) */
} VMX_SSDT_DUMP_REQUEST, *PVMX_SSDT_DUMP_REQUEST;

/*
 * IOCTL_VMX_SSDT_DUMP output
 */
typedef struct _VMX_SSDT_DUMP_RESPONSE {
    ULONG           TotalServices;              /* Total syscalls in SSDT */
    ULONG           ReturnedCount;              /* Entries actually returned */
    SSDT_ENTRY_INFO Entries[1];                 /* Variable length */
} VMX_SSDT_DUMP_RESPONSE, *PVMX_SSDT_DUMP_RESPONSE;

/*
 * IOCTL_VMX_SSDT_HOOK input
 */
typedef struct _VMX_SSDT_HOOK_REQUEST {
    BOOLEAN     ByName;                         /* TRUE = resolve FunctionName */
    ULONG       SyscallIndex;                   /* Used when ByName=FALSE */
    WCHAR       FunctionName[SSDT_MAX_NAME_LEN]; /* Nt* function name (ByName=TRUE) */
    HOOK_RULE   Rule;                           /* Reuse existing HOOK_RULE */
} VMX_SSDT_HOOK_REQUEST, *PVMX_SSDT_HOOK_REQUEST;

/*
 * IOCTL_VMX_SSDT_HOOK output
 */
typedef struct _VMX_SSDT_HOOK_RESPONSE {
    ULONG       HookId;                         /* Generic hook framework ID */
    ULONG       SyscallIndex;                   /* Resolved syscall index */
    ULONG64     FunctionVa;                     /* Hooked function VA */
    WCHAR       FunctionName[SSDT_MAX_NAME_LEN]; /* Resolved name */
} VMX_SSDT_HOOK_RESPONSE, *PVMX_SSDT_HOOK_RESPONSE;

/*
 * IOCTL_VMX_SSDT_UNHOOK input
 */
typedef struct _VMX_SSDT_UNHOOK_REQUEST {
    BOOLEAN     ByHookId;                       /* TRUE = use HookId, FALSE = use SyscallIndex */
    ULONG       HookId;
    ULONG       SyscallIndex;
} VMX_SSDT_UNHOOK_REQUEST, *PVMX_SSDT_UNHOOK_REQUEST;

/*
 * SSDT hook info entry (for SSDT_LIST_HOOKS)
 */
typedef struct _SSDT_HOOK_INFO {
    ULONG       HookId;                         /* Generic hook framework ID */
    ULONG       SyscallIndex;
    ULONG64     FunctionVa;
    HOOK_RULE   Rule;
    ULONG64     HitCount;
    WCHAR       FunctionName[SSDT_MAX_NAME_LEN];
} SSDT_HOOK_INFO, *PSSDT_HOOK_INFO;

/*
 * IOCTL_VMX_SSDT_LIST_HOOKS output
 */
typedef struct _VMX_SSDT_HOOK_LIST {
    ULONG           Count;
    SSDT_HOOK_INFO  Hooks[1];                   /* Variable length */
} VMX_SSDT_HOOK_LIST, *PVMX_SSDT_HOOK_LIST;

/*
 * IOCTL_VMX_SSDT_MONITOR input
 */
#define SSDT_MONITOR_MAX_FILTER 64

typedef struct _VMX_SSDT_MONITOR_REQUEST {
    ULONG       Mode;                           /* SSDT_MONITOR_OFF/ALL/FILTERED */
    ULONG       TargetPid;                      /* 0 = all processes */
    ULONG       FilterCount;                    /* Number of entries in FilterIndices[] */
    ULONG       FilterIndices[SSDT_MONITOR_MAX_FILTER]; /* Syscall indices for FILTERED mode */
} VMX_SSDT_MONITOR_REQUEST, *PVMX_SSDT_MONITOR_REQUEST;

/* ========================================================================= */
/*  Shadow SSDT (Win32k) Monitoring & Hook Framework                         */
/* ========================================================================= */

/*
 * IOCTL codes for Shadow SSDT operations (0x814–0x81A)
 *
 * The Shadow SSDT (KeServiceDescriptorTableShadow) is the second service
 * table containing win32k NtUser/NtGdi syscalls.  These IOCTLs mirror
 * the regular SSDT IOCTLs but target the Shadow table.
 */
#define IOCTL_VMX_SHADOW_SSDT_INIT          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SHADOW_SSDT_DUMP          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SHADOW_SSDT_HOOK          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SHADOW_SSDT_UNHOOK        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SHADOW_SSDT_UNHOOK_ALL    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SHADOW_SSDT_LIST_HOOKS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VMX_SHADOW_SSDT_MONITOR       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81A, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*
 * Shadow SSDT constants
 */
#define SHADOW_SSDT_MAX_SERVICES    2048    /* Win11 has ~1400, leave headroom */

/*
 * IOCTL_VMX_SHADOW_SSDT_INIT output
 */
typedef struct _VMX_SHADOW_SSDT_INIT_RESPONSE {
    BOOLEAN     Success;
    ULONG       ServiceCount;                   /* Number of Shadow SSDT entries */
    ULONG64     W32pServiceTableVa;             /* VA of win32k!W32pServiceTable */
    ULONG64     Win32kBase;                     /* win32k.sys base address */
} VMX_SHADOW_SSDT_INIT_RESPONSE, *PVMX_SHADOW_SSDT_INIT_RESPONSE;

/*
 * IOCTL_VMX_SHADOW_SSDT_DUMP input
 */
typedef struct _VMX_SHADOW_SSDT_DUMP_REQUEST {
    ULONG       StartIndex;                     /* First syscall index to dump */
    ULONG       Count;                          /* Number of entries (0 = all) */
} VMX_SHADOW_SSDT_DUMP_REQUEST, *PVMX_SHADOW_SSDT_DUMP_REQUEST;

/*
 * IOCTL_VMX_SHADOW_SSDT_DUMP output
 * Reuses SSDT_ENTRY_INFO for individual entries.
 */
typedef struct _VMX_SHADOW_SSDT_DUMP_RESPONSE {
    ULONG           TotalServices;
    ULONG           ReturnedCount;
    SSDT_ENTRY_INFO Entries[1];                 /* Variable length */
} VMX_SHADOW_SSDT_DUMP_RESPONSE, *PVMX_SHADOW_SSDT_DUMP_RESPONSE;

/*
 * IOCTL_VMX_SHADOW_SSDT_HOOK input
 */
typedef struct _VMX_SHADOW_SSDT_HOOK_REQUEST {
    BOOLEAN     ByName;                         /* TRUE = resolve FunctionName */
    ULONG       SyscallIndex;                   /* Used when ByName=FALSE */
    WCHAR       FunctionName[SSDT_MAX_NAME_LEN]; /* NtUser/NtGdi function name (ByName=TRUE) */
    HOOK_RULE   Rule;                           /* Reuse existing HOOK_RULE */
} VMX_SHADOW_SSDT_HOOK_REQUEST, *PVMX_SHADOW_SSDT_HOOK_REQUEST;

/*
 * IOCTL_VMX_SHADOW_SSDT_HOOK output
 */
typedef struct _VMX_SHADOW_SSDT_HOOK_RESPONSE {
    ULONG       HookId;                         /* Generic hook framework ID */
    ULONG       SyscallIndex;                   /* Resolved syscall index */
    ULONG64     FunctionVa;                     /* Hooked function VA */
    WCHAR       FunctionName[SSDT_MAX_NAME_LEN]; /* Resolved name */
} VMX_SHADOW_SSDT_HOOK_RESPONSE, *PVMX_SHADOW_SSDT_HOOK_RESPONSE;

/*
 * IOCTL_VMX_SHADOW_SSDT_UNHOOK input
 */
typedef struct _VMX_SHADOW_SSDT_UNHOOK_REQUEST {
    BOOLEAN     ByHookId;                       /* TRUE = use HookId, FALSE = use SyscallIndex */
    ULONG       HookId;
    ULONG       SyscallIndex;
} VMX_SHADOW_SSDT_UNHOOK_REQUEST, *PVMX_SHADOW_SSDT_UNHOOK_REQUEST;

/*
 * Shadow SSDT hook info (for LIST_HOOKS)
 * Reuses SSDT_HOOK_INFO structure layout.
 */
typedef struct _SHADOW_SSDT_HOOK_INFO {
    ULONG       HookId;
    ULONG       SyscallIndex;
    ULONG64     FunctionVa;
    HOOK_RULE   Rule;
    ULONG64     HitCount;
    WCHAR       FunctionName[SSDT_MAX_NAME_LEN];
} SHADOW_SSDT_HOOK_INFO, *PSHADOW_SSDT_HOOK_INFO;

/*
 * IOCTL_VMX_SHADOW_SSDT_LIST_HOOKS output
 */
typedef struct _VMX_SHADOW_SSDT_HOOK_LIST {
    ULONG                   Count;
    SHADOW_SSDT_HOOK_INFO   Hooks[1];           /* Variable length */
} VMX_SHADOW_SSDT_HOOK_LIST, *PVMX_SHADOW_SSDT_HOOK_LIST;

/*
 * IOCTL_VMX_SHADOW_SSDT_MONITOR input
 */
#define SHADOW_SSDT_MONITOR_MAX_FILTER 64

typedef struct _VMX_SHADOW_SSDT_MONITOR_REQUEST {
    ULONG       Mode;                           /* SSDT_MONITOR_OFF/ALL/FILTERED */
    ULONG       TargetPid;                      /* 0 = all processes */
    ULONG       FilterCount;
    ULONG       FilterIndices[SHADOW_SSDT_MONITOR_MAX_FILTER];
} VMX_SHADOW_SSDT_MONITOR_REQUEST, *PVMX_SHADOW_SSDT_MONITOR_REQUEST;

#endif /* _VMX_SHARED_H_ */
