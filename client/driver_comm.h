/*
 * driver_comm.h - VMX Hypervisor Toolbox
 * User-mode driver communication interface
 */

#ifndef _DRIVER_COMM_H_
#define _DRIVER_COMM_H_

#include <windows.h>
#include "../common/shared.h"

/* ========================================================================= */
/*  Driver Handle Management                                                 */
/* ========================================================================= */

BOOL    DriverOpen(HANDLE *OutHandle);
VOID    DriverClose(HANDLE DeviceHandle);

/* ========================================================================= */
/*  IOCTL Wrappers                                                           */
/* ========================================================================= */

BOOL    DriverInitVmx(HANDLE DeviceHandle);
BOOL    DriverStopVmx(HANDLE DeviceHandle);
BOOL    DriverSetTarget(HANDLE DeviceHandle, DWORD Pid, DWORD Flags);
BOOL    DriverRemoveTarget(HANDLE DeviceHandle, DWORD Pid);
BOOL    DriverSetConfig(HANDLE DeviceHandle, DWORD Pid, DWORD Flags);
BOOL    DriverQueryStatus(HANDLE DeviceHandle, VMX_STATUS *OutStatus);
BOOL    DriverGetLog(HANDLE DeviceHandle, VMX_LOG_BUFFER *Buffer, DWORD BufferSize, DWORD *BytesReturned);

/* ========================================================================= */
/*  Hypervisor Memory Read/Write IOCTL Wrappers                              */
/* ========================================================================= */

/*
 * Read memory from a target process via Hypervisor (EPT/NPT physical access).
 *
 * Bypasses all Windows API hooks:
 *   - No OpenProcess / handle creation
 *   - No NtReadVirtualMemory / MmCopyVirtualMemory
 *   - No KeStackAttachProcess
 *   - Direct physical memory access via CR3 page-table walk
 *
 * Pid:             Target process ID
 * VirtualAddress:  Address in target's virtual address space
 * OutBuffer:       Receives the read data
 * Size:            Bytes to read (max VMX_MEM_MAX_SIZE = 64KB)
 * BytesReturned:   Actual bytes read
 */
BOOL    DriverReadMemory(HANDLE DeviceHandle,
                         DWORD Pid,
                         ULONG64 VirtualAddress,
                         PVOID OutBuffer,
                         DWORD Size,
                         DWORD *BytesReturned);

/*
 * Write memory to a target process via Hypervisor (EPT/NPT physical access).
 *
 * Same bypass as ReadMemory. Anti-cheat cannot detect this write.
 *
 * Input layout sent to driver: [VMX_MEMORY_REQUEST header][payload bytes]
 *
 * Pid:             Target process ID
 * VirtualAddress:  Address in target's virtual address space
 * InBuffer:        Data to write
 * Size:            Bytes to write (max VMX_MEM_MAX_SIZE = 64KB)
 */
BOOL    DriverWriteMemory(HANDLE DeviceHandle,
                          DWORD Pid,
                          ULONG64 VirtualAddress,
                          const VOID *InBuffer,
                          DWORD Size);

/* ========================================================================= */
/*  Hook Framework IOCTL Wrappers                                            */
/* ========================================================================= */

/*
 * Install a hook on a kernel function.
 *
 * ByName=TRUE  -> resolve FunctionName via MmGetSystemRoutineAddress
 * ByName=FALSE -> hook the given TargetAddress directly
 *
 * On success, OutResponse receives the assigned HookId and resolved address.
 */
BOOL    DriverInstallHook(HANDLE DeviceHandle,
                          BOOL ByName,
                          const WCHAR *FunctionName,
                          ULONG64 TargetAddress,
                          DWORD ProcessId,
                          const HOOK_RULE *Rule,
                          VMX_HOOK_RESPONSE *OutResponse);

/*
 * Remove a previously installed hook by its HookId.
 */
BOOL    DriverRemoveHook(HANDLE DeviceHandle, DWORD HookId);

/*
 * List all active hooks.
 *
 * Buffer must be pre-allocated by the caller.
 * BufferSize should be large enough for the expected number of hooks.
 */
BOOL    DriverListHooks(HANDLE DeviceHandle,
                        VMX_HOOK_LIST *Buffer,
                        DWORD BufferSize,
                        DWORD *BytesReturned);

/*
 * Read hook event log entries from the ring buffer.
 *
 * This drains the ring buffer - events are returned once and then removed.
 * Buffer must be pre-allocated by the caller.
 */
BOOL    DriverGetHookEvents(HANDLE DeviceHandle,
                            VMX_HOOK_EVENT_BUFFER *Buffer,
                            DWORD BufferSize,
                            DWORD *BytesReturned);

/* ========================================================================= */
/*  SSDT Framework IOCTL Wrappers                                            */
/* ========================================================================= */

/*
 * Initialize SSDT discovery (KiServiceTable scan, address resolution, naming).
 * On success, OutResponse receives table info.
 */
BOOL    DriverSsdtInit(HANDLE DeviceHandle,
                       VMX_SSDT_INIT_RESPONSE *OutResponse);

/*
 * Dump SSDT entries starting from StartIndex, up to Count entries.
 * Buffer must be pre-allocated by the caller.
 */
BOOL    DriverSsdtDump(HANDLE DeviceHandle,
                       DWORD StartIndex, DWORD Count,
                       VMX_SSDT_DUMP_RESPONSE *Buffer,
                       DWORD BufferSize,
                       DWORD *BytesReturned);

/*
 * Hook an SSDT entry by syscall index or Nt* function name.
 * On success, OutResponse receives hookId, resolved index and VA.
 */
BOOL    DriverSsdtHook(HANDLE DeviceHandle,
                       BOOL ByName,
                       DWORD SyscallIndex,
                       const WCHAR *FunctionName,
                       const HOOK_RULE *Rule,
                       VMX_SSDT_HOOK_RESPONSE *OutResponse);

/*
 * Remove an SSDT hook by hookId or syscall index.
 */
BOOL    DriverSsdtUnhook(HANDLE DeviceHandle,
                         BOOL ByHookId,
                         DWORD HookId,
                         DWORD SyscallIndex);

/*
 * Remove all SSDT hooks.
 */
BOOL    DriverSsdtUnhookAll(HANDLE DeviceHandle);

/*
 * List all active SSDT hooks.
 */
BOOL    DriverSsdtListHooks(HANDLE DeviceHandle,
                            VMX_SSDT_HOOK_LIST *Buffer,
                            DWORD BufferSize,
                            DWORD *BytesReturned);

/*
 * Set SSDT monitor mode (off/all/filtered).
 */
BOOL    DriverSsdtMonitor(HANDLE DeviceHandle,
                          const VMX_SSDT_MONITOR_REQUEST *Request);

/* ========================================================================= */
/*  Shadow SSDT (Win32k) Framework IOCTL Wrappers                            */
/* ========================================================================= */

/*
 * Initialize Shadow SSDT discovery (KTHREAD scan, win32k module enumeration).
 * Requires regular SSDT to be initialized first.
 */
BOOL    DriverShadowSsdtInit(HANDLE DeviceHandle,
                              VMX_SHADOW_SSDT_INIT_RESPONSE *OutResponse);

/*
 * Dump Shadow SSDT entries starting from StartIndex, up to Count entries.
 */
BOOL    DriverShadowSsdtDump(HANDLE DeviceHandle,
                              DWORD StartIndex, DWORD Count,
                              VMX_SHADOW_SSDT_DUMP_RESPONSE *Buffer,
                              DWORD BufferSize,
                              DWORD *BytesReturned);

/*
 * Hook a Shadow SSDT entry by syscall index or NtUser/NtGdi name.
 */
BOOL    DriverShadowSsdtHook(HANDLE DeviceHandle,
                              BOOL ByName,
                              DWORD SyscallIndex,
                              const WCHAR *FunctionName,
                              const HOOK_RULE *Rule,
                              VMX_SHADOW_SSDT_HOOK_RESPONSE *OutResponse);

/*
 * Remove a Shadow SSDT hook by hookId or syscall index.
 */
BOOL    DriverShadowSsdtUnhook(HANDLE DeviceHandle,
                                BOOL ByHookId,
                                DWORD HookId,
                                DWORD SyscallIndex);

/*
 * Remove all Shadow SSDT hooks.
 */
BOOL    DriverShadowSsdtUnhookAll(HANDLE DeviceHandle);

/*
 * List all active Shadow SSDT hooks.
 */
BOOL    DriverShadowSsdtListHooks(HANDLE DeviceHandle,
                                   VMX_SHADOW_SSDT_HOOK_LIST *Buffer,
                                   DWORD BufferSize,
                                   DWORD *BytesReturned);

/*
 * Set Shadow SSDT monitor mode (off/all/filtered).
 */
BOOL    DriverShadowSsdtMonitor(HANDLE DeviceHandle,
                                 const VMX_SHADOW_SSDT_MONITOR_REQUEST *Request);

#endif /* _DRIVER_COMM_H_ */
