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

#endif /* _DRIVER_COMM_H_ */
