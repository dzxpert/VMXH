/*
 * driver_comm.c - VMX Hypervisor Toolbox
 * User-mode driver communication via DeviceIoControl
 */

#include "driver_comm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/*  Driver Handle                                                            */
/* ========================================================================= */

BOOL DriverOpen(HANDLE *OutHandle)
{
    HANDLE hDevice;

    hDevice = CreateFileA(
        VMX_USERMODE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Failed to open driver device: error %lu\n", GetLastError());
        fprintf(stderr, "    Make sure the driver (VMXToolboxDrv.sys) is loaded.\n");
        fprintf(stderr, "    Run: sc create VMXToolboxDrv type=kernel binPath=<path>\\VMXToolboxDrv.sys\n");
        fprintf(stderr, "         sc start VMXToolboxDrv\n");
        return FALSE;
    }

    *OutHandle = hDevice;
    return TRUE;
}

VOID DriverClose(HANDLE DeviceHandle)
{
    if (DeviceHandle && DeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(DeviceHandle);
    }
}

/* ========================================================================= */
/*  IOCTL Wrappers                                                           */
/* ========================================================================= */

BOOL DriverInitVmx(HANDLE DeviceHandle)
{
    DWORD BytesReturned = 0;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_INIT,
        NULL, 0,
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

BOOL DriverStopVmx(HANDLE DeviceHandle)
{
    DWORD BytesReturned = 0;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_STOP,
        NULL, 0,
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

BOOL DriverSetTarget(HANDLE DeviceHandle, DWORD Pid, DWORD Flags)
{
    VMX_TARGET_INFO Input = { 0 };
    DWORD BytesReturned = 0;

    Input.Pid = Pid;
    Input.Flags = Flags;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SET_TARGET,
        &Input, sizeof(Input),
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

BOOL DriverRemoveTarget(HANDLE DeviceHandle, DWORD Pid)
{
    VMX_REMOVE_TARGET Input = { 0 };
    DWORD BytesReturned = 0;

    Input.Pid = Pid;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_REMOVE_TARGET,
        &Input, sizeof(Input),
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

BOOL DriverSetConfig(HANDLE DeviceHandle, DWORD Pid, DWORD Flags)
{
    VMX_CONFIG_INFO Input = { 0 };
    DWORD BytesReturned = 0;

    Input.Pid = Pid;
    Input.Flags = Flags;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SET_CONFIG,
        &Input, sizeof(Input),
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

BOOL DriverQueryStatus(HANDLE DeviceHandle, VMX_STATUS *OutStatus)
{
    DWORD BytesReturned = 0;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_QUERY_STATUS,
        NULL, 0,
        OutStatus, sizeof(VMX_STATUS),
        &BytesReturned,
        NULL
    );
}

BOOL DriverGetLog(HANDLE DeviceHandle, VMX_LOG_BUFFER *Buffer, DWORD BufferSize, DWORD *BytesReturned)
{
    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_GET_LOG,
        NULL, 0,
        Buffer, BufferSize,
        BytesReturned,
        NULL
    );
}

/* ========================================================================= */
/*  Hypervisor Memory Read/Write IOCTL Wrappers                              */
/* ========================================================================= */

BOOL DriverReadMemory(HANDLE DeviceHandle,
                      DWORD Pid,
                      ULONG64 VirtualAddress,
                      PVOID OutBuffer,
                      DWORD Size,
                      DWORD *BytesReturned)
{
    VMX_MEMORY_REQUEST Input = { 0 };

    Input.Pid = Pid;
    Input.VirtualAddress = VirtualAddress;
    Input.Size = Size;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_READ_MEMORY,
        &Input, sizeof(Input),
        OutBuffer, Size,
        BytesReturned,
        NULL
    );
}

BOOL DriverWriteMemory(HANDLE DeviceHandle,
                       DWORD Pid,
                       ULONG64 VirtualAddress,
                       const VOID *InBuffer,
                       DWORD Size)
{
    /*
     * Write layout: [VMX_MEMORY_REQUEST header][payload bytes]
     * Total size = sizeof(VMX_MEMORY_REQUEST) + Size
     */
    DWORD TotalSize = sizeof(VMX_MEMORY_REQUEST) + Size;
    PUCHAR SendBuffer = (PUCHAR)malloc(TotalSize);
    PVMX_MEMORY_REQUEST Header;
    DWORD BytesReturned = 0;
    BOOL Result;

    if (!SendBuffer) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    /* Fill header */
    Header = (PVMX_MEMORY_REQUEST)SendBuffer;
    memset(Header, 0, sizeof(VMX_MEMORY_REQUEST));
    Header->Pid = Pid;
    Header->VirtualAddress = VirtualAddress;
    Header->Size = Size;

    /* Copy payload after header */
    memcpy(SendBuffer + sizeof(VMX_MEMORY_REQUEST), InBuffer, Size);

    Result = DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_WRITE_MEMORY,
        SendBuffer, TotalSize,
        NULL, 0,
        &BytesReturned,
        NULL
    );

    free(SendBuffer);
    return Result;
}

/* ========================================================================= */
/*  Hook Framework IOCTL Wrappers                                            */
/* ========================================================================= */

BOOL DriverInstallHook(HANDLE DeviceHandle,
                       BOOL ByName,
                       const WCHAR *FunctionName,
                       ULONG64 TargetAddress,
                       DWORD ProcessId,
                       const HOOK_RULE *Rule,
                       VMX_HOOK_RESPONSE *OutResponse)
{
    VMX_HOOK_REQUEST Input = { 0 };
    DWORD BytesReturned = 0;

    Input.ByName = (BOOLEAN)ByName;
    Input.TargetAddress = TargetAddress;
    Input.ProcessId = ProcessId;
    Input.Rule = *Rule;

    if (ByName && FunctionName) {
        wcsncpy(Input.FunctionName, FunctionName, HOOK_MAX_NAME_LEN - 1);
        Input.FunctionName[HOOK_MAX_NAME_LEN - 1] = L'\0';
    }

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_INSTALL_HOOK,
        &Input, sizeof(Input),
        OutResponse, sizeof(VMX_HOOK_RESPONSE),
        &BytesReturned,
        NULL
    );
}

BOOL DriverRemoveHook(HANDLE DeviceHandle, DWORD HookId)
{
    VMX_UNHOOK_REQUEST Input = { 0 };
    DWORD BytesReturned = 0;

    Input.HookId = HookId;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_REMOVE_HOOK,
        &Input, sizeof(Input),
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

BOOL DriverListHooks(HANDLE DeviceHandle,
                     VMX_HOOK_LIST *Buffer,
                     DWORD BufferSize,
                     DWORD *BytesReturned)
{
    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_LIST_HOOKS,
        NULL, 0,
        Buffer, BufferSize,
        BytesReturned,
        NULL
    );
}

BOOL DriverGetHookEvents(HANDLE DeviceHandle,
                         VMX_HOOK_EVENT_BUFFER *Buffer,
                         DWORD BufferSize,
                         DWORD *BytesReturned)
{
    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_GET_HOOK_EVENTS,
        NULL, 0,
        Buffer, BufferSize,
        BytesReturned,
        NULL
    );
}

/* ========================================================================= */
/*  SSDT Framework IOCTL Wrappers                                            */
/* ========================================================================= */

BOOL DriverSsdtInit(HANDLE DeviceHandle,
                    VMX_SSDT_INIT_RESPONSE *OutResponse)
{
    DWORD BytesReturned = 0;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SSDT_INIT,
        NULL, 0,
        OutResponse, sizeof(VMX_SSDT_INIT_RESPONSE),
        &BytesReturned,
        NULL
    );
}

BOOL DriverSsdtDump(HANDLE DeviceHandle,
                    DWORD StartIndex, DWORD Count,
                    VMX_SSDT_DUMP_RESPONSE *Buffer,
                    DWORD BufferSize,
                    DWORD *BytesReturned)
{
    VMX_SSDT_DUMP_REQUEST Input = { 0 };

    Input.StartIndex = StartIndex;
    Input.Count = Count;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SSDT_DUMP,
        &Input, sizeof(Input),
        Buffer, BufferSize,
        BytesReturned,
        NULL
    );
}

BOOL DriverSsdtHook(HANDLE DeviceHandle,
                    BOOL ByName,
                    DWORD SyscallIndex,
                    const WCHAR *FunctionName,
                    const HOOK_RULE *Rule,
                    VMX_SSDT_HOOK_RESPONSE *OutResponse)
{
    VMX_SSDT_HOOK_REQUEST Input = { 0 };
    DWORD BytesReturned = 0;

    Input.ByName = (BOOLEAN)ByName;
    Input.SyscallIndex = SyscallIndex;
    Input.Rule = *Rule;

    if (ByName && FunctionName) {
        wcsncpy(Input.FunctionName, FunctionName, SSDT_MAX_NAME_LEN - 1);
        Input.FunctionName[SSDT_MAX_NAME_LEN - 1] = L'\0';
    }

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SSDT_HOOK,
        &Input, sizeof(Input),
        OutResponse, sizeof(VMX_SSDT_HOOK_RESPONSE),
        &BytesReturned,
        NULL
    );
}

BOOL DriverSsdtUnhook(HANDLE DeviceHandle,
                      BOOL ByHookId,
                      DWORD HookId,
                      DWORD SyscallIndex)
{
    VMX_SSDT_UNHOOK_REQUEST Input = { 0 };
    DWORD BytesReturned = 0;

    Input.ByHookId = (BOOLEAN)ByHookId;
    Input.HookId = HookId;
    Input.SyscallIndex = SyscallIndex;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SSDT_UNHOOK,
        &Input, sizeof(Input),
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

BOOL DriverSsdtUnhookAll(HANDLE DeviceHandle)
{
    DWORD BytesReturned = 0;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SSDT_UNHOOK_ALL,
        NULL, 0,
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

BOOL DriverSsdtListHooks(HANDLE DeviceHandle,
                         VMX_SSDT_HOOK_LIST *Buffer,
                         DWORD BufferSize,
                         DWORD *BytesReturned)
{
    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SSDT_LIST_HOOKS,
        NULL, 0,
        Buffer, BufferSize,
        BytesReturned,
        NULL
    );
}

BOOL DriverSsdtMonitor(HANDLE DeviceHandle,
                       const VMX_SSDT_MONITOR_REQUEST *Request)
{
    DWORD BytesReturned = 0;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SSDT_MONITOR,
        (LPVOID)Request, sizeof(VMX_SSDT_MONITOR_REQUEST),
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

/* ========================================================================= */
/*  Shadow SSDT (Win32k) Framework IOCTL Wrappers                            */
/* ========================================================================= */

BOOL DriverShadowSsdtInit(HANDLE DeviceHandle,
                           VMX_SHADOW_SSDT_INIT_RESPONSE *OutResponse)
{
    DWORD BytesReturned = 0;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SHADOW_SSDT_INIT,
        NULL, 0,
        OutResponse, sizeof(VMX_SHADOW_SSDT_INIT_RESPONSE),
        &BytesReturned,
        NULL
    );
}

BOOL DriverShadowSsdtDump(HANDLE DeviceHandle,
                           DWORD StartIndex, DWORD Count,
                           VMX_SHADOW_SSDT_DUMP_RESPONSE *Buffer,
                           DWORD BufferSize,
                           DWORD *BytesReturned)
{
    VMX_SHADOW_SSDT_DUMP_REQUEST Input = { 0 };

    Input.StartIndex = StartIndex;
    Input.Count = Count;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SHADOW_SSDT_DUMP,
        &Input, sizeof(Input),
        Buffer, BufferSize,
        BytesReturned,
        NULL
    );
}

BOOL DriverShadowSsdtHook(HANDLE DeviceHandle,
                           BOOL ByName,
                           DWORD SyscallIndex,
                           const WCHAR *FunctionName,
                           const HOOK_RULE *Rule,
                           VMX_SHADOW_SSDT_HOOK_RESPONSE *OutResponse)
{
    VMX_SHADOW_SSDT_HOOK_REQUEST Input = { 0 };
    DWORD BytesReturned = 0;

    Input.ByName = (BOOLEAN)ByName;
    Input.SyscallIndex = SyscallIndex;
    Input.Rule = *Rule;

    if (ByName && FunctionName) {
        wcsncpy(Input.FunctionName, FunctionName, SSDT_MAX_NAME_LEN - 1);
        Input.FunctionName[SSDT_MAX_NAME_LEN - 1] = L'\0';
    }

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SHADOW_SSDT_HOOK,
        &Input, sizeof(Input),
        OutResponse, sizeof(VMX_SHADOW_SSDT_HOOK_RESPONSE),
        &BytesReturned,
        NULL
    );
}

BOOL DriverShadowSsdtUnhook(HANDLE DeviceHandle,
                             BOOL ByHookId,
                             DWORD HookId,
                             DWORD SyscallIndex)
{
    VMX_SHADOW_SSDT_UNHOOK_REQUEST Input = { 0 };
    DWORD BytesReturned = 0;

    Input.ByHookId = (BOOLEAN)ByHookId;
    Input.HookId = HookId;
    Input.SyscallIndex = SyscallIndex;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SHADOW_SSDT_UNHOOK,
        &Input, sizeof(Input),
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

BOOL DriverShadowSsdtUnhookAll(HANDLE DeviceHandle)
{
    DWORD BytesReturned = 0;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SHADOW_SSDT_UNHOOK_ALL,
        NULL, 0,
        NULL, 0,
        &BytesReturned,
        NULL
    );
}

BOOL DriverShadowSsdtListHooks(HANDLE DeviceHandle,
                                VMX_SHADOW_SSDT_HOOK_LIST *Buffer,
                                DWORD BufferSize,
                                DWORD *BytesReturned)
{
    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SHADOW_SSDT_LIST_HOOKS,
        NULL, 0,
        Buffer, BufferSize,
        BytesReturned,
        NULL
    );
}

BOOL DriverShadowSsdtMonitor(HANDLE DeviceHandle,
                              const VMX_SHADOW_SSDT_MONITOR_REQUEST *Request)
{
    DWORD BytesReturned = 0;

    return DeviceIoControl(
        DeviceHandle,
        IOCTL_VMX_SHADOW_SSDT_MONITOR,
        (LPVOID)Request, sizeof(VMX_SHADOW_SSDT_MONITOR_REQUEST),
        NULL, 0,
        &BytesReturned,
        NULL
    );
}
