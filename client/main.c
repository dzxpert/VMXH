/*
 * main.c - VMX Hypervisor Toolbox
 * User-mode CLI control program
 *
 * Usage:
 *   VMXToolbox.exe --pid <PID> [options]
 *   VMXToolbox.exe --status
 *   VMXToolbox.exe --stop
 *   VMXToolbox.exe --log
 *
 * Anti-Anti-Debug Options:
 *   --pid <PID>          Target process ID
 *   --hide-debugger      Hide debugger presence (PEB, NtQuery*)
 *   --hide-hwbp          Hide hardware breakpoints (DR registers)
 *   --hide-timing        Counter time-based detection (RDTSC)
 *   --hide-cpuid         Hide hypervisor from CPUID
 *   --hide-sysinfo       Spoof NtQuerySystemInformation
 *   --hide-exceptions    Normalize exception behavior
 *   --hide-ntclose       Suppress NtClose exception trick
 *   --hide-threadinfo    Block NtSetInformationThread(HideFromDebugger)
 *   --hide-all           Enable all anti-anti-debug features
 *   --remove             Remove target process
 *   --status             Query VMX status
 *   --stop               Stop VMX engine
 *   --log                Display intercepted event log
 *
 * Hook Framework Commands:
 *   --install-hook <name>       Hook kernel function by name
 *   --install-hook-addr <addr>  Hook kernel function by address (hex)
 *   --remove-hook <id>          Remove hook by ID
 *   --list-hooks                List all active hooks
 *   --hook-events               Display hook event log
 *   --action <0-3>              Hook action (0=pass,1=log,2=block,3=modify)
 *   --hook-pid <PID>            PID filter for hook (0=global)
 *   --block-retval <value>      Return value when blocking (hex)
 *   --new-retval <value>        Modified return value (hex)
 *   --hook-log                  Enable event logging for this hook
 *
 * Memory Read/Write Commands (via Hypervisor physical access):
 *   --read-mem <PID> <addr> [size]   Read memory from target process
 *   --write-mem <PID> <addr> <hex>   Write hex bytes to target process
 *   --dump-mem <PID> <addr> <size>   Dump memory region (full hex dump)
 *
 * SSDT Monitoring & Hook Framework:
 *   --ssdt-init                          Initialize SSDT discovery
 *   --ssdt-dump [start] [count]          Dump SSDT table entries
 *   --ssdt-hook <index|NtName>           Hook SSDT function
 *   --ssdt-unhook <index|hookid:N>       Remove SSDT hook
 *   --ssdt-unhook-all                    Remove all SSDT hooks
 *   --ssdt-list                          List active SSDT hooks
 *   --ssdt-monitor <off|all|filtered>    Set SSDT monitor mode
 *   --ssdt-filter <idx1,idx2,...>        Specify syscall indices for filtered mode
 *
 * Shadow SSDT (Win32k) Monitoring & Hook Framework:
 *   --shadow-ssdt-init                          Initialize Shadow SSDT discovery
 *   --shadow-ssdt-dump [start] [count]          Dump Shadow SSDT table entries
 *   --shadow-ssdt-hook <index|NtUserName>       Hook Shadow SSDT function
 *   --shadow-ssdt-unhook <index|hookid:N>       Remove Shadow SSDT hook
 *   --shadow-ssdt-unhook-all                    Remove all Shadow SSDT hooks
 *   --shadow-ssdt-list                          List active Shadow SSDT hooks
 *   --shadow-ssdt-monitor <off|all|filtered>    Set Shadow SSDT monitor mode
 *   --shadow-ssdt-filter <idx1,idx2,...>        Specify Shadow SSDT indices for filtered mode
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma warning(disable: 4028 4024)

#include <windows.h>
#include "driver_comm.h"
#include "../common/shared.h"

/* ========================================================================= */
/*  Banner                                                                   */
/* ========================================================================= */

static void PrintBanner(void)
{
    printf("\n");
    printf("  +=======================================+\n");
    printf("  |       VMX Hypervisor Toolbox          |\n");
    printf("  |   Intel VT-x / AMD SVM Platform       |\n");
    printf("  +=======================================+\n");
    printf("\n");
}

static void PrintUsage(const char *Argv0)
{
    printf("Usage:\n");
    printf("  %s --pid <PID> [hide options]    Set target process\n", Argv0);
    printf("  %s --pid <PID> --remove          Remove target process\n", Argv0);
    printf("  %s --status                      Query VMX status\n", Argv0);
    printf("  %s --stop                        Stop VMX engine\n", Argv0);
    printf("  %s --log                         Display event log\n", Argv0);
    printf("\n");
    printf("Hide Options:\n");
    printf("  --hide-debugger     PEB.BeingDebugged, NtQueryInformationProcess\n");
    printf("  --hide-hwbp         DR0-DR7 hardware breakpoint concealment\n");
    printf("  --hide-timing       RDTSC/RDTSCP time compensation\n");
    printf("  --hide-cpuid        Hide hypervisor from CPUID\n");
    printf("  --hide-sysinfo      NtQuerySystemInformation spoofing\n");
    printf("  --hide-exceptions   INT 2D/INT 3 behavior normalization\n");
    printf("  --hide-ntclose      NtClose invalid handle exception suppression\n");
    printf("  --hide-threadinfo   Block ThreadHideFromDebugger\n");
    printf("  --hide-all          Enable ALL anti-anti-debug features\n");
    printf("\n");
    printf("Hook Framework:\n");
    printf("  --install-hook <name>         Hook kernel function by export name\n");
    printf("  --install-hook-addr <hex>     Hook kernel function by virtual address\n");
    printf("  --remove-hook <id>            Remove a hook by its ID\n");
    printf("  --list-hooks                  List all active hooks\n");
    printf("  --hook-events                 Display hook event log\n");
    printf("\n");
    printf("Hook Options (use with --install-hook / --install-hook-addr):\n");
    printf("  --action <0-3>       Action: 0=passthrough 1=log 2=block 3=modify-retval\n");
    printf("  --hook-pid <PID>     PID filter (0=global, default=0)\n");
    printf("  --block-retval <hex> Return value when action=block\n");
    printf("  --new-retval <hex>   New return value when action=modify-retval\n");
    printf("  --hook-log           Enable event logging for this hook\n");
    printf("\n");
    printf("Memory Read/Write (via Hypervisor physical memory access):\n");
    printf("  --read-mem <PID> <addr> [size]  Read and display memory (default 64 bytes)\n");
    printf("  --write-mem <PID> <addr> <hex>  Write hex bytes (e.g. 90909090CC)\n");
    printf("  --dump-mem <PID> <addr> <size>  Full hex+ASCII dump of memory region\n");
    printf("\n");
    printf("SSDT Monitoring & Hook Framework:\n");
    printf("  --ssdt-init                       Initialize SSDT discovery\n");
    printf("  --ssdt-dump [start] [count]       Dump SSDT table entries\n");
    printf("  --ssdt-hook <index|NtName>        Hook SSDT function (use with --action, etc.)\n");
    printf("  --ssdt-unhook <index|hookid:N>    Remove SSDT hook by index or hookid:N\n");
    printf("  --ssdt-unhook-all                 Remove all SSDT hooks\n");
    printf("  --ssdt-list                       List active SSDT hooks\n");
    printf("  --ssdt-monitor <off|all|filtered> Set SSDT monitor mode\n");
    printf("  --ssdt-filter <idx1,idx2,...>      Syscall indices for filtered mode\n");
    printf("\n");
    printf("Shadow SSDT (Win32k) Monitoring & Hook Framework:\n");
    printf("  --shadow-ssdt-init                    Initialize Shadow SSDT discovery\n");
    printf("  --shadow-ssdt-dump [start] [count]    Dump Shadow SSDT table entries\n");
    printf("  --shadow-ssdt-hook <index|name>       Hook Shadow SSDT function\n");
    printf("  --shadow-ssdt-unhook <index|hookid:N> Remove Shadow SSDT hook\n");
    printf("  --shadow-ssdt-unhook-all              Remove all Shadow SSDT hooks\n");
    printf("  --shadow-ssdt-list                    List active Shadow SSDT hooks\n");
    printf("  --shadow-ssdt-monitor <off|all|filt>  Set Shadow SSDT monitor mode\n");
    printf("  --shadow-ssdt-filter <idx1,idx2,...>   Indices for filtered mode\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --pid 1234 --hide-all\n", Argv0);
    printf("  %s --pid 1234 --hide-debugger --hide-hwbp --hide-timing\n", Argv0);
    printf("  %s --pid 1234 --remove\n", Argv0);
    printf("  %s --status\n", Argv0);
    printf("\n");
    printf("  Hook Examples:\n");
    printf("  %s --install-hook NtOpenProcess --action 1 --hook-log\n", Argv0);
    printf("  %s --install-hook NtQuerySystemInformation --action 2 --block-retval 0xC0000001\n", Argv0);
    printf("  %s --install-hook NtClose --action 3 --new-retval 0 --hook-pid 1234\n", Argv0);
    printf("  %s --install-hook-addr 0xFFFFF80012345678 --action 1 --hook-log\n", Argv0);
    printf("  %s --remove-hook 1\n", Argv0);
    printf("  %s --list-hooks\n", Argv0);
    printf("  %s --hook-events\n", Argv0);
    printf("\n");
    printf("  Memory Read/Write Examples:\n");
    printf("  %s --read-mem 1234 0x7FF600000000 64\n", Argv0);
    printf("  %s --write-mem 1234 0x7FF600001000 90909090\n", Argv0);
    printf("  %s --dump-mem 1234 0x7FF600000000 256\n", Argv0);
    printf("\n");
    printf("  SSDT Examples:\n");
    printf("  %s --ssdt-init\n", Argv0);
    printf("  %s --ssdt-dump\n", Argv0);
    printf("  %s --ssdt-dump 0 20\n", Argv0);
    printf("  %s --ssdt-hook NtOpenProcess --action 1 --hook-log\n", Argv0);
    printf("  %s --ssdt-hook 38 --action 2 --block-retval 0xC0000022\n", Argv0);
    printf("  %s --ssdt-unhook 38\n", Argv0);
    printf("  %s --ssdt-unhook hookid:5\n", Argv0);
    printf("  %s --ssdt-unhook-all\n", Argv0);
    printf("  %s --ssdt-list\n", Argv0);
    printf("  %s --ssdt-monitor all --hook-pid 1234\n", Argv0);
    printf("  %s --ssdt-monitor filtered --ssdt-filter 35,38,55 --hook-pid 1234\n", Argv0);
    printf("  %s --ssdt-monitor off\n", Argv0);
    printf("  %s --hook-events\n", Argv0);
    printf("\n");
    printf("  Shadow SSDT Examples:\n");
    printf("  %s --shadow-ssdt-init\n", Argv0);
    printf("  %s --shadow-ssdt-dump\n", Argv0);
    printf("  %s --shadow-ssdt-dump 0 20\n", Argv0);
    printf("  %s --shadow-ssdt-hook NtUserGetForegroundWindow --action 1 --hook-log\n", Argv0);
    printf("  %s --shadow-ssdt-hook 10 --action 2 --block-retval 0\n", Argv0);
    printf("  %s --shadow-ssdt-unhook 10\n", Argv0);
    printf("  %s --shadow-ssdt-unhook hookid:5\n", Argv0);
    printf("  %s --shadow-ssdt-unhook-all\n", Argv0);
    printf("  %s --shadow-ssdt-list\n", Argv0);
    printf("  %s --shadow-ssdt-monitor all --hook-pid 1234\n", Argv0);
    printf("  %s --shadow-ssdt-monitor filtered --shadow-ssdt-filter 10,20,30\n", Argv0);
    printf("  %s --shadow-ssdt-monitor off\n", Argv0);
    printf("\n");
}

/* ========================================================================= */
/*  Helper: Hook Action to String                                            */
/* ========================================================================= */

static const char *HookActionToStr(ULONG Action)
{
    switch (Action) {
    case HOOK_ACTION_PASSTHROUGH:   return "PASSTHROUGH";
    case HOOK_ACTION_LOG_ONLY:      return "LOG_ONLY";
    case HOOK_ACTION_BLOCK:         return "BLOCK";
    case HOOK_ACTION_MODIFY_RETVAL: return "MODIFY_RETVAL";
    default:                        return "UNKNOWN";
    }
}

/* ========================================================================= */
/*  Log Level Strings                                                        */
/* ========================================================================= */

static const char *LogLevelToStr(ULONG Level)
{
    switch (Level) {
    case VMX_LOG_ERROR: return "ERR";
    case VMX_LOG_WARN:  return "WRN";
    case VMX_LOG_INFO:  return "INF";
    case VMX_LOG_DEBUG: return "DBG";
    default:            return "???";
    }
}

/* ========================================================================= */
/*  Anti-Anti-Debug Commands                                                 */
/* ========================================================================= */

static int CmdSetTarget(HANDLE hDevice, DWORD Pid, DWORD Flags)
{
    /* Initialize VMX first (if not already running) */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
        /* Already initialized is fine */
    }

    printf("[*] Setting target: PID=%u, Flags=0x%08X\n", Pid, Flags);

    /* Print active features */
    printf("[*] Active features:\n");
    if (Flags & AAD_HIDE_DEBUGGER)      printf("    + Hide Debugger (PEB, NtQuery*)\n");
    if (Flags & AAD_HIDE_HWBP)          printf("    + Hide Hardware Breakpoints (DR0-DR7)\n");
    if (Flags & AAD_HIDE_TIMING)        printf("    + Hide Timing (RDTSC compensation)\n");
    if (Flags & AAD_HIDE_CPUID)         printf("    + Hide CPUID (hypervisor presence)\n");
    if (Flags & AAD_HIDE_SYSINFO)       printf("    + Hide System Info (KernelDebugger)\n");
    if (Flags & AAD_HIDE_EXCEPTIONS)    printf("    + Hide Exceptions (INT 2D/3)\n");
    if (Flags & AAD_HIDE_NTCLOSE)       printf("    + Hide NtClose exception\n");
    if (Flags & AAD_HIDE_THREADINFO)    printf("    + Block ThreadHideFromDebugger\n");
    if (Flags & AAD_HIDE_HEAP)          printf("    + Hide Heap Flags\n");
    if (Flags & AAD_HIDE_PARENT)        printf("    + Hide Parent Process\n");

    if (!DriverSetTarget(hDevice, Pid, Flags)) {
        fprintf(stderr, "[!] Failed to set target: error %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Target process PID=%u is now protected.\n", Pid);
    printf("[*] You can now attach a debugger (x64dbg, WinDbg) to PID %u.\n", Pid);
    return 0;
}

static int CmdRemoveTarget(HANDLE hDevice, DWORD Pid)
{
    printf("[*] Removing target: PID=%u\n", Pid);

    if (!DriverRemoveTarget(hDevice, Pid)) {
        fprintf(stderr, "[!] Failed to remove target: error %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Target PID=%u removed.\n", Pid);
    return 0;
}

static int CmdQueryStatus(HANDLE hDevice)
{
    VMX_STATUS Status = { 0 };

    if (!DriverQueryStatus(hDevice, &Status)) {
        fprintf(stderr, "[!] Failed to query status: error %lu\n", GetLastError());
        return 1;
    }

    printf("[*] VMX Status:\n");
    printf("    VMX Active:       %s\n", Status.VmxActive ? "YES" : "NO");
    printf("    CPU Count:        %u\n", Status.CpuCount);
    printf("    Active Targets:   %u\n", Status.ActiveTargets);
    printf("    Total VM-Exits:   %u\n", Status.TotalExits);
    return 0;
}

static int CmdStop(HANDLE hDevice)
{
    printf("[*] Stopping VMX engine...\n");

    if (!DriverStopVmx(hDevice)) {
        fprintf(stderr, "[!] Failed to stop VMX: error %lu\n", GetLastError());
        return 1;
    }

    printf("[+] VMX engine stopped.\n");
    return 0;
}

static int CmdShowLog(HANDLE hDevice)
{
    DWORD BufferSize = sizeof(VMX_LOG_BUFFER) + sizeof(VMX_LOG_ENTRY) * 100;
    VMX_LOG_BUFFER *Buffer = (VMX_LOG_BUFFER *)malloc(BufferSize);
    DWORD BytesReturned = 0;
    ULONG i;

    if (!Buffer) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        return 1;
    }

    printf("[*] Fetching log entries...\n\n");

    if (!DriverGetLog(hDevice, Buffer, BufferSize, &BytesReturned)) {
        fprintf(stderr, "[!] Failed to get log: error %lu\n", GetLastError());
        free(Buffer);
        return 1;
    }

    if (Buffer->Count == 0) {
        printf("    (no log entries)\n");
    } else {
        printf("    %-5s %-8s %s\n", "LEVEL", "PID", "MESSAGE");
        printf("    %-5s %-8s %s\n", "-----", "--------", "-------");

        for (i = 0; i < Buffer->Count; i++) {
            VMX_LOG_ENTRY *Entry = &Buffer->Entries[i];
            printf("    [%s] PID=%-5u %s\n",
                   LogLevelToStr(Entry->Level),
                   Entry->Pid,
                   Entry->Message);
        }
    }

    printf("\n[*] Total entries: %u\n", Buffer->Count);
    free(Buffer);
    return 0;
}

/* ========================================================================= */
/*  Hook Framework Commands                                                  */
/* ========================================================================= */

/*
 * CmdInstallHook - Install hook by function name
 *
 * Initializes VMX if needed, then sends IOCTL_VMX_INSTALL_HOOK
 * with ByName=TRUE and the given function name.
 *
 * Test examples:
 *
 *   1) Monitor NtOpenProcess calls (log mode, global):
 *      VMXToolbox.exe --install-hook NtOpenProcess --action 1 --hook-log
 *
 *   2) Block NtQuerySystemInformation, return STATUS_ACCESS_DENIED:
 *      VMXToolbox.exe --install-hook NtQuerySystemInformation --action 2 --block-retval C0000022
 *
 *   3) Modify NtClose return to STATUS_SUCCESS, only for PID 1234:
 *      VMXToolbox.exe --install-hook NtClose --action 3 --new-retval 0 --hook-pid 1234
 *
 *   4) Passthrough-count NtCreateFile (no log, just hit counter):
 *      VMXToolbox.exe --install-hook NtCreateFile --action 0
 *
 *   5) Log NtAllocateVirtualMemory for all processes:
 *      VMXToolbox.exe --install-hook NtAllocateVirtualMemory --action 1 --hook-log
 *
 * Expected output on success:
 *   [*] Installing hook: Function=NtOpenProcess
 *       Action:     LOG_ONLY (1)
 *       PID Filter: GLOBAL (all processes)
 *       Logging:    ON
 *   [+] Hook installed successfully!
 *       Hook ID:    1
 *       Resolved:   0xFFFFF80012345678
 */
static int CmdInstallHook(HANDLE hDevice, const char *FuncName, DWORD HookPid,
                           const HOOK_RULE *Rule)
{
    VMX_HOOK_RESPONSE Response = { 0 };
    WCHAR WideName[HOOK_MAX_NAME_LEN] = { 0 };
    int j;

    /* Initialize VMX first (if not already running) */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    /* Convert function name to wide string */
    for (j = 0; j < HOOK_MAX_NAME_LEN - 1 && FuncName[j]; j++) {
        WideName[j] = (WCHAR)FuncName[j];
    }
    WideName[j] = L'\0';

    printf("[*] Installing hook: Function=%s\n", FuncName);
    printf("    Action:     %s (%u)\n", HookActionToStr(Rule->Action), Rule->Action);
    printf("    PID Filter: %s", Rule->TargetPid ? "" : "GLOBAL (all processes)\n");
    if (Rule->TargetPid) {
        printf("%u\n", Rule->TargetPid);
    }
    if (Rule->Action == HOOK_ACTION_BLOCK) {
        printf("    Block RetVal:  0x%llX\n", (unsigned long long)Rule->BlockReturnValue);
    }
    if (Rule->Action == HOOK_ACTION_MODIFY_RETVAL) {
        printf("    New RetVal:    0x%llX\n", (unsigned long long)Rule->NewReturnValue);
    }
    printf("    Logging:    %s\n", Rule->LogEnabled ? "ON" : "OFF");

    if (!DriverInstallHook(hDevice, TRUE, WideName, 0, HookPid, Rule, &Response)) {
        fprintf(stderr, "[!] Failed to install hook: error %lu\n", GetLastError());
        fprintf(stderr, "    Make sure the function name is a valid kernel export.\n");
        return 1;
    }

    printf("[+] Hook installed successfully!\n");
    printf("    Hook ID:    %u\n", Response.HookId);
    printf("    Resolved:   0x%llX\n", (unsigned long long)Response.ResolvedAddress);
    return 0;
}

/*
 * CmdInstallHookAddr - Install hook by virtual address
 *
 * Same as CmdInstallHook but with ByName=FALSE and a direct VA.
 * Used when hooking non-exported or custom-calculated kernel addresses.
 *
 * Test examples:
 *
 *   1) Hook a known kernel address (log mode):
 *      VMXToolbox.exe --install-hook-addr FFFFF80012345678 --action 1 --hook-log
 *
 *   2) Block execution at a specific address, return STATUS_UNSUCCESSFUL:
 *      VMXToolbox.exe --install-hook-addr FFFFF800AABBCCDD --action 2 --block-retval C0000001
 *
 *   3) Hook address with PID filter:
 *      VMXToolbox.exe --install-hook-addr FFFFF80012345678 --action 1 --hook-pid 5678 --hook-log
 *
 * Expected output on success:
 *   [*] Installing hook: Address=0xFFFFF80012345678
 *       Action:     LOG_ONLY (1)
 *       PID Filter: GLOBAL (all processes)
 *       Logging:    ON
 *   [+] Hook installed successfully!
 *       Hook ID:    2
 *       Address:    0xFFFFF80012345678
 */
static int CmdInstallHookAddr(HANDLE hDevice, ULONG64 Address, DWORD HookPid,
                               const HOOK_RULE *Rule)
{
    VMX_HOOK_RESPONSE Response = { 0 };

    /* Initialize VMX first (if not already running) */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    printf("[*] Installing hook: Address=0x%llX\n", (unsigned long long)Address);
    printf("    Action:     %s (%u)\n", HookActionToStr(Rule->Action), Rule->Action);
    printf("    PID Filter: %s", Rule->TargetPid ? "" : "GLOBAL (all processes)\n");
    if (Rule->TargetPid) {
        printf("%u\n", Rule->TargetPid);
    }
    if (Rule->Action == HOOK_ACTION_BLOCK) {
        printf("    Block RetVal:  0x%llX\n", (unsigned long long)Rule->BlockReturnValue);
    }
    if (Rule->Action == HOOK_ACTION_MODIFY_RETVAL) {
        printf("    New RetVal:    0x%llX\n", (unsigned long long)Rule->NewReturnValue);
    }
    printf("    Logging:    %s\n", Rule->LogEnabled ? "ON" : "OFF");

    if (!DriverInstallHook(hDevice, FALSE, NULL, Address, HookPid, Rule, &Response)) {
        fprintf(stderr, "[!] Failed to install hook: error %lu\n", GetLastError());
        fprintf(stderr, "    Make sure the address is valid and has >= 14 byte preamble.\n");
        return 1;
    }

    printf("[+] Hook installed successfully!\n");
    printf("    Hook ID:    %u\n", Response.HookId);
    printf("    Address:    0x%llX\n", (unsigned long long)Response.ResolvedAddress);
    return 0;
}

/*
 * CmdRemoveHook - Remove a hook by ID
 *
 * Test examples:
 *
 *   1) Remove hook ID 1:
 *      VMXToolbox.exe --remove-hook 1
 *
 *   2) Remove hook ID 3:
 *      VMXToolbox.exe --remove-hook 3
 *
 * Expected output on success:
 *   [*] Removing hook: ID=1
 *   [+] Hook ID=1 removed.
 *
 * Typical workflow:
 *   VMXToolbox.exe --install-hook NtOpenProcess --action 1 --hook-log   (returns HookID=1)
 *   VMXToolbox.exe --list-hooks                                         (verify hook is active)
 *   VMXToolbox.exe --hook-events                                        (check captured events)
 *   VMXToolbox.exe --remove-hook 1                                      (cleanup)
 *   VMXToolbox.exe --list-hooks                                         (verify removal)
 */
static int CmdRemoveHook(HANDLE hDevice, DWORD HookId)
{
    printf("[*] Removing hook: ID=%u\n", HookId);

    if (!DriverRemoveHook(hDevice, HookId)) {
        fprintf(stderr, "[!] Failed to remove hook: error %lu\n", GetLastError());
        fprintf(stderr, "    Hook ID %u may not exist. Use --list-hooks to check.\n", HookId);
        return 1;
    }

    printf("[+] Hook ID=%u removed.\n", HookId);
    return 0;
}

/*
 * CmdListHooks - List all active hooks with details
 *
 * Test example:
 *   VMXToolbox.exe --list-hooks
 *
 * Expected output (after installing several hooks):
 *   [*] Active Hooks: 3
 *
 *       ID   Active Address            Action         PID      HitCount   Function
 *       ---- ------ ------------------ -------------- -------- ---------- --------
 *       1    YES    0xFFFFF80012345678 LOG_ONLY       GLOBAL   42         NtOpenProcess
 *       2    YES    0xFFFFF80011223344 BLOCK          PID      0          NtQuerySystemInformation
 *                PID Filter: 1234
 *                Block RetVal: 0xC0000022
 *       3    YES    0xFFFFF800AABBCCDD MODIFY_RETVAL  GLOBAL   17         NtClose
 *                New RetVal: 0x0
 *                Logging: ON
 */
static int CmdListHooks(HANDLE hDevice)
{
    DWORD BufferSize = sizeof(VMX_HOOK_LIST) + sizeof(VMX_HOOK_INFO) * 1024;
    VMX_HOOK_LIST *Buffer = (VMX_HOOK_LIST *)malloc(BufferSize);
    DWORD BytesReturned = 0;
    ULONG i;
    char FuncNameA[HOOK_MAX_NAME_LEN];
    int k;
    VMX_HOOK_INFO *Hook;

    if (!Buffer) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        return 1;
    }

    memset(Buffer, 0, BufferSize);

    if (!DriverListHooks(hDevice, Buffer, BufferSize, &BytesReturned)) {
        fprintf(stderr, "[!] Failed to list hooks: error %lu\n", GetLastError());
        free(Buffer);
        return 1;
    }

    printf("[*] Active Hooks: %u\n\n", Buffer->Count);

    if (Buffer->Count == 0) {
        printf("    (no active hooks)\n");
    } else {
        printf("    %-4s %-6s %-18s %-14s %-8s %-10s %s\n",
               "ID", "Active", "Address", "Action", "PID", "HitCount", "Function");
        printf("    %-4s %-6s %-18s %-14s %-8s %-10s %s\n",
               "----", "------", "------------------", "--------------",
               "--------", "----------", "--------");

        for (i = 0; i < Buffer->Count; i++) {
            Hook = &Buffer->Hooks[i];

            /* Convert wide function name to ANSI for display */
            memset(FuncNameA, 0, sizeof(FuncNameA));
            for (k = 0; k < HOOK_MAX_NAME_LEN - 1 && Hook->FunctionName[k]; k++) {
                FuncNameA[k] = (char)Hook->FunctionName[k];
            }
            FuncNameA[k] = '\0';

            printf("    %-4u %-6s 0x%016llX %-14s %-8s %llu         %s\n",
                   Hook->HookId,
                   Hook->Active ? "YES" : "NO",
                   (unsigned long long)Hook->TargetAddress,
                   HookActionToStr(Hook->Rule.Action),
                   Hook->ProcessId ? "PID" : "GLOBAL",
                   (unsigned long long)Hook->HitCount,
                   FuncNameA[0] ? FuncNameA : "(by address)");

            /* Print PID if per-process filter */
            if (Hook->ProcessId) {
                printf("         PID Filter: %u\n", Hook->ProcessId);
            }

            /* Print return value details for block/modify actions */
            if (Hook->Rule.Action == HOOK_ACTION_BLOCK) {
                printf("         Block RetVal: 0x%llX\n",
                       (unsigned long long)Hook->Rule.BlockReturnValue);
            }
            if (Hook->Rule.Action == HOOK_ACTION_MODIFY_RETVAL) {
                printf("         New RetVal: 0x%llX\n",
                       (unsigned long long)Hook->Rule.NewReturnValue);
            }
            if (Hook->Rule.LogEnabled) {
                printf("         Logging: ON\n");
            }
        }
    }

    printf("\n");
    free(Buffer);
    return 0;
}

/*
 * CmdHookEvents - Display hook event log from ring buffer
 *
 * Events are drained on read - each call returns new events since last read.
 * Ring buffer holds up to 512 entries (HOOK_EVENT_RING_SIZE).
 *
 * Test example:
 *   VMXToolbox.exe --hook-events
 *
 * Expected output (after hooks with --hook-log triggered):
 *   [*] Hook Events: 5
 *
 *       HookID PID      Timestamp          CallerAddr         RetVal         Action
 *       ------ -------- ------------------ ------------------ -------------- --------------
 *       1      4        0x00000178A3B2C1D0 0xFFFFF80011112222 0x000000000000 LOG_ONLY
 *       1      1234     0x00000178A3B2C300 0xFFFFF80011112222 0x000000000000 LOG_ONLY
 *       2      1234     0x00000178A3B2C500 0xFFFFF80033334444 0x00C0000022   BLOCK
 *       3      888      0x00000178A3B2C700 0xFFFFF80055556666 0x000000000000 MODIFY_RETVAL
 *       1      4        0x00000178A3B2C900 0xFFFFF80011112222 0x000000000000 LOG_ONLY
 *
 *   [*] Note: Events are drained from ring buffer (shown once).
 *
 * Typical monitoring workflow (repeat in a loop):
 *   VMXToolbox.exe --install-hook NtOpenProcess --action 1 --hook-log
 *   VMXToolbox.exe --hook-events    (poll periodically to see new calls)
 *   VMXToolbox.exe --hook-events    (get next batch)
 *   VMXToolbox.exe --remove-hook 1  (done monitoring)
 */
static int CmdHookEvents(HANDLE hDevice)
{
    DWORD BufferSize = sizeof(VMX_HOOK_EVENT_BUFFER) +
                       sizeof(HOOK_EVENT) * HOOK_EVENT_RING_SIZE;
    VMX_HOOK_EVENT_BUFFER *Buffer = (VMX_HOOK_EVENT_BUFFER *)malloc(BufferSize);
    DWORD BytesReturned = 0;
    ULONG i;
    HOOK_EVENT *Evt;

    if (!Buffer) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        return 1;
    }

    memset(Buffer, 0, BufferSize);

    if (!DriverGetHookEvents(hDevice, Buffer, BufferSize, &BytesReturned)) {
        fprintf(stderr, "[!] Failed to get hook events: error %lu\n", GetLastError());
        free(Buffer);
        return 1;
    }

    printf("[*] Hook Events: %u\n\n", Buffer->Count);

    if (Buffer->Count == 0) {
        printf("    (no hook events - hooks may need --hook-log enabled)\n");
    } else {
        printf("    %-6s %-8s %-18s %-18s %-14s %s\n",
               "HookID", "PID", "Timestamp", "CallerAddr", "RetVal", "Action");
        printf("    %-6s %-8s %-18s %-18s %-14s %s\n",
               "------", "--------", "------------------", "------------------",
               "--------------", "--------------");

        for (i = 0; i < Buffer->Count; i++) {
            Evt = &Buffer->Events[i];

            printf("    %-6u %-8u 0x%016llX 0x%016llX 0x%012llX %s\n",
                   Evt->HookId,
                   Evt->ProcessId,
                   (unsigned long long)Evt->Timestamp,
                   (unsigned long long)Evt->ReturnAddress,
                   (unsigned long long)Evt->FinalRetVal,
                   HookActionToStr(Evt->ActionTaken));
        }
    }

    printf("\n[*] Note: Events are drained from ring buffer (shown once).\n");
    free(Buffer);
    return 0;
}

/* ========================================================================= */
/*  Memory Read/Write Commands                                               */
/* ========================================================================= */

/*
 * HexDump - Print a classic hex+ASCII dump of a memory buffer
 *
 * Output format (16 bytes per line):
 *   <base_addr>:  XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX  |ASCII_______...|
 */
static void HexDump(ULONG64 BaseAddr, const BYTE *Data, DWORD Size)
{
    DWORD Offset;
    DWORD j;

    for (Offset = 0; Offset < Size; Offset += 16) {
        DWORD LineLen = Size - Offset;
        if (LineLen > 16) LineLen = 16;

        /* Address */
        printf("    %016llX: ", (unsigned long long)(BaseAddr + Offset));

        /* Hex bytes */
        for (j = 0; j < 16; j++) {
            if (j == 8) printf(" ");
            if (j < LineLen) {
                printf("%02X ", Data[Offset + j]);
            } else {
                printf("   ");
            }
        }

        /* ASCII */
        printf(" |");
        for (j = 0; j < LineLen; j++) {
            BYTE c = Data[Offset + j];
            printf("%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        printf("|\n");
    }
}

/*
 * ParseHexBytes - Convert a hex string like "90909090CC" to byte array
 *
 * Returns number of bytes parsed, 0 on error.
 */
static DWORD ParseHexBytes(const char *HexStr, BYTE *OutBuffer, DWORD MaxSize)
{
    DWORD Len = (DWORD)strlen(HexStr);
    DWORD ByteCount;
    DWORD i;
    char ByteStr[3] = { 0 };

    /* Skip optional "0x" prefix */
    if (Len >= 2 && HexStr[0] == '0' && (HexStr[1] == 'x' || HexStr[1] == 'X')) {
        HexStr += 2;
        Len -= 2;
    }

    if (Len == 0 || (Len % 2) != 0) {
        return 0;
    }

    ByteCount = Len / 2;
    if (ByteCount > MaxSize) {
        return 0;
    }

    for (i = 0; i < ByteCount; i++) {
        ByteStr[0] = HexStr[i * 2];
        ByteStr[1] = HexStr[i * 2 + 1];
        ByteStr[2] = '\0';
        OutBuffer[i] = (BYTE)strtoul(ByteStr, NULL, 16);
    }

    return ByteCount;
}

/*
 * CmdReadMem - Read memory from target process and display as hex
 *
 * Reads via Hypervisor physical memory (CR3 page walk), invisible to
 * any user/kernel-mode hook or anti-cheat.
 *
 * Test examples:
 *
 *   1) Read PE header (default 64 bytes) from a process:
 *      VMXToolbox.exe --read-mem 1234 7FF600000000
 *
 *   2) Read 128 bytes from a specific address:
 *      VMXToolbox.exe --read-mem 1234 7FF600000000 128
 *
 *   3) Read kernel-mode address (PID=4 for System process):
 *      VMXToolbox.exe --read-mem 4 FFFFF80012340000 64
 *
 * Expected output:
 *   [*] Reading 64 bytes from PID=1234 at 0x7FF600000000
 *   [*] Method: Hypervisor physical memory access (CR3 -> page walk)
 *
 *   [+] Read 64 bytes successfully:
 *
 *       00007FF600000000: 4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  |MZ..............|
 *       00007FF600000010: B8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
 *       00007FF600000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
 *       00007FF600000030: 00 00 00 00 00 00 00 00  00 00 00 00 E8 00 00 00  |................|
 */
static int CmdReadMem(HANDLE hDevice, DWORD Pid, ULONG64 Address, DWORD Size)
{
    BYTE *Buffer;
    DWORD BytesReturned = 0;

    /* Initialize VMX first */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    if (Size == 0 || Size > VMX_MEM_MAX_SIZE) {
        fprintf(stderr, "[!] Invalid size: %u (max %u bytes)\n", Size, VMX_MEM_MAX_SIZE);
        return 1;
    }

    Buffer = (BYTE *)malloc(Size);
    if (!Buffer) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        return 1;
    }
    memset(Buffer, 0, Size);

    printf("[*] Reading %u bytes from PID=%u at 0x%llX\n",
           Size, Pid, (unsigned long long)Address);
    printf("[*] Method: Hypervisor physical memory access (CR3 -> page walk)\n\n");

    if (!DriverReadMemory(hDevice, Pid, Address, Buffer, Size, &BytesReturned)) {
        fprintf(stderr, "[!] Failed to read memory: error %lu\n", GetLastError());
        fprintf(stderr, "    Possible causes:\n");
        fprintf(stderr, "    - PID %u does not exist or has exited\n", Pid);
        fprintf(stderr, "    - Address 0x%llX is not mapped in target process\n",
                (unsigned long long)Address);
        fprintf(stderr, "    - VMX engine not initialized\n");
        free(Buffer);
        return 1;
    }

    printf("[+] Read %lu bytes successfully:\n\n", BytesReturned);
    HexDump(Address, Buffer, BytesReturned);
    printf("\n");

    free(Buffer);
    return 0;
}

/*
 * CmdWriteMem - Write hex bytes to target process memory
 *
 * Writes via Hypervisor physical memory, then reads back to verify.
 * Anti-cheat cannot detect this write (no NtWriteVirtualMemory call).
 *
 * Test examples:
 *
 *   1) Write NOP sled (4 bytes) at code address:
 *      VMXToolbox.exe --write-mem 1234 7FF600001000 90909090
 *
 *   2) Write INT3 breakpoint:
 *      VMXToolbox.exe --write-mem 1234 7FF600001000 CC
 *
 *   3) Write a JMP instruction (EB FE = infinite loop):
 *      VMXToolbox.exe --write-mem 1234 7FF600001000 EBFE
 *
 *   4) Write multiple bytes with 0x prefix:
 *      VMXToolbox.exe --write-mem 1234 7FF600001000 0x48C7C0010000004883C408C3
 *
 *   5) Patch a DWORD value at data address:
 *      VMXToolbox.exe --write-mem 1234 7FF600002000 DEADBEEF
 *
 * Expected output:
 *   [*] Writing 4 bytes to PID=1234 at 0x7FF600001000
 *   [*] Method: Hypervisor physical memory access (CR3 -> page walk)
 *   [*] Data to write:
 *
 *       00007FF600001000: 90 90 90 90                                       |....|
 *
 *   [+] Write completed. Verifying...
 *
 *   [+] Verification PASSED - data matches.
 */
static int CmdWriteMem(HANDLE hDevice, DWORD Pid, ULONG64 Address,
                        const char *HexData)
{
    BYTE WriteBuffer[512];
    DWORD ByteCount;
    BYTE VerifyBuffer[512];
    DWORD VerifyReturned = 0;

    /* Initialize VMX first */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    ByteCount = ParseHexBytes(HexData, WriteBuffer, sizeof(WriteBuffer));
    if (ByteCount == 0) {
        fprintf(stderr, "[!] Invalid hex data: '%s'\n", HexData);
        fprintf(stderr, "    Expected even-length hex string, e.g. 90909090CC\n");
        return 1;
    }

    printf("[*] Writing %u bytes to PID=%u at 0x%llX\n",
           ByteCount, Pid, (unsigned long long)Address);
    printf("[*] Method: Hypervisor physical memory access (CR3 -> page walk)\n");
    printf("[*] Data to write:\n\n");
    HexDump(Address, WriteBuffer, ByteCount);
    printf("\n");

    if (!DriverWriteMemory(hDevice, Pid, Address, WriteBuffer, ByteCount)) {
        fprintf(stderr, "[!] Failed to write memory: error %lu\n", GetLastError());
        fprintf(stderr, "    Possible causes:\n");
        fprintf(stderr, "    - PID %u does not exist or has exited\n", Pid);
        fprintf(stderr, "    - Address 0x%llX is not mapped or read-only\n",
                (unsigned long long)Address);
        fprintf(stderr, "    - VMX engine not initialized\n");
        return 1;
    }

    printf("[+] Write completed. Verifying...\n\n");

    /* Verify by reading back */
    memset(VerifyBuffer, 0, ByteCount);
    if (DriverReadMemory(hDevice, Pid, Address, VerifyBuffer, ByteCount, &VerifyReturned)) {
        if (VerifyReturned == ByteCount &&
            memcmp(WriteBuffer, VerifyBuffer, ByteCount) == 0) {
            printf("[+] Verification PASSED - data matches.\n");
        } else {
            printf("[!] Verification MISMATCH - read-back differs:\n\n");
            HexDump(Address, VerifyBuffer, VerifyReturned);
        }
    } else {
        printf("[!] Verification read-back failed: error %lu\n", GetLastError());
    }

    printf("\n");
    return 0;
}

/*
 * CmdDumpMem - Full hex+ASCII dump of a memory region
 *
 * Reads in VMX_MEM_MAX_SIZE (64KB) chunks for large regions.
 * Handles partial reads gracefully (unmapped pages mid-region).
 *
 * Test examples:
 *
 *   1) Dump first 256 bytes of process image (PE header):
 *      VMXToolbox.exe --dump-mem 1234 7FF600000000 256
 *
 *   2) Dump 4KB page (one full page):
 *      VMXToolbox.exe --dump-mem 1234 7FF600000000 4096
 *
 *   3) Dump large region (128KB, will be read in 64KB chunks):
 *      VMXToolbox.exe --dump-mem 1234 7FF600000000 131072
 *
 *   4) Dump stack memory (RSP area):
 *      VMXToolbox.exe --dump-mem 1234 00000030F5FFE000 512
 *
 *   5) Dump kernel memory (System process, PID=4):
 *      VMXToolbox.exe --dump-mem 4 FFFFF78000000000 64
 *
 * Expected output:
 *   [*] Dumping 256 bytes from PID=1234 starting at 0x7FF600000000
 *   [*] Method: Hypervisor physical memory access (CR3 -> page walk)
 *
 *       00007FF600000000: 4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  |MZ..............|
 *       00007FF600000010: B8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
 *       ... (16 rows total for 256 bytes)
 *
 *   [+] Total bytes dumped: 256
 */
static int CmdDumpMem(HANDLE hDevice, DWORD Pid, ULONG64 Address, DWORD Size)
{
    BYTE *Buffer;
    DWORD ChunkSize;
    DWORD BytesReturned = 0;
    DWORD TotalRead = 0;
    ULONG64 CurrentAddr;

    /* Initialize VMX first */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    if (Size == 0) {
        fprintf(stderr, "[!] Size must be > 0\n");
        return 1;
    }

    ChunkSize = (Size > VMX_MEM_MAX_SIZE) ? VMX_MEM_MAX_SIZE : Size;
    Buffer = (BYTE *)malloc(ChunkSize);
    if (!Buffer) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        return 1;
    }

    printf("[*] Dumping %u bytes from PID=%u starting at 0x%llX\n",
           Size, Pid, (unsigned long long)Address);
    printf("[*] Method: Hypervisor physical memory access (CR3 -> page walk)\n\n");

    CurrentAddr = Address;
    while (TotalRead < Size) {
        DWORD ReadSize = Size - TotalRead;
        if (ReadSize > ChunkSize) ReadSize = ChunkSize;

        memset(Buffer, 0, ChunkSize);
        BytesReturned = 0;

        if (!DriverReadMemory(hDevice, Pid, CurrentAddr, Buffer, ReadSize, &BytesReturned)) {
            if (TotalRead == 0) {
                fprintf(stderr, "[!] Failed to read memory at 0x%llX: error %lu\n",
                        (unsigned long long)CurrentAddr, GetLastError());
                free(Buffer);
                return 1;
            }
            /* Partial read - show what we got so far */
            printf("    --- read failed at offset 0x%llX (error %lu) ---\n",
                   (unsigned long long)CurrentAddr, GetLastError());
            break;
        }

        HexDump(CurrentAddr, Buffer, BytesReturned);

        TotalRead += BytesReturned;
        CurrentAddr += BytesReturned;

        /* If we got less than requested, the rest is unmapped */
        if (BytesReturned < ReadSize) {
            printf("    --- partial read: got %lu of %u bytes ---\n",
                   BytesReturned, ReadSize);
            break;
        }
    }

    printf("\n[+] Total bytes dumped: %u\n\n", TotalRead);
    free(Buffer);
    return 0;
}

/* ========================================================================= */
/*  SSDT Framework Commands                                                  */
/* ========================================================================= */

static int CmdSsdtInit(HANDLE hDevice)
{
    VMX_SSDT_INIT_RESPONSE Response = { 0 };

    /* Initialize VMX first (if not already running) */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    printf("[*] Initializing SSDT discovery...\n");

    if (!DriverSsdtInit(hDevice, &Response)) {
        fprintf(stderr, "[!] Failed to initialize SSDT: error %lu\n", GetLastError());
        return 1;
    }

    if (!Response.Success) {
        fprintf(stderr, "[!] SSDT discovery failed.\n");
        return 1;
    }

    printf("[+] SSDT initialized successfully!\n");
    printf("    KiSystemCall64:  0x%llX\n", (unsigned long long)Response.KiSystemCall64Va);
    printf("    KiServiceTable:  0x%llX\n", (unsigned long long)Response.KiServiceTableVa);
    printf("    Service Count:   %u\n", Response.ServiceCount);
    return 0;
}

static int CmdSsdtDump(HANDLE hDevice, DWORD StartIndex, DWORD Count)
{
    DWORD BufferSize;
    VMX_SSDT_DUMP_RESPONSE *Buffer;
    DWORD BytesReturned = 0;
    ULONG i;
    char FuncNameA[SSDT_MAX_NAME_LEN];
    int k;

    /* Limit buffer to reasonable size */
    if (Count == 0) Count = SSDT_MAX_SERVICES;
    if (Count > SSDT_MAX_SERVICES) Count = SSDT_MAX_SERVICES;

    BufferSize = (DWORD)(sizeof(VMX_SSDT_DUMP_RESPONSE) + sizeof(SSDT_ENTRY_INFO) * Count);
    Buffer = (VMX_SSDT_DUMP_RESPONSE *)malloc(BufferSize);
    if (!Buffer) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        return 1;
    }
    memset(Buffer, 0, BufferSize);

    printf("[*] Dumping SSDT entries (start=%u, count=%u)...\n\n", StartIndex, Count);

    if (!DriverSsdtDump(hDevice, StartIndex, Count, Buffer, BufferSize, &BytesReturned)) {
        fprintf(stderr, "[!] Failed to dump SSDT: error %lu\n", GetLastError());
        fprintf(stderr, "    Make sure --ssdt-init has been called first.\n");
        free(Buffer);
        return 1;
    }

    printf("    Total services: %u, Returned: %u\n\n", Buffer->TotalServices, Buffer->ReturnedCount);

    if (Buffer->ReturnedCount == 0) {
        printf("    (no entries)\n");
    } else {
        printf("    %-6s %-18s %-4s %-12s %s\n",
               "Index", "Address", "Args", "RawOffset", "Name");
        printf("    %-6s %-18s %-4s %-12s %s\n",
               "------", "------------------", "----", "------------", "----");

        for (i = 0; i < Buffer->ReturnedCount; i++) {
            SSDT_ENTRY_INFO *E = &Buffer->Entries[i];

            memset(FuncNameA, 0, sizeof(FuncNameA));
            for (k = 0; k < SSDT_MAX_NAME_LEN - 1 && E->FunctionName[k]; k++) {
                FuncNameA[k] = (char)E->FunctionName[k];
            }
            FuncNameA[k] = '\0';

            printf("    %-6u 0x%016llX %-4u 0x%08X   %s\n",
                   E->SyscallIndex,
                   (unsigned long long)E->FunctionVa,
                   E->ArgCount,
                   (unsigned int)E->RawOffset,
                   FuncNameA[0] ? FuncNameA : "(unknown)");
        }
    }

    printf("\n");
    free(Buffer);
    return 0;
}

static int CmdSsdtHook(HANDLE hDevice, const char *Target, DWORD HookPid,
                        const HOOK_RULE *Rule)
{
    VMX_SSDT_HOOK_RESPONSE Response = { 0 };
    WCHAR WideName[SSDT_MAX_NAME_LEN] = { 0 };
    BOOL ByName;
    DWORD SyscallIndex = 0;
    char FuncNameA[SSDT_MAX_NAME_LEN];
    int k;

    /* Initialize VMX first */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    /* Determine if Target is a name (contains letters) or index (all digits) */
    ByName = FALSE;
    {
        const char *p = Target;
        while (*p) {
            if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')) {
                ByName = TRUE;
                break;
            }
            p++;
        }
    }

    if (ByName) {
        int j;
        for (j = 0; j < SSDT_MAX_NAME_LEN - 1 && Target[j]; j++) {
            WideName[j] = (WCHAR)Target[j];
        }
        WideName[j] = L'\0';

        printf("[*] Hooking SSDT function: %s\n", Target);
    } else {
        SyscallIndex = (DWORD)atoi(Target);
        printf("[*] Hooking SSDT syscall index: %u\n", SyscallIndex);
    }

    printf("    Action:     %s (%u)\n", HookActionToStr(Rule->Action), Rule->Action);
    printf("    PID Filter: %s", Rule->TargetPid ? "" : "GLOBAL (all processes)\n");
    if (Rule->TargetPid) {
        printf("%u\n", Rule->TargetPid);
    }
    if (Rule->Action == HOOK_ACTION_BLOCK) {
        printf("    Block RetVal:  0x%llX\n", (unsigned long long)Rule->BlockReturnValue);
    }
    if (Rule->Action == HOOK_ACTION_MODIFY_RETVAL) {
        printf("    New RetVal:    0x%llX\n", (unsigned long long)Rule->NewReturnValue);
    }
    printf("    Logging:    %s\n", Rule->LogEnabled ? "ON" : "OFF");

    if (!DriverSsdtHook(hDevice, ByName, SyscallIndex, WideName, Rule, &Response)) {
        fprintf(stderr, "[!] Failed to hook SSDT: error %lu\n", GetLastError());
        fprintf(stderr, "    Make sure --ssdt-init has been called first.\n");
        return 1;
    }

    memset(FuncNameA, 0, sizeof(FuncNameA));
    for (k = 0; k < SSDT_MAX_NAME_LEN - 1 && Response.FunctionName[k]; k++) {
        FuncNameA[k] = (char)Response.FunctionName[k];
    }
    FuncNameA[k] = '\0';

    printf("[+] SSDT hook installed!\n");
    printf("    Hook ID:       %u\n", Response.HookId);
    printf("    Syscall Index: %u\n", Response.SyscallIndex);
    printf("    Function VA:   0x%llX\n", (unsigned long long)Response.FunctionVa);
    if (FuncNameA[0]) {
        printf("    Function:      %s\n", FuncNameA);
    }
    return 0;
}

static int CmdSsdtUnhook(HANDLE hDevice, const char *Target)
{
    /* Parse target: "hookid:N" or plain index number */
    if (strncmp(Target, "hookid:", 7) == 0) {
        DWORD HookId = (DWORD)atoi(Target + 7);
        printf("[*] Removing SSDT hook by hookId=%u\n", HookId);

        if (!DriverSsdtUnhook(hDevice, TRUE, HookId, 0)) {
            fprintf(stderr, "[!] Failed to unhook: error %lu\n", GetLastError());
            return 1;
        }
        printf("[+] SSDT hook (hookId=%u) removed.\n", HookId);
    } else {
        DWORD Index = (DWORD)atoi(Target);
        printf("[*] Removing SSDT hook for syscall index=%u\n", Index);

        if (!DriverSsdtUnhook(hDevice, FALSE, 0, Index)) {
            fprintf(stderr, "[!] Failed to unhook: error %lu\n", GetLastError());
            return 1;
        }
        printf("[+] SSDT hook (index=%u) removed.\n", Index);
    }
    return 0;
}

static int CmdSsdtUnhookAll(HANDLE hDevice)
{
    printf("[*] Removing all SSDT hooks...\n");

    if (!DriverSsdtUnhookAll(hDevice)) {
        fprintf(stderr, "[!] Failed to unhook all: error %lu\n", GetLastError());
        return 1;
    }

    printf("[+] All SSDT hooks removed.\n");
    return 0;
}

static int CmdSsdtList(HANDLE hDevice)
{
    DWORD BufferSize = (DWORD)(sizeof(VMX_SSDT_HOOK_LIST) + sizeof(SSDT_HOOK_INFO) * 64);
    VMX_SSDT_HOOK_LIST *Buffer = (VMX_SSDT_HOOK_LIST *)malloc(BufferSize);
    DWORD BytesReturned = 0;
    ULONG i;
    char FuncNameA[SSDT_MAX_NAME_LEN];
    int k;

    if (!Buffer) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        return 1;
    }
    memset(Buffer, 0, BufferSize);

    if (!DriverSsdtListHooks(hDevice, Buffer, BufferSize, &BytesReturned)) {
        fprintf(stderr, "[!] Failed to list SSDT hooks: error %lu\n", GetLastError());
        free(Buffer);
        return 1;
    }

    printf("[*] Active SSDT Hooks: %u\n\n", Buffer->Count);

    if (Buffer->Count == 0) {
        printf("    (no active SSDT hooks)\n");
    } else {
        printf("    %-6s %-6s %-18s %-14s %-8s %-10s %s\n",
               "HookID", "Index", "Address", "Action", "PID", "HitCount", "Function");
        printf("    %-6s %-6s %-18s %-14s %-8s %-10s %s\n",
               "------", "------", "------------------", "--------------",
               "--------", "----------", "--------");

        for (i = 0; i < Buffer->Count; i++) {
            SSDT_HOOK_INFO *H = &Buffer->Hooks[i];

            memset(FuncNameA, 0, sizeof(FuncNameA));
            for (k = 0; k < SSDT_MAX_NAME_LEN - 1 && H->FunctionName[k]; k++) {
                FuncNameA[k] = (char)H->FunctionName[k];
            }
            FuncNameA[k] = '\0';

            printf("    %-6u %-6u 0x%016llX %-14s %-8s %llu         %s\n",
                   H->HookId,
                   H->SyscallIndex,
                   (unsigned long long)H->FunctionVa,
                   HookActionToStr(H->Rule.Action),
                   H->Rule.TargetPid ? "PID" : "GLOBAL",
                   (unsigned long long)H->HitCount,
                   FuncNameA[0] ? FuncNameA : "(unknown)");

            if (H->Rule.TargetPid) {
                printf("         PID Filter: %u\n", H->Rule.TargetPid);
            }
            if (H->Rule.Action == HOOK_ACTION_BLOCK) {
                printf("         Block RetVal: 0x%llX\n",
                       (unsigned long long)H->Rule.BlockReturnValue);
            }
            if (H->Rule.Action == HOOK_ACTION_MODIFY_RETVAL) {
                printf("         New RetVal: 0x%llX\n",
                       (unsigned long long)H->Rule.NewReturnValue);
            }
            if (H->Rule.LogEnabled) {
                printf("         Logging: ON\n");
            }
        }
    }

    printf("\n");
    free(Buffer);
    return 0;
}

static int CmdSsdtMonitor(HANDLE hDevice, DWORD Mode, DWORD MonitorPid,
                           const DWORD *FilterIndices, DWORD FilterCount)
{
    VMX_SSDT_MONITOR_REQUEST Request = { 0 };
    DWORD i;
    const char *ModeStr;

    /* Initialize VMX first */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    Request.Mode = Mode;
    Request.TargetPid = MonitorPid;

    if (Mode == SSDT_MONITOR_FILTERED && FilterIndices && FilterCount > 0) {
        if (FilterCount > SSDT_MONITOR_MAX_FILTER)
            FilterCount = SSDT_MONITOR_MAX_FILTER;
        Request.FilterCount = FilterCount;
        for (i = 0; i < FilterCount; i++) {
            Request.FilterIndices[i] = FilterIndices[i];
        }
    }

    switch (Mode) {
    case SSDT_MONITOR_OFF:      ModeStr = "OFF"; break;
    case SSDT_MONITOR_ALL:      ModeStr = "ALL"; break;
    case SSDT_MONITOR_FILTERED: ModeStr = "FILTERED"; break;
    default:                    ModeStr = "UNKNOWN"; break;
    }

    printf("[*] Setting SSDT monitor mode: %s\n", ModeStr);
    if (MonitorPid) {
        printf("    PID Filter: %u\n", MonitorPid);
    }
    if (Mode == SSDT_MONITOR_FILTERED) {
        printf("    Filter indices (%u): ", FilterCount);
        for (i = 0; i < FilterCount; i++) {
            printf("%u%s", FilterIndices[i], (i < FilterCount - 1) ? "," : "");
        }
        printf("\n");
    }

    if (!DriverSsdtMonitor(hDevice, &Request)) {
        fprintf(stderr, "[!] Failed to set monitor mode: error %lu\n", GetLastError());
        fprintf(stderr, "    Make sure --ssdt-init has been called first.\n");
        return 1;
    }

    if (Mode == SSDT_MONITOR_OFF) {
        printf("[+] SSDT monitoring stopped.\n");
    } else {
        printf("[+] SSDT monitoring started. Use --hook-events to view captured calls.\n");
    }
    return 0;
}

/* ========================================================================= */
/*  Shadow SSDT (Win32k) Framework Commands                                  */
/* ========================================================================= */

static int CmdShadowSsdtInit(HANDLE hDevice)
{
    VMX_SHADOW_SSDT_INIT_RESPONSE Response = { 0 };

    /* Initialize VMX first (if not already running) */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    printf("[*] Initializing Shadow SSDT (Win32k) discovery...\n");
    printf("[*] Note: Regular SSDT must be initialized first (--ssdt-init).\n");

    if (!DriverShadowSsdtInit(hDevice, &Response)) {
        fprintf(stderr, "[!] Failed to initialize Shadow SSDT: error %lu\n", GetLastError());
        fprintf(stderr, "    Make sure --ssdt-init has been called first.\n");
        fprintf(stderr, "    A GUI process must be running on the system.\n");
        return 1;
    }

    if (!Response.Success) {
        fprintf(stderr, "[!] Shadow SSDT discovery failed.\n");
        return 1;
    }

    printf("[+] Shadow SSDT initialized successfully!\n");
    printf("    W32pServiceTable: 0x%llX\n", (unsigned long long)Response.W32pServiceTableVa);
    printf("    Win32k Base:      0x%llX\n", (unsigned long long)Response.Win32kBase);
    printf("    Service Count:    %u\n", Response.ServiceCount);
    return 0;
}

static int CmdShadowSsdtDump(HANDLE hDevice, DWORD StartIndex, DWORD Count)
{
    DWORD BufferSize;
    VMX_SHADOW_SSDT_DUMP_RESPONSE *Buffer;
    DWORD BytesReturned = 0;
    ULONG i;
    char FuncNameA[SSDT_MAX_NAME_LEN];
    int k;

    if (Count == 0) Count = SHADOW_SSDT_MAX_SERVICES;
    if (Count > SHADOW_SSDT_MAX_SERVICES) Count = SHADOW_SSDT_MAX_SERVICES;

    BufferSize = (DWORD)(sizeof(VMX_SHADOW_SSDT_DUMP_RESPONSE) + sizeof(SSDT_ENTRY_INFO) * Count);
    Buffer = (VMX_SHADOW_SSDT_DUMP_RESPONSE *)malloc(BufferSize);
    if (!Buffer) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        return 1;
    }
    memset(Buffer, 0, BufferSize);

    printf("[*] Dumping Shadow SSDT entries (start=%u, count=%u)...\n\n", StartIndex, Count);

    if (!DriverShadowSsdtDump(hDevice, StartIndex, Count, Buffer, BufferSize, &BytesReturned)) {
        fprintf(stderr, "[!] Failed to dump Shadow SSDT: error %lu\n", GetLastError());
        fprintf(stderr, "    Make sure --shadow-ssdt-init has been called first.\n");
        free(Buffer);
        return 1;
    }

    printf("    Total services: %u, Returned: %u\n\n", Buffer->TotalServices, Buffer->ReturnedCount);

    if (Buffer->ReturnedCount == 0) {
        printf("    (no entries)\n");
    } else {
        printf("    %-6s %-18s %-4s %-12s %s\n",
               "Index", "Address", "Args", "RawOffset", "Name");
        printf("    %-6s %-18s %-4s %-12s %s\n",
               "------", "------------------", "----", "------------", "----");

        for (i = 0; i < Buffer->ReturnedCount; i++) {
            SSDT_ENTRY_INFO *E = &Buffer->Entries[i];

            memset(FuncNameA, 0, sizeof(FuncNameA));
            for (k = 0; k < SSDT_MAX_NAME_LEN - 1 && E->FunctionName[k]; k++) {
                FuncNameA[k] = (char)E->FunctionName[k];
            }
            FuncNameA[k] = '\0';

            printf("    %-6u 0x%016llX %-4u 0x%08X   %s\n",
                   E->SyscallIndex,
                   (unsigned long long)E->FunctionVa,
                   E->ArgCount,
                   (unsigned int)E->RawOffset,
                   FuncNameA[0] ? FuncNameA : "(unknown)");
        }
    }

    printf("\n");
    free(Buffer);
    return 0;
}

static int CmdShadowSsdtHook(HANDLE hDevice, const char *Target, DWORD HookPid,
                               const HOOK_RULE *Rule)
{
    VMX_SHADOW_SSDT_HOOK_RESPONSE Response = { 0 };
    WCHAR WideName[SSDT_MAX_NAME_LEN] = { 0 };
    BOOL ByName;
    DWORD SyscallIndex = 0;
    char FuncNameA[SSDT_MAX_NAME_LEN];
    int k;

    /* Initialize VMX first */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    /* Determine if Target is a name or index */
    ByName = FALSE;
    {
        const char *p = Target;
        while (*p) {
            if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')) {
                ByName = TRUE;
                break;
            }
            p++;
        }
    }

    if (ByName) {
        int j;
        for (j = 0; j < SSDT_MAX_NAME_LEN - 1 && Target[j]; j++) {
            WideName[j] = (WCHAR)Target[j];
        }
        WideName[j] = L'\0';

        printf("[*] Hooking Shadow SSDT function: %s\n", Target);
    } else {
        SyscallIndex = (DWORD)atoi(Target);
        printf("[*] Hooking Shadow SSDT syscall index: %u\n", SyscallIndex);
    }

    printf("    Action:     %s (%u)\n", HookActionToStr(Rule->Action), Rule->Action);
    printf("    PID Filter: %s", Rule->TargetPid ? "" : "GLOBAL (all processes)\n");
    if (Rule->TargetPid) {
        printf("%u\n", Rule->TargetPid);
    }
    if (Rule->Action == HOOK_ACTION_BLOCK) {
        printf("    Block RetVal:  0x%llX\n", (unsigned long long)Rule->BlockReturnValue);
    }
    if (Rule->Action == HOOK_ACTION_MODIFY_RETVAL) {
        printf("    New RetVal:    0x%llX\n", (unsigned long long)Rule->NewReturnValue);
    }
    printf("    Logging:    %s\n", Rule->LogEnabled ? "ON" : "OFF");

    if (!DriverShadowSsdtHook(hDevice, ByName, SyscallIndex, WideName, Rule, &Response)) {
        fprintf(stderr, "[!] Failed to hook Shadow SSDT: error %lu\n", GetLastError());
        fprintf(stderr, "    Make sure --shadow-ssdt-init has been called first.\n");
        return 1;
    }

    memset(FuncNameA, 0, sizeof(FuncNameA));
    for (k = 0; k < SSDT_MAX_NAME_LEN - 1 && Response.FunctionName[k]; k++) {
        FuncNameA[k] = (char)Response.FunctionName[k];
    }
    FuncNameA[k] = '\0';

    printf("[+] Shadow SSDT hook installed!\n");
    printf("    Hook ID:       %u\n", Response.HookId);
    printf("    Syscall Index: %u\n", Response.SyscallIndex);
    printf("    Function VA:   0x%llX\n", (unsigned long long)Response.FunctionVa);
    if (FuncNameA[0]) {
        printf("    Function:      %s\n", FuncNameA);
    }
    return 0;
}

static int CmdShadowSsdtUnhook(HANDLE hDevice, const char *Target)
{
    if (strncmp(Target, "hookid:", 7) == 0) {
        DWORD HookId = (DWORD)atoi(Target + 7);
        printf("[*] Removing Shadow SSDT hook by hookId=%u\n", HookId);

        if (!DriverShadowSsdtUnhook(hDevice, TRUE, HookId, 0)) {
            fprintf(stderr, "[!] Failed to unhook: error %lu\n", GetLastError());
            return 1;
        }
        printf("[+] Shadow SSDT hook (hookId=%u) removed.\n", HookId);
    } else {
        DWORD Index = (DWORD)atoi(Target);
        printf("[*] Removing Shadow SSDT hook for syscall index=%u\n", Index);

        if (!DriverShadowSsdtUnhook(hDevice, FALSE, 0, Index)) {
            fprintf(stderr, "[!] Failed to unhook: error %lu\n", GetLastError());
            return 1;
        }
        printf("[+] Shadow SSDT hook (index=%u) removed.\n", Index);
    }
    return 0;
}

static int CmdShadowSsdtUnhookAll(HANDLE hDevice)
{
    printf("[*] Removing all Shadow SSDT hooks...\n");

    if (!DriverShadowSsdtUnhookAll(hDevice)) {
        fprintf(stderr, "[!] Failed to unhook all: error %lu\n", GetLastError());
        return 1;
    }

    printf("[+] All Shadow SSDT hooks removed.\n");
    return 0;
}

static int CmdShadowSsdtList(HANDLE hDevice)
{
    DWORD BufferSize = (DWORD)(sizeof(VMX_SHADOW_SSDT_HOOK_LIST) + sizeof(SHADOW_SSDT_HOOK_INFO) * 64);
    VMX_SHADOW_SSDT_HOOK_LIST *Buffer = (VMX_SHADOW_SSDT_HOOK_LIST *)malloc(BufferSize);
    DWORD BytesReturned = 0;
    ULONG i;
    char FuncNameA[SSDT_MAX_NAME_LEN];
    int k;

    if (!Buffer) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        return 1;
    }
    memset(Buffer, 0, BufferSize);

    if (!DriverShadowSsdtListHooks(hDevice, Buffer, BufferSize, &BytesReturned)) {
        fprintf(stderr, "[!] Failed to list Shadow SSDT hooks: error %lu\n", GetLastError());
        free(Buffer);
        return 1;
    }

    printf("[*] Active Shadow SSDT Hooks: %u\n\n", Buffer->Count);

    if (Buffer->Count == 0) {
        printf("    (no active Shadow SSDT hooks)\n");
    } else {
        printf("    %-6s %-6s %-18s %-14s %-8s %-10s %s\n",
               "HookID", "Index", "Address", "Action", "PID", "HitCount", "Function");
        printf("    %-6s %-6s %-18s %-14s %-8s %-10s %s\n",
               "------", "------", "------------------", "--------------",
               "--------", "----------", "--------");

        for (i = 0; i < Buffer->Count; i++) {
            SHADOW_SSDT_HOOK_INFO *H = &Buffer->Hooks[i];

            memset(FuncNameA, 0, sizeof(FuncNameA));
            for (k = 0; k < SSDT_MAX_NAME_LEN - 1 && H->FunctionName[k]; k++) {
                FuncNameA[k] = (char)H->FunctionName[k];
            }
            FuncNameA[k] = '\0';

            printf("    %-6u %-6u 0x%016llX %-14s %-8s %llu         %s\n",
                   H->HookId,
                   H->SyscallIndex,
                   (unsigned long long)H->FunctionVa,
                   HookActionToStr(H->Rule.Action),
                   H->Rule.TargetPid ? "PID" : "GLOBAL",
                   (unsigned long long)H->HitCount,
                   FuncNameA[0] ? FuncNameA : "(unknown)");

            if (H->Rule.TargetPid) {
                printf("         PID Filter: %u\n", H->Rule.TargetPid);
            }
            if (H->Rule.Action == HOOK_ACTION_BLOCK) {
                printf("         Block RetVal: 0x%llX\n",
                       (unsigned long long)H->Rule.BlockReturnValue);
            }
            if (H->Rule.Action == HOOK_ACTION_MODIFY_RETVAL) {
                printf("         New RetVal: 0x%llX\n",
                       (unsigned long long)H->Rule.NewReturnValue);
            }
            if (H->Rule.LogEnabled) {
                printf("         Logging: ON\n");
            }
        }
    }

    printf("\n");
    free(Buffer);
    return 0;
}

static int CmdShadowSsdtMonitor(HANDLE hDevice, DWORD Mode, DWORD MonitorPid,
                                  const DWORD *FilterIndices, DWORD FilterCount)
{
    VMX_SHADOW_SSDT_MONITOR_REQUEST Request = { 0 };
    DWORD i;
    const char *ModeStr;

    /* Initialize VMX first */
    if (!DriverInitVmx(hDevice)) {
        DWORD Err = GetLastError();
        if (Err != ERROR_ALREADY_REGISTERED && Err != 0) {
            fprintf(stderr, "[!] Failed to initialize VMX: error %lu\n", Err);
            return 1;
        }
    }

    Request.Mode = Mode;
    Request.TargetPid = MonitorPid;

    if (Mode == SSDT_MONITOR_FILTERED && FilterIndices && FilterCount > 0) {
        if (FilterCount > SHADOW_SSDT_MONITOR_MAX_FILTER)
            FilterCount = SHADOW_SSDT_MONITOR_MAX_FILTER;
        Request.FilterCount = FilterCount;
        for (i = 0; i < FilterCount; i++) {
            Request.FilterIndices[i] = FilterIndices[i];
        }
    }

    switch (Mode) {
    case SSDT_MONITOR_OFF:      ModeStr = "OFF"; break;
    case SSDT_MONITOR_ALL:      ModeStr = "ALL"; break;
    case SSDT_MONITOR_FILTERED: ModeStr = "FILTERED"; break;
    default:                    ModeStr = "UNKNOWN"; break;
    }

    printf("[*] Setting Shadow SSDT monitor mode: %s\n", ModeStr);
    if (MonitorPid) {
        printf("    PID Filter: %u\n", MonitorPid);
    }
    if (Mode == SSDT_MONITOR_FILTERED) {
        printf("    Filter indices (%u): ", FilterCount);
        for (i = 0; i < FilterCount; i++) {
            printf("%u%s", FilterIndices[i], (i < FilterCount - 1) ? "," : "");
        }
        printf("\n");
    }

    if (!DriverShadowSsdtMonitor(hDevice, &Request)) {
        fprintf(stderr, "[!] Failed to set Shadow SSDT monitor mode: error %lu\n", GetLastError());
        fprintf(stderr, "    Make sure --shadow-ssdt-init has been called first.\n");
        return 1;
    }

    if (Mode == SSDT_MONITOR_OFF) {
        printf("[+] Shadow SSDT monitoring stopped.\n");
    } else {
        printf("[+] Shadow SSDT monitoring started. Use --hook-events to view captured calls.\n");
    }
    return 0;
}

/* ========================================================================= */
/*  Argument Parsing                                                         */
/* ========================================================================= */

int main(int argc, char *argv[])
{
    HANDLE  hDevice = INVALID_HANDLE_VALUE;
    DWORD   Pid = 0;
    DWORD   Flags = 0;
    BOOL    DoRemove = FALSE;
    BOOL    DoStatus = FALSE;
    BOOL    DoStop = FALSE;
    BOOL    DoLog = FALSE;
    int     Result = 0;
    int     i;

    /* Hook framework parameters */
    BOOL        DoInstallHook = FALSE;
    BOOL        DoInstallHookAddr = FALSE;
    BOOL        DoRemoveHook = FALSE;
    BOOL        DoListHooks = FALSE;
    BOOL        DoHookEvents = FALSE;
    BOOL        IsHookCmd = FALSE;
    char        HookFuncName[HOOK_MAX_NAME_LEN] = { 0 };
    ULONG64     HookAddress = 0;
    DWORD       RemoveHookId = 0;
    DWORD       HookPid = 0;
    HOOK_RULE   HookRule = { 0 };

    /* Memory read/write parameters */
    BOOL        DoReadMem = FALSE;
    BOOL        DoWriteMem = FALSE;
    BOOL        DoDumpMem = FALSE;
    BOOL        IsMemCmd = FALSE;
    DWORD       MemPid = 0;
    ULONG64     MemAddress = 0;
    DWORD       MemSize = 64;           /* default read size */
    char        MemHexData[1024] = { 0 };  /* hex string for --write-mem (512 bytes max) */

    /* SSDT framework parameters */
    BOOL        DoSsdtInit = FALSE;
    BOOL        DoSsdtDump = FALSE;
    BOOL        DoSsdtHook = FALSE;
    BOOL        DoSsdtUnhook = FALSE;
    BOOL        DoSsdtUnhookAll = FALSE;
    BOOL        DoSsdtList = FALSE;
    BOOL        DoSsdtMonitor = FALSE;
    BOOL        IsSsdtCmd = FALSE;
    char        SsdtHookTarget[SSDT_MAX_NAME_LEN] = { 0 };
    char        SsdtUnhookTarget[SSDT_MAX_NAME_LEN] = { 0 };
    DWORD       SsdtDumpStart = 0;
    DWORD       SsdtDumpCount = 0;
    DWORD       SsdtMonitorMode = SSDT_MONITOR_OFF;
    DWORD       SsdtFilterIndices[SSDT_MONITOR_MAX_FILTER] = { 0 };
    DWORD       SsdtFilterCount = 0;

    /* Shadow SSDT framework parameters */
    BOOL        DoShadowSsdtInit = FALSE;
    BOOL        DoShadowSsdtDump = FALSE;
    BOOL        DoShadowSsdtHook = FALSE;
    BOOL        DoShadowSsdtUnhook = FALSE;
    BOOL        DoShadowSsdtUnhookAll = FALSE;
    BOOL        DoShadowSsdtList = FALSE;
    BOOL        DoShadowSsdtMonitor = FALSE;
    BOOL        IsShadowSsdtCmd = FALSE;
    char        ShadowSsdtHookTarget[SSDT_MAX_NAME_LEN] = { 0 };
    char        ShadowSsdtUnhookTarget[SSDT_MAX_NAME_LEN] = { 0 };
    DWORD       ShadowSsdtDumpStart = 0;
    DWORD       ShadowSsdtDumpCount = 0;
    DWORD       ShadowSsdtMonitorMode = SSDT_MONITOR_OFF;
    DWORD       ShadowSsdtFilterIndices[SHADOW_SSDT_MONITOR_MAX_FILTER] = { 0 };
    DWORD       ShadowSsdtFilterCount = 0;

    /* Default hook action = LOG_ONLY (most useful for first-time testing) */
    HookRule.Action = HOOK_ACTION_LOG_ONLY;

    PrintBanner();

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    /* Parse arguments */
    for (i = 1; i < argc; i++) {
        /* --- Anti-Anti-Debug options --- */
        if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            Pid = (DWORD)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--hide-debugger") == 0) {
            Flags |= AAD_HIDE_DEBUGGER;
        }
        else if (strcmp(argv[i], "--hide-hwbp") == 0) {
            Flags |= AAD_HIDE_HWBP;
        }
        else if (strcmp(argv[i], "--hide-timing") == 0) {
            Flags |= AAD_HIDE_TIMING;
        }
        else if (strcmp(argv[i], "--hide-cpuid") == 0) {
            Flags |= AAD_HIDE_CPUID;
        }
        else if (strcmp(argv[i], "--hide-sysinfo") == 0) {
            Flags |= AAD_HIDE_SYSINFO;
        }
        else if (strcmp(argv[i], "--hide-exceptions") == 0) {
            Flags |= AAD_HIDE_EXCEPTIONS;
        }
        else if (strcmp(argv[i], "--hide-ntclose") == 0) {
            Flags |= AAD_HIDE_NTCLOSE;
        }
        else if (strcmp(argv[i], "--hide-threadinfo") == 0) {
            Flags |= AAD_HIDE_THREADINFO;
        }
        else if (strcmp(argv[i], "--hide-all") == 0) {
            Flags = AAD_HIDE_ALL;
        }
        else if (strcmp(argv[i], "--remove") == 0) {
            DoRemove = TRUE;
        }
        else if (strcmp(argv[i], "--status") == 0) {
            DoStatus = TRUE;
        }
        else if (strcmp(argv[i], "--stop") == 0) {
            DoStop = TRUE;
        }
        else if (strcmp(argv[i], "--log") == 0) {
            DoLog = TRUE;
        }
        /* --- Hook framework options --- */
        else if (strcmp(argv[i], "--install-hook") == 0 && i + 1 < argc) {
            DoInstallHook = TRUE;
            strncpy(HookFuncName, argv[++i], HOOK_MAX_NAME_LEN - 1);
            HookFuncName[HOOK_MAX_NAME_LEN - 1] = '\0';
        }
        else if (strcmp(argv[i], "--install-hook-addr") == 0 && i + 1 < argc) {
            DoInstallHookAddr = TRUE;
            HookAddress = _strtoui64(argv[++i], NULL, 16);
        }
        else if (strcmp(argv[i], "--remove-hook") == 0 && i + 1 < argc) {
            DoRemoveHook = TRUE;
            RemoveHookId = (DWORD)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--list-hooks") == 0) {
            DoListHooks = TRUE;
        }
        else if (strcmp(argv[i], "--hook-events") == 0) {
            DoHookEvents = TRUE;
        }
        else if (strcmp(argv[i], "--action") == 0 && i + 1 < argc) {
            HookRule.Action = (ULONG)atoi(argv[++i]);
            if (HookRule.Action > HOOK_ACTION_MODIFY_RETVAL) {
                fprintf(stderr, "[!] Invalid action %u. Must be 0-3.\n", HookRule.Action);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--hook-pid") == 0 && i + 1 < argc) {
            HookPid = (DWORD)atoi(argv[++i]);
            HookRule.TargetPid = HookPid;
        }
        else if (strcmp(argv[i], "--block-retval") == 0 && i + 1 < argc) {
            HookRule.BlockReturnValue = _strtoui64(argv[++i], NULL, 16);
        }
        else if (strcmp(argv[i], "--new-retval") == 0 && i + 1 < argc) {
            HookRule.NewReturnValue = _strtoui64(argv[++i], NULL, 16);
        }
        else if (strcmp(argv[i], "--hook-log") == 0) {
            HookRule.LogEnabled = TRUE;
        }
        /* --- Memory read/write options --- */
        else if (strcmp(argv[i], "--read-mem") == 0 && i + 2 < argc) {
            DoReadMem = TRUE;
            MemPid = (DWORD)atoi(argv[++i]);
            MemAddress = _strtoui64(argv[++i], NULL, 16);
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                MemSize = (DWORD)atoi(argv[++i]);
            }
        }
        else if (strcmp(argv[i], "--write-mem") == 0 && i + 3 < argc) {
            DoWriteMem = TRUE;
            MemPid = (DWORD)atoi(argv[++i]);
            MemAddress = _strtoui64(argv[++i], NULL, 16);
            strncpy(MemHexData, argv[++i], sizeof(MemHexData) - 1);
        }
        else if (strcmp(argv[i], "--dump-mem") == 0 && i + 3 < argc) {
            DoDumpMem = TRUE;
            MemPid = (DWORD)atoi(argv[++i]);
            MemAddress = _strtoui64(argv[++i], NULL, 16);
            MemSize = (DWORD)atoi(argv[++i]);
        }
        /* --- SSDT framework options --- */
        else if (strcmp(argv[i], "--ssdt-init") == 0) {
            DoSsdtInit = TRUE;
        }
        else if (strcmp(argv[i], "--ssdt-dump") == 0) {
            DoSsdtDump = TRUE;
            /* Optional: start and count arguments */
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                SsdtDumpStart = (DWORD)atoi(argv[++i]);
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    SsdtDumpCount = (DWORD)atoi(argv[++i]);
                }
            }
        }
        else if (strcmp(argv[i], "--ssdt-hook") == 0 && i + 1 < argc) {
            DoSsdtHook = TRUE;
            strncpy(SsdtHookTarget, argv[++i], SSDT_MAX_NAME_LEN - 1);
            SsdtHookTarget[SSDT_MAX_NAME_LEN - 1] = '\0';
        }
        else if (strcmp(argv[i], "--ssdt-unhook") == 0 && i + 1 < argc) {
            DoSsdtUnhook = TRUE;
            strncpy(SsdtUnhookTarget, argv[++i], SSDT_MAX_NAME_LEN - 1);
            SsdtUnhookTarget[SSDT_MAX_NAME_LEN - 1] = '\0';
        }
        else if (strcmp(argv[i], "--ssdt-unhook-all") == 0) {
            DoSsdtUnhookAll = TRUE;
        }
        else if (strcmp(argv[i], "--ssdt-list") == 0) {
            DoSsdtList = TRUE;
        }
        else if (strcmp(argv[i], "--ssdt-monitor") == 0 && i + 1 < argc) {
            DoSsdtMonitor = TRUE;
            i++;
            if (strcmp(argv[i], "off") == 0) {
                SsdtMonitorMode = SSDT_MONITOR_OFF;
            } else if (strcmp(argv[i], "all") == 0) {
                SsdtMonitorMode = SSDT_MONITOR_ALL;
            } else if (strcmp(argv[i], "filtered") == 0) {
                SsdtMonitorMode = SSDT_MONITOR_FILTERED;
            } else {
                fprintf(stderr, "[!] Invalid monitor mode '%s'. Use off/all/filtered.\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--ssdt-filter") == 0 && i + 1 < argc) {
            /* Parse comma-separated index list: "35,38,55" */
            char *FilterStr = argv[++i];
            char *Token;
            char FilterBuf[512];
            strncpy(FilterBuf, FilterStr, sizeof(FilterBuf) - 1);
            FilterBuf[sizeof(FilterBuf) - 1] = '\0';
            SsdtFilterCount = 0;
            Token = strtok(FilterBuf, ",");
            while (Token && SsdtFilterCount < SSDT_MONITOR_MAX_FILTER) {
                SsdtFilterIndices[SsdtFilterCount++] = (DWORD)atoi(Token);
                Token = strtok(NULL, ",");
            }
        }
        /* --- Shadow SSDT framework options --- */
        else if (strcmp(argv[i], "--shadow-ssdt-init") == 0) {
            DoShadowSsdtInit = TRUE;
        }
        else if (strcmp(argv[i], "--shadow-ssdt-dump") == 0) {
            DoShadowSsdtDump = TRUE;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                ShadowSsdtDumpStart = (DWORD)atoi(argv[++i]);
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    ShadowSsdtDumpCount = (DWORD)atoi(argv[++i]);
                }
            }
        }
        else if (strcmp(argv[i], "--shadow-ssdt-hook") == 0 && i + 1 < argc) {
            DoShadowSsdtHook = TRUE;
            strncpy(ShadowSsdtHookTarget, argv[++i], SSDT_MAX_NAME_LEN - 1);
            ShadowSsdtHookTarget[SSDT_MAX_NAME_LEN - 1] = '\0';
        }
        else if (strcmp(argv[i], "--shadow-ssdt-unhook") == 0 && i + 1 < argc) {
            DoShadowSsdtUnhook = TRUE;
            strncpy(ShadowSsdtUnhookTarget, argv[++i], SSDT_MAX_NAME_LEN - 1);
            ShadowSsdtUnhookTarget[SSDT_MAX_NAME_LEN - 1] = '\0';
        }
        else if (strcmp(argv[i], "--shadow-ssdt-unhook-all") == 0) {
            DoShadowSsdtUnhookAll = TRUE;
        }
        else if (strcmp(argv[i], "--shadow-ssdt-list") == 0) {
            DoShadowSsdtList = TRUE;
        }
        else if (strcmp(argv[i], "--shadow-ssdt-monitor") == 0 && i + 1 < argc) {
            DoShadowSsdtMonitor = TRUE;
            i++;
            if (strcmp(argv[i], "off") == 0) {
                ShadowSsdtMonitorMode = SSDT_MONITOR_OFF;
            } else if (strcmp(argv[i], "all") == 0) {
                ShadowSsdtMonitorMode = SSDT_MONITOR_ALL;
            } else if (strcmp(argv[i], "filtered") == 0) {
                ShadowSsdtMonitorMode = SSDT_MONITOR_FILTERED;
            } else {
                fprintf(stderr, "[!] Invalid monitor mode '%s'. Use off/all/filtered.\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "--shadow-ssdt-filter") == 0 && i + 1 < argc) {
            char *FilterStr = argv[++i];
            char *Token2;
            char FilterBuf2[512];
            strncpy(FilterBuf2, FilterStr, sizeof(FilterBuf2) - 1);
            FilterBuf2[sizeof(FilterBuf2) - 1] = '\0';
            ShadowSsdtFilterCount = 0;
            Token2 = strtok(FilterBuf2, ",");
            while (Token2 && ShadowSsdtFilterCount < SHADOW_SSDT_MONITOR_MAX_FILTER) {
                ShadowSsdtFilterIndices[ShadowSsdtFilterCount++] = (DWORD)atoi(Token2);
                Token2 = strtok(NULL, ",");
            }
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        else {
            fprintf(stderr, "[!] Unknown option: %s\n", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        }
    }

    /* ------------------------------------------------------------------- */
    /*  Determine which command to execute                                  */
    /* ------------------------------------------------------------------- */

    /* Hook commands don't require --pid */
    IsHookCmd = DoInstallHook || DoInstallHookAddr || DoRemoveHook ||
                     DoListHooks || DoHookEvents;

    /* Memory commands don't require --pid either */
    IsMemCmd = DoReadMem || DoWriteMem || DoDumpMem;

    /* SSDT commands don't require --pid */
    IsSsdtCmd = DoSsdtInit || DoSsdtDump || DoSsdtHook || DoSsdtUnhook ||
                DoSsdtUnhookAll || DoSsdtList || DoSsdtMonitor;

    /* Shadow SSDT commands don't require --pid */
    IsShadowSsdtCmd = DoShadowSsdtInit || DoShadowSsdtDump || DoShadowSsdtHook ||
                      DoShadowSsdtUnhook || DoShadowSsdtUnhookAll ||
                      DoShadowSsdtList || DoShadowSsdtMonitor;

    /* Validate arguments for non-hook, non-memory, non-ssdt commands */
    if (!DoStatus && !DoStop && !DoLog && !IsHookCmd && !IsMemCmd && !IsSsdtCmd && !IsShadowSsdtCmd && Pid == 0) {
        fprintf(stderr, "[!] --pid is required (or use --status/--stop/--log/--list-hooks/--ssdt-*/--shadow-ssdt-*/etc.)\n\n");
        PrintUsage(argv[0]);
        return 1;
    }

    if (!IsHookCmd && !IsMemCmd && !IsSsdtCmd && !IsShadowSsdtCmd && Pid != 0 && !DoRemove && Flags == 0) {
        fprintf(stderr, "[!] No hide options specified. Use --hide-all or specific options.\n\n");
        PrintUsage(argv[0]);
        return 1;
    }

    /* Validate hook-specific args */
    if (DoInstallHook && HookFuncName[0] == '\0') {
        fprintf(stderr, "[!] --install-hook requires a function name.\n");
        return 1;
    }

    if (DoInstallHookAddr && HookAddress == 0) {
        fprintf(stderr, "[!] --install-hook-addr requires a non-zero hex address.\n");
        return 1;
    }

    /* Validate memory command args */
    if (IsMemCmd && MemPid == 0) {
        fprintf(stderr, "[!] Memory commands require a valid PID.\n");
        return 1;
    }
    if (IsMemCmd && MemAddress == 0) {
        fprintf(stderr, "[!] Memory commands require a valid address.\n");
        return 1;
    }
    if (DoWriteMem && MemHexData[0] == '\0') {
        fprintf(stderr, "[!] --write-mem requires hex data bytes.\n");
        return 1;
    }

    /* Open driver */
    if (!DriverOpen(&hDevice)) {
        return 1;
    }

    /* ------------------------------------------------------------------- */
    /*  Execute command (hook commands have priority)                        */
    /* ------------------------------------------------------------------- */

    if (DoInstallHook) {
        Result = CmdInstallHook(hDevice, HookFuncName, HookPid, &HookRule);
    }
    else if (DoInstallHookAddr) {
        Result = CmdInstallHookAddr(hDevice, HookAddress, HookPid, &HookRule);
    }
    else if (DoRemoveHook) {
        Result = CmdRemoveHook(hDevice, RemoveHookId);
    }
    else if (DoListHooks) {
        Result = CmdListHooks(hDevice);
    }
    else if (DoHookEvents) {
        Result = CmdHookEvents(hDevice);
    }
    else if (DoReadMem) {
        Result = CmdReadMem(hDevice, MemPid, MemAddress, MemSize);
    }
    else if (DoWriteMem) {
        Result = CmdWriteMem(hDevice, MemPid, MemAddress, MemHexData);
    }
    else if (DoDumpMem) {
        Result = CmdDumpMem(hDevice, MemPid, MemAddress, MemSize);
    }
    /* --- SSDT commands --- */
    else if (DoSsdtInit) {
        Result = CmdSsdtInit(hDevice);
    }
    else if (DoSsdtDump) {
        Result = CmdSsdtDump(hDevice, SsdtDumpStart, SsdtDumpCount);
    }
    else if (DoSsdtHook) {
        Result = CmdSsdtHook(hDevice, SsdtHookTarget, HookPid, &HookRule);
    }
    else if (DoSsdtUnhook) {
        Result = CmdSsdtUnhook(hDevice, SsdtUnhookTarget);
    }
    else if (DoSsdtUnhookAll) {
        Result = CmdSsdtUnhookAll(hDevice);
    }
    else if (DoSsdtList) {
        Result = CmdSsdtList(hDevice);
    }
    else if (DoSsdtMonitor) {
        Result = CmdSsdtMonitor(hDevice, SsdtMonitorMode, HookPid,
                                SsdtFilterIndices, SsdtFilterCount);
    }
    /* --- Shadow SSDT commands --- */
    else if (DoShadowSsdtInit) {
        Result = CmdShadowSsdtInit(hDevice);
    }
    else if (DoShadowSsdtDump) {
        Result = CmdShadowSsdtDump(hDevice, ShadowSsdtDumpStart, ShadowSsdtDumpCount);
    }
    else if (DoShadowSsdtHook) {
        Result = CmdShadowSsdtHook(hDevice, ShadowSsdtHookTarget, HookPid, &HookRule);
    }
    else if (DoShadowSsdtUnhook) {
        Result = CmdShadowSsdtUnhook(hDevice, ShadowSsdtUnhookTarget);
    }
    else if (DoShadowSsdtUnhookAll) {
        Result = CmdShadowSsdtUnhookAll(hDevice);
    }
    else if (DoShadowSsdtList) {
        Result = CmdShadowSsdtList(hDevice);
    }
    else if (DoShadowSsdtMonitor) {
        Result = CmdShadowSsdtMonitor(hDevice, ShadowSsdtMonitorMode, HookPid,
                                       ShadowSsdtFilterIndices, ShadowSsdtFilterCount);
    }
    else if (DoStatus) {
        Result = CmdQueryStatus(hDevice);
    }
    else if (DoStop) {
        Result = CmdStop(hDevice);
    }
    else if (DoLog) {
        Result = CmdShowLog(hDevice);
    }
    else if (DoRemove) {
        Result = CmdRemoveTarget(hDevice, Pid);
    }
    else {
        Result = CmdSetTarget(hDevice, Pid, Flags);
    }

    DriverClose(hDevice);
    return Result;
}
