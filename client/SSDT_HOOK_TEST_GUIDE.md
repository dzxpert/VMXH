[简体中文](SSDT_HOOK_TEST_GUIDE_CN.md) | English

# SSDT & Shadow SSDT Hook Testing Guide

## Prerequisites

1. Enable test signing in the VM: `bcdedit /set testsigning on`, then reboot.
2. Build the driver and client (`scripts/do_build.bat`).
3. Test-sign the driver (`scripts/sign_test.bat`).
4. Load the driver:
   ```cmd
   sc create VMXToolboxDrv type=kernel binPath=<path>\VMXToolboxDrv.sys
   sc start VMXToolboxDrv
   ```
5. Confirm the Hypervisor has started: `VMXToolbox.exe --status`

## Parameter Quick Reference

| Parameter | Description |
|------|------|
| `--action <0-3>` | 0=passthrough, 1=log, 2=block, 3=modify-retval |
| `--hook-pid <PID>` | Hook only targets the specified process (Note: do NOT use `--pid`) |
| `--block-retval <hex>` | Used when action=2, specifies the blocked return value |
| `--new-retval <hex>` | Used when action=3, specifies the overridden return value |
| `--hook-log` | Log hook events additionally, regardless of the action type |

---

## 1. SSDT Hook Testing

### 1.1 Initializing SSDT

```cmd
VMXToolbox.exe --ssdt-init
```

Discovers and parses the SSDT table (approx. 512 syscalls). Employs a two-tier strategy:
- **Primary**: Maps `ntoskrnl.exe` from disk (SEC_IMAGE) and reads clean signature files.
- **Fallback**: Resolves addresses in memory using `MmGetSystemRoutineAddress`.

### 1.2 Dumping the SSDT Table

```cmd
:: Dump all
VMXToolbox.exe --ssdt-dump

:: Dump a specific range (displays 20 items starting from index 0)
VMXToolbox.exe --ssdt-dump 0 20
```

### 1.3 Hooking a Single Syscall

**Hook by name (recommended):**
```cmd
:: Log only (action 1 = LOG_ONLY, default value)
VMXToolbox.exe --ssdt-hook NtCreateFile

:: Target a specific process
VMXToolbox.exe --ssdt-hook NtCreateFile --action 1 --hook-pid 1234

:: Block call, returning STATUS_ACCESS_DENIED (0xC0000022)
VMXToolbox.exe --ssdt-hook NtOpenProcess --action 2 --block-retval 0xC0000022

:: Modify return value
VMXToolbox.exe --ssdt-hook NtQuerySystemInformation --action 3 --new-retval 0
```

**Hook by index:**
```cmd
VMXToolbox.exe --ssdt-hook 85 --action 1
```

### 1.4 Viewing Active Hooks

```cmd
VMXToolbox.exe --ssdt-list
```

### 1.5 Viewing Hook Event Logs

```cmd
VMXToolbox.exe --hook-events
```

### 1.6 Removing Hooks

```cmd
:: By name
VMXToolbox.exe --ssdt-unhook NtCreateFile

:: By index
VMXToolbox.exe --ssdt-unhook 85

:: By Hook ID
VMXToolbox.exe --ssdt-unhook hookid:42

:: Remove all SSDT Hooks
VMXToolbox.exe --ssdt-unhook-all
```

### 1.7 Monitor Mode

```cmd
:: Monitor all syscalls
VMXToolbox.exe --ssdt-monitor all

:: Monitor all syscalls of a specific process
VMXToolbox.exe --ssdt-monitor all --hook-pid 1234

:: Filtered monitoring (only monitor specified indices, max 64)
VMXToolbox.exe --ssdt-monitor filtered --ssdt-filter 0,10,20,85

:: Filtered monitoring + specific process
VMXToolbox.exe --ssdt-monitor filtered --hook-pid 4096 --ssdt-filter 5,15,25

:: Disable monitoring
VMXToolbox.exe --ssdt-monitor off
```

---

## 2. Shadow SSDT Hook Testing

> **Important**: SSDT initialization (`--ssdt-init`) must be executed prior to Shadow SSDT initialization.

### 2.1 Initialization

```cmd
:: Initialize SSDT first (if not done already)
VMXToolbox.exe --ssdt-init

:: Initialize Shadow SSDT (approx. 1400 NtUser*/NtGdi* syscalls)
VMXToolbox.exe --shadow-ssdt-init
```

Shadow SSDT initialization goes through five phases:
1. Dynamically discovers the offset of `KTHREAD.ServiceTable` (compatible with Win7 to Win11).
2. Locates `KeServiceDescriptorTableShadow`.
3. Enumerates win32k modules (split into `win32kbase.sys`, `win32kfull.sys`, and `win32k.sys` on Win10+).
4. Switches to the GUI Session context to parse the address of `W32pServiceTable`.
5. Iterates through the PE export table to populate function names.

### 2.2 Dumping the Shadow SSDT Table

```cmd
VMXToolbox.exe --shadow-ssdt-dump

VMXToolbox.exe --shadow-ssdt-dump 0 30
```

### 2.3 Hooking Win32k Syscalls

```cmd
:: By name (default action=1 LOG_ONLY)
VMXToolbox.exe --shadow-ssdt-hook NtUserGetMessage --hook-pid 1234

:: By index, block call
VMXToolbox.exe --shadow-ssdt-hook 100 --action 2 --block-retval 0

:: By name, modify return value
VMXToolbox.exe --shadow-ssdt-hook NtGdiGetDC --action 3 --new-retval 0
```

### 2.4 Viewing Active Hooks

```cmd
VMXToolbox.exe --shadow-ssdt-list
```

### 2.5 Removing Hooks

```cmd
VMXToolbox.exe --shadow-ssdt-unhook NtUserGetMessage
VMXToolbox.exe --shadow-ssdt-unhook hookid:55
VMXToolbox.exe --shadow-ssdt-unhook-all
```

### 2.6 Monitor Mode

```cmd
:: Monitor all Win32k calls
VMXToolbox.exe --shadow-ssdt-monitor all --hook-pid 2048

:: Filtered monitoring
VMXToolbox.exe --shadow-ssdt-monitor filtered --shadow-ssdt-filter 0,50,100

:: Disable monitoring
VMXToolbox.exe --shadow-ssdt-monitor off
```

---

## 3. Hook Action Type Reference

| Action | `--action` Value | Behavior | Additional Parameters |
|--------|---------------|------|----------|
| Passthrough | `0` | Invokes the original function; only increments call count | None |
| Log | `1` | Invokes the original function; records each call (**Default**) | None |
| Block | `2` | Skips the original function; returns the specified value | `--block-retval <hex>` |
| Modify Return Value | `3` | Invokes the original function; overrides the return value | `--new-retval <hex>` |

> Tip: You can append `--hook-log` to any action to force-enable logging.

---

## 4. Typical Test Scenarios

### Scenario A: Monitor file operations of a specific process

```cmd
VMXToolbox.exe --ssdt-init
VMXToolbox.exe --ssdt-hook NtCreateFile --action 1 --hook-pid <PID>
VMXToolbox.exe --ssdt-hook NtReadFile --action 1 --hook-pid <PID>
VMXToolbox.exe --ssdt-hook NtWriteFile --action 1 --hook-pid <PID>

:: Let the target process run for a while...

VMXToolbox.exe --hook-events
VMXToolbox.exe --ssdt-unhook-all
```

### Scenario B: Block process enumeration

```cmd
VMXToolbox.exe --ssdt-init
VMXToolbox.exe --ssdt-hook NtQuerySystemInformation --action 2 --block-retval 0xC0000022 --hook-pid <PID>

:: The target process will receive STATUS_ACCESS_DENIED when calling NtQuerySystemInformation

VMXToolbox.exe --ssdt-unhook NtQuerySystemInformation
```

### Scenario C: Complete Syscall Tracing

```cmd
VMXToolbox.exe --ssdt-init
VMXToolbox.exe --ssdt-monitor all --hook-pid <PID>

:: Wait...
VMXToolbox.exe --hook-events
VMXToolbox.exe --log

VMXToolbox.exe --ssdt-monitor off
```

### Scenario D: Monitor GUI message loop

```cmd
VMXToolbox.exe --ssdt-init
VMXToolbox.exe --shadow-ssdt-init
VMXToolbox.exe --shadow-ssdt-hook NtUserGetMessage --action 1 --hook-pid <GUI_PID>
VMXToolbox.exe --shadow-ssdt-hook NtUserPeekMessage --action 1 --hook-pid <GUI_PID>

:: Wait...
VMXToolbox.exe --hook-events
VMXToolbox.exe --shadow-ssdt-unhook-all
```

---

## 5. Troubleshooting

| Issue | Diagnostics |
|------|----------|
| `--ssdt-init` fails | Check if the driver is loaded (`--status`); check the log (`--log`) |
| `--shadow-ssdt-init` fails | Verify `--ssdt-init` was executed first; ensure a GUI process is running in the system |
| No events recorded after installing Hook | Verify `--hook-pid` is specified correctly; verify the target process actually calls the syscall |
| Shadow SSDT function names are empty | Win32k PE export parsing is best-effort and does not affect hooking by index |
| Ring buffer overflow | The buffer has only 512 entries; frequently poll `--hook-events` when in `monitor all` mode |
| Blue Screen of Death (BSOD) | Analyze the minidump; typically caused by an incorrect hook address or concurrency issues; test in a VM with snapshots |
