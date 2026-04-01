# SSDT & Shadow SSDT Hook 测试指南

## 前置条件

1. 在 VM 中开启测试签名：`bcdedit /set testsigning on`，重启
2. 构建驱动和客户端（`scripts/do_build.bat`）
3. 对驱动进行测试签名（`scripts/sign_test.bat`）
4. 加载驱动：
   ```cmd
   sc create VMXToolboxDrv type=kernel binPath=<path>\VMXToolboxDrv.sys
   sc start VMXToolboxDrv
   ```
5. 确认 Hypervisor 已启动：`VMXToolbox.exe --status`

---

## 一、SSDT Hook 测试

### 1.1 初始化 SSDT

```cmd
VMXToolbox.exe --ssdt-init
```

发现并解析 SSDT 表（约 512 个 syscall）。采用两级策略：
- **优先**：从磁盘映射 ntoskrnl.exe（SEC_IMAGE），读取干净的签名文件
- **回退**：从内存中通过 `MmGetSystemRoutineAddress` 解析

### 1.2 查看 SSDT 表

```cmd
:: 导出全部
VMXToolbox.exe --ssdt-dump

:: 指定范围（从第 0 项开始，显示 20 项）
VMXToolbox.exe --ssdt-dump 0 20
```

### 1.3 Hook 单个 Syscall

**按名称 hook（推荐）：**
```cmd
:: 仅记录日志
VMXToolbox.exe --ssdt-hook NtCreateFile --action log_only

:: 针对特定进程
VMXToolbox.exe --ssdt-hook NtCreateFile --action log_only --pid 1234

:: 阻断调用，返回 STATUS_ACCESS_DENIED (0xC0000022)
VMXToolbox.exe --ssdt-hook NtOpenProcess --action block --retval 0xC0000022

:: 修改返回值
VMXToolbox.exe --ssdt-hook NtQuerySystemInformation --action modify_retval --retval 0
```

**按索引 hook：**
```cmd
VMXToolbox.exe --ssdt-hook 85 --action log_only
```

### 1.4 查看活跃 Hook

```cmd
VMXToolbox.exe --ssdt-list
```

### 1.5 查看 Hook 事件日志

```cmd
VMXToolbox.exe --hook-events
```

### 1.6 移除 Hook

```cmd
:: 按名称
VMXToolbox.exe --ssdt-unhook NtCreateFile

:: 按索引
VMXToolbox.exe --ssdt-unhook 85

:: 按 Hook ID
VMXToolbox.exe --ssdt-unhook hookid:42

:: 移除所有 SSDT Hook
VMXToolbox.exe --ssdt-unhook-all
```

### 1.7 监控模式

```cmd
:: 监控所有 syscall
VMXToolbox.exe --ssdt-monitor all

:: 监控特定进程的所有 syscall
VMXToolbox.exe --ssdt-monitor all --pid 1234

:: 过滤监控（仅监控指定索引，最多 64 个）
VMXToolbox.exe --ssdt-monitor filter --indices 0,10,20,85

:: 过滤监控 + 指定进程
VMXToolbox.exe --ssdt-monitor filter --pid 4096 --indices 5,15,25

:: 关闭监控
VMXToolbox.exe --ssdt-monitor off
```

---

## 二、Shadow SSDT Hook 测试

> **重要**：Shadow SSDT 初始化前必须先执行 `--ssdt-init`。

### 2.1 初始化

```cmd
:: 先初始化 SSDT（如果还没做）
VMXToolbox.exe --ssdt-init

:: 再初始化 Shadow SSDT（约 1400 个 NtUser*/NtGdi* syscall）
VMXToolbox.exe --shadow-ssdt-init
```

Shadow SSDT 初始化经过五个阶段：
1. 动态发现 `KTHREAD.ServiceTable` 偏移（兼容 Win7~Win11）
2. 定位 `KeServiceDescriptorTableShadow`
3. 枚举 win32k 模块（Win10+ 分为 win32kbase.sys / win32kfull.sys / win32k.sys）
4. 切换到 GUI Session 上下文解析 `W32pServiceTable` 地址
5. 遍历 PE 导出表填充函数名

### 2.2 查看 Shadow SSDT 表

```cmd
VMXToolbox.exe --shadow-ssdt-dump

VMXToolbox.exe --shadow-ssdt-dump 0 30
```

### 2.3 Hook Win32k Syscall

```cmd
:: 按名称
VMXToolbox.exe --shadow-ssdt-hook NtUserGetMessage --action log_only --pid 1234

:: 按索引
VMXToolbox.exe --shadow-ssdt-hook 100 --action block --retval 0

:: 按名称，修改返回值
VMXToolbox.exe --shadow-ssdt-hook NtGdiGetDC --action modify_retval --retval 0
```

### 2.4 查看活跃 Hook

```cmd
VMXToolbox.exe --shadow-ssdt-list
```

### 2.5 移除 Hook

```cmd
VMXToolbox.exe --shadow-ssdt-unhook NtUserGetMessage
VMXToolbox.exe --shadow-ssdt-unhook hookid:55
VMXToolbox.exe --shadow-ssdt-unhook-all
```

### 2.6 监控模式

```cmd
:: 监控所有 Win32k 调用
VMXToolbox.exe --shadow-ssdt-monitor all --pid 2048

:: 过滤监控
VMXToolbox.exe --shadow-ssdt-monitor filter --indices 0,50,100

:: 关闭
VMXToolbox.exe --shadow-ssdt-monitor off
```

---

## 三、Hook Action 类型参考

| Action | `--action` 值 | 行为 | 需要 `--retval` |
|--------|---------------|------|-----------------|
| 透传 | `passthrough` | 调用原函数，仅计数 | 否 |
| 日志 | `log_only` | 调用原函数，记录每次调用 | 否 |
| 阻断 | `block` | 跳过原函数，返回指定值 | 是 |
| 改返回值 | `modify_retval` | 调用原函数，覆盖返回值 | 是 |

---

## 四、典型测试场景

### 场景 A：监控某进程的文件操作

```cmd
VMXToolbox.exe --ssdt-init
VMXToolbox.exe --ssdt-hook NtCreateFile --action log_only --pid <PID>
VMXToolbox.exe --ssdt-hook NtReadFile --action log_only --pid <PID>
VMXToolbox.exe --ssdt-hook NtWriteFile --action log_only --pid <PID>

:: 让目标进程运行一段时间...

VMXToolbox.exe --hook-events
VMXToolbox.exe --ssdt-unhook-all
```

### 场景 B：阻断进程枚举

```cmd
VMXToolbox.exe --ssdt-init
VMXToolbox.exe --ssdt-hook NtQuerySystemInformation --action block --retval 0xC0000022 --pid <PID>

:: 目标进程调用 NtQuerySystemInformation 将收到 STATUS_ACCESS_DENIED

VMXToolbox.exe --ssdt-unhook NtQuerySystemInformation
```

### 场景 C：全量 Syscall 追踪

```cmd
VMXToolbox.exe --ssdt-init
VMXToolbox.exe --ssdt-monitor all --pid <PID>

:: 等待...
VMXToolbox.exe --hook-events
VMXToolbox.exe --log

VMXToolbox.exe --ssdt-monitor off
```

### 场景 D：监控 GUI 消息循环

```cmd
VMXToolbox.exe --ssdt-init
VMXToolbox.exe --shadow-ssdt-init
VMXToolbox.exe --shadow-ssdt-hook NtUserGetMessage --action log_only --pid <GUI_PID>
VMXToolbox.exe --shadow-ssdt-hook NtUserPeekMessage --action log_only --pid <GUI_PID>

:: 等待...
VMXToolbox.exe --hook-events
VMXToolbox.exe --shadow-ssdt-unhook-all
```

---

## 五、排查问题

| 问题 | 排查方法 |
|------|----------|
| `--ssdt-init` 失败 | 检查驱动是否已加载（`--status`），查看日志（`--log`） |
| `--shadow-ssdt-init` 失败 | 确认已先执行 `--ssdt-init`；确认系统中有 GUI 进程在运行 |
| Hook 安装后无事件 | 确认 `--pid` 指定正确；确认目标进程确实调用了该 syscall |
| Shadow SSDT 函数名为空 | Win32k PE 导出解析为 best-effort，不影响按索引 hook |
| 蓝屏 | 查看 minidump，通常是 hook 地址错误或并发问题；在快照 VM 中测试 |
