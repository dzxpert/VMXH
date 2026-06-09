简体中文 | [English](hook_framework.md)

# 通用 EPT/NPT Hook 框架 - 技术文档

> **2026-04 更新**: 经过稳定性 Review，以下相关行为已修复/优化：
> - **Thunk slot 回收**：`GENERIC_HOOK_ENTRY` 卸载后 Thunk 现会通过 `SlotBitmap` 回收（修复 H-3）。
> - **用户态 Hook**：`TargetVa < 0x8000_0000_0000_0000` 且 `ProcessId != 0` 时自动 `KeStackAttachProcess`（修复 L-5）。
> - **跨页保护**：hook 点离页尾 < 12 bytes 会被拒绝（修复 L-4）。
> - **SVM #DB 拦截**：仅在有 NPT hook 时开启，卸载全部后自动关闭（修复 C-3）。
> - **跨 CPU TLB 刷新**：卸载 hook 后使用 `EptInvalidateAllCpusSync / NptInvalidateAllCpusSync`（IPI 广播），避免 HLT CPU 导致的 UAF（修复 H-5）。
>
> 详见 [docs/BAREMETAL_REVIEW_FIXES.md](docs/BAREMETAL_REVIEW_FIXES.md)。

## 概述

通用 Hook 框架通过 Intel EPT / AMD NPT 页表操控，提供动态的、用户可控的函数挂钩能力。由于内核代码页从未被物理修改，Hook 对 PatchGuard 及任何 Guest 级完整性检查完全不可见。

**核心能力：**
- 按函数名挂钩任意内核函数（通过 `MmGetSystemRoutineAddress` 自动解析）
- 按显式虚拟地址（VA）挂钩任意地址（内核或用户态）
- 运行时通过 IOCTL 动态安装/移除
- Hook 数量无固定上限（动态 Thunk 页分配）
- 预定义动作：透传、记录日志、拦截、修改返回值
- 按进程 PID 过滤
- 事件日志环形缓冲区，用于监控 Hook 活动

---

## 架构

```
用户态 (VMXToolbox.exe)
  |  IOCTL_VMX_INSTALL_HOOK   (函数名或 VA + 动作规则)
  |  IOCTL_VMX_REMOVE_HOOK    (Hook ID)
  |  IOCTL_VMX_LIST_HOOKS     (查询活跃 Hook)
  |  IOCTL_VMX_GET_HOOK_EVENTS (读取事件日志)
  v
vmxdrv.c (IOCTL 处理程序)
  |  MmGetSystemRoutineAddress() 解析名称 -> VA
  |  GenericHookInstall() -> 分配 Thunk + EPT Hook
  v
hv_hook.c (Hook 框架核心)
  |  动态 Thunk 页分配
  |  Hook 条目链表管理
  |  GenericHookDecide() - C 决策函数
  |  GenericHookPostCall() - 日志记录
  v
hv_hook_asm.asm (ASM 分发器)
  |  保存原始参数 (RCX/RDX/R8/R9 + 栈参数 5-8)
  |  调用 GenericHookDecide() 获取动作
  |  调用跳板（原始函数）或拦截
  |  调用 GenericHookPostCall() 记录日志
  |  返回给原始调用者
  v
EPT/NPT 引擎
  |  Execute-Only 页拆分 (Intel) / R=0,W=0,X=0 回退 (不支持 Execute-Only 时)
  |  12 字节 MOV+JMP -> Thunk 存根
  |  Per-CPU PT 隔离：每 CPU 独立 PTE 切换，消除多核竞争
  |  MTF/TF 单步恢复（INVEPT SINGLE_CONTEXT 优化）
  |  O(1) 哈希表查找 Hook 和 Split Page
```

---

## 核心机制：Thunk 存根

### 问题

EPT Hook 将函数入口替换为一条 14 字节的 JMP，跳转到单一地址。如果所有 Hook 都跳转到同一个分发器，分发器将无法知道是哪个 Hook 被触发的。

### 解决方案：每 Hook 独立的 Thunk 存根

每个 Hook 获得一个唯一的 24 字节 Thunk 存根，在跳转到共享分发器之前将 R10 设置为 Hook ID：

```
Hook #5 的 Thunk：                Hook #42 的 Thunk：
  mov r10, 5                      mov r10, 42
  jmp AsmGenericHookDispatcher    jmp AsmGenericHookDispatcher
```

R10 是 Windows x64 ABI 中的易失性寄存器（不用于参数传递），因此设置它不会影响原始函数的 RCX/RDX/R8/R9 参数。

### Thunk 二进制布局（24 字节）

```
偏移    字节                           指令
+0:     49 BA [8字节 Hook ID]          mov r10, <hook_id>     (10 字节)
+10:    FF 25 00000000                 jmp [rip+0]            (6 字节)
+16:    [8字节分发器地址]               绝对跳转目标            (8 字节)
```

### 动态 Thunk 页

Thunk 从动态增长的页中分配：

```
THUNK_PAGE（链表节点）
  |-- CodeBase: 4KB 可执行页 (NonPagedPool)
  |-- Capacity: 每页 170 个 Thunk (4096 / 24 = 170)
  |-- UsedCount: 当前已分配数量
  |-- Next: 指向下一个 THUNK_PAGE 的指针

分配流程：
  1. 搜索现有页，查找 UsedCount < Capacity 的页
  2. 如果全部已满，分配新的 4KB 页并插入链表头部
  3. 在 CodeBase + (UsedCount * 24) 处写入 Thunk 字节
  4. 递增 UsedCount
  5. 返回 Thunk 代码地址

无固定上限 - 按需分配新页。
第一页：Hook 1-170，第二页：Hook 171-340，以此类推。
```

---

## ASM 分发器流程

当任何被挂钩的函数被调用时，执行流程如下：

```
原始调用者
  |
  | CALL NtCreateFile（现在通过 EPT 跳转到 Thunk）
  v
Thunk_N:
  mov r10, N                         ; 设置 Hook ID
  jmp AsmGenericHookDispatcher       ; 跳转到共享分发器
  |
  v
AsmGenericHookDispatcher:

  阶段 1 - 保存状态：
    push rbp; mov rbp,rsp; sub rsp, 0C0h
    将 RCX/RDX/R8/R9 保存到局部变量       ; 原始参数 1-4
    将 [rbp+30h..+48h] 复制到局部变量     ; 原始参数 5-8
    将 [rbp+08h] 保存为 CallerRetAddr     ; 谁调用了被挂钩的函数

  阶段 2 - 决策：
    call GenericHookDecide(R10, CallerRetAddr, &Decision)
    |
    |  GenericHookDecide()（C 代码）：
    |    FindHookById(R10) -> GENERIC_HOOK_ENTRY
    |    检查 PID 过滤 (Rule.TargetPid vs PsGetCurrentProcessId)
    |    InterlockedIncrement64(&HitCount)
    |    填充 HOOK_DECISION：
    |      .Action = Rule.Action
    |      .Trampoline = 原始函数指针
    |      .BlockReturnValue / NewReturnValue
    |      .ShouldLog
    |
    如果 Decision.Action == BLOCK -> 跳转到 _do_block

  阶段 3 - 调用原始函数：
    从保存的局部变量恢复 RCX/RDX/R8/R9
    将保存的参数 5-8 复制到 [rsp+20h..+38h]
    call Decision.Trampoline            ; 调用原始函数
    保存 RAX（返回值）
    如果 MODIFY_RETVAL：RAX = Decision.NewReturnValue

  阶段 4 - 调用后处理：
    call GenericHookPostCall(HookId, Action, FinalRetVal, CallerAddr, ShouldLog)
    |
    |  如果 ShouldLog：
    |    将 HOOK_EVENT 写入环形缓冲区
    |    (HookId, PID, 时间戳, CallerAddr, RetVal, Action)

  收尾：
    mov rax, FinalRetVal
    mov rsp,rbp; pop rbp; ret           ; 返回给原始调用者

  _do_block:
    RAX = Decision.BlockReturnValue
    -> 阶段 4（日志）-> 收尾
```

### 参数转发

分发器支持最多 12 个参数的函数：
- 参数 1-4：通过 RCX/RDX/R8/R9 寄存器保存/恢复
- 参数 5-8：从原始栈帧复制到跳板调用栈帧
- 参数 9+：保留在我们栈帧之上的栈中（从不触碰，自然转发）

---

## HOOK_DECISION 结构体

ASM 和 C 代码共享此结构体。偏移量必须完全匹配：

```c
typedef struct _HOOK_DECISION {
    ULONG       Action;             /* +0x00: HOOK_ACTION_* */
    ULONG       Pad0;              /* +0x04: 对齐填充 */
    ULONG64     BlockReturnValue;  /* +0x08: 拦截时的返回值 */
    ULONG64     NewReturnValue;    /* +0x10: 修改返回值时的值 */
    PVOID       Trampoline;        /* +0x18: 原始函数入口点 */
    BOOLEAN     ShouldLog;         /* +0x20: 是否写入事件日志 */
    UCHAR       Pad1[7];           /* +0x21: 对齐填充 */
} HOOK_DECISION;  /* 总计: 0x28 = 40 字节 */
```

ASM 直接引用这些偏移量：
```asm
mov eax, [rbp-90h]         ; Decision.Action      (+0x00)
mov rax, [rbp-90h+08h]     ; Decision.BlockRetVal (+0x08)
mov rax, [rbp-90h+10h]     ; Decision.NewRetVal   (+0x10)
mov rax, [rbp-90h+18h]     ; Decision.Trampoline  (+0x18)
movzx eax, byte ptr [rbp-90h+20h] ; Decision.ShouldLog (+0x20)
```

---

## Hook 动作

| 动作 | 值 | 行为 | 使用场景 |
|------|-----|------|----------|
| `HOOK_ACTION_PASSTHROUGH` | 0 | 调用原始函数，不做修改。仅计数。 | 性能监控 |
| `HOOK_ACTION_LOG_ONLY` | 1 | 调用原始函数，记录每次调用。 | 函数调用追踪 |
| `HOOK_ACTION_BLOCK` | 2 | 跳过原始函数，返回 `BlockReturnValue`。 | 访问拒绝、API 拦截 |
| `HOOK_ACTION_MODIFY_RETVAL` | 3 | 调用原始函数，用 `NewReturnValue` 覆盖 RAX。 | 返回值欺骗 |

### PID 过滤

每个 Hook 都有一个 `TargetPid` 字段：
- `TargetPid = 0`：对所有进程触发 Hook（全局）
- `TargetPid = 1234`：仅对 PID 1234 触发 Hook，其他进程均透传

此检查在 `GenericHookDecide()` 中通过 `PsGetCurrentProcessId()` 实现。

---

## IOCTL 接口

### IOCTL_VMX_INSTALL_HOOK (0x809)

安装新 Hook。

**输入：** `VMX_HOOK_REQUEST`
```c
typedef struct _VMX_HOOK_REQUEST {
    BOOLEAN     ByName;                          /* TRUE = 按名称解析 */
    WCHAR       FunctionName[128];               /* 例如 L"NtCreateFile" */
    ULONG64     TargetAddress;                   /* 直接 VA（当 !ByName 时） */
    ULONG       ProcessId;                       /* 0 = 内核 */
    HOOK_RULE   Rule;                            /* 动作 + 参数 */
} VMX_HOOK_REQUEST;

typedef struct _HOOK_RULE {
    ULONG       Action;             /* HOOK_ACTION_* */
    ULONG       TargetPid;          /* 0 = 全局，>0 = 指定 PID */
    ULONG64     BlockReturnValue;   /* 用于 BLOCK 动作 */
    ULONG64     NewReturnValue;     /* 用于 MODIFY_RETVAL 动作 */
    BOOLEAN     LogEnabled;         /* 启用事件日志 */
} HOOK_RULE;
```

**输出：** `VMX_HOOK_RESPONSE`
```c
typedef struct _VMX_HOOK_RESPONSE {
    ULONG       HookId;             /* 唯一 ID，用于后续操作 */
    ULONG64     ResolvedAddress;    /* 实际被挂钩的 VA */
} VMX_HOOK_RESPONSE;
```

**示例（C 用户态代码）：**
```c
VMX_HOOK_REQUEST req = {0};
VMX_HOOK_RESPONSE resp = {0};
DWORD ret;

req.ByName = TRUE;
wcscpy(req.FunctionName, L"NtCreateFile");
req.Rule.Action = HOOK_ACTION_LOG_ONLY;
req.Rule.LogEnabled = TRUE;

DeviceIoControl(hDev, IOCTL_VMX_INSTALL_HOOK,
    &req, sizeof(req), &resp, sizeof(resp), &ret, NULL);

printf("Hook 已安装: ID=%u, 地址=0x%llX\n", resp.HookId, resp.ResolvedAddress);
```

### IOCTL_VMX_REMOVE_HOOK (0x80A)

按 ID 移除 Hook。

**输入：** `VMX_UNHOOK_REQUEST`
```c
typedef struct _VMX_UNHOOK_REQUEST {
    ULONG HookId;
} VMX_UNHOOK_REQUEST;
```

### IOCTL_VMX_LIST_HOOKS (0x80B)

列出所有活跃 Hook。

**输出：** `VMX_HOOK_LIST`（可变长度）
```c
typedef struct _VMX_HOOK_LIST {
    ULONG           Count;
    VMX_HOOK_INFO   Hooks[1];  /* 可变长度数组 */
} VMX_HOOK_LIST;

typedef struct _VMX_HOOK_INFO {
    ULONG       HookId;
    BOOLEAN     Active;
    ULONG64     TargetAddress;
    ULONG       ProcessId;
    HOOK_RULE   Rule;
    ULONG64     HitCount;          /* 此 Hook 触发次数 */
    WCHAR       FunctionName[128];
} VMX_HOOK_INFO;
```

### IOCTL_VMX_GET_HOOK_EVENTS (0x80C)

读取 Hook 事件日志条目。

**输出：** `VMX_HOOK_EVENT_BUFFER`（可变长度）
```c
typedef struct _VMX_HOOK_EVENT_BUFFER {
    ULONG       Count;
    HOOK_EVENT  Events[1];
} VMX_HOOK_EVENT_BUFFER;

typedef struct _HOOK_EVENT {
    ULONG       HookId;
    ULONG       ProcessId;
    ULONG64     Timestamp;
    ULONG64     ReturnAddress;  /* 谁调用了被挂钩的函数 */
    ULONG64     FinalRetVal;    /* 返回给调用者的值 */
    ULONG       ActionTaken;    /* 所执行的 HOOK_ACTION_* */
} HOOK_EVENT;
```

环形缓冲区容纳 512 个条目。缓冲区满时，最旧的条目会被覆盖。

---

## 安装流程（内部）

```
用户: IOCTL_VMX_INSTALL_HOOK { ByName=TRUE, Name="NtCreateFile", Action=LOG }
  |
  v
HandleIoctlInstallHook():
  |
  +-- MmGetSystemRoutineAddress(L"NtCreateFile")
  |   -> TargetVa = 0xFFFFF80012345678
  |
  +-- GenericHookInstall(TargetVa, 0, "NtCreateFile", &Rule, &HookId)
       |
       +-- NextHookId++ -> HookId = 5
       |
       +-- AllocateThunk(5)
       |     搜索 Thunk 页查找空闲槽位
       |     如果全部已满：分配新的 4KB 可执行页
       |     写入 24 字节 Thunk：mov r10,5; jmp AsmGenericHookDispatcher
       |     -> ThunkAddr = 0xFFFFXXXXXXXX
       |
       +-- HvHookFunction(0xFFFFF80012345678, ThunkAddr, &Trampoline)
       |     |
       |     +-- EPT 引擎：
       |           1. VA -> PA 地址转换
       |           2. 将 2MB 页拆分为 4KB（O(1) 哈希表跟踪 split page）
       |           3. 复制原始页 -> OriginalPage
       |           4. 复制原始页 -> HookPage
       |           5. 修补 HookPage：MOV RAX,imm64 + JMP RAX（12 字节）
       |           6. 构建跳板：指令长度解码 -> 完整指令复制 -> RIP 相对修复
       |           7. EPT PTE：
       |              - 支持 Execute-Only：R=0,W=0,X=1 -> HookPage
       |              - 不支持时回退：R=0,W=0,X=0 + RIP 意图检测
       |           8. Per-CPU PT 隔离：克隆 PD+PT 到所有 CPU
       |           9. INVEPT SINGLE_CONTEXT 刷新当前 CPU TLB
       |
       +-- 分配 GENERIC_HOOK_ENTRY (NonPagedPool)
       |     .HookId = 5
       |     .TargetVirtualAddress = 0xFFFFF80012345678
       |     .FunctionName = "NtCreateFile"
       |     .Rule = { LOG_ONLY, LogEnabled=TRUE }
       |     .Trampoline = <EPT 跳板指针>
       |     .ThunkAddress = ThunkAddr
       |
       +-- 将条目链接到 HookListHead
       |
       +-- 返回 HookId=5
```

---

## 运行时 Hook 触发流程

```
[Guest] 任意进程调用 NtCreateFile(...)
  |
  +-- CPU 从 NtCreateFile 入口取指令
  |
  +-- [EPT] PTE 权限取决于 Execute-Only 支持情况：
  |   Mode A (支持): R=0,W=0,X=1，物理地址 = HookPage
  |   Mode B (不支持): R=0,W=0,X=0，通过 RIP 检测区分执行/读取
  |   HookPage 包含：MOV RAX,imm64; JMP RAX（12 字节绝对 JMP）
  |
  v
[Thunk_5]
  mov r10, 5                           ; "我是 Hook #5"
  jmp AsmGenericHookDispatcher         ; 共享入口点
  |
  v
[AsmGenericHookDispatcher]
  |
  +-- 保存 RCX/RDX/R8/R9、栈参数 5-8、调用者返回地址
  |
  +-- call GenericHookDecide(5, CallerRetAddr, &Decision)
  |     |
  |     +-- FindHookById(5) -> NtCreateFile 的条目
  |     +-- Rule.TargetPid == 0 -> 无 PID 过滤，处理所有进程
  |     +-- InterlockedIncrement64(&HitCount)
  |     +-- Decision = { LOG_ONLY, Trampoline=<原始>, ShouldLog=TRUE }
  |
  +-- 恢复所有参数
  +-- call Decision.Trampoline         ; 执行真正的 NtCreateFile
  |     |
  |     +-- [EPT 跳板]：
  |           执行原始 14 字节
  |           JMP 到 NtCreateFile+14
  |           真正的 NtCreateFile 运行至完成
  |           在 RAX 中返回 NTSTATUS
  |
  +-- RAX = 原始返回值（例如 STATUS_SUCCESS）
  |
  +-- call GenericHookPostCall(5, LOG_ONLY, RAX, CallerAddr, TRUE)
  |     |
  |     +-- HookLogEvent()：
  |           写入环形缓冲区：
  |           { HookId=5, PID=当前进程, 时间戳, CallerAddr, RetVal, LOG_ONLY }
  |
  +-- ret   ; 将原始 RAX 返回给调用者
  |
  v
[Guest] 调用者收到 NtCreateFile 结果，完全无感知 Hook 的存在
```

---

## PatchGuard 为何无法检测

```
PatchGuard 检查的内容：              实际发生的情况：

读取 NtCreateFile 字节：            EPT Violation -> 展示 OriginalPage
  预期：原始序言                    看到：未修改的原始字节            [通过]

计算 ntoskrnl 页面哈希：            所有读取都经过 OriginalPage
  预期：已知哈希值                  哈希值：未改变                    [通过]

检查 SSDT 条目：                    SSDT 未被修改
  预期：ntoskrnl 范围内             所有条目未改变                    [通过]

检查 IDT 条目：                     IDT 未被修改
  预期：ntoskrnl 范围内             所有条目未改变                    [通过]

关键技巧：EPT 对读取和执行展示不同的物理页
  - 读/写：OriginalPage（未修改）   -> 完整性检查通过
  - 执行：HookPage（带 JMP）        -> 调用时触发 Hook
```

---

## 数据结构总览

```
GENERIC_HOOK_STATE（全局单例）
  |
  +-- HookListHead -> GENERIC_HOOK_ENTRY -> GENERIC_HOOK_ENTRY -> ... -> NULL
  |                    .HookId = 1          .HookId = 5
  |                    .TargetVA = ...       .TargetVA = ...
  |                    .Rule = {...}         .Rule = {...}
  |                    .Trampoline = ...     .Trampoline = ...
  |
  +-- ThunkPageHead -> THUNK_PAGE -> THUNK_PAGE -> ... -> NULL
  |                    .CodeBase = [4KB 可执行页]
  |                    .UsedCount = 42
  |                    .Capacity = 170
  |
  +-- EventRing[512]   （HOOK_EVENT 条目的环形缓冲区）
  +-- EventWriteIndex, EventReadIndex, EventCount
```

---

## 文件

| 文件 | 说明 |
|------|------|
| `driver/hv_hook.h` | 框架头文件：所有结构体和函数声明 |
| `driver/hv_hook.c` | 核心实现：初始化、安装、移除、决策、日志 |
| `driver/hv_hook_asm.asm` | ASM 分发器：参数保存/恢复、跳板调用 |
| `driver/ept.c` | EPT 引擎：Per-CPU 隔离、O(1) 哈希表、指令解码、RIP 重定位、Violation 处理 |
| `driver/ept.h` | EPT 结构体：EPT_CPU_STATE、哈希常量、Per-CPU 函数声明 |
| `driver/npt.c` | NPT 引擎 (AMD)：类似的 Per-CPU 隔离实现 |
| `driver/npt.h` | NPT 结构体：NPT_CPU_STATE、Per-CPU 函数声明 |
| `common/shared.h` | IOCTL 代码 (0x809-0x80C) 和共享结构体 |
| `driver/vmxdrv.c` | 安装/移除/列表/事件的 IOCTL 处理程序 |

---

## 限制

| 限制 | 详情 |
|------|------|
| 12 字节最小序言 | 被挂钩函数在任何短跳转目标之前必须至少有 12 字节完整指令（指令解码器自动边界对齐） |
| 栈参数 9+ 未显式复制 | 参数 9-12+ 依赖栈帧布局兼容性（实际使用中有效） |
| Thunk 页不回收 | 释放的 Hook 会在 Thunk 页中留下空隙；页仅在清理时释放 |
| 事件环形缓冲区溢出 | 环形缓冲区（512 条目）满时，最旧的事件会被静默覆盖 |
| 用户态 Hook | 需要目标进程 CR3 解析；内核 Hook 完全支持 |
| RIP-relative 重定位范围 | 跳板与原始位置距离超过 ±2GB 时，RIP-relative 指令无法重定位，拒绝安装 |

---

## Per-CPU EPT/NPT Hook 页隔离

### 问题：多核竞争条件

EPT Hook 的工作原理是在 EPT Violation 时临时放宽 PTE 权限，执行一条指令（MTF 单步），然后恢复。当多个 CPU 同时触发同一 hook 时，共享 PTE 产生竞争：

```
CPU 0: EPT Violation → 放宽 PTE (R+W) → 启用 MTF
CPU 1: EPT Violation → 放宽 PTE (R+W) → 启用 MTF    ← 同一个 PTE!
CPU 0: MTF 触发 → 恢复 PTE (X-Only)                  ← 也恢复了 CPU 1 的 PTE!
CPU 1: 还在执行 → PTE 已恢复 → 再次 EPT Violation → 死循环
```

### 解决方案：每 CPU 独立 PT

```
        ┌──────────────────────────────────────────────┐
        │  共享模板 (EPT_STATE)                         │
        │  PML4 → PDPT → PD Pages → Split PT Pages     │
        │  (非 hook 区域所有 CPU 共享)                    │
        └──────────────────────────────────────────────┘

Per-CPU 层 (仅 hook 区域按需克隆):

  CPU 0:  PML4[0] → PDPT[0]                      CPU 1:  PML4[1] → PDPT[1]
            │                                               │
            ├─ PDPT[x] → 共享 PD (未 hook 的 GB 区域)        ├─ PDPT[x] → 共享 PD
            │                                               │
            └─ PDPT[y] → per-CPU PD[0][y]                  └─ PDPT[y] → per-CPU PD[1][y]
                           │                                               │
                           └─ PD[z] → per-CPU PT[0]                       └─ PD[z] → per-CPU PT[1]
                               (各自独立的 4KB PTE)                            (各自独立的 4KB PTE)
```

**分层隔离策略**：

| 层级 | 隔离策略 | 原因 |
|------|---------|------|
| PML4 | 每 CPU 独立副本 | 让 PML4[0] 指向各自的 PDPT |
| PDPT | 每 CPU 独立副本 | 让 PDPT entry 指向各自的 PD page |
| PD | **按需克隆** | 只有包含 hook 的 GB 区域才创建 per-CPU PD |
| PT (split) | **按需克隆** | 只有包含 hook 的 2MB 区域才创建 per-CPU PT |
| 非 hook 区域 | 所有 CPU 共享 | 通过 PDPT entry 指向共享 PD pages |

### 核心数据结构

```c
/* Per-CPU EPT 根结构 */
typedef struct _EPT_CPU_STATE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[512];   /* 独立 PML4 */
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[512];   /* 独立 PDPT */
    EPT_POINTER Eptp;      /* 该 CPU 的 EPTP 值 (写入 VMCS) */
    ULONG64     Pml4Pa;
} EPT_CPU_STATE;

/* Per-CPU PT 页副本 */
typedef struct _EPT_PER_CPU_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[512];      /* 独立 PTE 数组 */
    ULONG64     PhysicalAddress;   /* 该 per-CPU PTE 数组的物理地址 */
    BOOLEAN     Allocated;         /* 是否已分配 */
} EPT_PER_CPU_SPLIT;

/* Per-CPU PD 页副本 */
typedef struct _EPT_PER_CPU_PD_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Entries[512];
} EPT_PER_CPU_PD_PAGE;
```

### 初始化流程

```
EptInitPerCpu()  (在 EptInitialize 之后调用)
  |
  +-- 分配 g_EptCpuStates[g_MaxProcessors]
  +-- 分配 g_PerCpuSplitPages[g_MaxProcessors] 指针数组
  +-- 分配 g_PerCpuPdPages[g_MaxProcessors] 指针数组
  |
  +-- 对每个 CPU:
       +-- 克隆 PML4 和 PDPT (从共享模板)
       +-- PML4[0].PhysAddr = 该 CPU 的 PDPT 物理地址
       +-- 构建独立 EPTP 值
       |
       PDPT entries 初始仍指向共享 PD pages（非 hook 区域不浪费内存）
```

### Hook 安装时的 Per-CPU 设置

```
EptHookFunction()
  |
  +-- ... 常规 hook 安装（页拆分、HookPage 创建、跳板构建）...
  |
  +-- Per-CPU 隔离设置:
       |
       +-- EptEnsurePerCpuPdForRegion(PdptIndex)
       |     对每个 CPU: 克隆共享 PD page -> per-CPU PD page
       |     更新 CPU 的 PDPT[PdptIndex] 指向自己的 PD page
       |
       +-- EptEnsurePerCpuSplitPage(splitIdx, PdptIndex, PdIndex)
       |     对每个 CPU: 克隆共享 split PT page -> per-CPU PT page
       |     更新 CPU 的 PD[PdptIndex].Entries[PdIndex] 指向自己的 PT page
       |
       +-- 复制 hook PTE 权限到所有 per-CPU PT:
             for (cpu = 0; cpu < N; cpu++):
                 CpuPte = EptGetPerCpuPte(cpu, TargetPA)
                 CpuPte->Read/Write/Execute/PhysAddr = 与共享 PTE 相同
```

### 运行时 EPT Violation 处理（Per-CPU PTE）

```
HandleEptViolation()
  |
  +-- CpuIndex = KeGetCurrentProcessorNumber()
  |
  +-- Pte = EptGetPerCpuPte(CpuIndex, HookPA)  // 获取本 CPU 的私有 PTE
  |   如果 per-CPU 不可用: 回退到共享 PTE
  |
  +-- 修改 Pte 权限 (仅影响当前 CPU):
  |     Mode A: R=1,W=1,X=0 (数据访问) 或 R=0,W=0,X=1 (执行)
  |     Mode B: R=1,W=1,X=1 + RIP 检测选择 HookPage/OriginalPage
  |
  +-- INVEPT SINGLE_CONTEXT(当前 CPU 的 EPTP)  // 仅刷新当前 CPU
  |   (不再使用 ALL_CONTEXTS 影响所有 CPU)
  |
  +-- EptMtfTrackRelaxedPage(HookPA)  // 记录当前 CPU 放宽的页
  +-- 启用 MTF

HandleMtf()
  |
  +-- Pa = EptMtfGetAndClearRelaxedPage()  // 获取本 CPU 记录的页
  +-- 恢复本 CPU 的 PTE 为 hook 权限
  +-- INVEPT SINGLE_CONTEXT
  +-- 关闭 MTF
  |
  // 其他 CPU 的 PTE 不受影响 → 无竞争
```

### 内存开销

| 组件 | 大小 | 何时分配 |
|------|------|---------|
| EPT_CPU_STATE (PML4+PDPT+EPTP) | ~8KB × CPU数 | EptInitPerCpu() |
| Per-CPU PD pages | ~2MB × CPU数 | 首次 hook 安装时按需克隆 |
| Per-CPU Split PT pages | ~4KB × CPU数 × hook 的 2MB 区域数 | 首次 hook 安装时按需克隆 |

> **示例**：4 CPU 系统，3 个 hook 分布在 2 个不同的 2MB 区域：
> - EPT_CPU_STATE: 4 × 8KB = 32KB
> - Per-CPU PD: 4 × 2MB = 8MB（一次性，覆盖所有 PDPT 索引）
> - Per-CPU PT: 4 × 2 × 4KB = 32KB
> - **总额外开销**: ~8.06MB

---

## Execute-Only 回退 (Mode A / Mode B)

EPT Hook 依赖页权限分离来区分执行和数据访问。在硬件支持 Execute-Only 的平台上使用 Mode A；否则使用 Mode B。

### Mode A: Execute-Only (R=0, W=0, X=1)

```
PTE 设置: Read=0, Write=0, Execute=1, PhysAddr = HookPage

Guest 读取/写入 NtCreateFile 字节:
  → EPT Violation (数据访问)
  → Handler: 切换到 OriginalPage (R+W, X=0) + MTF
  → MTF 恢复: 切回 HookPage (X-only)
  → PatchGuard/完整性检查看到原始未修改代码 ✓

Guest 执行 NtCreateFile:
  → 直接命中 HookPage（X=1，无 Violation）
  → MOV RAX,ThunkAddr; JMP RAX → Thunk → 分发器
```

**优点**：执行路径零 Violation（无额外性能损失）。

### Mode B: 全禁止 (R=0, W=0, X=0)

```
PTE 设置: Read=0, Write=0, Execute=0, PhysAddr = HookPage

Guest 的任何访问:
  → EPT Violation (所有访问类型)
  → Handler: 检查 Guest RIP
    |
    +-- RIP 在目标页内 → 执行意图
    |   → 临时 R+W+X, PhysAddr = HookPage + MTF
    |   → JMP 补丁执行 → 进入 Thunk
    |
    +-- RIP 在页外 → 数据读/写意图
        → 临时 R+W+X, PhysAddr = OriginalPage + MTF
        → 读到的是未修改原始代码 (PatchGuard 安全)

  MTF 恢复: 切回 R=0,W=0,X=0
```

**RIP 检测原理**：利用 Guest CR3 页表遍历将 Guest RIP VA 转为 PA，比较其 4KB 页帧与目标页帧。

```c
/* VMX root 安全的 Guest VA → PA 转换（不依赖 Windows API） */
ULONG64 RipPa = EptGuestVaToPa(GuestCr3, GuestRip);
if ((RipPa & PAGE_MASK_4KB) == HookTargetPhysicalAddr) {
    /* 执行：展示 HookPage */
} else {
    /* 数据访问：展示 OriginalPage */
}
```

### 自动检测

```c
/* EptInitialize() 中检测 Execute-Only 支持 */
ULONG64 EptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
g_EptHookState.ExecuteOnlySupported = (EptVpidCap & 1) != 0;
/* 某些 CPU 型号可能不支持此位 → 自动回退 Mode B */
```

---

## O(1) 哈希表查找优化

EPT Violation 处理运行在 VMX root 模式的关键路径上，延迟直接影响 Guest 性能。原始实现使用线性扫描 O(n)，已优化为 O(1) 开放寻址哈希表。

### Hook 查找哈希表

```
用途: HandleEptViolation() → EptFindHookByPhysicalAddress()
键:   页物理地址 (PA >> 12)
值:   Hook 数组索引
大小: 2048 桶 (≤1024 hooks, 负载因子 ≤ 0.5)
哈希: Knuth 乘法哈希 (PFN × 2654435761 >> shift)
冲突: 线性探测 + EPT_HOOK_HASH_EMPTY 哨兵

操作:
  插入 - EptHookFunction()  : O(1)
  查找 - EptFindHookByPhysicalAddress() : O(1) 期望
  删除 - EptUnhookFunction() : O(n) 重建（非热路径）
```

### Split Page 查找哈希表

```
用途: EptGetPteForPhysicalAddress() / EptGetPerCpuPte()
键:   2MB 对齐基址 (Base2MB >> 21)
值:   g_SplitPages[] 数组索引
大小: 256 桶 (≤128 split pages, 负载因子 ≤ 0.5)
哈希: 同上 Knuth 乘法哈希

在 EptSplitLargePage() 中插入, 在 EptCleanup() 中清除.
```

### 性能对比

| 操作 | 旧方案 | 新方案 |
|------|--------|--------|
| Hook 查找 (每次 EPT Violation) | O(1024) 线性扫描 | O(1) 哈希查找 |
| Split page 查找 (每次 PTE 操作) | O(128) 线性扫描 | O(1) 哈希查找 |
| Hook 移除 (非热路径) | O(1) | O(n) 哈希重建 |

---

## 安全跳板构建

跳板（Trampoline）用于在 Hook 触发后调用原始函数。构建过程涉及三个关键组件：

### 指令长度解码器

`EptGetInstructionLength()` 是一个最小化的 x86-64 指令长度解码器，覆盖函数序言中常见的指令子集：

```
支持的指令类别:
  - 寄存器操作: MOV, LEA, XOR, AND, OR, SUB, ADD, CMP, TEST
  - 栈操作: PUSH reg/imm, POP reg
  - 流程控制: JMP rel8/rel32, Jcc rel8/rel32, CALL rel32, RET
  - 前缀: REX (0x40-0x4F), 操作数大小 (0x66), 地址大小 (0x67)
  - 两字节: 0F xx (CMOVcc, SETcc, MOVZX, MOVSX, NOP, Jcc rel32)
  - Group 1/3/5: 80/81/83, F6/F7, FF 系列

工作流程:
  1. 跳过前缀字节（REX、66、67、段覆盖、LOCK/REP）
  2. 识别一字节/两字节操作码
  3. 如有 ModRM：解码 Mod、RM、SIB、位移
  4. 累加立即数大小
  5. 返回总长度（0 = 无法解码 → 拒绝 hook）
```

**安全保证**：解码器循环直到累计字节 ≥ 12（JMP patch 大小），确保跳板只包含完整指令。

### RIP-Relative 指令检测与重定位

```c
/* 检测 RIP-relative 寻址: ModRM Mod=00, RM=101 */
BOOLEAN EptIsRipRelativeInstruction(Code, InsnLen, &DispOffset);

/* 重定位 disp32: new_disp = target - (TrampolineVA + InsnLen) */
BOOLEAN EptRelocateRipRelativeInstruction(TrampolineInsn, InsnLen,
    DispOffset, OriginalVA, TrampolineVA);
```

```
原始位置 (OriginalVA = 0xFFFFF800`12345678):
  LEA RAX, [RIP+0x1234]
  → 目标绝对地址 = 0xFFFFF800`12345678 + InsnLen + 0x1234

跳板位置 (TrampolineVA = 0xFFFFABCD`00001000):
  LEA RAX, [RIP+NewDisp]
  → NewDisp = 目标绝对地址 - (TrampolineVA + InsnLen)
  → 如果 |NewDisp| > 2GB → 重定位失败 → 拒绝安装 hook
```

### 跳板整体结构

```
Trampoline (最大 64 字节):
  +0:    [原始指令 1]          (已修复 RIP-relative)
  +N1:   [原始指令 2]          (已修复 RIP-relative)
  ...
  +Nk:   [原始指令 k]          (总计 ≥ 12 字节完整指令)
  +Total: FF 25 00000000        JMP [RIP+0]
  +Total+6: [8字节绝对地址]     → TargetVA + Total (跳回被覆盖部分之后)
```

---

## 共享页支持（同页多 Hook）

当同一 4KB 物理页上安装多个 Hook（例如同一模块中相邻的两个函数），它们共享 HookPage 和 OriginalPage：

```
EptHookFunction(FuncA) → 第一个 hook，分配 HookPage + OriginalPage
  Hook[0].OwnsPages = TRUE
  HookPage 上偏移 A 处写入 JMP → ThunkA

EptHookFunction(FuncB, 同页) → 检测到 PageOwner
  Hook[1].OwnsPages = FALSE
  复用 Hook[0] 的 HookPage/OriginalPage
  HookPage 上偏移 B 处写入 JMP → ThunkB（不覆盖偏移 A 的 JMP）

EptUnhookFunction(FuncA):
  恢复 HookPage 偏移 A 处为原始字节
  检测到 FuncB 仍在同页上 → 不释放 HookPage/OriginalPage
  将 OwnsPages 转移给 Hook[1]

EptUnhookFunction(FuncB):
  恢复 HookPage 偏移 B 处为原始字节
  同页无其他 hook → 恢复 EPT PTE 到原始页 → INVEPT → 释放页
```

**所有权转移规则**：移除页拥有者时，如果同页还有其他 hook，将 `OwnsPages = TRUE` 转移给另一个 hook。

---

## INVEPT 优化

### 旧方案：INVEPT ALL_CONTEXTS

每次 PTE 修改都刷新所有 CPU 的所有 EPTP 上下文的 TLB。

### 新方案：INVEPT SINGLE_CONTEXT

Per-CPU 隔离后，PTE 修改仅影响当前 CPU 的页表，使用 SINGLE_CONTEXT 刷新该 CPU 的 EPTP 上下文即可：

```c
ULONG64 CpuEptp = EptGetPerCpuEptp(CpuIndex);
if (CpuEptp)
    EptInvalidateSingleContext(CpuEptp);  /* 仅刷新当前 CPU */
else
    EptInvalidateAllContexts();           /* 回退 */
```

### 跨 CPU 刷新（Hook 安装/移除时）

Hook 安装和移除修改了所有 CPU 的 PTE，仍然需要全局刷新。使用代际计数器机制：

```
EptInvalidateFromGuest():
  InterlockedIncrement(&g_EptInveptGeneration)

每次 VM-Exit:
  EptCheckPendingInvept():
    if (g_EptInveptCpuGen[CPU] != g_EptInveptGeneration):
      g_EptInveptCpuGen[CPU] = g_EptInveptGeneration
      INVEPT ALL_CONTEXTS
```

---

## 两阶段 Unhook（防止 UAF）

移除 Hook 时必须确保所有 CPU 的 TLB 不再引用即将释放的 HookPage/OriginalPage：

```
EptUnhookAll():
  Pass 1: 遍历所有 hook，恢复 EPT PTE → 原始物理地址 (R+W+X)
          同时恢复所有 per-CPU PTE
          !! 不释放任何页 !!

  INVEPT: EptInvalidateFromGuest() → 所有 CPU 最终执行 INVEPT

  Pass 2: 遍历所有 hook，释放 HookPage/OriginalPage/Trampoline

  // Pass 1 → INVEPT → Pass 2 的顺序确保不存在 UAF 窗口
  // 如果在 Pass 1 直接释放页，其他 CPU 的 stale TLB 可能仍在翻译旧页 → use-after-free
```
