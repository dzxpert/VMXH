# 通用 EPT/NPT Hook 框架 - 技术文档

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
EPT/NPT 引擎（已有，无需修改）
  |  仅执行页拆分 (Intel) / 读+执行 (AMD)
  |  14 字节 JMP -> Thunk 存根
  |  MTF/TF 单步恢复
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
       |     +-- EPT 引擎（已有，无需修改）：
       |           1. VA -> PA 地址转换
       |           2. 将 2MB 页拆分为 4KB
       |           3. 复制原始页 -> OriginalPage
       |           4. 复制原始页 -> HookPage
       |           5. 修补 HookPage：在函数入口写入 JMP 到 ThunkAddr
       |           6. 构建跳板：原始 14 字节 + JMP 返回
       |           7. EPT PTE：仅执行 -> HookPage
       |              （读取看到 OriginalPage，PatchGuard 安全）
       |           8. INVEPT 刷新 TLB
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
  +-- [EPT] PTE 为仅执行，物理地址 = HookPage
  |   HookPage 包含：JMP ThunkAddr（14 字节绝对间接 JMP）
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
| `common/shared.h` | IOCTL 代码 (0x809-0x80C) 和共享结构体 |
| `driver/vmxdrv.c` | 安装/移除/列表/事件的 IOCTL 处理程序 |

---

## 限制

| 限制 | 详情 |
|------|------|
| 14 字节最小序言 | 被挂钩函数在任何短跳转目标之前必须至少有 14 字节 |
| 栈参数 9+ 未显式复制 | 参数 9-12+ 依赖栈帧布局兼容性（实际使用中有效） |
| Thunk 页不回收 | 释放的 Hook 会在 Thunk 页中留下空隙；页仅在清理时释放 |
| 事件环形缓冲区溢出 | 环形缓冲区（512 条目）满时，最旧的事件会被静默覆盖 |
| 用户态 Hook | 需要目标进程 CR3 解析；内核 Hook 完全支持 |
