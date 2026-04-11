# VMXHypervisorToolbox Bug 分析与修复报告

> **日期**：2026-04-11  
> **涉及模块**：EPT Hook Engine / VMX Exit Handler / Driver IOCTL Dispatch  
> **状态**：待 Review

---

## 目录

- [Bug #1：Trampoline 指令截断导致 #UD → BSOD](#bug-1trampoline-指令截断导致-ud--bsod)
- [Bug #3：HandleMtf 多核竞争条件导致无限 EPT Violation 循环](#bug-3handlemtf-多核竞争条件导致无限-ept-violation-循环)
- [Bug #5：EptSplitLargePage 后缺少 INVEPT 导致 EPT Misconfiguration](#bug-5eptsplitlargepage-后缺少-invept-导致-ept-misconfiguration)
- [Bug #6：IOCTL 分发中 IoStatus.Information 未初始化](#bug-6ioctl-分发中-iostatusinformation-未初始化)
- [修改文件清单](#修改文件清单)
- [编译兼容性说明](#编译兼容性说明)

---

## Bug #1：Trampoline 指令截断导致 #UD → BSOD

### 严重程度：🔴 Critical

### 问题描述

`EptHookFunction()` 在构建 trampoline（跳板）时，需要从目标函数头部"偷"走至少 12 字节（`48 B8 [imm64] FF E0` = MOV RAX, addr; JMP RAX），然后将这些原始字节复制到 trampoline 中，trampoline 末尾再 JMP 回原始函数 +12 的位置。

**原始代码**硬编码复制 14 字节：

```c
// 原始代码（有bug）
Hook->OriginalBytesSize = 14;  // 硬编码
RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, 14);
```

这存在一个致命问题：x86-64 指令是**变长的**（1~15 字节），14 字节很可能恰好切断某条指令的中间。例如：

```
目标函数前缀:
  48 89 5C 24 08    MOV [RSP+8], RBX     (5 字节)
  48 89 6C 24 10    MOV [RSP+10h], RBP   (5 字节)
  48 89 74 24 18    MOV [RSP+18h], RSI   (5 字节)  ← 第14字节在这条指令中间!
```

Trampoline 会执行截断的 `48 89 74` 然后跳到垃圾字节 → `#UD`（Undefined Opcode）异常 → 内核态 → **BSOD**。

### 修复方案

1. **实现 `EptGetInstructionLength()` 函数**：一个最小化的 x64 指令长度解码器（~300 行），覆盖内核函数前缀中常见的所有指令：
   - 前缀处理：Legacy prefixes（LOCK/REP/段覆盖）、66h/67h、REX（40h~4Fh）
   - 单字节操作码：PUSH/POP reg、MOV reg,imm、JMP/CALL rel、ALU 操作（ADD/SUB/XOR/CMP/...）、Group 1/3/5、Shift/Rotate 等
   - 双字节操作码（0Fh）：Jcc rel32、MOVZX/MOVSX、CMOVcc、SETcc、NOP(多字节)、SYSCALL 等
   - 完整的 ModRM + SIB + Displacement 解码

2. **修改 `EptHookFunction()` 的 trampoline 构建逻辑**：

```c
// 修复后代码
{
    ULONG TotalLen = 0;
    PUCHAR Code = (PUCHAR)TargetVa;
    while (TotalLen < 12) {                          // 至少覆盖 12 字节
        ULONG InsnLen = EptGetInstructionLength(Code + TotalLen);
        if (InsnLen == 0) {
            // 遇到无法解码的指令 → 安全退出，不安装 hook
            LOG_ERROR("EPT Hook: Cannot decode instruction at VA 0x%llX + 0x%X",
                      TargetVa, TotalLen);
            // ...释放资源...
            return STATUS_UNSUCCESSFUL;
        }
        TotalLen += InsnLen;
    }
    Hook->OriginalBytesSize = TotalLen;              // 可能是 12, 13, 14, 15...
}
RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, Hook->OriginalBytesSize);
```

**关键改进**：
- 逐条指令累积长度，直到总长度 ≥ 12 字节
- 保证不会截断任何指令
- 遇到无法解码的指令时安全退出（而非盲目复制导致崩溃）

### 追加修复：OriginalBytes 缓冲区溢出保护

原始修复中 `TotalLen` 按指令边界对齐，值可变（12, 13, 14, 15...），但 `Hook->OriginalBytes` 仅为 `UCHAR[16]`。极端情况下（如函数前缀包含长指令），`TotalLen` 可能超过 16 字节，导致 `RtlCopyMemory` 写越界，破坏结构体后续字段（`HookFunction` 指针等）。

**追加修复内容**：

1. **增大缓冲区**：`OriginalBytes[16]` → `OriginalBytes[32]`（x64 最长指令 15 字节，理论最大 TotalLen = 11 + 15 = 26，32 字节提供对齐余量）

2. **添加越界检查**：循环中每次累加前检查是否会超出缓冲区：

```c
if (TotalLen + InsnLen > sizeof(((EPT_HOOK_ENTRY*)0)->OriginalBytes)) {
    LOG_ERROR("EPT Hook: OriginalBytes overflow at VA 0x%llX "
              "(TotalLen=%u + InsnLen=%u > %u)",
              TargetVa, TotalLen, InsnLen,
              (ULONG)sizeof(((EPT_HOOK_ENTRY*)0)->OriginalBytes));
    // ...释放资源...
    return STATUS_BUFFER_TOO_SMALL;
}
```

3. **同步修复 AMD-V 侧 (`npt.c`)**：`NptHookFunction()` 原先硬编码 `OriginalBytesSize = 14`，存在相同的指令截断问题。已替换为与 `ept.c` 一致的指令边界对齐 + 越界保护逻辑。

### 涉及文件

| 文件 | 变更 |
|------|------|
| `driver/ept.c` | +`EptGetInstructionLength()` 函数实现（~300 行）；修改 trampoline 构建逻辑；+越界保护检查 |
| `driver/ept.h` | +`EptGetInstructionLength` 函数声明；`OriginalBytes[16]` → `OriginalBytes[32]` |
| `driver/npt.c` | 硬编码 14 字节 → 指令边界对齐 + 越界保护（与 ept.c 一致） |

---

## Bug #3：HandleMtf 多核竞争条件导致无限 EPT Violation 循环

### 严重程度：🔴 Critical

### 问题描述

EPT Hook 引擎使用 **execute-only** 页面实现隐藏 hook：
- 静息状态：hook 页面 `R=0, W=0, X=1`（只能执行，不能读写）
- 数据访问（如 PatchGuard 扫描）：EPT Violation → 切换到原始页面 `R=1, W=1, X=0` → 启用 MTF（Monitor Trap Flag）→ 一条指令后 MTF 触发 → 恢复为 hook 页面 `R=0, W=0, X=1`

**原始 `HandleMtf` 代码**在 MTF 触发时**恢复所有 1024 个 hook**：

```c
// 原始代码（有bug）
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    // ...disable MTF...
    
    // 遍历所有 hook，全部恢复
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
            PEPT_PTE Pte = g_EptHookState.Hooks[i].TargetPte;
            if (Pte->Read || Pte->Write) {
                Pte->Read = 0;
                Pte->Write = 0;
                // ...恢复 hook 页面...
            }
        }
    }
}
```

**多核竞争场景**：

```
时间线：
  T1: CPU 0 → Hook A 的 EPT Violation → 切换到 R=1,W=1 → 启用 MTF
  T2: CPU 1 → Hook B 的 EPT Violation → 切换到 R=1,W=1 → 启用 MTF
  T3: CPU 0 → MTF 触发 → 恢复 ALL hooks（包括 Hook B！）→ Hook B 变回 R=0,W=0
  T4: CPU 1 → 还没执行完那条数据访问指令 → 再次 EPT Violation（Hook B）
  T5: CPU 1 → 切换回 R=1,W=1 → 启用 MTF
  T6: CPU 0 → 可能又有新的 MTF → 再次恢复 ALL hooks...
  → 无限循环！CPU 1 永远无法完成那条指令
```

### 修复方案

引入 **per-CPU 跟踪机制**，每个 CPU 只恢复**它自己松弛的那个页面**上的 hook：

**1. 在 `ept.c` 中添加 per-CPU 跟踪数组和辅助函数**：

```c
// 每个 CPU 槽位记录它当前松弛了哪个物理页面
static volatile ULONG64 g_MtfRelaxedPagePa[64] = { 0 };

// HandleEptViolation 调用：记录当前 CPU 松弛的页面
VOID EptMtfTrackRelaxedPage(ULONG64 PagePhysicalAddr)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    if (CpuIndex < 64) {
        g_MtfRelaxedPagePa[CpuIndex] = PagePhysicalAddr;
    }
}

// HandleMtf 调用：获取并清除当前 CPU 松弛的页面
ULONG64 EptMtfGetAndClearRelaxedPage(VOID)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    ULONG64 Pa = 0;
    if (CpuIndex < 64) {
        Pa = g_MtfRelaxedPagePa[CpuIndex];
        g_MtfRelaxedPagePa[CpuIndex] = 0;
    }
    return Pa;
}
```

**2. 在 `HandleEptViolation` 中，每次松弛页面后记录**：

```c
// EPT Violation handler 中（Mode A 和 Mode B 两条路径都添加）
EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);  // ← 新增
ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
```

**3. `HandleMtf` 改为只恢复当前 CPU 的页面**：

```c
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    // ...disable MTF...
    
    // 获取当前 CPU 松弛的页面
    RelaxedPa = EptMtfGetAndClearRelaxedPage();
    
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
            // ★ 只恢复当前 CPU 松弛的页面，跳过其他
            if (RelaxedPa != 0 &&
                g_EptHookState.Hooks[i].TargetPhysicalAddr != RelaxedPa) {
                continue;
            }
            // ...恢复 hook...
        }
    }
}
```

**安全兜底**：如果 `RelaxedPa == 0`（理论上不会发生），回退到恢复所有 hook，避免漏恢复。

### 涉及文件

| 文件 | 变更 |
|------|------|
| `driver/ept.c` | +`g_MtfRelaxedPagePa[64]` 数组；+`EptMtfTrackRelaxedPage()`；+`EptMtfGetAndClearRelaxedPage()`；`HandleEptViolation` 两条路径各添加一处 `EptMtfTrackRelaxedPage` 调用 |
| `driver/ept.h` | +`EptMtfTrackRelaxedPage` 和 `EptMtfGetAndClearRelaxedPage` 声明 |
| `driver/vmx_exit.c` | `HandleMtf` 改为查询 per-CPU 跟踪数组，只恢复特定页面 |

---

## Bug #5：EptSplitLargePage 后缺少 INVEPT 导致 EPT Misconfiguration

### 严重程度：🔴 Critical

### 问题描述

`EptHookFunction()` 在安装 hook 前需要将目标地址所在的 2MB 大页拆分为 512 个 4KB 页（因为 hook 需要细粒度的页级别权限控制）。拆分操作通过 `EptSplitLargePage()` 实现，它会修改 EPT 页目录条目（PDE），将其从一个 2MB 大页条目改为指向一个新的 4KB 页表。

**原始代码**在拆分后没有刷新 EPT TLB：

```c
// 原始代码（有bug）
EptSplitLargePage(TargetPa);
// ← 缺少 INVEPT！
Pte = EptGetPteForPhysicalAddress(TargetPa);  // 获取 4KB PTE
```

**问题**：

```
CPU 0:  执行 EptSplitLargePage()
        → 修改 PDE: 2MB 大页条目 → 指向新的 4KB 页表
        
CPU 1-N: TLB 中仍然缓存着旧的 2MB PDE
        → 下一次内存访问时，CPU 用旧的 2MB PDE 格式解释新数据
        → PDE 格式不匹配新的 PT → EPT Misconfiguration
        → VMX shutdown → BSOD (BSOD 代码通常是 UNEXPECTED_STORE_EXCEPTION 或类似)
```

EPT Misconfiguration 与 EPT Violation 不同：Violation 是权限问题（可恢复），而 Misconfiguration 是页表结构错误（通常不可恢复，导致 VMX 直接关闭）。

### 修复方案

在 `EptSplitLargePage()` 调用后**立即**执行 `EptInvalidateFromGuest()`，刷新所有 CPU 的 EPT TLB：

```c
// 修复后代码
EptSplitLargePage(TargetPa);

/*
 * BUG FIX: After splitting a 2MB page into 4KB pages, other CPUs may
 * still have stale TLB entries pointing to the old 2MB PDE.  If they
 * access memory in this range before seeing the new 4KB PTEs, the CPU
 * will detect an EPT Misconfiguration (the old PDE format doesn't match
 * the new PT) and trigger HandleEptMisconfig → VMX shutdown → BSOD.
 *
 * Fix: Invalidate EPT TLB immediately after page split so all CPUs
 * pick up the new page table structure before any further accesses.
 */
EptInvalidateFromGuest();  // ← 新增

Pte = EptGetPteForPhysicalAddress(TargetPa);
```

> **注意**：`EptInvalidateFromGuest()` 使用 generation counter 机制（`InterlockedIncrement`），每个 CPU 在下一次 VM-Exit 时检查并执行 INVEPT。这比 VMCALL 方式更兼容（避免 VMware 嵌套虚拟化下的拦截问题）。

### 涉及文件

| 文件 | 变更 |
|------|------|
| `driver/ept.c` | `EptHookFunction()` 中 `EptSplitLargePage()` 后添加 `EptInvalidateFromGuest()` |

---

## Bug #6：IOCTL 分发中 IoStatus.Information 未初始化

### 严重程度：🟡 Medium

### 问题描述

`DispatchDeviceControl` 函数处理用户态 IOCTL 请求，使用 `METHOD_BUFFERED` 方式。在此方式下，`Irp->IoStatus.Information` 字段告诉 I/O 管理器应该从系统缓冲区复制多少字节回用户态缓冲区。

**原始代码**没有在分发前初始化这个字段：

```c
// 原始代码（有bug）
IoStack = IoGetCurrentIrpStackLocation(Irp);
IoControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;
// ← 没有初始化 Irp->IoStatus.Information

switch (IoControlCode) {
    case IOCTL_VMX_INIT:
        Status = HandleIoctlInit(Irp, IoStack);
        break;
    // ...
    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
}
```

**问题**：
- 成功路径：各 handler 通常会设置 `Information` → 无问题
- **失败路径**：如果 handler 返回错误状态但忘记设置 `Information`，或者进入 `default` 分支：
  - `Information` 保持未初始化的值（可能是上一次 IRP 复用留下的脏数据）
  - I/O 管理器根据这个脏值复制数据到用户态 → **信息泄露**（内核内存内容泄露到用户态）
  - 或者脏值很大 → 复制越界 → **蓝屏**

### 修复方案

在 switch 分发前统一初始化：

```c
// 修复后代码
IoStack = IoGetCurrentIrpStackLocation(Irp);
IoControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;

/*
 * BUG FIX: Initialize IoStatus.Information to 0 before dispatching.
 * Individual handlers set it to the correct output size on success.
 * Without this, on failure paths where handlers don't set Information,
 * the I/O manager would copy garbage data back to the user-mode buffer
 * (METHOD_BUFFERED uses Information as the output byte count).
 */
Irp->IoStatus.Information = 0;  // ← 新增

switch (IoControlCode) {
```

这样即使某个 handler 忘记设置 `Information`，也不会泄露数据或越界复制。

### 涉及文件

| 文件 | 变更 |
|------|------|
| `driver/vmxdrv.c` | `DispatchDeviceControl` 中 switch 前添加 `Irp->IoStatus.Information = 0` |

---

## 修改文件清单

| 文件 | Bug # | 变更摘要 |
|------|-------|----------|
| `driver/ept.c` | #1 | 新增 `EptGetInstructionLength()` 函数（~300 行最小 x64 指令解码器） |
| `driver/ept.c` | #1 | 修改 trampoline 构建逻辑：从硬编码 14 字节改为按指令边界累积 ≥12 字节 |
| `driver/ept.c` | #3 | 新增 `g_MtfRelaxedPagePa[64]` per-CPU 跟踪数组 |
| `driver/ept.c` | #3 | 新增 `EptMtfTrackRelaxedPage()` 和 `EptMtfGetAndClearRelaxedPage()` |
| `driver/ept.c` | #3 | `HandleEptViolation` 两条路径（Mode A / Mode B）各添加 `EptMtfTrackRelaxedPage` 调用 |
| `driver/ept.c` | #5 | `EptHookFunction()` 中 `EptSplitLargePage()` 后添加 `EptInvalidateFromGuest()` |
| `driver/ept.h` | #1 | 新增 `EptGetInstructionLength` 声明 |
| `driver/ept.h` | #3 | 新增 `EptMtfTrackRelaxedPage` 和 `EptMtfGetAndClearRelaxedPage` 声明 |
| `driver/vmx_exit.c` | #3 | `HandleMtf` 改为调用 `EptMtfGetAndClearRelaxedPage()`，只恢复当前 CPU 松弛的页面 |
| `driver/vmxdrv.c` | #6 | `DispatchDeviceControl` 中 switch 前添加 `Irp->IoStatus.Information = 0` |

---

## 编译兼容性说明

本项目使用 **WDK 7600**（Windows 7 DDK），其 MSVC 编译器要求 **C89 风格**的变量声明（所有变量必须在代码块开头声明，不能在语句之间声明）。

`EptGetInstructionLength()` 函数的所有局部变量已移至函数开头：

```c
ULONG EptGetInstructionLength(PUCHAR Code)
{
    ULONG   Pos = 0;
    BOOLEAN HasRex = FALSE;
    BOOLEAN OperandSize66 = FALSE;
    BOOLEAN AddressSize67 = FALSE;
    UCHAR   Rex = 0;
    UCHAR   Opcode;
    UCHAR   ModRM;
    UCHAR   Mod, RM;
    BOOLEAN HasModRM = FALSE;
    ULONG   ImmSize = 0;
    UCHAR   b;        // 循环内使用
    UCHAR   Op2;      // 两字节操作码
    UCHAR   Group;    // ALU 分组
    UCHAR   SubOp;    // ALU 子操作码
    UCHAR   SIB;      // SIB 字节
    UCHAR   SibBase;  // SIB.Base 字段
    UCHAR   EffRM;    // 有效 RM（含 REX.B 扩展）
    // ...函数体...
}
```

所有其他修改（per-CPU 数组、`Information` 初始化等）都不涉及 C89 兼容性问题。

---

## 待确认事项

1. **Bug #1 - 指令解码器覆盖范围**：当前解码器覆盖了内核函数前缀的绝大多数常见指令。如果目标函数使用了极其罕见的前缀指令（如 SSE/AVX 等），解码器会返回 0 并安全地拒绝安装 hook。是否需要扩展覆盖范围？

2. **Bug #3 - per-CPU 数组大小**：当前硬编码为 64 个处理器槽位。如果系统有超过 64 个逻辑处理器（如大型服务器），超出范围的 CPU 将无法被跟踪（回退到恢复全部 hook）。是否需要动态分配或增大上限？

3. **Bug #5 - INVEPT 时机**：当前使用 generation counter + lazy INVEPT 机制。理论上在 `EptSplitLargePage` 到下一次 VM-Exit 之间存在一个很小的时间窗口。是否需要更激进的同步机制（如 IPI）？

---

*文档结束。请 review 以上分析和修复方案。*
