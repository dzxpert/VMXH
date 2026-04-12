# VMXHypervisorToolbox 完整 Bug 分析与修复报告

> **日期**：2026-04-11 ~ 2026-04-12  
> **项目**：VMXHypervisorToolbox（Intel VT-x Blue Pill Hypervisor）  
> **运行环境**：VMware Workstation（L0 Hypervisor）→ VMXToolbox（L1 Hypervisor）→ Windows Guest（L2）  
> **状态**：✅ 全部修复，运行正常

---

## 目录

### Part 1：VMware 嵌套虚拟化卡住问题（2026-04-12）

- [问题现象](#问题现象)
- [背景：嵌套虚拟化架构](#背景嵌套虚拟化架构)
- [排查历程与迭代](#排查历程与迭代)
- [根因 #1：External Interrupt Handler 丢弃所有中断（IPI 丢失）](#根因-1external-interrupt-handler-丢弃所有中断ipi-丢失)
- [根因 #2：HLT Handler 在 VMX Root Mode 中执行 \_enable() + \_\_halt()](#根因-2hlt-handler-在-vmx-root-mode-中执行-_enable--__halt)
- [辅助优化 #3：I/O Bitmap 消除 UNCONDITIONAL\_IO\_EXIT 风暴](#辅助优化-3io-bitmap-消除-unconditional_io_exit-风暴)
- [辅助优化 #4：CR3 Load Exit / MOV DR Exit / Exception Bitmap 优化](#辅助优化-4cr3-load-exit--mov-dr-exit--exception-bitmap-优化)

### Part 2：EPT Hook 引擎与驱动框架 Bug（2026-04-11）

- [Bug #A：Trampoline 指令截断导致 #UD → BSOD](#bug-atrampoline-指令截断导致-ud--bsod)
- [Bug #B：HandleMtf 多核竞争条件导致无限 EPT Violation 循环](#bug-bhandlemtf-多核竞争条件导致无限-ept-violation-循环)
- [Bug #C：EptSplitLargePage 后缺少 INVEPT 导致 EPT Misconfiguration](#bug-ceptsplitlargepage-后缺少-invept-导致-ept-misconfiguration)
- [Bug #D：IOCTL 分发中 IoStatus.Information 未初始化](#bug-dioct-分发中-iostatusinformation-未初始化)

### 总览

- [全部修复方案汇总](#全部修复方案汇总)
- [完整修改文件清单](#完整修改文件清单)
- [编译兼容性说明](#编译兼容性说明)
- [关键经验教训](#关键经验教训)

---

# Part 1：VMware 嵌套虚拟化卡住问题

## 问题现象

在 VMware Workstation 中运行 VMXToolbox 驱动时，执行 `IOCTL_VMX_INIT` 初始化 Hypervisor 后，**整个虚拟机冻结（hang）**，WinDbg 不再输出任何信息，VMware 窗口完全无响应。

问题经历了多个阶段：

| 阶段 | 现象 | 卡住位置 |
|------|------|---------|
| 初始 | CPU 0 VMLAUNCH 成功，CPU 1 永远等不到 DPC | `KeWaitForSingleObject` 超时 |
| 中期 | CPU 0/1 都 VMLAUNCH 成功，但系统立即冻结 | VMLAUNCH 后无任何日志输出 |
| 最终 | 正常运行 | ✅ 不再卡住 |

---

## 背景：嵌套虚拟化架构

```
┌──────────────────────────────────────────────┐
│                  物理硬件                      │
├──────────────────────────────────────────────┤
│  L0: VMware Workstation (Host Hypervisor)     │
│    ├─ 拦截所有 L1 的 VMXON/VMCS/VMLAUNCH     │
│    ├─ 为 L1 模拟 VMX 指令                     │
│    └─ 每次 L1 的 VM-Exit 都经过 L1→L0→L1     │
├──────────────────────────────────────────────┤
│  L1: VMXToolbox (Our Blue Pill Hypervisor)    │
│    ├─ 使用 VMXON/VMLAUNCH 虚拟化 Guest        │
│    ├─ 处理 VM-Exit（CPUID/MSR/EPT/中断等）     │
│    └─ Guest = 原始 Windows OS（透明接管）      │
├──────────────────────────────────────────────┤
│  L2: Windows Guest (被虚拟化的原始 OS)         │
│    ├─ 不知道自己在 hypervisor 之下              │
│    └─ 正常运行 kernel + user-mode              │
└──────────────────────────────────────────────┘
```

**关键特性**：
- **Blue Pill 架构**：Guest 就是原始运行的 Windows。Hypervisor 在运行时"潜入"并透明接管。
- **嵌套虚拟化代价**：每次 L1 VM-Exit 实际上经历 `L2→L1→L0→L1→L2` 的完整路径，开销是原生的 **100-1000 倍**。
- **must-be-1 bits**：VMware 通过 `IA32_VMX_PROCBASED_CTLS` 等 MSR 强制开启某些控制位（如 `HLT_EXIT`、`UNCONDITIONAL_IO_EXIT`、`EXTERNAL_INT_EXIT` 等），即使 L1 不想拦截这些事件。

---

## 排查历程与迭代

整个排查过程经历了 **5 轮迭代**，从症状修补逐步深入到真正的根因：

### 第 1 轮：禁用高频 VM-Exit 源

**假设**：VM-Exit 风暴导致 VMware L0 过载  
**措施**：
- 禁用 `PROC_BASED_CR3_LOAD_EXIT`（每次进程切换触发 VM-Exit）
- 禁用 `PROC_BASED_MOV_DR_EXIT`（`SwapContext` 中频繁保存/恢复 DR 寄存器）
- Exception Bitmap 设为 0（不拦截任何异常）

**结果**：❌ 仍然卡住。减少了 VM-Exit 数量但没有解决根本问题。

### 第 2 轮：系统性代码审查

**转变**：不再逐个尝试，而是对所有 VM-Exit handler 做全面审查。

**发现了三个根本性 Bug**：
1. External Interrupt handler 丢弃所有中断
2. HLT handler 把 HLT 变成了 NOP（busy-wait）
3. Interrupt Window handler 没注入保存的 pending interrupt

### 第 3 轮：修复中断丢弃 + HLT busy-wait

**措施**：
- External Interrupt handler：将中断向量重新注入 Guest
- HLT handler：执行 `_enable() + __halt()` 让 CPU 在 VMX root mode 中真正 HLT
- Interrupt Window handler：注入 pending interrupt

**结果**：⚡ **CPU 0 和 CPU 1 都成功 VMLAUNCH！** 但系统在 VMLAUNCH 后立即冻结。说明中断修复解决了 IPI 丢失问题（CPU 1 的 DPC 能送达了），但 HLT 修复引入了新的致命 Bug。

### 第 4 轮：分析 HLT handler 的致命问题

**发现**：在 VMX root mode 中执行 `_enable() + __halt()` 会导致中断在 Host stack 上通过 Host IDT 递送——这会破坏 VM-Exit handler 的执行流并可能导致 stack overflow。

**措施**：
- HLT handler 改为设置 `Guest Activity State = HLT`（让硬件在 Guest 模式中 HLT）
- External Interrupt handler 添加 HLT Activity State 唤醒逻辑
- NMI handler 同样添加 HLT Activity State 唤醒逻辑
- 添加 I/O Bitmap 消除 UNCONDITIONAL_IO_EXIT 风暴

### 第 5 轮（最终）：运行正常 ✅

所有修复就位后，VMware 嵌套虚拟化环境下 Hypervisor 正常运行。

---

## 根因 #1：External Interrupt Handler 丢弃所有中断（IPI 丢失）

### 严重程度：🔴 Critical — 直接导致 CPU 间 DPC 无法递送

### 问题分析

当 `PIN_BASED_EXTERNAL_INT_EXIT` 被设置时（VMware must-be-1 强制开启），**所有外部中断**（时钟中断、IPI、设备中断等）都会导致 VM-Exit，中断向量保存在 `VMCS_EXIT_INTERRUPTION_INFO` 中。

**旧代码**：

```c
case EXIT_REASON_EXTERNAL_INT:
    /* 什么都没做，直接 break */
    break;
```

这意味着：
- ⏱️ 时钟中断 → **丢弃** → 调度器无法调度线程
- 📨 IPI（处理器间中断）→ **丢弃** → DPC 无法跨 CPU 派发
- 🔌 设备中断 → **丢弃** → 设备驱动无法响应

### 为什么导致卡住

VMXToolbox 使用**串行 CPU 初始化**：CPU 0 先 VMLAUNCH，成功后主线程在 CPU 0（已在 Guest mode）上排队 CPU 1 的 DPC。

```
主线程（CPU 0，已虚拟化）：
  KeInsertQueueDpc(DPC for CPU 1)
      → 内核发送 IPI 到 CPU 1
      → CPU 1 收到中断 → VM-Exit (EXTERNAL_INT)
      → Handler 丢弃中断 → IPI 丢失！
      → CPU 1 永远不知道有 DPC 等待执行
      → 主线程的 KeWaitForSingleObject 超时
      → VMware 卡住
```

### 修复方案

将中断向量通过 `VMCS_CTRL_VMENTRY_INT_INFO` 重新注入 Guest：

```c
case EXIT_REASON_EXTERNAL_INT:
{
    ULONG64 IntInfo = VmxRead(VMCS_EXIT_INTERRUPTION_INFO);
    if (IntInfo & INTERRUPT_INFO_VALID) {
        ULONG Vector = (ULONG)(IntInfo & INTERRUPT_INFO_VECTOR_MASK);
        ULONG64 GuestRflags = VmxRead(VMCS_GUEST_RFLAGS);
        ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);
        ULONG64 ActivityState = VmxRead(VMCS_GUEST_ACTIVITY_STATE);

        if ((GuestRflags & (1ULL << 9)) &&    /* IF=1 */
            !(Interruptibility & 0x3)) {       /* No STI/MOV SS blocking */
            /* 立即注入 */
            VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                     INTERRUPT_INFO_VALID |
                     (INTERRUPT_TYPE_EXTERNAL << INTERRUPT_INFO_TYPE_SHIFT) |
                     Vector);
        } else {
            /* 延迟注入：保存 pending，启用 interrupt-window exiting */
            CpuContext->PendingInterrupt = TRUE;
            CpuContext->PendingInterruptVector = Vector;

            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased |= PROC_BASED_INT_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

            /* 如果 Guest 在 HLT 状态，必须唤醒 */
            if (ActivityState == 1)
                VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 0);
        }
    }
    break;
}
```

**关键设计点**：
- 当 Guest RFLAGS.IF=1 且无 STI/MOV SS 阻塞时，立即注入
- 当 Guest 不可中断时，保存到 `PendingInterrupt` 并启用 interrupt-window exiting
- 如果 Guest 处于 HLT Activity State，必须重置为 Active，否则 Guest 永远不能执行 STI 来使能中断

---

## 根因 #2：HLT Handler 在 VMX Root Mode 中执行 \_enable() + \_\_halt()

### 严重程度：🔴 Critical — 直接导致系统在 VMLAUNCH 后冻结

### 问题演变

HLT handler 经历了三个版本：

| 版本 | 实现 | 问题 |
|------|------|------|
| V1（原始） | `VmxAdvanceGuestRip(); break;` | HLT 变成 NOP → 空闲 CPU 100% 忙等待 |
| V2（第一次修复） | `_enable(); __halt(); _disable();` | 在 VMX root mode 中接收中断 → 致命 |
| V3（最终修复） | `VmxAdvanceGuestRip(); VmxWrite(ACTIVITY_STATE, 1);` | ✅ 正确 |

### V1 的问题：HLT 变 NOP

```
Guest idle loop:
    HLT
    ↓ VM-Exit (EXIT_REASON_HLT)
    ↓ Handler: AdvanceGuestRip → 跳过 HLT
    ↓ VMRESUME
    ↓ Guest: JMP back to HLT  (idle loop 的循环)
    ↓ HLT
    ↓ VM-Exit...
    ↓ (无限循环，每次都是 L1→L0→L1 完整路径)
```

每个空闲 CPU **每秒数万次 VM-Exit**，在嵌套虚拟化下每次耗费数微秒，累积消耗可以 100% 占满 VMware 的 L0 CPU。

### V2 的问题：VMX Root Mode 中断递送致命

```
┌─────────────────────────────────────────────────────┐
│ VM-Exit Handler (运行在 Host Stack, 16KB)            │
│                                                      │
│   case EXIT_REASON_HLT:                              │
│     _enable();    ← CPU 中断打开（VMX root mode！）    │
│     __halt();     ← CPU 停止等待中断                   │
│       │                                               │
│       │  ←── 中断到来！                                │
│       │                                               │
│   ┌───▼──────────────────────────────────────────┐   │
│   │ 中断通过 Host IDT 递送（= Guest IDT）          │   │
│   │ ISR 运行在 Host Stack 上！                     │   │
│   │                                               │   │
│   │ 问题 1: Host Stack 只有 16KB，ISR 调用链      │   │
│   │         可能导致 stack overflow                 │   │
│   │                                               │   │
│   │ 问题 2: ISR 运行在 VM-Exit handler 的调用     │   │
│   │         栈帧中间，局部变量被覆盖               │   │
│   │                                               │   │
│   │ 问题 3: ISR 中的 KeInsertQueueDpc/调度器      │   │
│   │         代码假设正常的 kernel stack             │   │
│   │                                               │   │
│   │ 问题 4: IRET 回到 __halt() 后面但 stack       │   │
│   │         frame 可能已损坏                       │   │
│   └──────────────────────────────────────────────┘   │
│                                                      │
│     _disable();   ← 可能永远执行不到这里              │
│     break;                                           │
└─────────────────────────────────────────────────────┘
```

**为什么没有任何日志输出**：中断在 VMX root mode 中递送后，ISR 在损坏的栈上执行，系统进入不可恢复状态。WinDbg 的 `DbgPrintEx` 也依赖中断系统正常工作，所以连诊断信息都无法输出。

### V3 最终修复：Guest Activity State = HLT

```c
case EXIT_REASON_HLT:
    VmxAdvanceGuestRip();
    VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 1);  /* 1 = HLT */
    break;
```

**工作原理**：

```
Guest idle loop:
    HLT
    ↓ VM-Exit (EXIT_REASON_HLT)
    ↓ Handler: AdvanceGuestRip, 设置 Activity State = HLT
    ↓ VMRESUME → CPU 在 Guest 模式进入 HLT 状态
    ↓ (CPU 真正停止，零功耗等待)
    ↓
    ↓ 外部中断到来
    ↓ VM-Exit (EXIT_REASON_EXTERNAL_INT)
    ↓ Handler: 注入中断到 Guest
    ↓   → 注入时硬件自动将 Activity State 从 HLT → Active
    ↓ VMRESUME → Guest 唤醒，ISR 在 Guest kernel stack 上正确执行
```

**优势**：
- ✅ CPU 在 **Guest 模式** 中 HLT，中断通过正常的 VM-Exit 路径处理
- ✅ 不涉及 VMX root mode 中断递送的任何风险
- ✅ 真正节能——CPU 硬件 HLT，没有 busy-wait
- ✅ 中断注入时硬件自动唤醒 HLT 状态（Intel SDM Vol. 3C, 26.6.2）

---

## 辅助优化 #3：I/O Bitmap 消除 UNCONDITIONAL\_IO\_EXIT 风暴

### 严重程度：🟡 Medium — 显著减少 VM-Exit 数量

### 问题

VMware 通过 must-be-1 bits 强制开启 `UNCONDITIONAL_IO_EXIT`，导致 **每条 IN/OUT 指令**（包括 PCI 配置、ACPI timer 读取、串口等）都触发 VM-Exit。虽然 I/O handler 能正确处理，但每次 exit 在嵌套虚拟化下耗费数微秒。

### 修复

利用 Intel SDM 的规则：**当 `USE_IO_BITMAPS` 和 `UNCONDITIONAL_IO_EXIT` 同时设置时，I/O Bitmap 优先**。

```c
/* vmx.h — VMX_CPU_CONTEXT 中添加 */
PVOID       IoBitmapAVa;    /* 4KB, 覆盖端口 0x0000-0x7FFF */
ULONG64     IoBitmapAPa;
PVOID       IoBitmapBVa;    /* 4KB, 覆盖端口 0x8000-0xFFFF */
ULONG64     IoBitmapBPa;

/* vmx_init.c — VmxSetupVmcs 中配置 */
RequestedProcBased |= PROC_BASED_USE_IO_BITMAPS;
VmxWrite(VMCS_CTRL_IO_BITMAP_A, CpuCtx->IoBitmapAPa);  /* 全零 = 不触发 exit */
VmxWrite(VMCS_CTRL_IO_BITMAP_B, CpuCtx->IoBitmapBPa);
```

Bitmap 全零 → 没有任何端口触发 VM-Exit → 完全中和了 `UNCONDITIONAL_IO_EXIT`。

---

## 辅助优化 #4：CR3 Load Exit / MOV DR Exit / Exception Bitmap 优化

### 严重程度：🟢 Low — 减少不必要的 VM-Exit

| 优化项 | 原因 | 效果 |
|--------|------|------|
| 禁用 `CR3_LOAD_EXIT` | 每次进程上下文切换（`SwapContext`）都会写 CR3 → VM-Exit | 每秒减少数千次 exit |
| 禁用 `MOV_DR_EXIT` | `SwapContext` 保存/恢复 DR0-DR7 → 每次上下文切换多次 exit | 每秒减少数千次 exit |
| Exception Bitmap 设为 0 | 不需要拦截任何异常（#BP/#DB 在调试功能未启用时无用） | 消除不必要的异常 exit |

这些优化单独不足以解决 hang 问题，但在嵌套虚拟化环境下能显著降低 VM-Exit 总量，改善系统响应性。

---

---

# Part 2：EPT Hook 引擎与驱动框架 Bug

> 以下 Bug 在嵌套虚拟化卡住问题之前修复（2026-04-11），涉及 EPT Hook 引擎的正确性和驱动框架的健壮性。

---

## Bug #A：Trampoline 指令截断导致 #UD → BSOD

### 严重程度：🔴 Critical

### 问题描述

`EptHookFunction()` 在构建 trampoline（跳板）时，需要从目标函数头部"偷"走至少 12 字节（`48 B8 [imm64] FF E0` = MOV RAX, addr; JMP RAX），然后将这些原始字节复制到 trampoline 中，trampoline 末尾再 JMP 回原始函数 +12 的位置。

**原始代码**硬编码复制 14 字节：

```c
// 原始代码（有bug）
Hook->OriginalBytesSize = 14;  // 硬编码
RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, 14);
```

x86-64 指令是**变长的**（1~15 字节），14 字节很可能恰好切断某条指令的中间：

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
   - 单字节操作码：PUSH/POP reg、MOV reg,imm、JMP/CALL rel、ALU 操作等
   - 双字节操作码（0Fh）：Jcc rel32、MOVZX/MOVSX、CMOVcc、SETcc 等
   - 完整的 ModRM + SIB + Displacement 解码

2. **修改 trampoline 构建逻辑**：

```c
// 修复后代码
{
    ULONG TotalLen = 0;
    PUCHAR Code = (PUCHAR)TargetVa;
    while (TotalLen < 12) {
        ULONG InsnLen = EptGetInstructionLength(Code + TotalLen);
        if (InsnLen == 0) {
            LOG_ERROR("EPT Hook: Cannot decode instruction at VA 0x%llX + 0x%X",
                      TargetVa, TotalLen);
            return STATUS_UNSUCCESSFUL;
        }
        TotalLen += InsnLen;
    }
    Hook->OriginalBytesSize = TotalLen;  // 可能是 12, 13, 14, 15...
}
RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, Hook->OriginalBytesSize);
```

3. **追加：OriginalBytes 缓冲区溢出保护**

`OriginalBytes[16]` → `OriginalBytes[32]`（理论最大 TotalLen = 11 + 15 = 26，32 字节提供余量），并在循环中添加越界检查。

4. **同步修复 AMD-V 侧 (`npt.c`)**：`NptHookFunction()` 存在相同问题，已同步修复。

### 涉及文件

| 文件 | 变更 |
|------|------|
| `driver/ept.c` | +`EptGetInstructionLength()`（~300 行）；修改 trampoline 构建逻辑；+越界保护 |
| `driver/ept.h` | +`EptGetInstructionLength` 声明；`OriginalBytes[16]` → `OriginalBytes[32]` |
| `driver/npt.c` | 硬编码 14 字节 → 指令边界对齐 + 越界保护（与 ept.c 一致） |

---

## Bug #B：HandleMtf 多核竞争条件导致无限 EPT Violation 循环

### 严重程度：🔴 Critical

### 问题描述

EPT Hook 引擎使用 **execute-only** 页面实现隐藏 hook：
- 静息状态：hook 页面 `R=0, W=0, X=1`（只能执行，不能读写）
- 数据访问（如 PatchGuard 扫描）：EPT Violation → 切换到原始页面 `R=1, W=1, X=0` → 启用 MTF → 一条指令后 MTF 触发 → 恢复为 hook 页面

**原始 `HandleMtf` 代码**在 MTF 触发时**恢复所有 1024 个 hook**：

```c
// 原始代码（有bug）
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    // 遍历所有 hook，全部恢复
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
            Pte->Read = 0;
            Pte->Write = 0;
            // ...恢复 hook 页面...
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

```c
// 每个 CPU 槽位记录它当前松弛了哪个物理页面
static volatile ULONG64 g_MtfRelaxedPagePa[64] = { 0 };

// HandleEptViolation 中记录当前 CPU 松弛的页面
EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);

// HandleMtf 改为只恢复当前 CPU 松弛的页面
RelaxedPa = EptMtfGetAndClearRelaxedPage();
for (i = 0; i < MAX_EPT_HOOKS; i++) {
    if (RelaxedPa != 0 &&
        g_EptHookState.Hooks[i].TargetPhysicalAddr != RelaxedPa) {
        continue;  // ★ 跳过不是当前 CPU 松弛的页面
    }
    // ...恢复 hook...
}
```

**安全兜底**：如果 `RelaxedPa == 0`（理论上不会发生），回退到恢复所有 hook。

### 涉及文件

| 文件 | 变更 |
|------|------|
| `driver/ept.c` | +`g_MtfRelaxedPagePa[64]`；+`EptMtfTrackRelaxedPage()`；+`EptMtfGetAndClearRelaxedPage()` |
| `driver/ept.h` | +上述两个函数的声明 |
| `driver/vmx_exit.c` | `HandleMtf` 改为查询 per-CPU 跟踪数组，只恢复特定页面 |

---

## Bug #C：EptSplitLargePage 后缺少 INVEPT 导致 EPT Misconfiguration

### 严重程度：🔴 Critical

### 问题描述

`EptHookFunction()` 在安装 hook 前需要将 2MB 大页拆分为 512 个 4KB 页。**原始代码**在拆分后没有刷新 EPT TLB：

```c
// 原始代码（有bug）
EptSplitLargePage(TargetPa);
// ← 缺少 INVEPT！
Pte = EptGetPteForPhysicalAddress(TargetPa);
```

**后果**：

```
CPU 0:  执行 EptSplitLargePage()
        → 修改 PDE: 2MB 大页条目 → 指向新的 4KB 页表
        
CPU 1-N: TLB 中仍然缓存着旧的 2MB PDE
        → 下一次内存访问时，CPU 用旧的 2MB PDE 格式解释新数据
        → PDE 格式不匹配新的 PT → EPT Misconfiguration
        → VMX shutdown → BSOD
```

EPT Misconfiguration（页表结构错误）不可恢复，直接导致 VMX 关闭。

### 修复方案

在 `EptSplitLargePage()` 调用后**立即**执行 `EptInvalidateFromGuest()`：

```c
EptSplitLargePage(TargetPa);
EptInvalidateFromGuest();  // ← 新增：刷新所有 CPU 的 EPT TLB
Pte = EptGetPteForPhysicalAddress(TargetPa);
```

> `EptInvalidateFromGuest()` 使用 generation counter 机制（`InterlockedIncrement`），每个 CPU 在下一次 VM-Exit 时检查并执行 INVEPT。

### 涉及文件

| 文件 | 变更 |
|------|------|
| `driver/ept.c` | `EptHookFunction()` 中 `EptSplitLargePage()` 后添加 `EptInvalidateFromGuest()` |

---

## Bug #D：IOCTL 分发中 IoStatus.Information 未初始化

### 严重程度：🟡 Medium

### 问题描述

`DispatchDeviceControl` 在 `METHOD_BUFFERED` 模式下处理 IOCTL 请求。`Irp->IoStatus.Information` 告诉 I/O 管理器应复制多少字节回用户态。

**原始代码**没有在分发前初始化该字段：

```c
// 原始代码（有bug）
IoStack = IoGetCurrentIrpStackLocation(Irp);
IoControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;
// ← 没有初始化 Irp->IoStatus.Information

switch (IoControlCode) {
    case IOCTL_VMX_INIT:
        Status = HandleIoctlInit(Irp, IoStack);
        break;
    default:
        Status = STATUS_INVALID_DEVICE_REQUEST;
        break;  // ← Information 保持未初始化的脏值！
}
```

**问题**：
- 失败路径或 `default` 分支中 `Information` 保持未初始化的脏值
- I/O 管理器根据脏值复制数据 → **内核信息泄露** 或 **越界复制 → BSOD**

### 修复方案

```c
Irp->IoStatus.Information = 0;  // ← 在 switch 前统一初始化

switch (IoControlCode) {
    // ...
}
```

### 涉及文件

| 文件 | 变更 |
|------|------|
| `driver/vmxdrv.c` | `DispatchDeviceControl` 中 switch 前添加 `Irp->IoStatus.Information = 0` |

---

# 总览

## 全部修复方案汇总

### Part 1：嵌套虚拟化卡住问题

| # | 修复 | 解决的问题 | 影响 |
|---|------|-----------|------|
| 1 | External Interrupt 重注入 | IPI 丢失 → CPU 间 DPC 无法递送 | 🔴 主因：CPU 1 初始化卡住 |
| 2 | HLT → Guest Activity State | VMX root mode 中断递送 → 系统崩溃 | 🔴 主因：VMLAUNCH 后系统冻结 |
| 3 | Interrupt Window 注入 pending 中断 | 延迟中断无法递送 | 🟠 配合修复 #1 |
| 4 | NMI handler HLT 唤醒 | NMI 无法唤醒 HLT 状态 Guest | 🟠 配合修复 #2 |
| 5 | I/O Bitmap 全零 | UNCONDITIONAL_IO_EXIT 风暴 | 🟡 性能优化 |
| 6 | 禁用 CR3 Load Exit | 上下文切换 VM-Exit 风暴 | 🟢 性能优化 |
| 7 | 禁用 MOV DR Exit | DR 访问 VM-Exit 风暴 | 🟢 性能优化 |
| 8 | Exception Bitmap = 0 | 不必要的异常拦截 | 🟢 性能优化 |

**因果链**：

```
修复 #1（中断重注入）解决了：
  IPI 不再丢失 → DPC 正确派发 → CPU 1 能收到初始化 DPC → VMLAUNCH 成功

修复 #2（HLT Activity State）解决了：
  不再在 VMX root mode 递送中断 → Host stack 不被破坏 →
  VM-Exit handler 正常运行 → 中断正确注入回 Guest →
  调度器/定时器/设备驱动正常工作 → 系统不再冻结
```

### Part 2：EPT Hook 引擎与驱动框架 Bug

| # | 修复 | 解决的问题 | 影响 |
|---|------|-----------|------|
| A | Trampoline 指令边界对齐 | 截断指令 → #UD → BSOD | 🔴 hook 时必现崩溃 |
| B | HandleMtf per-CPU 跟踪 | 多核 MTF 竞争 → 无限 EPT Violation 循环 | 🔴 多核 hook 时死锁 |
| C | EptSplitLargePage 后 INVEPT | 过时 TLB → EPT Misconfiguration → BSOD | 🔴 首次 hook 时概率崩溃 |
| D | IoStatus.Information 初始化 | 脏值 → 信息泄露或越界复制 | 🟡 IOCTL 失败时触发 |

---

## 完整修改文件清单

| 文件 | 来源 | 修改内容 |
|------|------|---------|
| `driver/vmx.h` | Part 1 | `VMX_CPU_CONTEXT` 添加 `IoBitmapAVa/Pa`、`IoBitmapBVa/Pa` 字段 |
| `driver/vmx_init.c` | Part 1 | `VmxAllocateCpuContext()`: 分配 I/O Bitmap A/B（各 4KB，全零） |
| `driver/vmx_init.c` | Part 1 | `VmxFreeCpuContext()`: 释放 I/O Bitmap A/B |
| `driver/vmx_init.c` | Part 1 | `VmxSetupVmcs()`: 添加 `PROC_BASED_USE_IO_BITMAPS`，写入 I/O Bitmap 物理地址 |
| `driver/vmx_init.c` | Part 1 | `VmxSetupVmcs()`: 禁用 `CR3_LOAD_EXIT`、`MOV_DR_EXIT`，Exception Bitmap=0 |
| `driver/vmx_init.c` | Part 1 | `VmxInitialize()` 循环后添加直接 `DbgPrintEx` 诊断输出 |
| `driver/vmx_exit.c` | Part 1 | `EXIT_REASON_HLT`: V1(NOP)→V2(`__halt()`)→V3(Activity State=HLT) |
| `driver/vmx_exit.c` | Part 1 | `EXIT_REASON_EXTERNAL_INT`: 丢弃→重注入，含 HLT 唤醒逻辑 |
| `driver/vmx_exit.c` | Part 1 | `EXIT_REASON_INT_WINDOW`: 添加 pending interrupt 注入 |
| `driver/vmx_exit.c` | Part 1 | NMI handler: 延迟路径添加 HLT Activity State 唤醒 |
| `driver/vmx_exit.c` | Part 2 | `HandleMtf` 改为 per-CPU 跟踪，只恢复当前 CPU 松弛的页面 |
| `driver/ept.c` | Part 2 | +`EptGetInstructionLength()`（~300 行 x64 指令解码器） |
| `driver/ept.c` | Part 2 | 修改 trampoline 构建逻辑：硬编码 14 字节 → 指令边界对齐 ≥12 字节 |
| `driver/ept.c` | Part 2 | +`g_MtfRelaxedPagePa[64]` per-CPU 跟踪数组及辅助函数 |
| `driver/ept.c` | Part 2 | `HandleEptViolation` 两条路径添加 `EptMtfTrackRelaxedPage` 调用 |
| `driver/ept.c` | Part 2 | `EptHookFunction()` 中 `EptSplitLargePage()` 后添加 `EptInvalidateFromGuest()` |
| `driver/ept.h` | Part 2 | +`EptGetInstructionLength` 声明；`OriginalBytes[16]` → `OriginalBytes[32]` |
| `driver/ept.h` | Part 2 | +`EptMtfTrackRelaxedPage` 和 `EptMtfGetAndClearRelaxedPage` 声明 |
| `driver/npt.c` | Part 2 | 硬编码 14 字节 → 指令边界对齐 + 越界保护（与 ept.c 一致） |
| `driver/vmxdrv.c` | Part 2 | `DispatchDeviceControl` 中 switch 前添加 `Irp->IoStatus.Information = 0` |

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
    UCHAR   b, Op2, Group, SubOp, SIB, SibBase, EffRM;
    // ...函数体...
}
```

所有其他修改（per-CPU 数组、I/O Bitmap、中断注入等）都不涉及 C89 兼容性问题。

---

## 关键经验教训

### 1. Blue Pill Hypervisor 中的中断处理是核心中的核心

在 Blue Pill 架构下，Guest 就是原始 OS。**所有中断都必须正确递送回 Guest**，包括：
- 时钟中断（调度器依赖）
- IPI（多 CPU 通信依赖）
- 设备中断（驱动依赖）
- NMI（系统检查依赖）

任何一类中断被丢弃，都会导致系统功能异常或完全冻结。

### 2. VMX Root Mode 中不要递送中断

VMX root mode 运行在专用的 Host stack（通常很小）上，通过 Host IDT 递送中断会导致：
- ISR 在错误的栈上执行
- 可能的 stack overflow
- VM-Exit handler 执行流被破坏
- 不可恢复的系统状态

正确的做法是利用 Intel VT-x 提供的硬件机制（VM-Entry injection、Activity State、interrupt-window exiting）在 **Guest 模式** 中递送中断。

### 3. 嵌套虚拟化环境下的 must-be-1 bits 必须全面处理

VMware 通过 `IA32_VMX_PROCBASED_CTLS` 等 MSR 强制开启的控制位不是可选的——它们**必须被正确处理**。对于每个 forced-on 的 VM-Exit 源，handler 必须有正确的实现，否则就是一颗定时炸弹。

### 4. 多核环境下的 EPT 操作需要精确的同步

EPT 页表是所有 CPU 共享的全局结构：
- **页表修改后必须 INVEPT**：否则其他 CPU 的 TLB 中有过时条目 → EPT Misconfiguration
- **MTF 恢复必须 per-CPU 隔离**：否则一个 CPU 的 MTF 会破坏另一个 CPU 正在进行的 EPT 权限切换
- **指令边界必须精确计算**：x86-64 变长指令意味着不能硬编码字节数

### 5. 逐症修补 vs 系统性审查

前几轮的"禁用 CR3 Exit"、"禁用 DR Exit"等修改是**症状缓解**，没有触及根因。真正解决问题需要：
1. 列出所有 VM-Exit 类型及其 handler
2. 逐一验证每个 handler 的正确性
3. 特别关注中断/异常处理路径（最容易出错也影响最大）
4. 特别关注多核竞争路径（单核测试无法复现）

### 6. 日志系统也可能是受害者

当中断处理有问题时，日志 flush thread（依赖调度器中断）可能无法运行。**在关键路径上添加直接 `DbgPrintEx` 调用**（绕过 ring buffer）对调试至关重要。

### 7. 防御性编程：初始化所有输出字段

IOCTL handler 的 `IoStatus.Information` 未初始化看似小问题，但在失败路径上可能导致内核信息泄露或蓝屏。**所有输出字段在分发前应统一初始化为安全值（0）**。

---

## 待确认事项

1. **Bug #A - 指令解码器覆盖范围**：当前解码器覆盖了内核函数前缀的绝大多数常见指令。如果目标函数使用了极其罕见的前缀指令（如 SSE/AVX 等），解码器会返回 0 并安全地拒绝安装 hook。是否需要扩展覆盖范围？

2. **Bug #B - per-CPU 数组大小**：当前硬编码为 64 个处理器槽位。如果系统有超过 64 个逻辑处理器（如大型服务器），超出范围的 CPU 将无法被跟踪（回退到恢复全部 hook）。是否需要动态分配或增大上限？

3. **Bug #C - INVEPT 时机**：当前使用 generation counter + lazy INVEPT 机制。理论上在 `EptSplitLargePage` 到下一次 VM-Exit 之间存在一个很小的时间窗口。是否需要更激进的同步机制（如 IPI）？

---

*文档结束。*
