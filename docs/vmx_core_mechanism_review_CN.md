简体中文 | [English](vmx_core_mechanism_review.md)

# VMX 核心执行机制审查报告

> **日期**：2026-04-11  
> **审查范围**：VMX 裸机虚拟化引擎（不含 EPT Hook 逻辑）  
> **涉及文件**：`vmx_init.c`, `vmx_exit.c`, `vmx_asm.asm`, `vmx.h`, `vmxdrv.c`, `msr.c`, `hv_detect.c`  
> **状态**：✅ 已修复

---

## 目录

- [一、架构概述](#一架构概述)
- [二、发现的问题](#二发现的问题)
  - [问题 A：VmxOpsGetCurrentCpuContext 使用 static 局部变量（非线程安全）](#问题-avmxopsgetcurrentcpucontext-使用-static-局部变量非线程安全)
  - [问题 B：HandleCrAccess 对 MOV to CR0 写了 ReadShadow 但值不正确](#问题-bhandlecraccess-对-mov-to-cr0-写了-readshadow-但值不正确)
  - [问题 C：外部中断处理缺少 Interruptibility State 检查](#问题-c外部中断处理缺少-interruptibility-state-检查)
  - [问题 D：HandleRdtscp 存在 RIP 双重推进风险](#问题-dhandlerdtscp-存在-rip-双重推进风险)
  - [问题 E：DPC 初始化上下文存在栈生命周期风险](#问题-edpc-初始化上下文存在栈生命周期风险)
  - [问题 F：HandleException 中 NMI 重注入缺少 NMI-window 控制](#问题-fhandleexception-中-nmi-重注入缺少-nmi-window-控制)
  - [问题 G：LMSW 处理未应用 CR0 固定位](#问题-glmsw-处理未应用-cr0-固定位)
  - [问题 H：VmxShutdown 路径 RFLAGS 未恢复](#问题-hvmxshutdown-路径-rflags-未恢复)
- [三、代码质量观察（非 Bug，但值得注意）](#三代码质量观察非-bug但值得注意)
- [四、整体评估](#四整体评估)
- [五、修改文件汇总](#五修改文件汇总)

---

## 一、架构概述

整体 VMX 引擎采用经典的 Blue Pill 架构：

```
DriverEntry (vmxdrv.c)
  → VmxInitialize (vmx_init.c)
    → VmxCheckCapabilities()        读取 MSR 能力
    → EptInitialize()               全局 EPT 初始化
    → for each CPU:
        DPC → VmxInitDpcRoutine()
          → VmxEnableOnCpu()        CR4.VMXE + VMXON
          → VmxSetupVmcs()          写入 VMCS 所有字段
          → AsmVmxLaunch()          VMLAUNCH 进入 Guest
            (CPU 现在运行在 VMX non-root)

VM-Exit → AsmVmxExitHandler (vmx_asm.asm)
  → save GP regs → call VmxExitHandler (vmx_exit.c)
    → dispatch by exit reason
    → return TRUE → vmresume
    → return FALSE → VmxShutdown → vmxoff → ret to guest

VmxTerminate (vmx_init.c)
  → for each CPU:
      DPC → VmxTerminateDpcRoutine()
        → VMCALL(VMCALL_MAGIC_SHUTDOWN) → vmxoff
  → EptCleanup()
  → free per-CPU resources
```

**总体代码质量**：非常好。VMCS 字段设置完整，GDT 解析正确，True Controls 路径正确，Enlightened VMCS 嵌套模式支持完整。以下是审查中发现的问题。

---

## 二、发现的问题

---

### 问题 A：VmxOpsGetCurrentCpuContext 使用 static 局部变量（非线程安全）

**严重程度**：🟡 Medium → ✅ 已修复

**位置**：`vmx_init.c` — `VmxOpsGetCurrentCpuContext()`

**问题描述**：

```c
static PHV_CPU_CONTEXT VmxOpsGetCurrentCpuContext(VOID)
{
    static HV_CPU_CONTEXT VmxHvCtx;  // ← 全局唯一的 static 变量！
    ULONG Cpu = KeGetCurrentProcessorNumber();
    if (Cpu < MAX_PROCESSORS) {
        VmxHvCtx.ProcessorNumber = g_VmxState.CpuContexts[Cpu].ProcessorNumber;
        VmxHvCtx.HvEnabled = g_VmxState.CpuContexts[Cpu].VmxEnabled;
        // ...填充其他字段...
    }
    return &VmxHvCtx;
}
```

`VmxHvCtx` 是 `static` 局部变量——**全局唯一**。如果两个 CPU 同时（或近乎同时）调用这个函数，CPU 0 填充了自己的数据后返回指针，CPU 1 在 CPU 0 使用这个指针之前又覆盖了 `VmxHvCtx` 的内容 → **CPU 0 读到的是 CPU 1 的数据**。

虽然在 VMX root mode（VM-Exit handler）中，中断被禁止，单个 CPU 上不会被抢占，但**不同 CPU 可以同时进入 VM-Exit handler**，所以这个 race condition 是真实的。

**影响分析**：需要看 `GetCurrentCpuContext` 的调用方。如果调用方只是短暂读取返回值然后丢弃（不保存指针跨越可能被中断的代码段），问题可能不会 manifest。但这是一个**潜在定时炸弹**。

#### ✅ 修复方案

**修改文件**：`vmx_init.c`

将单一 `static HV_CPU_CONTEXT` 改为 `static HV_CPU_CONTEXT[MAX_PROCESSORS]` per-CPU 数组，每个 CPU 使用自己的槽位，彻底消除竞态条件：

```c
static PHV_CPU_CONTEXT VmxOpsGetCurrentCpuContext(VOID)
{
    static HV_CPU_CONTEXT VmxHvCtx[MAX_PROCESSORS];
    ULONG Cpu = KeGetCurrentProcessorNumber();
    if (Cpu < MAX_PROCESSORS) {
        VmxHvCtx[Cpu].ProcessorNumber = g_VmxState.CpuContexts[Cpu].ProcessorNumber;
        VmxHvCtx[Cpu].HvEnabled = g_VmxState.CpuContexts[Cpu].VmxEnabled;
        VmxHvCtx[Cpu].GuestLaunched = g_VmxState.CpuContexts[Cpu].VmcsLaunched;
        VmxHvCtx[Cpu].TscOffset = g_VmxState.CpuContexts[Cpu].TscOffset;
        VmxHvCtx[Cpu].LastDebugPauseTsc = g_VmxState.CpuContexts[Cpu].LastDebugPauseTsc;
        VmxHvCtx[Cpu].InDebugPause = g_VmxState.CpuContexts[Cpu].InDebugPause;
        VmxHvCtx[Cpu].ExitCount = g_VmxState.CpuContexts[Cpu].ExitCount;
        return &VmxHvCtx[Cpu];
    }
    return NULL;
}
```

**关键变化**：
- `static HV_CPU_CONTEXT VmxHvCtx` → `static HV_CPU_CONTEXT VmxHvCtx[MAX_PROCESSORS]`
- 所有字段访问改为 `VmxHvCtx[Cpu].xxx`
- `Cpu >= MAX_PROCESSORS` 时返回 `NULL` 而非未初始化的数据

---

### 问题 B：HandleCrAccess 对 MOV to CR0 写了 ReadShadow 但值不正确

**严重程度**：🟡 Medium → ✅ 已修复

**位置**：`vmx_exit.c` — `HandleCrAccess()` 中 `CR_ACCESS_TYPE_MOV_TO_CR, CrNum == 0`

**问题描述**：

`HandleCrAccess` 对 `MOV to CR0` 正确地应用了 VMX 固定位（`VMX_CR0_FIXED0` / `FIXED1`），但把 **adjust 后的值** 写入了 ReadShadow：

```c
if (CrNum == 0) {
    NewValue |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);  // ✅ 正确
    NewValue &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    VmxWrite(VMCS_GUEST_CR0, NewValue);
    VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, NewValue);    // ← BUG: 应为原始值
}
```

Intel SDM 建议：**Read Shadow 应该保存 Guest 期望看到的值**（即 Guest 写入的原始值），而 **实际 Guest CR0 字段** 保存的是 adjust 后的值。这样 Guest 的 `MOV from CR0` 读回的是它自己写的值（不含 VMX 强制位），实现透明虚拟化。

**注意**：由于当前 `CR0_GUEST_HOST_MASK = 0`（不拦截 CR0），这段代码当前不会执行。这是**潜在 bug**，在修改 guest/host mask 后会触发。

#### ✅ 修复方案

**修改文件**：`vmx_exit.c`

在应用固定位之前先保存 Guest 原始值，将原始值写入 ReadShadow：

```c
else if (CrNum == 0) {
    ULONG64 ShadowValue = NewValue;             /* 保存 Guest 原始值 */
    NewValue |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    NewValue &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    VmxWrite(VMCS_GUEST_CR0, NewValue);
    VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, ShadowValue);  /* shadow = 原始值 */
}
```

**同时更新**：`vmx_init.c` 的 `VmxSetupVmcs()` 中初始 ReadShadow 添加了说明注释（由于初始时 Cr0 已经含 VMX 固定位，值相同，但添加注释保持一致性）。

---

### 问题 C：外部中断处理缺少 Interruptibility State 检查

**严重程度**：🔴 High → ✅ 已修复

**位置**：`vmx_exit.c` — `EXIT_REASON_EXTERNAL_INT` 处理

**问题描述**：

`EXIT_REASON_EXTERNAL_INT` 处理代码在注入中断前只检查了 `RFLAGS.IF`：

```c
ULONG64 GuestRflags = VmxRead(VMCS_GUEST_RFLAGS);
if (GuestRflags & (1ULL << 9)) {
    // IF=1: inject immediately
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, ...);
}
```

但 Intel SDM Vol. 3C, Section 26.3.1.5 规定，VM-Entry 注入外部中断的前提条件不仅仅是 `RFLAGS.IF=1`，还包括：

- **Guest Interruptibility State** 的以下位必须为 0：
  - Bit 0：Blocking by STI（`STI` 指令后的一条指令窗口）
  - Bit 1：Blocking by MOV SS（`MOV SS` 后的一条指令窗口）

**触发场景**：

```asm
; Guest 代码
cli             ; IF=0
; ...某些操作...
sti             ; IF=1, 但接下来一条指令期间 "blocking by STI" = 1
nop             ; ← 如果恰好在这里 VM-Exit 了
```

VM-Exit 时 `RFLAGS.IF=1` 但 `Interruptibility.BlockingBySTI=1` → 直接注入中断 → VM-Entry failure → BSOD。

#### ✅ 修复方案

**修改文件**：`vmx_exit.c`

注入前同时检查 `RFLAGS.IF` 和 `VMCS_GUEST_INTERRUPTIBILITY` 的 blocking 位（bit 0 和 bit 1）：

```c
ULONG64 GuestRflags = VmxRead(VMCS_GUEST_RFLAGS);
ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);

if ((GuestRflags & (1ULL << 9)) && !(Interruptibility & 0x3)) {
    /* IF=1 and not blocked by STI/MOV SS: safe to inject */
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, ...);
} else {
    /* IF=0 or blocked: defer to interrupt window */
    // ...save pending + request INT_WINDOW_EXIT...
}
```

**关键变化**：注入条件从 `if (GuestRflags & IF_BIT)` 改为 `if ((GuestRflags & IF_BIT) && !(Interruptibility & 0x3))`，不满足条件时走延迟注入路径。

---

### 问题 D：HandleRdtscp 存在 RIP 双重推进风险

**严重程度**：🟢 Low → ✅ 已处理（添加防御性文档）

**位置**：`vmx_exit.c` — `HandleRdtscp()`

**问题描述**：

```c
static BOOLEAN HandleRdtscp(PGUEST_CONTEXT Ctx)
{
    AadHandleRdtsc(Ctx);               // ← 内部调用 HvAdvanceGuestRip()
    Ctx->Rcx = __readmsr(MSR_IA32_TSC_AUX) & 0xFFFFFFFF;
    /* Note: AadHandleRdtsc already advanced RIP */
    return TRUE;
}
```

存在**隐性耦合风险**：
- 若 `AadHandleRdtsc` 被修改为不推进 RIP → Guest 无限循环
- 若有人在此函数末尾误加 `VmxAdvanceGuestRip()` → 双重推进 → 跳过指令 → 崩溃

#### ✅ 修复方案

**修改文件**：`vmx_exit.c`

在 `HandleRdtscp` 中添加详细的防御性注释块，明确标注 `AadHandleRdtsc` 内部已推进 RIP 的设计契约，以及如果未来重构时需要注意的事项：

```c
static BOOLEAN HandleRdtscp(PGUEST_CONTEXT Ctx)
{
    /*
     * BUG FIX (Problem D): Document the implicit coupling.
     * AadHandleRdtsc() internally calls HvAdvanceGuestRip().
     * Do NOT add another VmxAdvanceGuestRip() here.
     * If AadHandleRdtsc is refactored to NOT advance RIP,
     * a VmxAdvanceGuestRip() call MUST be added here.
     */
    AadHandleRdtsc(Ctx);
    Ctx->Rcx = __readmsr(MSR_IA32_TSC_AUX) & 0xFFFFFFFF;
    return TRUE;
}
```

---

### 问题 E：DPC 初始化上下文存在栈生命周期风险

**严重程度**：🟢 Low → ✅ 已处理（添加安全注释）

**位置**：`vmx_init.c` — `VmxInitialize()` DPC 循环

**问题描述**：

```c
for (i = 0; i < CpuCount; i++) {
    KDPC            Dpc;
    VMX_DPC_CONTEXT DpcCtx;       // ← 栈上分配
    // ...
    KeWaitForSingleObject(&DpcCtx.Event, ...);  // ← 阻塞等待保证安全
}
```

当前代码是正确的（`KeWaitForSingleObject` 保证了栈对象的生命周期）。但这种模式很脆弱：如果未来有人移除 wait 或改为并行，栈变量可能在 DPC 执行前被覆盖 → BSOD。

#### ✅ 修复方案

**修改文件**：`vmx_init.c`

在 DPC 循环前添加醒目的安全注释块，明确说明：
1. `Dpc` 和 `DpcCtx` 必须保持有效直到 `KeSetEvent` 被调用
2. 绝对不能移除或延迟 `KeWaitForSingleObject`
3. 如果需要并行启动，必须从 NonPagedPool 分配

---

### 问题 F：HandleException 中 NMI 重注入缺少 NMI-window 控制

**严重程度**：🟡 Medium → ✅ 已修复

**位置**：`vmx_exit.c` — `HandleException()` NMI 分支

**问题描述**：

```c
if (IntType == INTERRUPT_TYPE_NMI) {
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
             INTERRUPT_INFO_VALID |
             (INTERRUPT_TYPE_NMI << INTERRUPT_INFO_TYPE_SHIFT) |
             2);
    return TRUE;
}
```

直接重注入 NMI 而不检查 "blocking by NMI" 位。如果某些 CPU 通过 `VmxAdjustControls` 的 must-be-1 位强制启用了 `VIRTUAL_NMIS`，NMI blocking 可能未被自动清除，导致 VM-Entry 失败。

#### ✅ 修复方案

**修改文件**：`vmx_exit.c`

1. NMI 注入前检查 `VMCS_GUEST_INTERRUPTIBILITY` 的 bit 3（blocking by NMI）
2. 如果被阻塞，设置 `PROC_BASED_NMI_WINDOW_EXIT` 延迟注入
3. 新增 `EXIT_REASON_NMI_WINDOW` 分支处理：清除 NMI-window exiting 位并注入 NMI

```c
if (IntType == INTERRUPT_TYPE_NMI) {
    ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);

    if (!(Interruptibility & (1ULL << 3))) {
        /* Not blocked: inject immediately */
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, ...);
    } else {
        /* Blocked: request NMI-window exiting */
        ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
        ProcBased |= PROC_BASED_NMI_WINDOW_EXIT;
        VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
    }
    return TRUE;
}
```

**新增处理分支**：

```c
case EXIT_REASON_NMI_WINDOW:
    /* Clear NMI-window exiting and inject deferred NMI */
    ProcBased &= ~PROC_BASED_NMI_WINDOW_EXIT;
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, NMI_INFO);
    break;
```

---

### 问题 G：LMSW 处理未应用 CR0 固定位

**严重程度**：🟡 Medium → ✅ 已修复

**位置**：`vmx_exit.c` — `HandleCrAccess()` 中 `CR_ACCESS_TYPE_LMSW`

**问题描述**：

```c
case CR_ACCESS_TYPE_LMSW:
    {
        ULONG64 Cr0 = VmxRead(VMCS_GUEST_CR0);
        USHORT  Msw = (USHORT)(ExitQual >> 16);
        Cr0 = (Cr0 & ~0xFFFFULL) | Msw;
        Cr0 |= CR0_PE;
        VmxWrite(VMCS_GUEST_CR0, Cr0);  // ← 未应用固定位
    }
```

VMX 要求 Guest CR0 的某些位必须为 1/0。如果 LMSW 指令改变了受限位（如清除 NE），下次 VM-Entry 会失败。

**注意**：由于当前 `CR0_GUEST_HOST_MASK = 0`，LMSW 不会触发 VM-Exit。但修改 mask 后这是真实 bug。

#### ✅ 修复方案

**修改文件**：`vmx_exit.c`

在 LMSW 处理末尾、写入 Guest CR0 之前，应用 VMX 固定位：

```c
case CR_ACCESS_TYPE_LMSW:
    {
        ULONG64 Cr0 = VmxRead(VMCS_GUEST_CR0);
        USHORT  Msw = (USHORT)(ExitQual >> 16);
        Cr0 = (Cr0 & ~0xFFFFULL) | Msw;
        Cr0 |= CR0_PE;
        /* Apply VMX fixed bits (Problem G fix) */
        Cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
        Cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
        VmxWrite(VMCS_GUEST_CR0, Cr0);
    }
    break;
```

---

### 问题 H：VmxShutdown 路径 RFLAGS 未恢复

**严重程度**：🟢 Low → ✅ 已修复

**位置**：`vmx_asm.asm` — `VmxShutdown` 标签

**问题描述**：

`VmxShutdown` 在执行 `vmxoff` 后恢复了所有 GP 寄存器（RAX~R15），但**没有恢复 Guest RFLAGS**。`vmxoff` 后 RFLAGS 是 Host 上下文的值而非 Guest 的值。

**影响分析**：实际影响较小（后续 C 代码会覆盖大部分标志位），但 TF（Trap Flag）等特殊标志不会被正确恢复。

#### ✅ 修复方案

**修改文件**：`vmx_asm.asm`

1. 新增 `VMCS_GUEST_RFLAGS_ENCODING EQU 06820h` 常量
2. 在 `vmxoff` 之前通过 `vmread` 读取 Guest RFLAGS
3. 将 Guest RFLAGS 压入 Guest 栈
4. 恢复 GP 寄存器后，通过 `popfq` 恢复 RFLAGS
5. 最后 `ret` 跳转到 Guest RIP

```asm
VmxShutdown:
    ; 1. vmread Guest RSP, RIP, RFLAGS
    mov     rcx, VMCS_GUEST_RSP_ENCODING
    vmread  rdx, rcx            ; rdx = Guest RSP
    mov     rcx, VMCS_GUEST_RIP_ENCODING
    vmread  rax, rcx            ; rax = Guest RIP
    mov     rcx, VMCS_GUEST_RFLAGS_ENCODING
    vmread  rcx, rcx            ; rcx = Guest RFLAGS

    ; 2. Push Guest RIP onto Guest stack
    sub     rdx, 8
    mov     [rdx], rax

    ; 3. Push Guest RFLAGS onto Guest stack
    sub     rdx, 8
    mov     [rdx], rcx
    mov     [rsp + 020h], rdx   ; save adjusted Guest RSP

    ; 4. vmxoff
    vmxoff

    ; 5. Restore GP registers
    mov     rax, [rsp + 000h]
    ; ...restore all 15 registers...
    mov     r15, [rsp + 078h]

    ; 6. Switch to Guest stack, restore RFLAGS, ret to Guest RIP
    mov     rsp, [rsp + 020h]
    popfq                       ; restore Guest RFLAGS
    ret                         ; pop Guest RIP, resume
```

**Guest 栈布局**（从高到低）：
```
[Guest RSP - 8]  = Guest RIP   (由 ret 弹出)
[Guest RSP - 16] = Guest RFLAGS (由 popfq 弹出)
```

---

## 三、代码质量观察（非 Bug，但值得注意）

### 1. IA32_FEATURE_CONTROL 未锁定时的处理

**位置**：`vmx_init.c` 第 62-68 行 / `hv_detect.c` 第 81-83 行

当 `IA32_FEATURE_CONTROL` MSR 未锁定时（bit 0 = 0），代码只是打了一个 warning 然后继续。根据 Intel SDM，在某些情况下 `VMXON` 会失败如果 MSR 未锁定。建议至少尝试写入 MSR 来锁定它（设置 bit 0 和 bit 2）：

```c
if (!(FeatureControl & FEATURE_CONTROL_LOCKED)) {
    __writemsr(MSR_IA32_FEATURE_CONTROL,
               FeatureControl | FEATURE_CONTROL_LOCKED | FEATURE_CONTROL_VMXON_ENABLED);
}
```

### 2. MSR bitmap 只拦截了 IA32_DEBUGCTL

**位置**：`msr.c` 第 63-77 行

当前只拦截了 `MSR_IA32_DEBUGCTL` 的读写。如果未来需要拦截更多 MSR（如 `IA32_EFER`、`IA32_KERNEL_GS_BASE` 等），需要在 `MsrBitmapInitialize` 中添加。目前的设计是清晰的（bitmap 默认全 0 = 全部直通），但建议在代码注释中说明这个设计决策。

### 3. Host Stack 16KB 可能不足

**位置**：`vmx_init.c` 第 203-204 行

```c
CpuCtx->HostStackSize = 4 * PAGE_SIZE_4KB;  // 16KB
```

VM-Exit handler 会在 Host Stack 上运行，包括调用 `VmxExitHandler` 以及它调用的所有子函数（EPT violation handler、anti-anti-debug、logging 等）。如果调用链很深，16KB 可能不够（Windows 内核默认线程栈是 12KB-24KB，DPC 共享 16KB）。如果遇到栈溢出，表现为随机内存损坏，极难调试。

建议考虑增大到 32KB（`8 * PAGE_SIZE_4KB`），或者在 Host Stack 底部放置 guard page。

### 4. VmxIsSupported 和 HvCheckVmxSupport 功能重复

**位置**：`vmx_init.c` 第 42-71 行 / `hv_detect.c` 第 61-87 行

这两个函数做了几乎相同的事情。`VmxIsSupported` 在 `vmx_init.c` 中定义但实际上被 `g_VmxOps.IsSupported` 指向，而 `HvCheckVmxSupport` 在 `hv_detect.c` 中定义被 `DriverEntry` 调用。建议统一为一个函数。

### 5. XSETBV 处理未做 XCR0 合法性检查 → ✅ 已修复

**位置**：`vmx_exit.c` — `HandleXsetbv()`

**原始问题**：代码直接将 Guest 请求的 XCR0 值写入物理 XCR0，没有做合法性检查。如果 Guest 写入非法的 XCR0 组合（例如设置 AVX 位但不设置 SSE 位），`XSETBV` 会触发 `#GP`，但这发生在 Host 上下文中 → **Hypervisor 自身的 #GP** → BSOD。

**修复方案**：在执行 `AsmXsetbv` 前添加 XCR0 合法性验证：
- XCR 索引必须为 0（只有 XCR0 有效）
- Bit 0（x87 FPU）必须为 1
- AVX（bit 2）要求 SSE（bit 1）也被设置

验证失败时注入 `#GP(0)` 到 Guest 而非执行非法操作：

```c
if (Ecx != 0) goto InjectGp;               /* 只有 XCR0 有效 */
if (!(Value & 1)) goto InjectGp;            /* x87 必须为 1 */
if ((Value & 4) && !(Value & 2)) goto InjectGp;  /* AVX 要求 SSE */

AsmXsetbv(Ecx, Value);
VmxAdvanceGuestRip();
return TRUE;

InjectGp:
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, GP_FAULT_INFO);
    VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, 0);
    return TRUE;
```

---

## 四、整体评估

| 分类 | 评价 |
|------|------|
| **VMCS 初始化** | ✅ 完整正确：所有 Guest/Host 状态字段、控制字段、True Controls、段描述符解析都正确 |
| **VM-Exit 分发** | ✅ 覆盖全面：CPUID、MSR、CR、DR、Exception、RDTSC、XSETBV、INVD、INVLPG、WBINVD、Triple Fault 等都有处理 |
| **外部中断** | ✅ 逻辑完整（IF + Interruptibility 检查 + interrupt window）—— 问题 C 已修复 |
| **NMI 处理** | ✅ NMI blocking 检查 + NMI-window 延迟注入 —— 问题 F 已修复 |
| **VMLAUNCH / VMRESUME** | ✅ ASM 实现正确：寄存器保存/恢复顺序正确，RSP 对齐正确，shutdown 路径含 RFLAGS 恢复 |
| **嵌套模式** | ✅ Enlightened VMCS 支持完整：VP Assist Page、eVMCS 分配/激活、Clean Fields 管理 |
| **DPC 序列化** | ✅ 正确使用 per-CPU DPC + Event 实现串行初始化/终止，添加安全注释 |
| **内存管理** | ✅ 分配清零、释放检查、物理地址获取都正确 |
| **错误处理** | ✅ VmxInitialize 的 InitFailed 路径能正确回滚已启动的 CPU |
| **CR0/CR4 处理** | ✅ ReadShadow 保存 Guest 原始值，LMSW 应用固定位 —— 问题 B、G 已修复 |
| **XSETBV** | ✅ XCR0 合法性验证，非法值注入 #GP(0) 而非崩溃 |

**总体结论**：所有 8 个发现的问题 + 1 个代码质量问题（XSETBV）均已修复。

---

## 五、修改文件汇总

| 文件 | 修复的问题 | 修改内容 |
|------|-----------|---------|
| `vmx_init.c` | A, B, E | A: `VmxOpsGetCurrentCpuContext` 改为 per-CPU 数组；B: 初始 CR0 ReadShadow 添加注释；E: DPC 循环添加安全注释 |
| `vmx_exit.c` | B, C, D, F, G, XSETBV | B: CR0 ReadShadow 保存原始值；C: 外部中断检查 Interruptibility；D: RDTSCP 添加耦合文档；F: NMI blocking 检查 + NMI-window 处理分支；G: LMSW 应用 CR0 固定位；XSETBV: XCR0 合法性验证 |
| `vmx_asm.asm` | H | VmxShutdown 路径：vmread Guest RFLAGS → push 到 Guest 栈 → vmxoff → 恢复 GP 寄存器 → popfq → ret |

**C89 兼容性**：所有新增变量声明均放在代码块顶部，符合 WDK 7600 的 MSVC C89 要求。

---

*文档结束。所有问题已修复并补充到此报告中。*
