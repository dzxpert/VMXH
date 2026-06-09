简体中文 | [English](nbp-0.32-analysis.md)

# New Blue Pill (NBP) v0.32 源码深度分析报告

> 分析目标：`D:\VMX\nbp-0.32-public`
> 对比项目：VMXHypervisorToolbox
> 分析日期：2026-04-14

---

## 一、项目概述

New Blue Pill v0.32 是 Joanna Rutkowska 的经典 Type-II (Blue Pill) hypervisor 概念验证。核心能力是在**不重启**的情况下将运行中的 OS 转化为虚拟机 Guest，实现运行时 OS 吞噬 (Runtime OS Subversion)。

| 属性 | 说明 |
|------|------|
| 架构 | Intel VMX + AMD SVM 双平台 |
| 模式 | Blue Pill（运行时注入 Hypervisor） |
| 语言 | C + x64 MASM |
| 亮点 | 多 CPU 原子吞噬 + IPI 协调 + 回滚机制 |
| 反检测 | BLUE_CHICKEN 机制（检测到探测即自动卸载） |
| 局限 | 无 EPT/NPT、无 Hook 框架、无反反调试 |

---

## 二、项目结构

```
nbp-0.32-public/
├── common/                    # 架构无关公共代码
│   ├── common.c             # 内存管理（恒等页表、Spare Page 映射）
│   ├── common.h             # 全局结构体、CPU 结构、配置宏
│   ├── common-asm.asm       # CmSubvert 入口点、寄存器保存/恢复
│   ├── cpuid.asm            # CPUID 指令封装
│   ├── interrupts.h         # 中断/异常帧结构
│   ├── msr.asm              # MSR 读写封装
│   ├── regs.asm             # CPU 寄存器存取器（CR0/CR3/CR4/DR/段寄存器）
│   ├── traps.c              # Trap 注册/查找/分发管理
│   └── traps.h              # Trap 结构体与回调定义
├── vmx/                      # Intel VMX 实现
│   ├── vmx.c                # VMX 初始化、VMCS 配置、VM-Exit 分发
│   ├── vmx.h                # VMX 结构体
│   ├── vmcs.h               # VMCS 字段编码（完整）
│   ├── vmx-asm.asm          # VMXON/VMLAUNCH/VMRESUME/VMREAD/VMWRITE
│   └── vmxtraps.c           # CPUID/MSR/CR 拦截处理器
├── svm/                      # AMD SVM 实现
│   ├── svm.c                # SVM 初始化、VMCB 配置
│   ├── svm.h                # SVM 结构体
│   ├── vmcb.h               # VMCB 字段编码
│   ├── svm-asm.asm          # VMRUN/VMLOAD/VMSAVE
│   └── svmtraps.c           # SVM Trap 处理器
├── hvm.c                     # Hypervisor 抽象层（HVM_DEPENDENT 分发）
├── hvm.h                     # HVM 结构体（CPU、函数指针表）
└── newbp.c                   # 驱动入口 (DriverEntry / DriverUnload)
```

---

## 三、架构抽象模式

NBP 使用 `HVM_DEPENDENT` 函数指针表实现 Intel/AMD 双平台抽象：

```c
typedef struct {
  BOOLEAN  (*ArchIsImplemented)(VOID);
  NTSTATUS (*ArchInitialize)(PCPU Cpu, PVOID GuestRip, PVOID GuestRsp);
  VOID     (*ArchDispatchEvent)(PCPU Cpu, PGUEST_REGS GuestRegs);
  VOID     (*ArchRegisterTraps)(PCPU Cpu);
  NTSTATUS (*ArchShutdown)(PCPU Cpu, PGUEST_REGS GuestRegs, BOOLEAN bSetupTimeBomb);
} HVM_DEPENDENT;
```

运行时 `Hvm` 指向 `&Vmx` 或 `&Svm`，所有上层代码通过 `Hvm->ArchXxx()` 调用。

**对比 VMXHypervisorToolbox**：我们的 `hv_ops.h` 中的 `HV_OPS` 结构体与此设计思路完全一致（函数指针 vtable 模式），但我们的接口更丰富（包含 ReadGuestRip、InjectException、HookFunction 等更多操作）。

---

## 四、初始化流程详解

### 4.1 驱动加载 (`newbp.c: DriverEntry`)

```
DriverEntry
  → MmInitManager()              // 初始化内存管理器
  → MmInitIdentityPageTable()    // 构建恒等页表 (VA=PA)
  → MmMapGuestKernelPages()      // 映射内核页到 Guest 地址空间
  → HvmInit()                    // 选择 VMX 或 SVM 后端
  → HvmSwallowBluepill()         // 执行多 CPU 吞噬
```

### 4.2 多 CPU 吞噬 (`hvm.c: HvmSwallowBluepill`)

关键设计：**逐 CPU 顺序虚拟化 + 失败时原子回滚**

```c
for (uCpu = 0; uCpu < KeNumberProcessors; uCpu++) {
    status = CmDeliverToProcessor(uCpu, CmSubvert);  // IPI 投递
    if (FAILED(status)) {
        // 回滚：逐个解除已虚拟化的 CPU
        for (j = 0; j < uCpu; j++)
            CmDeliverToProcessor(j, CmSlipIntoMatrix);  // 执行 VMXOFF
        return STATUS_FAILURE;
    }
}
```

**⭐ 借鉴价值**：我们的 `VmxInitialize` 也是逐 CPU DPC 顺序 VMLAUNCH + 失败回滚，设计思路一致。但 NBP 用 IPI (`CmDeliverToProcessor`) 而非 DPC，IPI 更直接、延迟更低。

### 4.3 单 CPU 虚拟化 (`hvm.c: HvmSubvertCpu`)

```
CmSubvert (ASM)
  → 保存所有通用寄存器到栈
  → 调用 HvmSubvertCpu(RSP)
      → 在 Host 栈末尾放置 CPU 结构体
      → HvmSetupGdt() / HvmSetupIdt()  // 自定义 GDT/IDT
      → Hvm->ArchRegisterTraps()        // 注册 Trap 处理器
      → Hvm->ArchInitialize()           // VMXON + VMCS 配置 + VMLAUNCH
```

**⭐ 关键技术：CPU 结构体放在 Host 栈末尾**

```c
PCPU Cpu = (PCPU)((PCHAR)HostStackBase + HOST_STACK_SIZE - 8 - sizeof(CPU));
```

Host RSP 指向 CPU 结构体 → VM-Exit handler 通过 `[RSP]` 直接访问 PCPU，无需全局变量或 KeGetCurrentProcessorNumber() 查找。

**对比**：我们用 `g_VmxState.CpuContexts[KeGetCurrentProcessorNumber()]` 查找，多一次数组索引。NBP 的方式更高效但更脆弱（依赖栈布局）。

---

## 五、VMCS 配置对比

### 5.1 Pin-Based Controls

| 控制位 | NBP | VMXHypervisorToolbox | 说明 |
|--------|-----|---------------------|------|
| EXTERNAL_INT_EXIT | ✅ 请求 | ❌ 不请求 | NBP 拦截所有外部中断 |
| NMI_EXIT | ❌ 未请求 | ✅ 请求 | 我们拦截 NMI |

**⭐ 分析**：NBP 拦截外部中断但不拦截 NMI，我们相反。NBP 的方式意味着它需要在 VM-Exit handler 中重新注入所有外部中断（开销大），但获得了完全的中断控制权。

### 5.2 Processor-Based Controls

| 控制位 | NBP | VMXHypervisorToolbox |
|--------|-----|---------------------|
| MSR_BITMAP | ✅ | ✅ |
| IO_BITMAP | ✅ | ✅ |
| HLT_EXIT | ✅ | ❌（不请求） |
| RDTSC_EXIT | ✅ | ❌ |
| MOV_DR_EXIT | ✅ | ✅ |
| CR3_LOAD_EXIT | ❌ | ✅ |
| UNCOND_IO_EXIT | ✅ | ❌ |
| INVLPG_EXIT | ✅ | ❌（不请求） |
| SECONDARY_CONTROLS | ❌ | ✅ |

**⭐ 关键差异**：
- NBP 拦截 RDTSC（用于反检测时间伪装），我们不拦截
- NBP 没有 Secondary Controls（**无 EPT/VPID 支持**）
- 我们启用了 EPT + VPID + RDTSCP + INVPCID + XSAVES

### 5.3 Exit/Entry Controls

NBP 只请求 `VM_EXIT_IA32E_MODE` 和 `VM_ENTRY_IA32E_MODE`（64位模式）。我们额外保存/加载 IA32_EFER。

---

## 六、VM-Exit 处理对比

### 6.1 NBP 的 Trap 注册系统

NBP 独特的设计：**运行时注册的 Trap 回调链**

```c
typedef struct _NBP_TRAP {
    ULONG TrapType;            // TRAP_GENERAL / TRAP_MSR / TRAP_IO
    ULONG ExitCode;            // VM-Exit reason
    NBP_TRAP_CALLBACK Callback; // 处理函数指针
    struct _NBP_TRAP *Next;     // 链表
} NBP_TRAP;
```

VM-Exit 发生时：
```
VmxHandleInterception()
  → TrFindRegisteredTrap(exitReason)  // 查链表找 handler
  → TrExecuteGeneralTrapHandler()     // 执行回调
```

**对比**：我们用巨大的 `switch (ExitReason)` 直接分发。NBP 的链表方式更灵活（运行时可动态注册/注销），但有链表查找开销。对于性能敏感的 VM-Exit hot path，我们的 switch 更快。

### 6.2 CPUID 处理

```c
// NBP: vmxtraps.c
static BOOLEAN VmxDispatchCpuid(PCPU Cpu, PGUEST_REGS GuestRegs, ...)
{
    // 后门检测
    if (GuestRegs->rax == 0xbabecafe) {
        GuestRegs->rax = 0x69696969;  // 返回后门标记
        return TRUE;
    }
    // 直接执行真实 CPUID
    GetCpuIdInfo(GuestRegs->rax, &cpuRegs);
    GuestRegs->rax = cpuRegs.eax;
    // ... 复制结果
}
```

**对比**：NBP 的 CPUID 处理极其简单——直接执行 + 后门。我们的 `AadHandleCpuid` 做了大量伪装工作（隐藏 VMX 位、伪造 Hypervisor 叶子、隐藏 CPUID 特征）。

**⭐ 借鉴**：NBP 的 `0xbabecafe` 后门模式可考虑引入，用于调试时快速确认 Hypervisor 是否活跃。

### 6.3 MSR 处理

NBP 拦截特定 MSR 并从 VMCS Guest 字段读取/写入：

```c
case MSR_IA32_SYSENTER_CS:
    VmxRead(GUEST_SYSENTER_CS, &msrValue);  // 从 VMCS 读
    break;
case MSR_IA32_EFER:
    msrValue = Cpu->Vmx.GuestEFER;  // 从缓存读
    break;
default:
    msrValue = MsrRead(msr);  // 直接执行
```

**对比**：我们的 `HandleRdmsrImpl` 做了更多工作——无效 MSR 预探测、安全网 #GP 注入、反反调试 IA32_DEBUGCTL 伪造。NBP 的 MSR 处理更简单但不如我们健壮。

### 6.4 CR 访问处理

NBP 的亮点：**CR0 关闭分页时切换到恒等页表**

```c
case 0:  // MOV-to-CR0
    if (!(value & CR0_PG))           // Guest 关闭分页？
        RegSetCr3(IdentityPageTablePA);  // 切换到恒等页表
    VmxWrite(GUEST_CR0, value);
    break;
```

**⭐ 借鉴价值**：我们的 CR 处理没有考虑 Guest 禁用分页的场景。虽然 64 位 Windows 不会禁用分页，但这是一个防御性好习惯。

### 6.5 中断/NMI/异常处理

**NBP 完全没有**：
- ❌ 无 NMI 处理（不拦截 NMI_EXIT）
- ❌ 无 IDT-Vectoring 事件重注入
- ❌ 无异常重注入（#PF/#GP 等）
- ✅ 外部中断通过 PIN_BASED_EXT_INTR_MASK 拦截

**⭐ 重要发现**：NBP **缺少 IDT-Vectoring 重注入**，这意味着如果 VM-Exit 发生在 IDT 事件传递期间，Guest 会丢失该事件。这是一个已知的 NBP 缺陷。我们刚刚修复了同样的问题。

---

## 七、内存管理

### 7.1 恒等页表 (Identity Page Table)

NBP 在初始化时构建 VA=PA 的恒等映射页表，用于：
- Guest 禁用分页时 Hypervisor 仍可安全访问内存
- Guest 页表遍历时的中间状态保护

**对比**：我们使用 EPT 恒等映射实现类似功能，但 NBP 没有 EPT，必须通过手动页表切换来处理。

### 7.2 Spare Page 映射

NBP 有一个 `HvmMapGuestVAToSparePage` 函数，通过手动遍历 4 级页表将 Guest 物理页映射到 Host VA：

```
Guest VA → CR3 → PML4 → PDP → PD → PT → Guest PA → Spare Page VA
```

**对比**：我们的 `hv_mem.c` 做了同样的事情（CR3 Walk + MmMapIoSpace），但实现更完整（支持 2MB/1GB 大页、PSE、错误处理）。

### 7.3 Host 栈

| | NBP | VMXHypervisorToolbox |
|---|---|---|
| 大小 | 16 页 (64KB) | 4 页 (16KB) |
| CPU 结构位置 | 栈末尾 | 独立全局数组 |
| 访问方式 | `[RSP]` 直接偏移 | `g_VmxState.CpuContexts[CpuIndex]` |

**⭐ 借鉴**：NBP 的 64KB Host 栈更保守安全。我们的 16KB 在深度调用链（如 EPT violation handler → Hook engine → log write）下可能有栈溢出风险。可考虑增大到 32KB。

---

## 八、反检测机制

### 8.1 BLUE_CHICKEN

NBP 的独特反检测策略：**被检测到就自动卸载**

```c
if (BLUE_CHICKEN_CHECK) {
    CmMakeCpuLeaveVirtualMode();  // 立即 VMXOFF + 恢复 Guest
}
```

逻辑：如果有人通过 CPUID 后门（`0xbabecafe`）探测到 Hypervisor，就主动退出虚拟化。这比隐藏更激进——直接消除证据。

### 8.2 RDTSC 拦截

NBP 拦截 RDTSC 指令（`CPU_BASED_RDTSC_EXITING`），可以伪造时间戳来对抗基于时间差的检测。

**⭐ 借鉴价值**：我们目前不拦截 RDTSC，而是使用 TSC_OFFSETTING 硬件机制（更高效）。但如果需要更精细的 RDTSC 控制（如针对反调试的 RDTSC 伪造），可以考虑在特定场景下切换到 RDTSC_EXIT。

---

## 九、VM 卸载 (Guest Liberation)

### 9.1 动态 Trampoline 生成

NBP 最精巧的技术之一：**运行时生成汇编 Trampoline 代码**

```c
VmxGenerateTrampolineToGuest(PCPU Cpu, PVOID TrampolineBase)
{
    PUCHAR pCode = (PUCHAR)TrampolineBase;
    
    // 动态生成机器码：
    // 1. 恢复所有 Guest 寄存器
    // 2. 恢复 CR0/CR3/CR4
    // 3. 恢复 GDT/IDT
    // 4. 恢复 FS_BASE/GS_BASE
    // 5. 构建 IRETQ 栈帧 (SS:RSP:RFLAGS:CS:RIP)
    // 6. VMXOFF
    // 7. IRETQ → 回到 Guest
}
```

**对比**：我们的 `VmxShutdown`（vmx_asm.asm）是静态汇编代码，从 VMCS vmread Guest 状态后 VMXOFF + RET。NBP 的动态 Trampoline 更灵活（支持任意 Guest 状态恢复），但我们的静态方式更简单可靠。

**⭐ 借鉴**：NBP 使用 `IRETQ` 恢复 Guest（可同时恢复 CS:RIP + SS:RSP + RFLAGS），我们使用 `popfq` + `ret` 组合。IRETQ 是更规范的方式。

---

## 十、可借鉴的关键技术总结

### ⭐⭐⭐ 高优先级借鉴

| # | 技术 | NBP 实现 | 当前状态 | 建议 |
|---|------|----------|----------|------|
| 1 | **CPUID 后门** | `CPUID(0xbabecafe)` → `0x69696969` | 无 | 添加调试后门，方便确认 Hypervisor 存活 |
| 2 | **Host 栈大小** | 16 页 (64KB) | 4 页 (16KB) | 考虑增大到 32KB，防止深度调用栈溢出 |
| 3 | **IRETQ 恢复** | VMXOFF 后用 IRETQ 一次性恢复 CS:RIP+SS:RSP+RFLAGS | popfq + ret | 考虑改用 IRETQ，更规范 |

### ⭐⭐ 中优先级借鉴

| # | 技术 | NBP 实现 | 当前状态 | 建议 |
|---|------|----------|----------|------|
| 4 | **Trap 注册系统** | 链表 + 回调 | switch 分发 | 当前 switch 方式性能更好，但可为未来动态 Hook 场景保留 |
| 5 | **EFER 缓存** | 缓存 GuestEFER + 同步 VM_ENTRY_IA32E_MODE | 部分实现 | 确认 EFER 处理完整 |
| 6 | **CR0 分页检查** | 禁用分页时切换恒等页表 | 未处理 | 防御性添加（64位 Windows 不会触发） |

### ⭐ 低优先级 / 参考

| # | 技术 | 说明 |
|---|------|------|
| 7 | BLUE_CHICKEN 反检测 | 被探测到就自动卸载——极端但有效 |
| 8 | RDTSC 拦截 | 用于时间伪造反检测，我们用 TSC_OFFSETTING 更高效 |
| 9 | 恒等页表 | 我们有 EPT 不需要，但概念可用于 EPT-less 场景 |
| 10 | IPI 替代 DPC | IPI 比 DPC 延迟低，但 DPC 更安全（可等待完成） |

---

## 十一、NBP 的不足之处（我们已超越的方面）

| 方面 | NBP | VMXHypervisorToolbox |
|------|-----|---------------------|
| EPT/NPT | ❌ 无 | ✅ 完整 EPT + NPT + Hook 框架 |
| IDT-Vectoring 重注入 | ❌ 无（会丢失 Guest 异常）| ✅ 已实现 |
| NMI 处理 | ❌ 不拦截 | ✅ 拦截 + 重注入 |
| 反反调试 | ❌ 无 | ✅ 10+ 独立技术 |
| SSDT/Shadow SSDT | ❌ 无 | ✅ 发现 + Hook + 监控 |
| 进程内存读写 | ❌ 基本的 Spare Page | ✅ 完整 CR3 Walk + 物理内存直接访问 |
| MSR 安全 | ❌ 直接执行可能 #GP | ✅ 预探测 + 安全网 |
| 日志系统 | ❌ DbgPrint 仅 | ✅ Lock-free Ring Buffer + Flush Thread |
| VPID | ❌ 无 | ✅ Per-CPU VPID |
| XSAVES | ❌ 无 | ✅ 支持 |

---

## 十二、结论

NBP v0.32 是一个精巧的 Blue Pill 概念验证，代码量小（~5000 行）但设计优雅。其架构抽象模式（HVM_DEPENDENT）与我们的 hv_ops 设计高度一致，验证了我们的架构方向正确。

**最有价值的借鉴点**：
1. **CPUID 后门** — 简单实用的调试工具
2. **更大的 Host 栈** — 防止深层调用栈溢出
3. **IRETQ 恢复方式** — 更规范的 Guest 状态恢复

**我们已远超 NBP 的方面**：EPT/NPT Hook 框架、完整的反反调试引擎、SSDT 监控、IDT-Vectoring 重注入、MSR 安全处理、进程内存读写引擎。NBP 作为教学和概念验证优秀，但不适合直接用于生产。
