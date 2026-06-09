简体中文 | [English](deep_dive_article.md)

# VMX Hypervisor Toolbox 深度技术剖析


> **面向安全研究员与内核开发者的超长技术文章**
>
> 本文从 x86-64 硬件虚拟化原理出发，逐层深入剖析一个完整的 Type-2 (Blue Pill) Hypervisor 实现——VMX Hypervisor Toolbox。涵盖 Intel VT-x / AMD SVM 双平台架构、EPT/NPT 页分裂 Hook、PatchGuard 绕过机制、Hyper-V 嵌套虚拟化优化、反反调试引擎、Hypervisor 级内存读写引擎、SSDT/Shadow SSDT 监控框架等全部核心子系统的源码级技术细节。

---

## 目录

- [第一章：x86-64 硬件辅助虚拟化原理](#第一章x86-64-硬件辅助虚拟化原理)
- [第二章：Intel VT-x vs AMD SVM 架构对比](#第二章intel-vt-x-vs-amd-svm-架构对比)
- [第三章：PatchGuard (KPP) 原理与绕过机制](#第三章patchguard-kpp-原理与绕过机制)
- [第四章：Windows Hyper-V 与嵌套虚拟化](#第四章windows-hyper-v-与嵌套虚拟化)
- [第五章：Blue Pill 后加载虚拟化](#第五章blue-pill-后加载虚拟化)
- [第六章：VMX 初始化全流程](#第六章vmx-初始化全流程)
- [第七章：通用 EPT/NPT Hook 框架](#第七章通用-eptnpt-hook-框架)
- [第八章：反反调试引擎](#第八章反反调试引擎)
- [第九章：Hypervisor 内存读写引擎](#第九章hypervisor-内存读写引擎)
- [第十章：SSDT & Shadow SSDT 监控与 Hook 框架](#第十章ssdt--shadow-ssdt-监控与-hook-框架)
- [第十一章：驱动-用户态通信架构](#第十一章驱动-用户态通信架构)
- [附录](#附录)

---

## 第一章：x86-64 硬件辅助虚拟化原理

> 📊 架构图参考: `vmx_nested_virtualization.drawio`, `vmx_init_flow.drawio`

### 1.1 从软件虚拟化到硬件虚拟化的演进

在硬件虚拟化出现之前，x86 架构存在所谓的「虚拟化漏洞」——17 条敏感指令在 Ring 0 和 Ring 3 下表现不同，但不会触发异常（trap）。例如 `POPF` 指令在 Ring 0 下会修改 IF（中断标志位），在 Ring 3 下则静默忽略。传统的 Trap-and-Emulate 模型依赖于「所有特权指令都触发 trap」这一假设，因此在原始 x86 上无法直接实现。

VMware 等早期虚拟化方案采用 **Binary Translation (BT)** 技术——在 Guest 代码执行前动态扫描并替换敏感指令为等价的安全序列。这种方案性能开销大（约 10-30%），且实现极为复杂。

2005-2006 年，Intel 和 AMD 分别推出了硬件虚拟化扩展：

| 特性 | Intel | AMD |
|------|-------|-----|
| 品牌名 | VT-x (Vanderpool) | AMD-V (Pacifica) |
| 指令集 | VMX (Virtual Machine Extensions) | SVM (Secure Virtual Machine) |
| 首发 CPU | Pentium 4 672/662 (2005) | Athlon 64 X2 (2006) |
| 控制结构 | VMCS (4KB) | VMCB (4KB) |
| 二级地址翻译 | EPT (Nehalem, 2008) | NPT (Barcelona, 2007) |

硬件虚拟化的核心思想是：**在硬件层面引入一个比 Ring 0 更高特权的执行模式（Ring -1）**，让 Hypervisor 运行在此模式，Guest OS 运行在被 Hypervisor 控制的受限 Ring 0 中。

### 1.2 VMX Root / Non-Root 双模式架构

Intel VT-x 将 CPU 执行状态分为两种根本性不同的模式：

```
┌─────────────────────────────────────────────┐
│            VMX Root Mode (Ring -1)           │
│  ┌───────────────────────────────────────┐   │
│  │  Hypervisor / VMM                     │   │
│  │  - 完全的硬件控制权                   │   │
│  │  - 可拦截 Guest 的任何敏感操作        │   │
│  │  - 管理 VMCS / EPT                    │   │
│  └───────────────────────────────────────┘   │
├─────────────────────────────────────────────┤
│          VMX Non-Root Mode (Guest)           │
│  ┌─────────────────────┐ ┌────────────────┐ │
│  │ Ring 0: Guest Kernel │ │ Ring 3: App    │ │
│  │ (认为自己拥有最高权限│ │ (正常用户态)   │ │
│  │  但实际被 Hypervisor │ │                │ │
│  │  监控和控制)         │ │                │ │
│  └─────────────────────┘ └────────────────┘ │
└─────────────────────────────────────────────┘
```

关键特性：

- **VMX Root Mode**: Hypervisor 运行的模式。拥有对硬件的完全控制权，可以通过 VMCS 配置决定 Guest 的哪些操作会触发 VM-Exit。
- **VMX Non-Root Mode**: Guest OS 运行的模式。在语义上与正常 Ring 0 几乎相同，但 Hypervisor 可以选择性地拦截任何敏感操作。
- **模式切换**: VM-Entry 从 Root 切换到 Non-Root；VM-Exit 从 Non-Root 切换回 Root。

AMD SVM 使用不同的术语但概念等价：Host Mode 对应 VMX Root，Guest Mode 对应 VMX Non-Root。

### 1.3 VM-Entry 与 VM-Exit 的完整生命周期

一次完整的虚拟化循环如下：

```
          ┌──── VM-Entry ────┐
          │  (VMLAUNCH/      │
          │   VMRESUME)      │
          ▼                  │
    ┌───────────┐      ┌───────────┐
    │ Non-Root  │─────→│   Root    │
    │ (Guest)   │      │ (Host)    │
    │           │      │           │
    │ 执行 Guest │ VM-Exit│ 分析退出 │
    │ 代码...    │──────→│ 原因,    │
    │           │      │ 处理后   │
    └───────────┘      │ 恢复 Guest│
                       └───────────┘
```

**VM-Entry 过程**（约数百个时钟周期）：
1. 检查 VMCS 中所有 Guest State 字段的合法性
2. 加载 Guest 的 CR0/CR3/CR4、段寄存器、MSR
3. 加载 Guest 的 RIP/RSP/RFLAGS
4. 切换到 Non-Root Mode，开始执行 Guest 代码

**VM-Exit 触发条件**（取决于 VMCS 配置）：
- 执行特权指令：CPUID、RDMSR/WRMSR、MOV-to-CR、HLT...
- 外部中断（如果配置了 `External-interrupt exiting`）
- 异常（如果 Exception Bitmap 中对应位被设置）
- EPT Violation（二级页表权限违规）
- Monitor Trap Flag（单步调试标志）

**VM-Exit 处理过程**：
1. CPU 自动保存 Guest 状态到 VMCS Guest-State 区域
2. 加载 Host 状态（VMCS Host-State 区域 → CPU 寄存器）
3. 将退出原因写入 VMCS Exit-Information 字段
4. 跳转到 Host RIP（VM-Exit Handler 入口）

### 1.4 VMCS 控制结构深度剖析

VMCS (Virtual Machine Control Structure) 是 Intel VT-x 的核心数据结构——一个 4KB 对齐的内存页，包含了控制虚拟化行为所需的全部信息。其内部被划分为 **6 大区域**：

```
┌──────────────────────────────────────────┐
│  VMCS (4KB Page)                         │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │ 1. Guest-State Area               │  │
│  │   CR0/CR3/CR4, 段寄存器, RIP/RSP, │  │
│  │   RFLAGS, GDT/IDT, MSRs          │  │
│  ├────────────────────────────────────┤  │
│  │ 2. Host-State Area                │  │
│  │   CR0/CR3/CR4, 段选择子, RIP/RSP, │  │
│  │   GDT/IDT Base, MSRs             │  │
│  ├────────────────────────────────────┤  │
│  │ 3. VM-Execution Control Fields    │  │
│  │   Pin-Based / Proc-Based Controls │  │
│  │   Exception Bitmap, EPT Pointer,  │  │
│  │   MSR Bitmap, CR Masks/Shadows    │  │
│  ├────────────────────────────────────┤  │
│  │ 4. VM-Exit Control Fields         │  │
│  │   Exit Controls, MSR Store/Load   │  │
│  ├────────────────────────────────────┤  │
│  │ 5. VM-Entry Control Fields        │  │
│  │   Entry Controls, Event Injection │  │
│  ├────────────────────────────────────┤  │
│  │ 6. VM-Exit Information (只读)     │  │
│  │   Exit Reason, Qualification,     │  │
│  │   Interruption Info, Guest PA     │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

**VMCS 字段编码格式**：

每个 VMCS 字段由一个 32 位编码标识，格式为：

```
Bits [14:13] = 字段宽度:  00=16位, 01=64位, 10=32位, 11=自然宽度
Bits [11:10] = 字段类型:  00=控制, 01=只读, 10=Guest, 11=Host
Bits [9:1]   = 字段索引
Bit  [0]     = 高半部分访问标记(仅64位字段)
```

**AdjustControls 公式**——Intel SDM Vol. 3C §31.5.1：

设置 VMCS 控制字段时，必须满足 CPU 的 Allowed-0 和 Allowed-1 约束。本项目的实现如下：

```c
static ULONG VmxAdjustControls(ULONG RequestedControls, ULONG64 Capability)
{
    ULONG Low  = (ULONG)(Capability & 0xFFFFFFFF);   /* Allowed 0-settings (must-be-1) */
    ULONG High = (ULONG)(Capability >> 32);           /* Allowed 1-settings (can-be-1) */

    RequestedControls |= Low;   /* 将 must-be-1 位强制置位 */
    RequestedControls &= High;  /* 将 must-be-0 位强制清零 */

    return RequestedControls;
}
```

公式本质：`Result = (Requested | Must1) & Can1`。这保证了结果中的每一位都满足：
- 如果某位必须为 1（Low 中该位 = 1），则结果中该位 = 1
- 如果某位必须为 0（High 中该位 = 0），则结果中该位 = 0
- 其余位按请求值设置

### 1.5 EPT 二级地址翻译

Extended Page Tables (EPT) 是 Intel 的二级地址翻译机制，提供了 **GVA → GPA → HPA** 的两层地址转换：

```
Guest 虚拟地址 (GVA)
    │
    ▼  [Guest 页表遍历, CR3 控制]
Guest 物理地址 (GPA)
    │
    ▼  [EPT 页表遍历, EPTP 控制]
Host 物理地址 (HPA)
    │
    ▼  [实际内存访问]
```

EPT 采用与传统 x86-64 分页相同的 4 级页表结构：

```
EPTP (EPT Pointer, 存于 VMCS)
  │
  ▼
PML4 (512 条目, 每条目覆盖 512GB)
  │
  ▼
PDPT (512 条目, 每条目覆盖 1GB)
  │
  ▼
PD (512 条目, 每条目覆盖 2MB)     ← 可在此级使用 Large Page
  │
  ▼
PT (512 条目, 每条目覆盖 4KB)
```

每个 EPT 页表条目（PTE）包含以下关键字段：

| 位 | 名称 | 说明 |
|----|------|------|
| 0 | Read | 允许读访问 |
| 1 | Write | 允许写访问 |
| 2 | Execute | 允许执行访问 |
| 7 | LargePage | 标记为大页（2MB/1GB） |
| [51:12] | PhysAddr | 下一级页表/物理页帧地址 |
| [5:3] | MemoryType | 内存类型 (WB/UC/WT 等) |

**EPT 的核心优势**：Hypervisor 可以精确控制每个 4KB 物理页的 R/W/X 权限，而 Guest OS 完全无法感知——这是实现透明 Hook 的技术基础。

**TLB 缓存**: EPT 地址翻译结果被缓存在 TLB 中。修改 EPT 条目后必须执行 `INVEPT` 指令使缓存失效。VPID (Virtual Processor Identifier) 允许为不同的 Guest 分配不同的 TLB 标签，避免 VM-Entry/VM-Exit 时全量刷新 TLB。

---

## 第二章：Intel VT-x vs AMD SVM 架构对比

> 📊 架构图参考: `svm_vs_vmx_architecture.drawio`

### 2.1 VMCS vs VMCB — 控制结构的根本差异

Intel 的 VMCS 和 AMD 的 VMCB 虽然都是 4KB 的控制结构，但在访问方式上有着根本性的差异：

| 特性 | Intel VMCS | AMD VMCB |
|------|-----------|----------|
| **访问方式** | 通过 VMREAD/VMWRITE 指令间接访问 | 直接内存读写（结构体成员偏移） |
| **内部布局** | CPU 内部格式，对软件不透明 | 公开定义的 C 结构体 |
| **活跃状态** | 每个 CPU 同一时间只能激活一个 VMCS | VMCB 地址作为 VMRUN 参数传递 |
| **切换方式** | VMCLEAR + VMPTRLD | 直接更换 RAX 中的 VMCB 地址 |
| **大小** | 4KB (由 IA32_VMX_BASIC 报告) | 4KB (固定) |

**VMCB 的结构化布局**（取自 `svm.h`）:

```c
typedef struct _VMCB {
    struct {                        /* 控制区域 (offset 0x000-0x3FF) */
        ULONG   InterceptCr;       /* +0x000: CR read/write intercepts */
        ULONG   InterceptDr;       /* +0x004: DR read/write intercepts */
        ULONG   InterceptExceptions; /* +0x008: 异常拦截位图 */
        ULONG64 Intercept;         /* +0x00C: 指令拦截位图(64位) */
        ULONG64 IopmBasePa;        /* +0x040: I/O 权限图 PA */
        ULONG64 MsrpmBasePa;       /* +0x048: MSR 权限图 PA */
        ULONG64 TscOffset;         /* +0x050: TSC 偏移 */
        ULONG   Asid;              /* +0x058: 地址空间 ID */
        ULONG   TlbCtl;            /* +0x05C: TLB 控制 */
        ULONG64 IntCtl;            /* +0x060: 中断控制 */
        ULONG64 ExitCode;          /* +0x070: #VMEXIT 原因码 */
        ULONG64 ExitInfo1;         /* +0x078: 退出信息 1 */
        ULONG64 ExitInfo2;         /* +0x080: 退出信息 2 */
        ULONG64 ExitIntInfo;       /* +0x088: 退出中断信息 */
        ULONG64 NestedCtl;         /* +0x090: 嵌套分页控制 */
        ULONG64 NestedCr3;         /* +0x0B0: 嵌套页表根(NCR3) */
        ULONG64 NextRip;           /* +0x0C8: NRIP Save */
        ULONG64 EventInj;          /* +0x0A8: 事件注入 */
        // ... 更多控制字段
    } Control;

    struct {                        /* 状态保存区域 (offset 0x400-0xFFF) */
        USHORT  EsSel, CsSel, SsSel, DsSel, FsSel, GsSel;
        // 段基址、限长、属性
        ULONG64 Cr0, Cr2, Cr3, Cr4;
        ULONG64 Dr6, Dr7;
        ULONG64 Rflags, Rip, Rsp, Rax;
        ULONG64 Star, Lstar, Cstar, Sfmask;
        ULONG64 KernelGsBase;
        ULONG64 SysenterCs, SysenterEsp, SysenterEip;
        // ... 更多 Guest 状态
    } Save;
} VMCB;
```

对比 Intel VMCS 的间接访问：

```c
/* Intel: 必须通过 VMREAD/VMWRITE 指令 */
ULONG64 guestRip = VmxRead(VMCS_GUEST_RIP);     /* __vmx_vmread() */
VmxWrite(VMCS_GUEST_RIP, newRip);                /* __vmx_vmwrite() */

/* AMD: 直接结构体成员访问 */
ULONG64 guestRip = Vmcb->Save.Rip;
Vmcb->Save.Rip = newRip;
```

### 2.2 VMLAUNCH/VMRESUME vs VMRUN — 进入 Guest 的不同路径

**Intel 进入 Guest 的流程**：
```
VMXON → VMCLEAR → VMPTRLD → (配置 VMCS) → VMLAUNCH
                                              │
                                        VM-Exit 后
                                              │
                                           VMRESUME → (再次 VM-Exit) → VMRESUME → ...
```

Intel 区分首次进入（VMLAUNCH）和后续恢复（VMRESUME）。VMLAUNCH 成功后，该 VMCS 被标记为 "launched"，此后只能使用 VMRESUME。

**AMD 进入 Guest 的流程**：
```
设置 EFER.SVME → 配置 VMCB → VMLOAD → VMRUN → (#VMEXIT) → VMSAVE → VMRUN → ...
                                  ▲               │
                                  └───────────────┘
```

AMD 的模型更简洁：只有一个 `VMRUN` 指令，不区分首次/后续。但需要手动执行 `VMLOAD`（加载隐藏的 Host 状态）和 `VMSAVE`（保存 Guest 隐藏状态）。

在本项目的汇编实现中（`svm_asm.asm`）：

```asm
AsmSvmVmrun PROC
    push    rbp
    mov     rbp, rsp
    ; ... 保存 callee-saved 寄存器 ...
    mov     rax, rcx            ; RAX = VMCB 物理地址
    mov     r15, rdx            ; R15 = GUEST_CONTEXT 指针

    ; 从 GUEST_CONTEXT 恢复 Guest GP 寄存器
    mov     rcx, [r15+08h]      ; RCX
    mov     rdx, [r15+10h]      ; RDX
    ; ... 恢复 R8-R14 ...

    vmload                      ; 从 VMCB 加载隐藏状态
    vmrun                       ; 进入 Guest (VMCB PA 在 RAX 中)
    vmsave                      ; Guest 退出后保存隐藏状态

    ; 保存 Guest GP 寄存器回 GUEST_CONTEXT
    mov     [r15+08h], rcx
    mov     [r15+10h], rdx
    ; ...
    pop     rbp
    ret
AsmSvmVmrun ENDP
```

### 2.3 EPT vs NPT — 二级页表的实现差异

Intel EPT 和 AMD NPT 在功能上等价（都提供 GPA → HPA 的二级翻译），但在具体实现上有细微差异：

| 特性 | Intel EPT | AMD NPT |
|------|-----------|---------|
| **页表格式** | 类似 x86-64，但独立的权限位 | 复用 x86-64 PTE 格式 |
| **权限位** | 独立的 R/W/X 三个位 | 复用 P/R/W 位 + NX 位 |
| **Execute-Only** | 支持 (R=0, W=0, X=1) | **不支持** |
| **TLB 刷新** | INVEPT 指令 | 标准 TLB flush + ASID |
| **ASID/VPID** | VPID (16-bit) | ASID (32-bit) |
| **Violation 信息** | Exit Qualification 有详细 R/W/X 标志 | ExitInfo1 有 P/W/U/ID 标志 |

### 2.4 MTF vs RFLAGS.TF — 单步调试机制

Intel VT-x 提供了专门的 **Monitor Trap Flag (MTF)**：在 VMCS Primary Processor-Based Controls 中设置 MTF 位后，Guest 执行恰好一条指令就会触发 VM-Exit（Exit Reason = MTF）。

AMD SVM 没有 MTF 等价物。本项目使用 **Guest RFLAGS.TF（Trap Flag）** 作为替代：设置 TF 位后，Guest 执行一条指令就会触发 #DB 异常，被 Hypervisor 拦截。

```c
/* Intel: 使用 MTF */
static VOID VmxOpsEnableSingleStep(VOID)
{
    ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
    ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
}

/* AMD: 使用 RFLAGS.TF + #DB 异常拦截 */
/* 在 NptHandlePageFault 中：*/
Vmcb->Save.Rflags |= (1ULL << 8);    /* 设置 TF 位 */
/* 在 SvmHandleDbException 中恢复：*/
Vmcb->Save.Rflags &= ~(1ULL << 8);   /* 清除 TF 位 */
```

### 2.5 Execute-Only 支持差异及其对 Hook 隐蔽性的影响

这是两个平台之间**最具实际影响的差异**。

**Intel EPT** 支持 Execute-Only 页（R=0, W=0, X=1）。这意味着：
- 内存页可以被**执行**但不能被**读取或写入**
- PatchGuard 等完整性检查工具读取代码页时看到的是**原始的、未修改的内容**
- 只有 CPU 执行指令时才会使用 Hook 版本的页面

**AMD NPT** 不支持 Execute-Only。最接近的替代方案是 R+X（R=1, W=0, X=1）：
- 代码页可以被**执行和读取**
- PatchGuard 读取代码页时看到的是**修改后的 Hook 页面内容**
- 隐蔽性降低，但通过 MTF/TF 单步法可以在读取时动态切换回原始页

### 2.6 hv_ops 抽象层 — 如何用一套代码支持双平台

本项目通过一个 **HV_OPS 虚函数表（vtable）** 实现了 Intel/AMD 的完美抽象：

```c
typedef struct _HV_OPS {
    const char  *Name;                     /* "Intel VMX" 或 "AMD SVM" */
    CPU_VENDOR  Vendor;

    /* 生命周期管理 */
    BOOLEAN     (*IsSupported)(VOID);
    NTSTATUS    (*Initialize)(VOID);
    VOID        (*Terminate)(VOID);

    /* Guest 状态读写 */
    ULONG64     (*ReadGuestRip)(VOID);
    VOID        (*WriteGuestRip)(ULONG64 Value);
    ULONG64     (*ReadGuestCr3)(VOID);
    // ... 更多 Guest 状态访问函数

    /* EPT/NPT 操作 */
    NTSTATUS    (*HookFunction)(ULONG64 TargetVa, PVOID HookFunc, PVOID *OrigFunc);
    NTSTATUS    (*UnhookFunction)(ULONG64 TargetVa);
    VOID        (*UnhookAll)(VOID);

    /* 单步控制 */
    VOID        (*EnableSingleStep)(VOID);
    VOID        (*DisableSingleStep)(VOID);

    // ... 共计 30+ 个函数指针
} HV_OPS;
```

全局指针 `g_HvOps` 在 `DriverEntry` 中根据 CPU 厂商检测结果设置：

```c
/* CPU 检测 → 选择后端 */
g_CpuVendor = HvDetectCpuVendor();
if (g_CpuVendor == CPU_VENDOR_INTEL && HvCheckVmxSupport()) {
    g_HvOps = &g_VmxOps;    /* Intel VMX 后端 */
} else if (g_CpuVendor == CPU_VENDOR_AMD && HvCheckSvmSupport()) {
    g_HvOps = &g_SvmOps;    /* AMD SVM 后端 */
}
```

所有其他模块通过便利宏访问，从不直接依赖特定平台：

```c
#define HvReadGuestRip()       g_HvOps->ReadGuestRip()
#define HvReadGuestCr3()       g_HvOps->ReadGuestCr3()
#define HvHookFunction(t,h,o)  g_HvOps->HookFunction(t,h,o)
#define HvAdvanceGuestRip()    g_HvOps->AdvanceGuestRip()
```

---

## 第三章：PatchGuard (KPP) 原理与绕过机制

> 📊 架构图参考: `vmx_hook_framework.drawio`

### 3.1 PatchGuard 的工作原理

Kernel Patch Protection (KPP, 商品名 PatchGuard) 是 Windows x64 引入的内核完整性保护机制。其核心职责是：**定期校验关键内核数据结构，发现篡改则触发 BSOD (Bug Check 0x109: CRITICAL_STRUCTURE_CORRUPTION)**。

PatchGuard 保护的对象包括但不限于：
- **SSDT** (KiServiceTable): 系统服务调度表
- **IDT** (Interrupt Descriptor Table): 中断描述符表
- **GDT** (Global Descriptor Table): 全局描述符表
- **关键内核函数**: ntoskrnl.exe 的代码段
- **MSR**: IA32_LSTAR (SYSCALL 入口) 等
- **关键数据结构**: EPROCESS/ETHREAD 的校验

PatchGuard 的运作方式：
1. 在系统初始化时计算上述结构的**哈希/校验值**
2. 使用**随机化的定时器**（间隔从数秒到数分钟不等）触发校验
3. 校验时**读取**这些内存区域并与存储的校验值比较
4. 检测到差异则调用 `KeBugCheckEx(0x109, ...)`

### 3.2 传统 Hook 为什么会被 PatchGuard 检测

传统的 Inline Hook 方法是直接修改目标函数的前几个字节：

```
原始函数:                     Hook 后:
NtCreateFile:                NtCreateFile:
  mov r11, rsp               jmp MyHook        ← PatchGuard 会读到这个
  sub rsp, 10h               nop
  push rbp                   nop
  ...                        ...
```

PatchGuard 的校验逻辑运行在 **Ring 0**（内核态），直接使用 `memcmp` 或类似方法读取代码页内存进行比对。由于传统 Hook 修改了实际的物理内存内容，PatchGuard 一定能检测到变化。

### 3.3 EPT/NPT 页分裂 — 读取与执行的权限分离

本项目的核心突破在于利用 EPT/NPT 的**权限分离特性**，实现对同一地址空间的**读取和执行返回不同内容**。

原理图：

```
Guest VA: NtCreateFile (0xfffff800`12345678)
                │
                ▼
          GPA: 0x1A2B3000 (通过 Guest 页表)
                │
         ┌──────┴──────┐
         │ EPT PTE 查询 │
         │  R=0 W=0 X=1 │  ← Execute-Only
         └──────┬──────┘
                │
    ┌───────────┼───────────┐
    │           │           │
    ▼           ▼           ▼
  读取访问    写入访问    执行访问
    │           │           │
    ▼           ▼           ▼
  EPT Violation EPT Violation 正常执行
  (VM-Exit)    (VM-Exit)    ↓
    │           │       Hook 页面
    ▼           ▼    (含 JMP 指令)
  临时切换到    临时切换到
  原始页面     原始页面
  (R=1,W=1)   (R=1,W=1)
  + MTF 单步   + MTF 单步
    │           │
    ▼           ▼
  MTF Exit 后  MTF Exit 后
  恢复 X-only  恢复 X-only
```

### 3.4 Execute-Only 的精妙之处

在 Intel EPT 中设置 `Read=0, Write=0, Execute=1` 后：

- **执行**（IF/IP 取指令）：不触发 EPT Violation，直接使用 Hook 页面（含 JMP 到我们的函数）
- **读取**（MOV / CMP 等数据访问）：触发 EPT Violation，Hypervisor 介入，临时展示**原始页面**

这意味着 PatchGuard 的 `memcmp` 校验读到的**永远是未修改的原始代码**，而 CPU 执行的**永远是 Hook 后的代码**。

本项目的实现（`ept.c` 中的 `HandleEptViolation`）:

```c
if (IsRead || IsWrite) {
    /* 读/写访问 → 展示原始页面 */
    Hook->TargetPte->Read = 1;
    Hook->TargetPte->Write = 1;
    Hook->TargetPte->Execute = 0;
    Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;  /* 原始物理页 */

    EptInvalidateAllContexts();

    /* 启用 MTF: 执行一条指令后 VM-Exit, 恢复 Execute-Only */
    ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
}
```

### 3.5 NPT 的妥协方案：Read+Execute 策略与隐蔽性分析

由于 AMD NPT 不支持 Execute-Only 页面，本项目在 AMD 平台上采用 **R+X（Read=1, Write=0, Execute=1）** 策略：

- **执行和读取**都直接访问 Hook 页面
- 只有**写入**才触发 NPT Fault
- PatchGuard 读取时会看到**含 JMP 指令的 Hook 页面**

妥协方案：通过 NPT Fault + RFLAGS.TF 单步机制，在检测到读取操作时动态切换页面。但由于 NPT 不区分读取和执行（都设置 R=1），无法做到 Intel 那样精确的读/执分离。

**隐蔽性对比**：

| 场景 | Intel EPT | AMD NPT |
|------|-----------|---------|
| PatchGuard 代码校验 | ✅ 完全隐蔽 | ⚠️ 需要额外处理 |
| memcmp 完整性检查 | ✅ 读取返回原始 | ❌ 读取返回 Hook |
| 代码签名验证 | ✅ 完全通过 | ⚠️ 依赖写保护触发 |
| 调试器代码检查 | ✅ 隐蔽 | ⚠️ 可见 |

### 3.6 为什么 Ring -1 的修改对 Ring 0 的 PatchGuard 完全不可见

最终的关键洞察：

1. **PatchGuard 运行在 Ring 0**（Guest 的内核态），它只能使用 Guest 视角的内存访问
2. **EPT/NPT 是硬件层面的地址翻译**，完全由 Hypervisor（Ring -1）控制
3. Guest 的任何内存访问指令都**必须**经过 EPT/NPT 翻译
4. PatchGuard **无法感知** EPT/NPT 的存在，更无法绕过它
5. 即使 PatchGuard 使用 `CR3` 直接遍历页表，翻译出的仍然是 **GPA**，最终还是要经过 EPT 翻译

这是一个**不可逾越的特权层级差**：Ring 0 的代码完全运行在 Ring -1 控制的「沙箱」内，Ring -1 对 Ring 0 拥有**完全的感知和控制能力**，而反过来 Ring 0 **无法感知** Ring -1 的存在（除非 Ring -1 允许）。

---

## 第四章：Windows Hyper-V 与嵌套虚拟化

> 📊 架构图参考: `vmx_nested_virtualization.drawio`

### 4.1 Hyper-V 架构

Microsoft Hyper-V 是一个 **Type-1 Hypervisor**，在硬件之上直接运行。即使 Windows 看起来像是 Host OS，实际上启用了 Hyper-V 后，Windows 本身也变成了一个 Guest（Root Partition）：

```
┌──────────────────────────────────────────────────────┐
│                    硬件 (CPU/内存)                     │
├──────────────────────────────────────────────────────┤
│              Hyper-V Hypervisor (L0)                  │
│                     Ring -1                           │
├──────────────┬───────────────────────────────────────┤
│ Root Partition│        Child Partitions               │
│ (Windows Host)│   (VMs: Linux, Windows Guest...)      │
│   Ring 0/3    │         Ring 0/3                     │
└──────────────┴───────────────────────────────────────┘
```

### 4.2 嵌套虚拟化的 L0/L1/L2 三层模型

当我们的 Type-2 Hypervisor（VMX Toolbox）在 Hyper-V 管理的 Windows 上运行时，形成了三层嵌套结构：

```
L0: Hyper-V        (实际控制硬件, 真正的 VMX Root)
 └─ L1: VMX Toolbox (我们的 Hypervisor, 运行在 Hyper-V Guest 中)
     └─ L2: Windows 内核 + 应用 (被 VMX Toolbox 虚拟化的 Guest)
```

**嵌套虚拟化的核心挑战**：L1 执行 VMLAUNCH/VMRESUME 等 VMX 指令时，这些指令本身就会触发 VM-Exit 到 L0。L0 需要：
1. 模拟 L1 对 VMCS 的操作
2. 管理 L1 和 L2 之间的状态切换
3. 合并两层 EPT（L1 的 EPT-12 + L0 的 EPT-01 → 实际的 EPT-02）

### 4.3 VMCS Shadowing — L0 如何虚拟化 L1 的 VMREAD/VMWRITE

传统方案中，L1 每次执行 VMREAD/VMWRITE 都会触发 VM-Exit 到 L0，由 L0 模拟。对于频繁的 VMCS 访问（每次 VM-Exit 处理几十次读写），这会导致巨大的性能开销。

**VMCS Shadowing**（Haswell+）允许 L0 为 L1 提供一个 "Shadow VMCS"。L1 的 VMREAD/VMWRITE 不再触发 VM-Exit，而是直接操作 Shadow VMCS 的内存。L0 通过位图控制哪些字段的 VMREAD/VMWRITE 允许直接执行、哪些仍需 Exit。

### 4.4 Enlightened VMCS — VP Assist Page + Clean Fields 位掩码优化

Microsoft 提供了一种更激进的优化：**Enlightened VMCS**。这是 Hyper-V 特有的协议（不在 Intel SDM 中），定义在 Hypervisor Top-Level Functional Specification (TLFS) 中。

**核心思想**：完全放弃 VMREAD/VMWRITE 指令，将 VMCS 字段映射为一个 **C 结构体**的成员，L1 直接读写结构体。

启用流程：

```c
/* 1. 写 VP Assist Page 的物理地址到 Hyper-V MSR */
__writemsr(HV_X64_MSR_VP_ASSIST_PAGE,
           CpuCtx->VpAssistPagePa | HV_VP_ASSIST_PAGE_ENABLE);

/* 2. 在 VP Assist Page 中启用 Enlightened VMCS */
VpAssist->EnlightenedVmcsEnabled = 1;
VpAssist->CurrentEnlightenedVmcs = CpuCtx->EvmcsPa;

/* 3. 初始化 eVMCS 版本和清空 Clean Fields */
Evmcs->VersionNumber = 1;
Evmcs->CleanFields = HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
```

**Clean Fields 位掩码优化**：

每个 VMCS 字段属于一个「Clean Field 组」（共 16 组）。当 L1 写入某个字段时，对应组的 Clean Bit 被**清除**。L0 在处理 VMRESUME 时，只检查 Clean Bit 被清除的字段组，**跳过未修改的字段组**。

```c
/* 写入 eVMCS 字段并自动清除对应 Clean Bit */
FORCEINLINE VOID EvmcsWrite(PHV_VMX_ENLIGHTENED_VMCS Evmcs, ULONG Field, ULONG64 Value)
{
    USHORT Offset = EvmcsFieldOffset(Field);
    PUCHAR Base = (PUCHAR)Evmcs;

    /* 按字段宽度写入 */
    switch ((Field >> 13) & 0x3) {
    case 0: *(PUSHORT)(Base + Offset) = (USHORT)Value; break;
    case 1: *(PULONG64)(Base + Offset) = Value; break;
    case 2: *(PULONG)(Base + Offset) = (ULONG)Value; break;
    case 3: *(PULONG64)(Base + Offset) = Value; break;
    }

    /* 标记对应组为 dirty */
    USHORT CleanBit = EvmcsFieldCleanBit(Field);
    if (CleanBit != HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE) {
        Evmcs->CleanFields &= ~(ULONG)CleanBit;
    }
}
```

VMRESUME 成功后，将所有 Clean Bits 重新置位：

```c
if (g_IsNestedMode && CpuCtx->EvmcsVa) {
    PHV_VMX_ENLIGHTENED_VMCS Evmcs = (PHV_VMX_ENLIGHTENED_VMCS)CpuCtx->EvmcsVa;
    Evmcs->CleanFields = HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;  /* 0xFFFF */
}
```

### 4.5 Enlightened VMCB — AMD 的嵌套优化

AMD 平台的嵌套优化类似但更简单。在 VMCB offset 0x3E0 处有一个 Enlightened VMCB 覆盖区域，包含：

```c
typedef struct _SVM_ENLIGHTENED_VMCB {
    ULONG       Version;                    /* +0x3E0: 版本号 (1) */
    ULONG       NptTlbControl;              /* +0x3E4: NPT TLB 控制 */
    ULONG       MsrBitmapEnable;            /* +0x3E8: MSR 位图使能 */
    ULONG       Reserved1;
    ULONG       VpId;                       /* +0x3F0: VP Identifier */
    ULONG       Reserved2;
    ULONG64     VmId;                       /* +0x3F8: VM Identifier */
    ULONG64     PartitionAssistPagePa;      /* +0x400: Partition Assist PA */
} SVM_ENLIGHTENED_VMCB;
```

### 4.6 嵌套 EPT 合并

当 L2 访问内存时，地址翻译需要经过两层 EPT：

```
L2 GVA → [L2 页表] → L2 GPA → [L1 的 EPT-12] → L1 GPA → [L0 的 EPT-01] → HPA
```

这个两层翻译如果每次都走两遍页表，性能极差。L0 通常会**合并**两层 EPT 为一个 EPT-02（L2 GPA → HPA），并缓存合并结果。当任何一层 EPT 发生变化时，合并缓存需要失效重建。

### 4.7 嵌套 VM-Exit 路由

L2 运行时触发的 VM-Exit 需要决定由 L0 直接处理还是转发给 L1：

- **L0 处理**：硬件中断、EPT-02 Violation（由 L0 自身的 EPT 引起的）
- **转发给 L1**：L1 配置的拦截条件匹配（CPUID、MSR 访问等）

L0 检查 L1 的 VMCS（或 eVMCS）中的控制字段来做此决策。

### 4.8 检测流程：CPUID Leaf 0x40000000 → Hyper-V 识别

本项目使用三步检测流程（`hv_detect.c`）：

```c
BOOLEAN HvDetectNestedMode(VOID)
{
    int CpuInfo[4];

    /* Step 1: 检查 Hypervisor Present 位 */
    __cpuid(CpuInfo, 1);
    if (!(CpuInfo[2] & (1 << 31)))       /* ECX[31] = 0 → 裸机 */
        return FALSE;

    /* Step 2: 识别 Microsoft Hyper-V */
    __cpuid(CpuInfo, 0x40000000);
    if (CpuInfo[1] != 0x7263694D ||       /* "Micr" */
        CpuInfo[2] != 0x666F736F ||       /* "osof" */
        CpuInfo[3] != 0x76482074)         /* "t Hv" */
        return FALSE;

    /* Step 3: 探测嵌套虚拟化 Enlightenments */
    if (g_HypervisorMaxLeaf >= 0x4000000A) {
        __cpuid(CpuInfo, 0x4000000A);
        /* EAX[0] = Enlightened VMCS support */
        /* EAX[1] = Direct virtual flush support */
    }

    g_IsNestedMode = TRUE;
    return TRUE;
}
```

---

## 第五章：Blue Pill 后加载虚拟化

> 📊 架构图参考: `late_launch_virtualization.drawio`

### 5.1 Type-2 (Blue Pill) vs Type-1 Hypervisor 的根本区别

| 特性 | Type-1 (裸机 Hypervisor) | Type-2 (Blue Pill) |
|------|-------------------------|-------------------|
| 典型代表 | Hyper-V, VMware ESXi | 本项目, HyperPlatform |
| 启动时机 | 系统启动最早期 | OS 完全运行后加载 |
| OS 地位 | OS 是 Guest | OS 不知道自己变成了 Guest |
| 内存布局 | Hypervisor 预分配 | 必须兼容现有内存布局 |
| 驱动依赖 | 无 | 作为内核驱动加载 |

Blue Pill 的名字来自电影《黑客帝国》——蓝色药丸让你留在虚拟世界中而毫无知觉。同理，Blue Pill Hypervisor 在操作系统完全运行后「悄无声息地」将整个 OS 放入虚拟机中，OS 完全不知道自己的世界发生了变化。

### 5.2 恒等映射（Identity Mapping）— GPA == HPA 的设计精髓

这是 Blue Pill 最关键的设计——**EPT/NPT 恒等映射**：将 Guest 物理地址直接映射到相同的 Host 物理地址。

```
GPA 0x00000000 → HPA 0x00000000
GPA 0x00001000 → HPA 0x00001000
GPA 0x00002000 → HPA 0x00002000
...
GPA 0x7FFFFFFFFF → HPA 0x7FFFFFFFFF   (512GB 范围)
```

本项目的实现（`ept.c`）：

```c
/* 使用 2MB 大页建立恒等映射，覆盖 512GB 物理地址空间 */
for (i = 0; i < MAX_PD_PAGES; i++) {          /* 512 个 PDPT 条目 */
    for (j = 0; j < EPT_PDE_COUNT; j++) {      /* 每个 512 个 PDE */
        PhysAddr = ((ULONG64)i * 512 + j) * (2 * 1024 * 1024);  /* 2MB 步进 */

        g_PdPages[i].Entries[j].Read = 1;
        g_PdPages[i].Entries[j].Write = 1;
        g_PdPages[i].Entries[j].Execute = 1;
        g_PdPages[i].Entries[j].LargePage = 1;    /* 2MB 大页 */
        g_PdPages[i].Entries[j].PhysAddr = PhysAddr >> 12;
    }
}
```

**为什么恒等映射如此重要**：

由于 GPA == HPA，操作系统的所有现有内存映射在启用虚拟化前后**完全不变**。OS 不需要重新映射任何页面、不需要修改任何页表、不需要通知任何驱动——一切照旧运行。

### 5.3 启用时间线 T0→T3

```
T0: DriverEntry() 执行
    - 检测 CPU 类型 (Intel/AMD)
    - 检测 Hyper-V 嵌套模式
    - 选择 g_HvOps 后端

T1: VmxInitialize() / SvmInitialize()
    - 分配 per-CPU 内存结构
    - 建立 EPT/NPT 恒等映射
    - 初始化 Hook 框架

T2: Per-CPU DPC (VmxInitDpcRoutine)
    - 在每个逻辑 CPU 上执行
    - CR4.VMXE = 1 / EFER.SVME = 1
    - VMXON / (SVM: write VM_HSAVE_PA MSR)
    - 配置 VMCS/VMCB: Guest 状态 = 当前 CPU 状态
    - Guest RIP = VmxInitDpcRoutine 中 VMLAUNCH 后的下一条指令

T3: VMLAUNCH / VMRUN 成功
    ★ 此刻 CPU 从 Root Mode 进入 Non-Root Mode
    ★ 但执行的下一条指令地址完全不变
    ★ 所有内存映射不变 (恒等映射)
    ★ 所有寄存器状态不变
    → Windows 内核继续正常执行，浑然不知
```

### 5.4 为什么 Windows 和所有 Guest 软件毫无感知

**6 个维度的无感知分析**：

1. **内存地址不变**: 恒等映射使所有虚拟/物理地址翻译结果相同
2. **指令流不中断**: Guest RIP 被设置为 VMLAUNCH 后的紧接下一条指令
3. **寄存器保留**: 所有通用寄存器、段寄存器、CR 寄存器的值在虚拟化前后完全相同
4. **CR4.VMXE 隐藏**: 通过 CR4 Guest-Host Mask 和 Read Shadow 隐藏 VMXE 位
5. **时间连续**: TSC（Time Stamp Counter）连续递增，无跳变
6. **中断正常**: NMI 和外部中断被正确转发到 Guest

```c
/* CR4 Shadow 隐藏 VMXE 位 */
VmxWrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMXE);        /* 只监控 VMXE 位 */
VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, Cr4 & ~CR4_VMXE);    /* Guest 读 CR4 时看不到 VMXE */
```

### 5.5 与传统虚拟机的根本区别

传统虚拟机 (VMware Workstation, VirtualBox) 创建一个**全新的虚拟硬件环境**，Guest OS 从零启动。而 Blue Pill：

- 不创建新的虚拟硬件
- 不启动新的 OS 实例
- 只是在现有运行环境的「下面」插入一个 Hypervisor 层
- 类比：在一个正在运行的鱼缸下面悄悄放入一个透明的支架

### 5.6 EPT/NPT 性能开销分析

恒等映射的 2MB 大页策略极大减少了 EPT/NPT 开销：

- **2MB 大页**：只需 3 级页表遍历（PML4 → PDPT → PD），不需要第 4 级 PT
- **TLB 缓存**：2MB 页的 TLB 条目更少但覆盖范围更大
- **VPID/ASID**：避免 VM-Entry/Exit 时刷新 TLB

只有在需要 Hook 时才将 2MB 大页拆分为 512 个 4KB 小页——这将开销限制在被 Hook 的具体函数所在的 2MB 区域内。

实际性能影响：
- **无 Hook 场景**: < 1% CPU 开销（仅 EPT 翻译 + 必要的 VM-Exit）
- **有 Hook 场景**: 2-5% CPU 开销（EPT Violation 处理 + MTF 单步）
- **内存开销**: ~1MB (EPT 页表) + 每个 Hook ~12KB (原始页 + Hook 页 + 元数据)

---

## 第六章：VMX 初始化全流程

> 📊 架构图参考: `vmx_init_flow.drawio`

### 6.1 DriverEntry → CPU 检测 → 后端选择

驱动加载的第一步是检测 CPU 厂商并选择对应的虚拟化后端。检测通过 `CPUID Leaf 0` 的厂商字符串完成：

```c
CPU_VENDOR HvDetectCpuVendor(VOID)
{
    int CpuInfo[4] = { 0 };
    __cpuid(CpuInfo, 0);

    /* Intel: EBX:EDX:ECX = "GenuineIntel" */
    if (CpuInfo[1] == 0x756E6547 &&    /* "Genu" */
        CpuInfo[3] == 0x49656E69 &&    /* "ineI" */
        CpuInfo[2] == 0x6C65746E)      /* "ntel" */
        return CPU_VENDOR_INTEL;

    /* AMD: EBX:EDX:ECX = "AuthenticAMD" */
    if (CpuInfo[1] == 0x68747541 &&    /* "Auth" */
        CpuInfo[3] == 0x69746E65 &&    /* "enti" */
        CpuInfo[2] == 0x444D4163)      /* "cAMD" */
        return CPU_VENDOR_AMD;

    return CPU_VENDOR_UNKNOWN;
}
```

注意 CPUID 返回的字符串是 **EBX:EDX:ECX** 顺序（不是 EBX:ECX:EDX），这是一个常见的新手陷阱。

### 6.2 能力探测：MSR 读取链

Intel VMX 的能力探测通过一系列 MSR 读取完成（`VmxCheckCapabilities`）：

```
IA32_VMX_BASIC (0x480)
    ├─ Bits [30:0]:  VMCS Revision ID
    ├─ Bit  [55]:    True Controls 支持标志
    │   └─ 如果 = 1, 读取 True 版本的 MSR:
    │       ├─ IA32_VMX_TRUE_PINBASED_CTLS  (0x48D)
    │       ├─ IA32_VMX_TRUE_PROCBASED_CTLS (0x48E)
    │       ├─ IA32_VMX_TRUE_EXIT_CTLS      (0x48F)
    │       └─ IA32_VMX_TRUE_ENTRY_CTLS     (0x490)
    └─ 否则使用标准版本:
        ├─ IA32_VMX_PINBASED_CTLS  (0x481)
        ├─ IA32_VMX_PROCBASED_CTLS (0x482)
        ├─ IA32_VMX_EXIT_CTLS      (0x483)
        └─ IA32_VMX_ENTRY_CTLS     (0x484)

IA32_VMX_PROCBASED_CTLS (0x482)
    └─ 如果 Secondary Controls 可用:
        └─ IA32_VMX_PROCBASED_CTLS2 (0x48B)
            ├─ Bit 1: Enable EPT
            ├─ Bit 3: Enable RDTSCP
            └─ Bit 5: Enable VPID

IA32_VMX_EPT_VPID_CAP (0x48C)
    ├─ Bit 0: Execute-Only EPT 支持
    ├─ Bit 6: 4-level EPT 支持
    ├─ Bit 14: WB 内存类型 EPT 支持
    ├─ Bit 16: 2MB 大页 EPT 支持
    └─ Bit 20: INVEPT 指令支持
```

关键代码：

```c
State->VmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
State->VmcsRevisionId = (ULONG)(State->VmxBasic & 0x7FFFFFFF);
State->TrueControlsSupported = (State->VmxBasic >> 55) & 1;

/* 验证必要特性: EPT 是强制要求 */
ULONG SecondaryAdj = VmxAdjustControls(
    PROC_BASED2_ENABLE_EPT | PROC_BASED2_ENABLE_RDTSCP | PROC_BASED2_ENABLE_VPID,
    State->ProcBased2Cap
);
if (!(SecondaryAdj & PROC_BASED2_ENABLE_EPT)) {
    LOG_ERROR("EPT not supported - cannot continue");
    return FALSE;
}
```

### 6.3 Per-CPU 内存分配

每个逻辑 CPU 需要独立的内存结构集合：

```
Per-CPU 内存 (VMX_CPU_CONTEXT):
┌──────────────────────────────────────────┐
│ VMXON Region    (4KB, 页对齐, 物理连续)  │ ← 必须写入 VMCS Revision ID
│ VMCS Region     (4KB, 页对齐, 物理连续)  │ ← 同上
│ MSR Bitmap      (4KB, 页对齐, 物理连续)  │ ← 控制哪些 MSR 触发 Exit
│ Host Stack      (16KB, NonPagedPool)     │ ← VM-Exit Handler 的栈
├──────────── 嵌套模式额外分配 ────────────┤
│ VP Assist Page  (4KB, 页对齐, 物理连续)  │ ← Enlightened VMCS 控制页
│ eVMCS Page      (4KB, 页对齐, 物理连续)  │ ← Enlightened VMCS 数据页
└──────────────────────────────────────────┘
```

VMXON Region 和 VMCS Region 的前 4 字节必须写入 VMCS Revision ID：

```c
CpuCtx->VmxonRegionVa = VmxAllocateAlignedMemory(PAGE_SIZE_4KB, &CpuCtx->VmxonRegionPa);
*(PULONG)CpuCtx->VmxonRegionVa = VmcsRevision;    /* 前 4 字节 = Revision ID */

CpuCtx->VmcsRegionVa = VmxAllocateAlignedMemory(PAGE_SIZE_4KB, &CpuCtx->VmcsRegionPa);
*(PULONG)CpuCtx->VmcsRegionVa = VmcsRevision;
```

### 6.4 VMCS 五阶段配置

`VmxSetupVmcs()` 函数按照 5 个阶段配置 VMCS 的约 100 个字段：

**阶段 1: VM-Execution Controls**

```c
/* Pin-Based Controls: NMI 退出 */
PinBased = VmxAdjustControls(PIN_BASED_NMI_EXIT, PinBasedCap);

/* Primary Processor-Based Controls */
ProcBased = VmxAdjustControls(
    PROC_BASED_USE_MSR_BITMAPS |        /* 使用 MSR Bitmap 而非全部拦截 */
    PROC_BASED_SECONDARY_CONTROLS |     /* 启用 Secondary Controls */
    PROC_BASED_CR3_LOAD_EXIT |          /* 拦截 CR3 写入(进程切换检测) */
    PROC_BASED_MOV_DR_EXIT |            /* 拦截 DR 寄存器访问 */
    PROC_BASED_RDTSC_EXIT,              /* 拦截 RDTSC 指令 */
    ProcBasedCap);

/* Secondary Controls */
ProcBased2 = VmxAdjustControls(
    PROC_BASED2_ENABLE_EPT |            /* 启用 EPT */
    PROC_BASED2_ENABLE_RDTSCP |         /* 允许 Guest 使用 RDTSCP */
    PROC_BASED2_ENABLE_VPID |           /* 启用 VPID (TLB 标签) */
    PROC_BASED2_ENABLE_INVPCID,         /* 允许 INVPCID 指令 */
    ProcBased2Cap);

/* Exception Bitmap: 只拦截 #DB(1) 和 #BP(3) */
VmxWrite(VMCS_CTRL_EXCEPTION_BITMAP,
         EXCEPTION_BITMAP_DB | EXCEPTION_BITMAP_BP);
```

**阶段 2: VM-Exit Controls**

```c
ExitCtls = VmxAdjustControls(
    VMEXIT_HOST_ADDR_SPACE_SIZE |       /* Host 是 64 位 */
    VMEXIT_SAVE_IA32_EFER |             /* 退出时保存 EFER */
    VMEXIT_LOAD_IA32_EFER |             /* 退出时加载 Host EFER */
    VMEXIT_ACK_INT_ON_EXIT,             /* 自动确认外部中断 */
    ExitCap);
```

**阶段 3: VM-Entry Controls**

```c
EntryCtls = VmxAdjustControls(
    VMENTRY_IA32E_MODE_GUEST |          /* Guest 运行在 64 位模式 */
    VMENTRY_LOAD_IA32_EFER,             /* 进入时加载 Guest EFER */
    EntryCap);
```

**阶段 4: Guest State**

将当前 CPU 的完整状态复制到 VMCS Guest-State 区域：

```c
/* 段寄存器: 需要从 GDT 解析 Base/Limit/AccessRights */
VmxWrite(VMCS_GUEST_CS_SEL, Cs);
VmxWrite(VMCS_GUEST_CS_BASE, VmxGetSegmentBase(GdtBase, Cs));
VmxWrite(VMCS_GUEST_CS_LIMIT, VmxGetSegmentLimit(GdtBase, Cs));
VmxWrite(VMCS_GUEST_CS_ACCESS_RIGHTS, VmxGetSegmentAccessRights(GdtBase, Cs));
/* FS/GS 的 Base 从 MSR 读取而非 GDT */
VmxWrite(VMCS_GUEST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
VmxWrite(VMCS_GUEST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));

/* 控制寄存器 */
VmxWrite(VMCS_GUEST_CR0, __readcr0());
VmxWrite(VMCS_GUEST_CR3, __readcr3());
VmxWrite(VMCS_GUEST_CR4, __readcr4());

/* VMCS Link Pointer: 0xFFFFFFFF_FFFFFFFF (无 Shadow VMCS) */
VmxWrite(VMCS_GUEST_VMCS_LINK_PTR, 0xFFFFFFFFFFFFFFFF);
```

**阶段 5: Host State**

```c
/* Host RIP: VM-Exit 时跳转的地址 = 汇编入口点 */
VmxWrite(VMCS_HOST_RIP, (ULONG64)AsmVmxExitHandler);

/* Host RSP: 使用预分配的 16KB 栈的顶部 */
VmxWrite(VMCS_HOST_RSP,
         (ULONG64)CpuCtx->HostStackBase + CpuCtx->HostStackSize - 8);

/* Host 段选择子: RPL 必须为 0 */
VmxWrite(VMCS_HOST_CS_SEL, Cs & 0xFFF8);
```

### 6.5 CR4 Shadow 隐藏技巧

启用 VMX 需要设置 `CR4.VMXE` 位，但这会暴露 Hypervisor 的存在。通过 CR4 Guest-Host Mask 和 Read Shadow 隐藏：

```c
/* Guest-Host Mask: 只对 VMXE 位感兴趣 */
VmxWrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMXE);

/* Read Shadow: 返回不含 VMXE 的 CR4 值 */
VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, Cr4 & ~CR4_VMXE);
```

当 Guest 执行 `MOV RAX, CR4` 时，对于 Mask 中标记的位（VMXE），CPU 返回 Shadow 中的值（0）而非实际值（1）。Guest 永远看不到 VMXE 被设置。

### 6.6 VMLAUNCH 与 AsmVmxExitHandler 汇编入口

VMLAUNCH 成功后，CPU 进入 Non-Root Mode，从 Guest RIP 继续执行。当 VM-Exit 发生时，CPU 跳转到 Host RIP——即 `AsmVmxExitHandler`：

```asm
AsmVmxExitHandler PROC
    ; VM-Exit 时 CPU 已自动:
    ;   - 保存 Guest 状态到 VMCS
    ;   - 加载 Host 段寄存器、CR、RSP、RIP
    ; 但 GP 寄存器仍然是 Guest 的值！必须手动保存。

    sub     rsp, 128                ; GUEST_CONTEXT 大小 (16 个 64 位寄存器)

    ; 保存全部 Guest GP 寄存器
    mov     [rsp+000h], rax         ; Rax
    mov     [rsp+008h], rcx         ; Rcx
    mov     [rsp+010h], rdx         ; Rdx
    mov     [rsp+018h], rbx         ; Rbx
    ; (RSP 从 VMCS 读取, 不保存在此)
    mov     [rsp+028h], rbp         ; Rbp
    mov     [rsp+030h], rsi         ; Rsi
    mov     [rsp+038h], rdi         ; Rdi
    mov     [rsp+040h], r8
    ; ... r9 到 r15 ...

    ; 调用 C 语言的 VM-Exit 分发函数
    mov     rcx, rsp                ; 第一个参数 = GUEST_CONTEXT 指针
    sub     rsp, 28h                ; Shadow space + 对齐
    call    VmxExitHandler          ; 返回值: AL = TRUE(继续) / FALSE(关闭)
    add     rsp, 28h

    test    al, al
    jz      VmxShutdown             ; AL == 0 → 关闭 VMX

    ; 恢复 Guest GP 寄存器
    mov     rax, [rsp+000h]
    mov     rcx, [rsp+008h]
    ; ... 恢复全部 ...
    add     rsp, 128

    vmresume                        ; 恢复 Guest 执行
    ; 如果 VMRESUME 失败, 不会到下一行
    jmp     VmxResumeFailed

VmxShutdown:
    ; 恢复所有寄存器
    ; ... 恢复代码 ...
    add     rsp, 128
    vmxoff                          ; 退出 VMX 操作
    ret
AsmVmxExitHandler ENDP
```

### 6.7 VM-Exit 分发器完整映射

`VmxExitHandler` 中的 switch 语句覆盖了 **17+ 种退出原因**：

```c
BOOLEAN VmxExitHandler(PGUEST_CONTEXT GuestContext)
{
    ULONG ExitReason = (ULONG)VmxRead(VMCS_EXIT_REASON);
    InterlockedIncrement64(&g_VmxState.CpuContexts[CpuIndex].ExitCount);

    /* 检查 VM-Entry 失败 (bit 31) */
    if (ExitReason & 0x80000000) {
        LOG_ERROR("VM-Entry failure! Reason: %u", ExitReason & 0xFFFF);
        return FALSE;
    }

    switch (ExitReason & 0xFFFF) {
    case EXIT_REASON_CPUID:         return HandleCpuid(Ctx);        /* → AadHandleCpuid */
    case EXIT_REASON_RDMSR:         return HandleRdmsr(Ctx);        /* → HandleRdmsrImpl */
    case EXIT_REASON_WRMSR:         return HandleWrmsr(Ctx);        /* → HandleWrmsrImpl */
    case EXIT_REASON_CR_ACCESS:     return HandleCrAccess(Ctx);     /* CR0/3/4 读写 */
    case EXIT_REASON_DR_ACCESS:     return HandleDrAccess(Ctx);     /* → AadHandleDrAccess */
    case EXIT_REASON_EXCEPTION_NMI: return HandleException(Ctx);    /* #DB/#BP/NMI */
    case EXIT_REASON_RDTSC:         return HandleRdtsc(Ctx);        /* → AadHandleRdtsc */
    case EXIT_REASON_RDTSCP:        return HandleRdtscp(Ctx);       /* RDTSC + TSC_AUX */
    case EXIT_REASON_EPT_VIOLATION: return HandleEptViol(Ctx);      /* → HandleEptViolation */
    case EXIT_REASON_EPT_MISCONFIG: return HandleEptMisconfig(Ctx); /* 致命错误 */
    case EXIT_REASON_MTF:           return HandleMtf(Ctx);          /* 单步完成 */
    case EXIT_REASON_VMCALL:        return HandleVmcall(Ctx);       /* Hypercall */
    case EXIT_REASON_XSETBV:        return HandleXsetbv(Ctx);       /* XCR0 写入 */
    case EXIT_REASON_INVD:          return HandleInvd(Ctx);         /* → WBINVD */
    case EXIT_REASON_INVLPG:        return HandleInvlpg(Ctx);       /* TLB 失效 */
    case EXIT_REASON_WBINVD:        return HandleWbinvd(Ctx);       /* 缓存回写 */
    case EXIT_REASON_TRIPLE_FAULT:  return HandleTripleFault(Ctx);  /* 致命 */
    case EXIT_REASON_HLT:           VmxAdvanceGuestRip(); break;
    case EXIT_REASON_EXTERNAL_INT:  break;                          /* ACK_INT 处理 */
    case EXIT_REASON_INT_WINDOW:    /* 清除中断窗口位 */ break;
    default:                        VmxAdvanceGuestRip(); break;
    }
    return TRUE;
}
```

---

## 第七章：通用 EPT/NPT Hook 框架

> 📊 架构图参考: `vmx_hook_framework.drawio`

### 7.1 架构总览：Thunk Stub → AsmGenericHookDispatcher → C Decision

本项目实现了一个与平台无关的通用 Hook 框架，其核心数据流如下：

```
被 Hook 的函数 (Guest 执行)
    │
    ▼ [EPT/NPT: Execute-Only → Hook 页面]
Thunk Stub (24 字节)
    │ mov r10, HookId      ← 标识是哪个 Hook
    │ jmp AsmGenericHookDispatcher
    ▼
AsmGenericHookDispatcher (汇编)
    ├─ Phase 1: 保存参数 (RCX/RDX/R8/R9/栈参数)
    ├─ Phase 2: call GenericHookDecide() → HOOK_DECISION
    │   ├─ PASSTHROUGH: call Trampoline, 返回原始结果
    │   ├─ LOG_ONLY:    call Trampoline, 记录日志
    │   ├─ BLOCK:       不调用, 返回 BlockReturnValue
    │   └─ MODIFY_RETVAL: call Trampoline, 替换返回值
    ├─ Phase 3: call GenericHookPostCall() (日志记录)
    └─ 返回到原始调用者
```

### 7.2 动态 Thunk 分配（每页 170 个，按需增长）

Thunk Stub 是一个 24 字节的机器码片段，负责将 Hook ID 传递给分发器：

```
┌─── Thunk Stub (24 字节) ───┐
│ 49 BA [8字节 HookId]       │  mov r10, <hook_id>    (10 字节)
│ FF 25 00000000              │  jmp [rip+0]           (6 字节)
│ [8字节 Dispatcher地址]      │  (绝对地址)            (8 字节)
└─────────────────────────────┘
```

R10 在 Windows x64 调用约定中是 volatile 寄存器（不用于参数传递），因此可以安全使用而不影响被 Hook 函数的参数（RCX, RDX, R8, R9）。

Thunk 以 4KB 页为单位动态分配：

```c
#define THUNK_STUB_SIZE     24
#define THUNKS_PER_PAGE     (0x1000 / THUNK_STUB_SIZE)   /* 170 per 4KB page */

typedef struct _THUNK_PAGE {
    struct _THUNK_PAGE *Next;       /* 链表 */
    PVOID               CodeBase;   /* 4KB 可执行页 */
    ULONG               Capacity;   /* 170 */
    ULONG               UsedCount;
    ULONG               BaseId;
} THUNK_PAGE;
```

当所有现有 Thunk 页用满时，自动分配新页并追加到链表。

### 7.3 Hook 安装流程：VA→PA→页分裂→权限设置→INVEPT

完整的 Hook 安装流程：

```
GenericHookInstall(TargetVa, ProcessId, FunctionName, Rule)
    │
    ├─1. 分配 HookId (全局自增计数器)
    │
    ├─2. AllocateThunk(HookId)
    │       → 在 Thunk 页中写入: mov r10, HookId; jmp AsmGenericHookDispatcher
    │
    ├─3. HvHookFunction(TargetVa, ThunkAddr, &Trampoline)
    │   │
    │   ├─ MmGetPhysicalAddress(TargetVa) → 获取物理地址 (PA)
    │   │
    │   ├─ EptSplitLargePage(PA)
    │   │   → 将 2MB 大页拆分为 512 个 4KB 页
    │   │   → 查找空闲 EPT_SPLIT_PAGE 结构
    │   │   → 初始化 512 个 PTE (恒等映射)
    │   │   → 修改 PDE: LargePage=0, 指向新的 PT 页
    │   │
    │   ├─ 分配 3 个辅助页:
    │   │   ├─ OriginalPage (4KB): 目标页的完整副本
    │   │   ├─ HookPage (4KB): 目标页副本 + JMP 补丁
    │   │   └─ Trampoline (64B): 原始前 14 字节 + JMP 回续地址
    │   │
    │   ├─ 在 HookPage 的目标偏移处写入 14 字节绝对 JMP:
    │   │   FF 25 00000000 [8字节: ThunkAddr]
    │   │
    │   ├─ 修改 EPT PTE:
    │   │   Read=0, Write=0, Execute=1    ← Execute-Only!
    │   │   PhysAddr = HookPage 的物理地址
    │   │
    │   └─ INVEPT (刷新 EPT TLB)
    │
    └─4. 创建 GENERIC_HOOK_ENTRY 并链入全局列表
```

### 7.4 4 种 Hook 动作

| 动作 | 值 | 行为 | 典型用途 |
|------|---|------|---------|
| `PASSTHROUGH` | 0 | 调用原始函数，返回原始结果，仅计数 | 性能统计 |
| `LOG_ONLY` | 1 | 调用原始函数，记录调用信息和返回值 | 行为审计 |
| `BLOCK` | 2 | 不调用原始函数，直接返回 `BlockReturnValue` | 功能禁用 |
| `MODIFY_RETVAL` | 3 | 调用原始函数，但将返回值替换为 `NewReturnValue` | 结果篡改 |

### 7.5 ASM 调度器三阶段

`AsmGenericHookDispatcher` 的汇编实现：

```asm
; ===== Phase 1: 保存状态 =====
push    rbp
mov     rbp, rsp
sub     rsp, 0C0h              ; 192 字节局部空间

; 保存原始参数 (被 Hook 函数的参数仍在寄存器中)
mov     [rbp-08h], rcx         ; 参数 1
mov     [rbp-10h], rdx         ; 参数 2
mov     [rbp-18h], r8          ; 参数 3
mov     [rbp-20h], r9          ; 参数 4
mov     [rbp-28h], r10         ; HookId (来自 Thunk)

; 保存调用者返回地址和栈上的第 5-8 个参数
mov     rax, [rbp+08h]
mov     [rbp-30h], rax         ; 返回地址

; ===== Phase 2: 决策 + 调用 =====
mov     rcx, r10               ; HookId
mov     rdx, [rbp-30h]         ; 调用者返回地址
lea     r8, [rbp-90h]          ; &Decision 结构体
call    GenericHookDecide       ; C 函数填充 Decision

; 检查 Action
cmp     eax, 2                 ; BLOCK?
je      _do_block

; 恢复参数并通过 Trampoline 调用原始函数
mov     rcx, [rbp-08h]
mov     rdx, [rbp-10h]
mov     r8,  [rbp-18h]
mov     r9,  [rbp-20h]
mov     rax, [rbp-90h+18h]    ; Decision.Trampoline
call    rax                    ; 调用原始函数
; RAX = 原始返回值

cmp     ecx, 3                 ; MODIFY_RETVAL?
jne     _post_call
mov     rax, [rbp-90h+10h]    ; 替换为 NewReturnValue

; ===== Phase 3: 日志 =====
_post_call:
mov     rcx, [rbp-28h]        ; HookId
mov     edx, [rbp-98h]        ; Action
mov     r8, [rbp-0A0h]        ; FinalRetVal
mov     r9, [rbp-30h]         ; CallerRetAddr
call    GenericHookPostCall

; 返回
mov     rax, [rbp-0A0h]       ; 最终返回值
mov     rsp, rbp
pop     rbp
ret
```

### 7.6 事件环形缓冲区与日志系统

Hook 事件通过一个 512 条目的环形缓冲区记录：

```c
typedef struct _HOOK_EVENT {
    ULONG       HookId;
    ULONG       ProcessId;
    ULONG64     Timestamp;
    ULONG64     ReturnAddress;      /* 调用者的返回地址 */
    ULONG64     FinalRetVal;        /* 最终返回值 */
    ULONG       ActionTaken;        /* 实际执行的动作 */
} HOOK_EVENT;

#define HOOK_EVENT_RING_SIZE    512

/* 写入端 */
Index = g_GenericHookState.EventWriteIndex;
Event = &g_GenericHookState.EventRing[Index];
/* ... 填充事件字段 ... */
g_GenericHookState.EventWriteIndex = (Index + 1) % HOOK_EVENT_RING_SIZE;

/* 读取端 (通过 IOCTL_VMX_GET_HOOK_EVENTS) */
while (Copied < MaxEntries && EventCount > 0) {
    RtlCopyMemory(&OutputBuffer[Copied],
                   &EventRing[EventReadIndex], sizeof(HOOK_EVENT));
    EventReadIndex = (EventReadIndex + 1) % HOOK_EVENT_RING_SIZE;
    EventCount--;
    Copied++;
}
```

缓冲区满时采用 **覆盖最旧条目** 策略，读写操作由 SpinLock 保护。

---

## 第八章：反反调试引擎 — 10 种技术的双层拦截

> 📊 架构图参考: `anti_anti_debug_engine.drawio`

### 8.1 双层架构概述

反反调试引擎采用 **VM-Exit Handler 层 + EPT Hook 层** 的双层架构：

```
┌──────────────────────────────────────────────────────────┐
│                 VM-Exit Handler 层 (Ring -1)              │
│                                                          │
│  拦截 CPU 指令级别的操作:                                 │
│  ① CPUID (隐藏 Hypervisor 存在)                         │
│  ② MOV DR (隐藏硬件断点)                                │
│  ③ RDTSC/RDTSCP (补偿调试暂停时间)                      │
│  ④ 异常 #DB/#BP (规范化到 SEH)                          │
│  ⑤ RDMSR/WRMSR (调试相关 MSR 拦截)                     │
├──────────────────────────────────────────────────────────┤
│                  EPT Hook 层 (Ring -1)                    │
│                                                          │
│  Hook 内核 API 函数:                                     │
│  ⑥ NtQueryInformationProcess (ProcessDebugPort 等)      │
│  ⑦ NtQuerySystemInformation (KernelDebuggerInfo)        │
│  ⑧ NtSetInformationThread (ThreadHideFromDebugger)      │
│  ⑨ NtClose (无效句柄异常抑制)                           │
│  ⑩ PEB 修改 (BeingDebugged/NtGlobalFlag/Heap Flags)    │
└──────────────────────────────────────────────────────────┘
```

### 8.2 VM-Exit 层 5 种技术详解

**① CPUID 隐藏 (`AadHandleCpuid`)**

某些保护程序通过 `CPUID Leaf 1, ECX[31]`（Hypervisor Present 位）检测虚拟化环境：

```c
if (!g_IsNestedMode && IsFeatureEnabled(GuestCr3, AAD_HIDE_CPUID)) {
    switch (Leaf) {
    case 1:
        CpuInfo[2] &= ~(1 << 31);    /* 清除 Hypervisor Present 位 */
        break;
    case 0x40000000 ... 0x40000006:
        /* 将 Hypervisor 专用叶全部清零 */
        CpuInfo[0] = CpuInfo[1] = CpuInfo[2] = CpuInfo[3] = 0;
        break;
    }
}
```

**关键细节**：在嵌套模式（运行在 Hyper-V 下）时，自动禁用 CPUID 隐藏，避免干扰 Hyper-V 自己的 CPUID 叶。

**② DR 寄存器欺骗 (`AadHandleDrAccess`)**

硬件断点存储在 DR0-DR3 中。反调试检测通过读取 DR 寄存器判断是否设置了断点：

```c
if (IsFeatureEnabled(GuestCr3, AAD_HIDE_HWBP)) {
    if (Direction == DR_ACCESS_DIRECTION_READ) {
        switch (DrNumber) {
        case 0: case 1: case 2: case 3:
            FakeValue = 0;                  /* 硬件断点地址→返回 0 */
            break;
        case 6:
            FakeValue = DR6_DEFAULT_VALUE;  /* 调试状态→返回默认值 */
            break;
        case 7:
            FakeValue = DR7_DEFAULT_VALUE;  /* 调试控制→返回无断点 */
            break;
        }
        *RegPtr = FakeValue;
    } else {
        /* 写入 DR: 允许实际写入(断点仍然生效) */
        /* 只在读取时隐藏 */
        switch (DrNumber) {
            case 0: __writedr(0, Value); break;
            /* ... */
        }
    }
}
```

**核心设计**：写入 DR 是正常执行的（硬件断点生效），只在**读取**时返回假值。这样调试器可以正常设置断点，但程序自检时看不到断点的存在。

**③ RDTSC 时间补偿 (`AadHandleRdtsc`)**

反调试常用模式：在代码段前后各读一次 TSC，如果差值过大则认为被调试。

```c
if (IsFeatureEnabled(GuestCr3, AAD_HIDE_TIMING)) {
    PHV_CPU_CONTEXT HvCtx = g_HvOps->GetCurrentCpuContext();
    if (HvCtx) {
        LONG64 Offset = HvCtx->TscOffset;
        RealTsc -= (ULONG64)Offset;    /* 减去累计的暂停时间 */
    }
}
GuestContext->Rax = (RealTsc & 0xFFFFFFFF);     /* EDX:EAX = TSC */
GuestContext->Rdx = (RealTsc >> 32);
```

**TSC 偏移累积机制**：

```c
/* 调试暂停开始 */
VOID AadNotifyDebugPause(ULONG CpuIndex) {
    HvCtx->LastDebugPauseTsc = __rdtsc();
    HvCtx->InDebugPause = TRUE;
}

/* 调试恢复 */
VOID AadNotifyDebugResume(ULONG CpuIndex) {
    ULONG64 PauseDuration = __rdtsc() - HvCtx->LastDebugPauseTsc;
    HvCtx->TscOffset += (LONG64)PauseDuration;   /* 累积到偏移量 */
    HvCtx->InDebugPause = FALSE;
}
```

**④ 异常规范化 (`AadHandleException`)**

`INT 2D` 和 `INT 3` 在调试和非调试环境下的行为不同。我们将这些异常**原样重注入 Guest**，让应用的 SEH/VEH 处理器正常处理：

```c
/* 构造注入信息 */
InjectInfo = INTERRUPT_INFO_VALID;
InjectInfo |= (Vector & INTERRUPT_INFO_VECTOR_MASK);
InjectInfo |= (IntType << INTERRUPT_INFO_TYPE_SHIFT);
if (HasErrorCode) {
    InjectInfo |= INTERRUPT_INFO_DELIVER_ERR_CODE;
    HvSetEntryExceptionErrorCode((ULONG)ErrorCode);
}
HvSetEntryInterruptionInfo(InjectInfo);
```

**⑤ MSR 拦截**

通过 MSR Bitmap 和 MSRPM 拦截调试相关 MSR（如 `IA32_DEBUGCTL`），在目标进程中返回正常值。

### 8.3 EPT Hook 层 4+2 种技术详解

**⑥ NtQueryInformationProcess Hook**

Hook 后版本调用原始函数，然后篡改返回结果：

```c
static NTSTATUS NTAPI HookNtQueryInformationProcess(...)
{
    /* 先调用原始函数 */
    Status = g_AadState.OrigNtQueryInformationProcess(
        ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);

    /* 检查是否是目标进程 */
    CurrentCr3 = __readcr3();
    Target = ProcessFindByCr3(CurrentCr3);
    if (!Target || !(Target->Flags & AAD_HIDE_DEBUGGER))
        return Status;

    /* 篡改调试相关信息类 */
    switch (ProcessInformationClass) {
    case ProcessDebugPort:          /* 0x07: 调试端口 */
        *(PULONG_PTR)ProcessInformation = 0;        /* 伪装为无调试器 */
        break;
    case ProcessDebugObjectHandle:  /* 0x1E: 调试对象句柄 */
        *(PHANDLE)ProcessInformation = NULL;
        Status = STATUS_PORT_NOT_SET;               /* 返回"未设置" */
        break;
    case ProcessDebugFlags:         /* 0x1F: 调试标志 */
        *(PULONG)ProcessInformation = 1;            /* 1 = 无调试 */
        break;
    }
    return Status;
}
```

**⑦ NtQuerySystemInformation Hook**

拦截 `SystemKernelDebuggerInformation`：

```c
if (SystemInformationClass == SystemKernelDebuggerInformation) {
    Info->KernelDebuggerEnabled = FALSE;      /* 内核调试器未启用 */
    Info->KernelDebuggerNotPresent = TRUE;    /* 内核调试器不存在 */
}
```

**⑧ NtSetInformationThread Hook**

阻止 `ThreadHideFromDebugger`（反调试常用的「投毒」技术）：

```c
if (ThreadInformationClass == 0x11 &&       /* ThreadHideFromDebugger */
    IsFeatureEnabled(CurrentCr3, AAD_HIDE_THREADINFO)) {
    return STATUS_SUCCESS;                  /* 假装成功但什么也不做 */
}
```

**⑨ NtClose Hook**

`CloseHandle` 传入无效句柄时，在调试环境下会触发异常。我们抑制这个异常：

```c
if (IsFeatureEnabled(CurrentCr3, AAD_HIDE_NTCLOSE)) {
    __try {
        Status = g_AadState.OrigNtClose(Handle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();    /* 吞掉异常 */
    }
    return Status;
}
```

### 8.4 PEB 字段修改

PEB (Process Environment Block) 包含两个常用的调试检测字段：
- `BeingDebugged` (offset +0x002): 非零表示正在被调试
- `NtGlobalFlag` (offset +0x0BC): `FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS` 组合表明调试堆

通过内存引擎直接修改这些字段（具体实现在 Heap Flags 和 Parent PID 技术中）。

### 8.5 per-process 位掩码标志与 CR3 快速匹配

每个受保护进程有一个独立的位掩码标志 `Flags`，由 `AAD_HIDE_*` 常量组合：

```c
#define AAD_HIDE_DEBUGGER       (1 << 0)    /* PEB + NtQueryInformationProcess */
#define AAD_HIDE_HWBP           (1 << 1)    /* DR0-DR7 */
#define AAD_HIDE_TIMING         (1 << 2)    /* RDTSC 补偿 */
#define AAD_HIDE_CPUID          (1 << 3)    /* CPUID 隐藏 */
#define AAD_HIDE_SYSINFO        (1 << 4)    /* NtQuerySystemInformation */
#define AAD_HIDE_EXCEPTIONS     (1 << 5)    /* 异常规范化 */
#define AAD_HIDE_NTCLOSE        (1 << 6)    /* NtClose 异常抑制 */
#define AAD_HIDE_THREADINFO     (1 << 7)    /* ThreadHideFromDebugger */
#define AAD_HIDE_HEAP           (1 << 8)    /* 堆标志隐藏 */
#define AAD_HIDE_PARENT         (1 << 9)    /* 父进程伪装 */
#define AAD_HIDE_ALL            (0xFFFFFFFF)
```

在 VM-Exit Handler 中，通过 **CR3 快速匹配** 确定当前进程是否为目标：

```c
ULONG64 GuestCr3 = HvReadGuestCr3();
Target = ProcessFindByCr3(GuestCr3);
if (Target && (Target->Flags & AAD_HIDE_HWBP)) {
    /* 此进程启用了硬件断点隐藏 */
}
```

CR3 匹配比 PID 匹配更快，因为 CR3 值可以直接从 VMCS/VMCB 读取（无需调用任何 API）。

### 8.6 嵌套模式下的兼容性处理

在 Hyper-V 嵌套虚拟化模式下，**CPUID 隐藏自动禁用**：

```c
/* 在嵌套模式下跳过 CPUID 隐藏，避免干扰 Hyper-V 的 0x40000000+ 叶 */
if (!g_IsNestedMode && IsFeatureEnabled(GuestCr3, AAD_HIDE_CPUID)) {
    /* 只在非嵌套模式下修改 CPUID 输出 */
}
```

这是因为 Hyper-V 使用 `0x40000000` 系列 CPUID 叶与 Guest OS 通信（Enlightenments, 时钟同步等），如果我们将这些叶清零会导致 Guest OS 丢失与 Hyper-V 的通信能力。

---

## 第九章：Hypervisor 内存读写引擎

> 📊 架构图参考: `hypervisor_memory_engine.drawio`

### 9.1 为什么能绕过所有反作弊驱动

传统的进程内存读写（`ReadProcessMemory`、`NtReadVirtualMemory`、`MmCopyVirtualMemory`）都经过 Windows 内核的安全检查链：

```
用户态调用 ReadProcessMemory()
    → ntdll!NtReadVirtualMemory
        → nt!NtReadVirtualMemory  ← ObRegisterCallbacks 可以拦截
            → MmCopyVirtualMemory ← 反作弊驱动可以 Hook
                → 目标进程页表遍历
                    → 物理内存读取
```

反作弊驱动（如 EAC、BattlEye）通常在以下层级部署防护：
- `ObRegisterCallbacks`：拦截 `PROCESS_VM_READ` 句柄权限
- SSDT Hook / Inline Hook：拦截 `NtReadVirtualMemory`
- `MmCopyVirtualMemory` Inline Hook

**Hypervisor 内存引擎的读写路径完全不经过任何这些检查**：

```
VMXToolbox.exe → IOCTL_VMX_READ_MEMORY → 驱动内核
    → VMCALL → Hypervisor (Ring -1)
        → 手动遍历目标进程 CR3 页表 (物理内存级别)
        → 通过恒等映射直接读取物理地址
        → 结果返回
```

在这个路径中：
1. **不使用任何 Windows API** —— 反作弊的 API Hook 无效
2. **不通过 Object Manager** —— ObRegisterCallbacks 无效
3. **不经过 Guest 页表** —— Guest 的 PTE 权限无效
4. **运行在 Ring -1** —— Ring 0 的任何驱动无法检测或拦截

### 9.2 Guest 4 级页表遍历（CR3→PML4→PDPT→PD→PT→PA）

`HvGuestVaToPa()` 函数手动遍历目标进程的 4 级页表，将虚拟地址翻译为物理地址：

```c
ULONG64 HvGuestVaToPa(ULONG64 GuestCr3, ULONG64 VirtualAddress)
{
    ULONG64 Pml4Base, Pml4e, Pdpte, Pde, Pte;

    /* 索引计算公式 (x86-64 4级分页) */
    /* PML4  Index = VA[47:39] (9 bits) */
    /* PDPT  Index = VA[38:30] (9 bits) */
    /* PD    Index = VA[29:21] (9 bits) */
    /* PT    Index = VA[20:12] (9 bits) */
    /* Offset      = VA[11:0]  (12 bits) */

    /* CR3 → PML4 基地址 (低 12 位是 PCID/标志) */
    Pml4Base = GuestCr3 & 0x000FFFFFFFFFF000ULL;

    /* Level 4: PML4 */
    Pml4eAddr = Pml4Base + ((VirtualAddress >> 39) & 0x1FF) * 8;
    if (!SafeReadPhysU64(Pml4eAddr, &Pml4e) || !(Pml4e & PAGE_PRESENT))
        return 0;

    /* Level 3: PDPT */
    PdpteAddr = (Pml4e & PAGE_ADDR_MASK_4K) + ((VirtualAddress >> 30) & 0x1FF) * 8;
    if (!SafeReadPhysU64(PdpteAddr, &Pdpte) || !(Pdpte & PAGE_PRESENT))
        return 0;
    if (Pdpte & PAGE_LARGE)    /* 1GB 大页 */
        return (Pdpte & PAGE_ADDR_MASK_1G) | (VirtualAddress & 0x3FFFFFFF);

    /* Level 2: PD */
    PdeAddr = (Pdpte & PAGE_ADDR_MASK_4K) + ((VirtualAddress >> 21) & 0x1FF) * 8;
    if (!SafeReadPhysU64(PdeAddr, &Pde) || !(Pde & PAGE_PRESENT))
        return 0;
    if (Pde & PAGE_LARGE)      /* 2MB 大页 */
        return (Pde & PAGE_ADDR_MASK_2M) | (VirtualAddress & 0x1FFFFF);

    /* Level 1: PT */
    PteAddr = (Pde & PAGE_ADDR_MASK_4K) + ((VirtualAddress >> 12) & 0x1FF) * 8;
    if (!SafeReadPhysU64(PteAddr, &Pte) || !(Pte & PAGE_PRESENT))
        return 0;

    return (Pte & PAGE_ADDR_MASK_4K) | (VirtualAddress & 0xFFF);
}
```

`SafeReadPhysU64()` 利用恒等映射直接将物理地址当作指针解引用：

```c
static BOOLEAN SafeReadPhysU64(ULONG64 PhysAddr, PULONG64 Value)
{
    if (PhysAddr == 0 || PhysAddr >= (512ULL * 1024 * 1024 * 1024))
        return FALSE;    /* 超出 512GB 恒等映射范围 */

    PULONG64 Ptr = (PULONG64)PhysAddr;    /* PA == VA (恒等映射) */
    __try {
        *Value = *Ptr;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}
```

### 9.3 物理内存直接访问（Identity Map: PA==VA）

由于 EPT/NPT 恒等映射，物理地址可以**直接作为虚拟地址使用**。这避免了使用 `MmMapIoSpace` 等系统 API，完全绕过了 Guest 操作系统。

```c
/* 直接通过物理地址访问内存 */
PhysPtr = (PVOID)PhysAddr;    /* 恒等映射: PA == VA */
if (IsRead) {
    RtlCopyMemory(Buffer + BytesDone, PhysPtr, ChunkSize);
} else {
    RtlCopyMemory(PhysPtr, Buffer + BytesDone, ChunkSize);
}
```

### 9.4 IOCTL 路径 vs VMCALL 路径对比

本项目提供两种内存访问路径：

| 特性 | IOCTL 路径 | VMCALL 路径 |
|------|-----------|-------------|
| **入口** | DeviceIoControl → IRP | VMCALL 指令 → VM-Exit |
| **执行上下文** | Ring 0 (驱动中) | Ring -1 (Hypervisor 中) |
| **性能** | 稍快 (无 VM-Exit 开销) | 稍慢 (VM-Exit + VM-Entry) |
| **隐蔽性** | 需要打开设备句柄 | 无 API 调用痕迹 |
| **参数传递** | SystemBuffer | RAX=Magic, RDX=ParamsVA |

VMCALL 路径的参数通过 `VMCALL_MEM_PARAMS` 结构传递：

```c
BOOLEAN HvHandleMemoryVmcall(PVOID GuestContext, ULONG SubCommand)
{
    ULONG64 ParamsVa = Ctx->Rdx;            /* RDX = 参数块的虚拟地址 */
    ULONG64 CallerCr3 = HvReadGuestCr3();   /* 调用者(驱动)的 CR3 */

    /* 翻译参数地址: 调用者的 VA → PA */
    ULONG64 ParamsPa = HvGuestVaToPa(CallerCr3, ParamsVa);
    PVMCALL_MEM_PARAMS Params = (PVMCALL_MEM_PARAMS)ParamsPa;  /* 恒等映射 */

    /* 执行跨进程复制: 需要两个 CR3 */
    /* Source: TargetCr3 + TargetVa → SrcPA */
    /* Dest:   CallerCr3 + BufferVa → DstPA */
    /* 直接 PA-to-PA 复制 */
    RtlCopyMemory((PVOID)DstPa, (PVOID)SrcPa, Chunk);
}
```

### 9.5 跨页边界自动处理与安全限制

`HvCopyGuestMemory()` 自动处理跨 4KB 页边界的读写：

```c
while (BytesDone < Size) {
    PhysAddr = HvGuestVaToPa(GuestCr3, GuestVa + BytesDone);

    /* 当前页内剩余字节数 */
    PageOffset = (ULONG)(PhysAddr & 0xFFF);
    ChunkSize = 0x1000 - PageOffset;
    if (ChunkSize > (Size - BytesDone))
        ChunkSize = Size - BytesDone;

    /* 复制这一块 */
    RtlCopyMemory(..., ChunkSize);
    BytesDone += ChunkSize;
    /* 下一轮循环将翻译下一个 VA → 可能是完全不同的物理页 */
}
```

安全限制：
- 单次请求最大 **64KB** (`VMX_MEM_MAX_SIZE`)
- 物理地址必须在 **512GB** 恒等映射范围内
- 使用 `__try/__except` 保护所有物理内存访问
- 翻译失败（页面未映射/Paged Out）返回 `STATUS_INVALID_ADDRESS`

---

## 第十章：SSDT & Shadow SSDT 监控与 Hook 框架

> 📊 架构图参考: `ssdt_shadow_ssdt_framework.drawio`

### 10.1 SSDT 两层发现策略

**Tier 1: 磁盘映射 (SEC_IMAGE)**

最可信的 SSDT 发现方法——从磁盘文件读取，避免内存中可能被其他驱动修改的数据：

```c
static NTSTATUS SsdtDiscoverAndResolveFromDisk(VOID)
{
    /* 1. 获取 ntoskrnl.exe 磁盘路径和加载地址 */
    SsdtGetNtoskrnlBase();

    /* 2. 以 SEC_IMAGE 方式映射到内核地址空间 */
    /*    ZwCreateSection(SEC_IMAGE) → ZwMapViewOfSection */
    SsdtMapNtoskrnlFromDisk();

    /* 3. 遍历 PE 导出表, 查找 KeServiceDescriptorTable */
    /*    比对导出名 → 获取 RVA */

    /* 4. 从映射的文件镜像中读取 KiServiceTable 条目 */
    for (i = 0; i < ServiceCount; i++) {
        LONG entry = KiServiceTable[i];
        ResolvedAddresses[i] = LiveTableVa + (entry >> 4);
    }
}
```

**Tier 2: 内存读取 (回退方案)**

如果磁盘映射失败，从 PatchGuard 保护的内存中读取：

```c
static NTSTATUS SsdtDiscoverAndResolveFromMemory(VOID)
{
    PVOID KeServiceDescTable = MmGetSystemRoutineAddress(
        L"KeServiceDescriptorTable");
    PKSERVICE_TABLE_DESCRIPTOR Desc = (PKSERVICE_TABLE_DESCRIPTOR)KeServiceDescTable;

    for (i = 0; i < Desc->Limit; i++) {
        LONG entry = Desc->Base[i];
        ResolvedAddresses[i] = (ULONG64)Desc->Base + (entry >> 4);
    }
}
```

### 10.2 KSERVICE_TABLE_DESCRIPTOR 结构与地址解析

```c
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PLONG       Base;       /* +0x00: KiServiceTable (LONG 偏移数组) */
    PULONG      Count;      /* +0x08: 未使用 (x64 永远为 NULL) */
    ULONG64     Limit;      /* +0x10: 服务总数 */
    PUCHAR      Number;     /* +0x18: 参数字节数表 (KiArgumentTable) */
} KSERVICE_TABLE_DESCRIPTOR;
```

**x64 SSDT 地址解析公式**：

```
LONG RawEntry = KiServiceTable[Index]
FunctionVA = (ULONG64)KiServiceTable + (LONG64)(RawEntry >> 4)
ArgCount   = RawEntry & 0x0F
```

低 4 位编码参数计数（单位为 ULONG64），高 28 位是**有符号相对偏移**（右移 4 位以扩大寻址范围）。

### 10.3 Shadow SSDT 发现

Shadow SSDT（`KeServiceDescriptorTableShadow`）包含 win32k 的 `NtUser*` / `NtGdi*` 系统调用。发现过程更为复杂，因为它**不作为公开导出**，且 win32k 是 **per-Session 映射**。

**Phase 1: KTHREAD.ServiceTable 偏移扫描**

KTHREAD 结构中有一个指针 `ServiceTable`，指向该线程使用的服务表。对于非 GUI 进程（如 System 进程），它指向 `KeServiceDescriptorTable`；对于 GUI 进程，它指向 `KeServiceDescriptorTableShadow`。

```c
NTSTATUS KthreadResolveServiceTableOffset(VOID)
{
    /* 1. 获取已知的 KeServiceDescriptorTable 地址 */
    PVOID KnownSdt = MmGetSystemRoutineAddress(L"KeServiceDescriptorTable");

    /* 2. 获取 System 进程 (PID=4) 的线程 */
    /* 3. 扫描 KTHREAD 结构 (前 0x400 字节) */
    for (offset = 0; offset < 0x400; offset += 8) {
        ULONG64 value = *(PULONG64)((PUCHAR)Thread + offset);
        if (value == (ULONG64)KnownSdt) {
            /* 找到匹配! 这就是 ServiceTable 偏移 */
            g_ShadowSsdtState.KthreadOffsets.ServiceTableOffset = offset;
            break;
        }
    }
    /* 4. 用第二个 System 线程验证 */
}
```

**Phase 2: 定位 Shadow 表**

```c
/* 遍历所有 GUI 进程的线程 */
for (each thread in GUI processes) {
    ULONG64 ThreadSdt = *(PULONG64)(Thread + ServiceTableOffset);
    if (ThreadSdt != KnownSdt && ThreadSdt > 0xFFFF800000000000) {
        /* 不同于普通 SSDT, 且在内核地址空间 → 候选 Shadow Table */

        /* 三重验证 */
        PKSERVICE_TABLE_DESCRIPTOR Shadow = (PKSERVICE_TABLE_DESCRIPTOR)ThreadSdt;
        if (Shadow[0].Base == NormalSsdt[0].Base &&      /* ntoskrnl 部分匹配 */
            Shadow[0].Limit == NormalSsdt[0].Limit &&
            Shadow[1].Limit > 0 && Shadow[1].Limit < 2048) {  /* win32k 部分合理 */
            /* 找到 Shadow SSDT! */
            g_ShadowSsdtState.W32pServiceTableVa = (ULONG64)Shadow[1].Base;
        }
    }
}
```

### 10.4 Win10+ 模块分裂

从 Windows 10 开始，`win32k.sys` 被拆分为三个模块：

| 模块 | 职责 |
|------|------|
| `win32kbase.sys` | 基础 GDI/User 实现 |
| `win32kfull.sys` | 完整 GDI/User 功能 |
| `win32k.sys` | 瘦包装器/调度器 |

Shadow SSDT 的函数可能分布在三个模块中。名称解析需要遍历所有 win32k* 模块的导出表。

### 10.5 Monitor 模式

```c
#define SSDT_MONITOR_OFF        0    /* 不监控 */
#define SSDT_MONITOR_ALL        1    /* 监控所有系统调用 */
#define SSDT_MONITOR_FILTERED   2    /* 只监控指定索引 */
```

FILTERED 模式允许指定最多 64 个系统调用索引进行针对性监控。

### 10.6 SSDT_HOOK_MAPPING → GenericHookInstall 委托机制

SSDT Hook 模块不直接操作 EPT/NPT，而是委托给通用 Hook 框架：

```c
typedef struct _SSDT_HOOK_MAPPING {
    struct _SSDT_HOOK_MAPPING *Next;
    ULONG       SyscallIndex;       /* SSDT 索引 */
    ULONG       GenericHookId;      /* 通用框架分配的 Hook ID */
    BOOLEAN     IsMonitorHook;      /* 是否为 Monitor 模式自动安装 */
} SSDT_HOOK_MAPPING;

NTSTATUS SsdtHookByIndex(ULONG Index, PHOOK_RULE Rule, PULONG OutHookId)
{
    ULONG64 FuncVa = g_SsdtState.ResolvedAddresses[Index];

    /* 委托给通用 Hook 框架 */
    Status = GenericHookInstall(
        FuncVa,                                 /* 目标虚拟地址 */
        0,                                      /* PID=0 (内核级) */
        g_SsdtState.NameCache[Index],           /* 函数名 */
        Rule,                                   /* Hook 规则 */
        &HookId                                 /* 返回 Hook ID */
    );

    /* 记录 SSDT Index → HookId 映射 */
    PSSDT_HOOK_MAPPING Mapping = AllocMapping();
    Mapping->SyscallIndex = Index;
    Mapping->GenericHookId = HookId;
}
```

---

## 第十一章：驱动-用户态通信架构

> 📊 架构图参考: `ioctl_communication_protocol.drawio`

### 11.1 IOCTL 协议总览

所有通信通过 `DeviceIoControl` 到设备 `\\.\VMXToolbox`，共 **27 个 IOCTL 码**，分为 **6 大功能组**：

```
功能组 1: Hypervisor 生命周期 (0x800-0x806)
┌─────────────────────────────────────────────────┐
│ IOCTL_VMX_INIT          (0x800) 初始化 VMX/SVM │
│ IOCTL_VMX_SET_TARGET    (0x801) 设置目标进程    │
│ IOCTL_VMX_REMOVE_TARGET (0x802) 移除目标进程    │
│ IOCTL_VMX_SET_CONFIG    (0x803) 更新进程配置    │
│ IOCTL_VMX_GET_LOG       (0x804) 获取日志        │
│ IOCTL_VMX_STOP          (0x805) 停止 Hypervisor │
│ IOCTL_VMX_QUERY_STATUS  (0x806) 查询状态        │
└─────────────────────────────────────────────────┘

功能组 2: 内存读写 (0x807-0x808)
┌─────────────────────────────────────────────────┐
│ IOCTL_VMX_READ_MEMORY   (0x807) 读进程内存     │
│ IOCTL_VMX_WRITE_MEMORY  (0x808) 写进程内存     │
└─────────────────────────────────────────────────┘

功能组 3: 通用 Hook (0x809-0x80C)
┌─────────────────────────────────────────────────┐
│ IOCTL_VMX_INSTALL_HOOK  (0x809) 安装 Hook      │
│ IOCTL_VMX_REMOVE_HOOK   (0x80A) 移除 Hook      │
│ IOCTL_VMX_LIST_HOOKS    (0x80B) 列出所有 Hook  │
│ IOCTL_VMX_GET_HOOK_EVENTS(0x80C) 获取事件日志  │
└─────────────────────────────────────────────────┘

功能组 4: SSDT 监控 (0x80D-0x813)
┌─────────────────────────────────────────────────┐
│ IOCTL_VMX_SSDT_INIT        (0x80D) 初始化 SSDT │
│ IOCTL_VMX_SSDT_DUMP        (0x80E) 转储 SSDT   │
│ IOCTL_VMX_SSDT_HOOK        (0x80F) Hook 系统调用│
│ IOCTL_VMX_SSDT_UNHOOK      (0x810) 移除 Hook   │
│ IOCTL_VMX_SSDT_UNHOOK_ALL  (0x811) 移除所有    │
│ IOCTL_VMX_SSDT_LIST_HOOKS  (0x812) 列出 Hook   │
│ IOCTL_VMX_SSDT_MONITOR     (0x813) 设置监控模式│
└─────────────────────────────────────────────────┘

功能组 5: Shadow SSDT 监控 (0x814-0x81A)
┌─────────────────────────────────────────────────┐
│ IOCTL_VMX_SHADOW_SSDT_INIT       (0x814)       │
│ IOCTL_VMX_SHADOW_SSDT_DUMP       (0x815)       │
│ IOCTL_VMX_SHADOW_SSDT_HOOK       (0x816)       │
│ IOCTL_VMX_SHADOW_SSDT_UNHOOK     (0x817)       │
│ IOCTL_VMX_SHADOW_SSDT_UNHOOK_ALL (0x818)       │
│ IOCTL_VMX_SHADOW_SSDT_LIST_HOOKS (0x819)       │
│ IOCTL_VMX_SHADOW_SSDT_MONITOR    (0x81A)       │
└─────────────────────────────────────────────────┘
```

所有 IOCTL 使用 `METHOD_BUFFERED`，输入/输出通过 `SystemBuffer` 传递。

### 11.2 变长输出缓冲区模式（Count + Entries[1]）

对于返回可变数量条目的查询，所有响应结构统一采用 **Count + Entries[1] 柔性数组**模式：

```c
/* 日志缓冲区 */
typedef struct _VMX_LOG_BUFFER {
    ULONG           Count;          /* 实际条目数 */
    VMX_LOG_ENTRY   Entries[1];     /* 柔性数组 */
} VMX_LOG_BUFFER;

/* Hook 列表 */
typedef struct _VMX_HOOK_LIST {
    ULONG           Count;
    VMX_HOOK_INFO   Hooks[1];
} VMX_HOOK_LIST;

/* SSDT 转储 */
typedef struct _VMX_SSDT_DUMP_RESPONSE {
    ULONG           TotalServices;
    ULONG           ReturnedCount;
    SSDT_ENTRY_INFO Entries[1];
} VMX_SSDT_DUMP_RESPONSE;

/* Hook 事件 */
typedef struct _VMX_HOOK_EVENT_BUFFER {
    ULONG       Count;
    HOOK_EVENT  Events[1];
} VMX_HOOK_EVENT_BUFFER;
```

用户态客户端需要计算所需缓冲区大小：

```c
/* 客户端示例: 查询 SSDT Hook 列表 */
ULONG BufSize = sizeof(VMX_SSDT_HOOK_LIST) +
                (MaxExpectedHooks - 1) * sizeof(SSDT_HOOK_INFO);
PVMX_SSDT_HOOK_LIST List = (PVMX_SSDT_HOOK_LIST)malloc(BufSize);
DeviceIoControl(hDevice, IOCTL_VMX_SSDT_LIST_HOOKS,
                NULL, 0, List, BufSize, &BytesReturned, NULL);
```

### 11.3 CLI 命令映射与典型使用场景

`VMXToolbox.exe` 提供了完整的命令行接口，主要命令组：

```
反反调试命令:
  --pid <PID>                     设置目标进程
  --hide-all                      启用全部 10 种隐藏技术
  --hide-debugger                 仅隐藏 PEB.BeingDebugged
  --hide-hwbp                     仅隐藏硬件断点
  --hide-timing                   仅补偿 TSC 时间
  --remove <PID>                  停止保护指定进程

Hook 管理命令:
  --install-hook <name|addr>      安装 EPT/NPT Hook
    --action <pass|log|block|modify>
    --block-retval <value>
    --new-retval <value>
    --target-pid <PID>
  --list-hooks                    列出所有活跃 Hook
  --remove-hook <id>              移除指定 Hook
  --hook-events                   读取 Hook 事件日志

内存操作命令:
  --read-mem <PID> <addr> <size>  读取进程内存
  --write-mem <PID> <addr> <hex>  写入进程内存

SSDT 监控命令:
  --ssdt-init                     初始化 SSDT 模块
  --ssdt-dump [start] [count]     转储 SSDT 条目
  --ssdt-hook <name|index>        Hook 系统调用
  --ssdt-monitor <off|all|filtered>

Shadow SSDT 命令:
  --shadow-ssdt-init              初始化 Shadow SSDT
  --shadow-ssdt-dump              转储 win32k 系统调用
  --shadow-ssdt-hook <name>       Hook NtUser/NtGdi

诊断命令:
  --status                        查询 Hypervisor 状态
  --log                           获取内核日志
```

**典型使用场景**：

```bash
# 场景 1: 对进程 1234 启用完整反反调试保护
VMXToolbox.exe --pid 1234 --hide-all

# 场景 2: 监控 NtCreateFile 系统调用
VMXToolbox.exe --ssdt-init
VMXToolbox.exe --ssdt-hook NtCreateFile --action log

# 场景 3: 读取进程 5678 地址 0x7FF12340000 处的 256 字节
VMXToolbox.exe --read-mem 5678 0x7FF12340000 256

# 场景 4: 阻止 NtTerminateProcess 并返回 STATUS_ACCESS_DENIED
VMXToolbox.exe --ssdt-hook NtTerminateProcess --action block --block-retval 0xC0000022
```

---

## 附录

### A. 关键数据结构速查表

| 结构体 | 文件 | 用途 |
|--------|------|------|
| `HV_OPS` | `hv_ops.h` | Hypervisor 操作虚函数表 (30+ 函数指针) |
| `HV_CPU_CONTEXT` | `hv_ops.h` | 通用 Per-CPU 上下文 |
| `VMX_STATE` | `vmx.h` | Intel VMX 全局状态 |
| `VMX_CPU_CONTEXT` | `vmx.h` | VMX Per-CPU: VMXON/VMCS/MSR Bitmap/Stack |
| `SVM_STATE` | `svm.h` | AMD SVM 全局状态 |
| `SVM_CPU_CONTEXT` | `svm.h` | SVM Per-CPU: VMCB/HostSaveArea/MSRPM |
| `VMCB` | `svm.h` | AMD VMCB 控制+保存区域 |
| `EPT_STATE` | `ept.h` | EPT 页表: PML4/PDPT/PD/EPTP |
| `EPT_HOOK_STATE` | `ept.h` | EPT Hook 注册表 |
| `EPT_HOOK_ENTRY` | `ept.h` | 单个 EPT Hook: 原始页/Hook页/Trampoline |
| `EPT_SPLIT_PAGE` | `ept.c` | 2MB→4KB 拆分页 (512 PTEs) |
| `GENERIC_HOOK_STATE` | `hv_hook.h` | 通用 Hook 框架全局状态 |
| `GENERIC_HOOK_ENTRY` | `hv_hook.h` | 单个通用 Hook 条目 |
| `HOOK_DECISION` | `hv_hook.h` | ASM↔C 共享决策结构 (40B) |
| `THUNK_PAGE` | `hv_hook.h` | Thunk 代码页 (170 stubs/page) |
| `AAD_STATE` | `anti_anti_debug.h` | 反反调试全局状态 |
| `SSDT_STATE` | `ssdt.h` | SSDT 全局: 地址/名称/Hook 映射 |
| `SHADOW_SSDT_STATE` | `shadow_ssdt.h` | Shadow SSDT: per-Session 状态 |
| `KSERVICE_TABLE_DESCRIPTOR` | `ssdt.c` | Windows 服务表描述符 |
| `HV_VMX_ENLIGHTENED_VMCS` | `vmx_enlightened.h` | Enlightened VMCS 4KB 结构体 |
| `HV_VP_ASSIST_PAGE` | `vmx_enlightened.h` | VP Assist Page 4KB 结构体 |
| `HOOK_RULE` | `shared.h` | Hook 行为规则 (动作/PID/返回值) |
| `HOOK_EVENT` | `shared.h` | Hook 事件日志条目 |

### B. 所有 IOCTL 码一览

| IOCTL 名 | 代码 | 方向 | 输入结构 | 输出结构 |
|-----------|------|------|----------|----------|
| `IOCTL_VMX_INIT` | 0x800 | → | 无 | 无 |
| `IOCTL_VMX_SET_TARGET` | 0x801 | → | `VMX_TARGET_INFO` | 无 |
| `IOCTL_VMX_REMOVE_TARGET` | 0x802 | → | `VMX_REMOVE_TARGET` | 无 |
| `IOCTL_VMX_SET_CONFIG` | 0x803 | → | `VMX_CONFIG_INFO` | 无 |
| `IOCTL_VMX_GET_LOG` | 0x804 | ← | 无 | `VMX_LOG_BUFFER` |
| `IOCTL_VMX_STOP` | 0x805 | → | 无 | 无 |
| `IOCTL_VMX_QUERY_STATUS` | 0x806 | ← | 无 | `VMX_STATUS` |
| `IOCTL_VMX_READ_MEMORY` | 0x807 | ↔ | `VMX_MEMORY_REQUEST` | Raw bytes |
| `IOCTL_VMX_WRITE_MEMORY` | 0x808 | → | `VMX_MEMORY_REQUEST` + data | 无 |
| `IOCTL_VMX_INSTALL_HOOK` | 0x809 | ↔ | `VMX_HOOK_REQUEST` | `VMX_HOOK_RESPONSE` |
| `IOCTL_VMX_REMOVE_HOOK` | 0x80A | → | `VMX_UNHOOK_REQUEST` | 无 |
| `IOCTL_VMX_LIST_HOOKS` | 0x80B | ← | 无 | `VMX_HOOK_LIST` |
| `IOCTL_VMX_GET_HOOK_EVENTS` | 0x80C | ← | 无 | `VMX_HOOK_EVENT_BUFFER` |
| `IOCTL_VMX_SSDT_INIT` | 0x80D | ← | 无 | `VMX_SSDT_INIT_RESPONSE` |
| `IOCTL_VMX_SSDT_DUMP` | 0x80E | ↔ | `VMX_SSDT_DUMP_REQUEST` | `VMX_SSDT_DUMP_RESPONSE` |
| `IOCTL_VMX_SSDT_HOOK` | 0x80F | ↔ | `VMX_SSDT_HOOK_REQUEST` | `VMX_SSDT_HOOK_RESPONSE` |
| `IOCTL_VMX_SSDT_UNHOOK` | 0x810 | → | `VMX_SSDT_UNHOOK_REQUEST` | 无 |
| `IOCTL_VMX_SSDT_UNHOOK_ALL` | 0x811 | → | 无 | 无 |
| `IOCTL_VMX_SSDT_LIST_HOOKS` | 0x812 | ← | 无 | `VMX_SSDT_HOOK_LIST` |
| `IOCTL_VMX_SSDT_MONITOR` | 0x813 | → | `VMX_SSDT_MONITOR_REQUEST` | 无 |
| `IOCTL_VMX_SHADOW_SSDT_INIT` | 0x814 | ← | 无 | `VMX_SHADOW_SSDT_INIT_RESPONSE` |
| `IOCTL_VMX_SHADOW_SSDT_DUMP` | 0x815 | ↔ | `VMX_SHADOW_SSDT_DUMP_REQUEST` | `VMX_SHADOW_SSDT_DUMP_RESPONSE` |
| `IOCTL_VMX_SHADOW_SSDT_HOOK` | 0x816 | ↔ | `VMX_SHADOW_SSDT_HOOK_REQUEST` | `VMX_SHADOW_SSDT_HOOK_RESPONSE` |
| `IOCTL_VMX_SHADOW_SSDT_UNHOOK` | 0x817 | → | `VMX_SHADOW_SSDT_UNHOOK_REQUEST` | 无 |
| `IOCTL_VMX_SHADOW_SSDT_UNHOOK_ALL` | 0x818 | → | 无 | 无 |
| `IOCTL_VMX_SHADOW_SSDT_LIST_HOOKS` | 0x819 | ← | 无 | `VMX_SHADOW_SSDT_HOOK_LIST` |
| `IOCTL_VMX_SHADOW_SSDT_MONITOR` | 0x81A | → | `VMX_SHADOW_SSDT_MONITOR_REQUEST` | 无 |

### C. 参考文献

1. **Intel® 64 and IA-32 Architectures Software Developer's Manual (SDM)**
   - Volume 3C: Chapter 23-33 (VMX)
   - Volume 3A: Chapter 4 (Paging), Chapter 28 (EPT)

2. **AMD64 Architecture Programmer's Manual (APM)**
   - Volume 2: Chapter 15 (SVM)
   - Volume 2: Appendix B (VMCB Layout)

3. **Microsoft Hypervisor Top-Level Functional Specification (TLFS)**
   - Version 6.0b: Chapters 10-16 (Nested Virtualization, Enlightenments)
   - VP Assist Page, Enlightened VMCS, Partition Assist Page

4. **Windows Internals, 7th Edition** (Yosifovich, Ionescu, Russinovich, Solomon)
   - Part 2: Chapter 8 (System Mechanisms - PatchGuard)
   - Part 1: Chapter 4 (Memory Management - Page Tables)

5. **相关开源项目**
   - HyperPlatform (Satoshi Tanda)
   - hvpp (wbenny)
   - SimpleVisor (Alex Ionescu)

---

> 📊 **本文引用的架构图文件清单**:
> 1. `vmx_nested_virtualization.drawio` — 嵌套虚拟化三层模型 (第一章、第四章)
> 2. `vmx_init_flow.drawio` — VMX 初始化流程 (第一章、第六章)
> 3. `svm_vs_vmx_architecture.drawio` — Intel/AMD 架构对比 (第二章)
> 4. `vmx_hook_framework.drawio` — EPT/NPT Hook 框架 (第三章、第七章)
> 5. `late_launch_virtualization.drawio` — 后加载虚拟化 (第五章)
> 6. `anti_anti_debug_engine.drawio` — 反反调试引擎 (第八章)
> 7. `hypervisor_memory_engine.drawio` — Hypervisor 内存引擎 (第九章)
> 8. `ssdt_shadow_ssdt_framework.drawio` — SSDT/Shadow SSDT 框架 (第十章)
> 9. `ioctl_communication_protocol.drawio` — IOCTL 通信协议 (第十一章)
