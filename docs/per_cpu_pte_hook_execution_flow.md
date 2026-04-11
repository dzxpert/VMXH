# Per-CPU PTE 方案：Hook 与非 Hook 执行流程全分析

## 一、核心原理：EPT 权限分流

整个方案的核心是利用 **EPT（Extended Page Tables）的权限位** 来实现执行（Execute）和读（Read）访问的物理地址分流：

- **原始页面**（`OriginalPage`）：未修改的原始代码页面副本
- **Hook 页面**（`HookPage`）：包含 JMP 跳板的修改后代码页面副本

CPU 的每次内存访问都会经过 EPT 翻译，EPT PTE 上的 R/W/X 权限位决定了哪种访问被允许、哪种会触发 **EPT Violation**。

---

## 二、两种模式

### 模式 A：支持 Execute-Only（R=0, W=0, X=1）

这是最理想的模式，现代物理 CPU 通常支持。

### 模式 B：不支持 Execute-Only（R=0, W=0, X=0）

嵌套虚拟化（VMware/Hyper-V）通常不暴露 Execute-Only 位。

检测逻辑在初始化时完成（`ept.c`）：

```c
{
    ULONG64 EptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
    g_EptHookState.ExecuteOnlySupported = (EptVpidCap & 1) != 0;

    LOG_INFO("EPT Execute-Only pages: %s",
             g_EptHookState.ExecuteOnlySupported ? "supported" : "NOT supported (fallback to R+X)");
}
```

---

## 三、详细执行流程

### ▶ 阶段 1：Hook 安装（`EptHookFunction`）

```
EptHookFunction(TargetVa, HookFunction, &OriginalFunction)
```

**步骤：**

1. **翻译目标 VA → PA**，确定所在的 4KB 物理页面（`PageBase`）
2. **Split 2MB → 4KB**：调用 `EptSplitLargePage`，将包含目标的 2MB 大页拆分成 512 个 4KB PTE
3. **分配两个页面副本**：
   - `OriginalPageVa`：原始代码的完整副本（给读/写看的）
   - `HookPageVa`：在目标函数入口处写入了 `MOV RAX, <HookFunction>; JMP RAX` 的修改副本
4. **构建 Trampoline**：保存原始指令 + JMP 回原函数（`OriginalBytes + JMP TargetVa+size`）
5. **设置 EPT PTE 权限**，指向 Hook 页面（`ept.c`）：

```c
Pte->Read = 0;
Pte->Write = 0;
Pte->PhysAddr = Hook->HookPagePa >> 12;

if (g_EptHookState.ExecuteOnlySupported) {
    Pte->Execute = 1;
} else {
    Pte->Execute = 0;
}
```

6. **Per-CPU 隔离**：将 PD 和 PT 页克隆到每个 CPU 的私有副本，并将相同的权限设置复制到所有 CPU 的私有 PTE 上（`ept.c`）：

```c
if (g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages) {
    // ... 确保 per-CPU PD 和 PT 页存在 ...
    // 复制 hook PTE 权限到所有 CPU
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        PEPT_PTE CpuPte = EptGetPerCpuPte(cpu, TargetPa);
        if (CpuPte) {
            CpuPte->Read = Pte->Read;
            CpuPte->Write = Pte->Write;
            CpuPte->Execute = Pte->Execute;
            CpuPte->PhysAddr = Pte->PhysAddr;
        }
    }
}
```

**Hook 安装后的 EPT PTE 状态：**

| 模式 | R | W | X | PhysAddr 指向 |
|------|---|---|---|--------------|
| 模式 A (Execute-Only) | 0 | 0 | 1 | HookPage |
| 模式 B (无 Execute-Only) | 0 | 0 | 0 | HookPage |

---

### ▶ 阶段 2：稳态下的各种访问

#### 场景 1：代码执行（Guest 执行到 Hook 地址）

**模式 A（Execute-Only 支持）：**

```
Guest 执行到 TargetVa
    → CPU 做 EPT 翻译
    → PTE: R=0, W=0, X=1, PhysAddr = HookPage
    → 执行被允许（X=1），CPU 直接从 HookPage 取指
    → 执行到 Hook 入口处的 JMP 跳板
    → MOV RAX, <HookFunction>; JMP RAX
    → 跳转到我们的 Hook 函数
    ✅ 没有 VM-Exit，零开销！
```

**模式 B（无 Execute-Only）：**

```
Guest 执行到 TargetVa
    → CPU 做 EPT 翻译
    → PTE: R=0, W=0, X=0
    → EPT Violation！（instruction fetch，无执行权限）
    → VM-Exit，进入 HandleEptViolation()
```

然后在 Handler 中（`ept.c` `HandleEptViolation`）：

```c
{
    // 获取 Guest RIP 的物理页面
    RipPa = MmGetPhysicalAddress((PVOID)GuestRip);
    GuestRipPagePa = RipPa.QuadPart & PAGE_MASK_4KB;

    // 临时放开为 RWX
    Pte->Read = 1;
    Pte->Write = 1;
    Pte->Execute = 1;

    if (GuestRipPagePa == Hook->TargetPhysicalAddr) {
        /* 执行：RIP 在 hook 页面内 → 用 HookPage */
        Pte->PhysAddr = Hook->HookPagePa >> 12;
    } else {
        /* 数据访问：RIP 在别处 → 用 OriginalPage */
        Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
    }

    // 启用 MTF 单步，执行一条指令后恢复
    EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);
    ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
}
```

**关键判断**：比较 Guest RIP 所在物理页面 vs Hook 目标物理页面：
- RIP 在 hook 页面上 → 是 instruction fetch → 指向 HookPage（带 JMP）
- RIP 不在 hook 页面上 → 是数据读/写 → 指向 OriginalPage（干净代码）

---

#### 场景 2：数据读取（如 PatchGuard 扫描代码完整性）

**模式 A（Execute-Only）：**

```
PatchGuard 读取 TargetVa 的内容
    → CPU 做 EPT 翻译
    → PTE: R=0, W=0, X=1, PhysAddr = HookPage
    → 读被拒绝（R=0）！EPT Violation
    → VM-Exit，进入 HandleEptViolation()
```

Handler 中的处理（`ept.c` `HandleEptViolation`）：

```c
if (IsRead || IsWrite) {
    /* 数据访问：展示原始页面（仅在当前 CPU 上） */
    Pte->Read = 1;
    Pte->Write = 1;
    Pte->Execute = 0;
    Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;  // ← 原始物理页面！

    EptInvalidateAllContexts();

    /* 记录当前 CPU 放松了哪个页面 */
    EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);

    // 启用 MTF，执行一条指令后恢复
    ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
}
```

注意切换到的状态：**R=1, W=1, X=0, PhysAddr = 原始物理页面**

这意味着：
- ✅ 读到的是**原始未修改的代码**（PatchGuard 看到干净的原始代码）
- ✅ 执行被禁止（X=0），防止在此状态下误执行

**模式 B（无 Execute-Only）：** 与模式 A 相似，但是通过比较 `GuestRipPagePa != Hook->TargetPhysicalAddr` 来判断是数据读取，然后指向原始页面。

---

#### 场景 3：MTF 触发后恢复（`HandleMtf`）

在放松权限让 Guest 执行完一条指令后，MTF（Monitor Trap Flag）会在下一条指令前触发 VM-Exit，此时恢复原始 hook 状态（`vmx_exit.c` `HandleMtf`）：

```c
for (i = 0; i < MAX_EPT_HOOKS; i++) {
    if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
        if (RelaxedPa != 0 &&
            g_EptHookState.Hooks[i].TargetPhysicalAddr != RelaxedPa) {
            continue;  // 只恢复当前 CPU 放松的页面
        }

        {
            PEPT_PTE Pte = EptGetPerCpuPte(CpuIndex, ...);
            if (!Pte) Pte = g_EptHookState.Hooks[i].TargetPte;

            if (Pte->Read || Pte->Write) {
                Pte->Read = 0;
                Pte->Write = 0;
                Pte->PhysAddr = g_EptHookState.Hooks[i].HookPagePa >> 12;

                if (g_EptHookState.ExecuteOnlySupported) {
                    Pte->Execute = 1;  // 恢复 X-only
                } else {
                    Pte->Execute = 0;  // 恢复全禁止
                }
            }
        }
    }
}
```

恢复为初始的 hook 状态（模式 A: `R=0,W=0,X=1`；模式 B: `R=0,W=0,X=0`），继续守卫。

---

## 四、Per-CPU 隔离如何解决多核竞争

### 问题：共享 PTE 的竞态条件

如果没有 per-CPU PTE 隔离，以下竞态会发生：

```
时间线:
  CPU 0: EPT Violation → PTE 改为 R=1,W=1,X=0 → 等 MTF
  CPU 1: EPT Violation → 同一个 PTE 改为 R=1,W=1,X=0 → 等 MTF
  CPU 0: MTF 触发 → 恢复 PTE 为 R=0,W=0,X=1
  CPU 1: 还没执行完，但 PTE 已经被 CPU 0 改回去了！→ 再次 EPT Violation → 死循环
```

### 解决：Per-CPU 方案的页表链路

```
       共享模板                      CPU 0 私有                CPU 1 私有
      ┌─────────┐                ┌─────────┐              ┌─────────┐
      │ PML4    │                │ PML4[0] │              │ PML4[0] │
      │ (模板)   │                │→CPU0 PDPT│             │→CPU1 PDPT│
      └─────────┘                └─────────┘              └─────────┘
                                      ↓                        ↓
                                ┌──────────┐             ┌──────────┐
                                │ PDPT[x]  │             │ PDPT[x]  │
                                │→CPU0 PD  │             │→CPU1 PD  │
                                └──────────┘             └──────────┘
                                      ↓                        ↓
                   非Hook区域 → 共享 PD 页（相同物理地址）
                   Hook 区域  → 各自私有 PD 页
                                      ↓                        ↓
                                ┌──────────┐             ┌──────────┐
                                │ PD[y]    │             │ PD[y]    │
                                │→CPU0 PT  │             │→CPU1 PT  │
                                └──────────┘             └──────────┘
                                      ↓                        ↓
                                ┌──────────┐             ┌──────────┐
                                │ PT[z]    │             │ PT[z]    │
                                │R=0,W=0   │             │R=1,W=1   │  ← 独立！
                                │X=1,Hook  │             │X=0,Orig  │
                                └──────────┘             └──────────┘
```

### VMCS 中的 Per-CPU EPTP

每个 CPU 的 VMCS 中写入了各自的 EPTP（`vmx_init.c` → `EptSetupIdentityMap`）：

```c
if (g_EptCpuStates && CpuNum < g_MaxProcessors) {
    VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptCpuStates[CpuNum].Eptp.Value);
} else {
    VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptState.Eptp.Value);
}
```

### EPT Violation Handler 中使用 Per-CPU PTE

在 EPT Violation Handler 中优先使用 per-CPU PTE（`ept.c` `HandleEptViolation`）：

```c
Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
if (!Pte) {
    /* 回退到共享 PTE */
    Pte = Hook->TargetPte;
}
```

这样 **CPU 0 修改自己的 PTE 不会影响 CPU 1 的 PTE**，彻底消除竞态条件。

---

## 五、完整状态机总结

```
┌─────────────────────────────────────────────────────────┐
│                  稳态 (HOOK 安装后)                       │
│  模式A: R=0, W=0, X=1, PhysAddr = HookPage              │
│  模式B: R=0, W=0, X=0, PhysAddr = HookPage              │
└───────────────┬──────────────────────┬──────────────────┘
                │                      │
        [执行访问]                [读/写访问]
                │                      │
                ▼                      ▼
   ┌────────────────────┐  ┌──────────────────────────┐
   │  模式A: 直接执行     │  │ EPT Violation             │
   │  HookPage 上的代码   │  │ → 切换到 OriginalPage     │
   │  → JMP HookFunc     │  │ → R=1,W=1,X=0            │
   │  (零VM-Exit开销!)    │  │ → 启用 MTF               │
   │                     │  │ → Guest 读到原始代码       │
   │  模式B: EPT Violation│  └──────────┬───────────────┘
   │  → 判断 RIP 在页面内  │             │
   │  → 切换到 HookPage   │        [MTF: 下一条指令]
   │  → R=1,W=1,X=1      │             │
   │  → 启用 MTF          │             ▼
   │  → 执行 JMP          │  ┌──────────────────────────┐
   └──────────┬──────────┘  │ HandleMtf:               │
              │             │ 恢复为稳态               │
         [MTF: 模式B]       │ 模式A: R=0,W=0,X=1,Hook  │
              │             │ 模式B: R=0,W=0,X=0,Hook  │
              ▼             └──────────────────────────┘
   ┌────────────────────┐
   │ HandleMtf:         │
   │ 恢复为稳态          │
   └────────────────────┘
```

---

## 六、关键设计保证

| 保证 | 实现方式 |
|------|---------|
| **执行走 Hook** | EPT PTE 的 PhysAddr 指向 HookPage（含 JMP 跳板） |
| **读走原始** | EPT Violation → 临时切换 PhysAddr 到 OriginalPage |
| **单指令后恢复** | MTF（Monitor Trap Flag）单步后立即恢复 hook 状态 |
| **多核不冲突** | 每 CPU 独立 PML4→PDPT→PD→PT 链，修改私有 PTE |
| **PatchGuard 看到干净代码** | 读操作永远看到 OriginalPage 的未修改内容 |
| **Fallback 安全** | 若 per-CPU 未初始化，回退到共享 PTE（功能不变，但有竞态风险） |

---

## 七、涉及的关键源文件

| 文件 | 功能 |
|------|------|
| `driver/ept.c` | EPT 核心引擎：页表构建、Split 2MB→4KB、Hook 安装、EPT Violation 处理、Per-CPU PTE 管理 |
| `driver/ept.h` | EPT 数据结构定义：`EPT_CPU_STATE`、`EPT_HOOK_ENTRY`、函数声明 |
| `driver/vmx_exit.c` | VMX Exit Handler：`HandleEptViolation` 调度、`HandleMtf` 恢复 hook 状态 |
| `driver/vmx_init.c` | VMX 初始化：设置 VMCS、写入 Per-CPU EPTP |
| `driver/npt.c` | AMD NPT 对应实现（SVM 架构的镜像版本） |
| `driver/npt.h` | NPT 数据结构定义：`NPT_CPU_STATE`、函数声明 |
| `driver/svm_exit.c` | SVM Exit Handler：对应 AMD 的 #NPF 处理和 #DB 恢复 |
| `driver/svm_init.c` | SVM 初始化：设置 VMCB、写入 Per-CPU nested_cr3 |
