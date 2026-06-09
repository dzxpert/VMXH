简体中文 | [English](EPT_Analysis.md)

# EPT (Extended Page Tables) 深度分析

> **注意（2026-04 更新）**: 本文档中多处描述的 "512GB identity map" / `MAX_PD_PAGES=512` / `for (i = 0; i < MAX_PD_PAGES; i++)` 等均已升级为**动态尺寸**。实际运行期：
> - `g_EptPdptTotal` 是启动时由 `EptComputeRequiredPdPages()` 根据 `MmGetPhysicalMemoryRanges()` 返回值（+2GB MMIO 余量）动态计算的 PDPT 项数。
> - `g_EptPml4Count` 可 > 1，额外 PDPT 页存在 `g_EptExtPdptPages`，通过 `EptPaToFlatPdptIdx()` + `EptGetSharedPdptePtr()` 统一扁平索引访问。
> - `HandleEptViolation` 对超出映射范围的 GPA 直接 fatal-shutdown VMX，避免死循环。
>
> NPT 侧（`g_NptPdptTotal` / `g_NptPml4Count`）镜像实现同样优化。
>
> 详见 [BAREMETAL_REVIEW_FIXES.md](./BAREMETAL_REVIEW_FIXES.md) 的 H-2。

## 1. EPT 是什么？

EPT 是 **Intel VT-x 虚拟化专有的硬件特性**，只有在 VMX non-root（Guest）模式下才会被 CPU 激活使用。AMD 对应的技术叫 **NPT (Nested Page Tables)**，原理相同。

### 没有虚拟化时的地址转换

```
普通环境 (无 Hypervisor):

  程序虚拟地址 (VA)  ──→  CR3 页表  ──→  物理地址 (PA)  ──→  内存
                         (1次页表遍历)
```

只有一层翻译：VA → PA，由 CR3 指向的页表完成。

### 有虚拟化时的地址转换

```
虚拟化环境 (EPT 开启):

  Guest VA  ──→  Guest CR3 页表  ──→  Guest PA (GPA)
                                          │
                                          ▼
                                    EPT 页表 (EPTP)  ──→  Host PA (HPA)  ──→  内存
                                   (第2次页表遍历)
```

两层翻译：
1. **Guest CR3 页表**：VA → GPA（Guest 操作系统自己管理，它以为 GPA 就是真实物理地址）
2. **EPT 页表**：GPA → HPA（Hypervisor 管理，Guest 完全不知道这层存在）

### 关键点

| 问题 | 答案 |
|------|------|
| EPT 在裸机上存在吗？ | **不存在**，CPU 没进入 VMX 模式就不会走 EPT |
| 谁开启 EPT？ | Hypervisor 在 VMCS 的 Secondary Proc-Based Controls 中设置 `Enable EPT` 位 |
| Guest 知道 EPT 吗？ | **不知道**，Guest 以为自己的 GPA 就是真实物理地址 |
| EPT 是 Intel 专有吗？ | Intel 叫 **EPT**，AMD 叫 **NPT (Nested Page Tables)**，原理相同 |

### 性能代价

EPT 引入后，**每次 Guest CR3 页表遍历的每一级**都要通过 EPT 再做一次翻译：

```
Guest VA → PA 的 4 级页表遍历中:
  读 PML4E → EPT 翻译 (4级)    = 4次内存访问
  读 PDPTE → EPT 翻译 (4级)    = 4次内存访问
  读 PDE   → EPT 翻译 (4级)    = 4次内存访问
  读 PTE   → EPT 翻译 (4级)    = 4次内存访问
  最终数据 → EPT 翻译 (4级)    = 4次内存访问
                                ─────────────
  最坏情况: 4×5 = 20 次内存访问  (vs 裸机 4 次)
```

这就是为什么 CPU 有 **TLB 缓存** — 一旦缓存了 GVA → HPA 的映射，后续访问就不需要重复遍历两层页表了。`INVEPT` 指令就是刷新这个 EPT TLB 缓存。

---

## 2. EPT 4级页表结构（本项目实现）

### 数据结构总览

```
EPT 4 级页表 (恒等映射 512GB 物理地址空间):

PML4[0] ──> PDPT[512] ──> PD[512][512] ──> 2MB Large Pages
                                |
                         EptSplitLargePage()
                                |
                                v
                          PT[512] ──> 4KB Pages (用于 Hook)
```

### 代码中的数据结构映射

```c
// ept.h - 4级 EPT 表项定义

EPT_PML4E  (ept.h:78)    // 第1级: PML4 表项 (512个)
EPT_PDPTE  (ept.h:97)    // 第2级: PDPT 表项 (512个)
EPT_PDE    (ept.h:117)   // 第3级: PD 表项   (512个/PD, 共512个PD)
EPT_PTE    (ept.h:137)   // 第4级: PT 表项   (512个, 仅拆分后存在)

// ept.c - 全局状态
EPT_STATE     g_EptState          // 共享模板 (PML4 + PDPT + EPTP)
EPT_PD_PAGE  *g_PdPages          // PD 页面数组 [512]
EPT_SPLIT_PAGE *g_SplitPages     // 拆分页面池 [128]
EPT_CPU_STATE *g_EptCpuStates    // Per-CPU EPT 根 (每CPU独立)
```

### 每一级表项的 Bit 布局

```
EPT PML4E / PDPTE / PDE / PTE 通用字段:
 ┌───────────────────────────────────────────────────────────────────┐
 │ 63  62:52  51:12        11  10  9  8  7     6:3     2  1  0     │
 │  │   Ign   │ PhysAddr   │Ign│UX│Ign│A│L/Ign│MemType│ X│ W│ R   │
 └───────────────────────────────────────────────────────────────────┘
  R (bit 0):  Read  允许读
  W (bit 1):  Write 允许写
  X (bit 2):  Execute 允许执行
  A (bit 8):  Accessed (CPU自动设置)
  L (bit 7):  LargePage (PDE: 2MB大页 / PDPTE: 1GB大页)
  PhysAddr (bits 51:12): 下一级表/最终物理页的 物理地址>>12
```

---

## 3. EPT 地址转换：GPA → HPA（硬件自动完成）

### 整体架构图

```
┌─────────────────────────────────────────────────────────────────────┐
│                        代码中的数据结构                              │
│                                                                     │
│  EPT_STATE.g_EptState:                                              │
│  ┌──────────┐                                                       │
│  │ PML4[512]│ ──→ 只有 PML4[0] 有效                                 │
│  │   [0]    │ ──→ 指向 PDPT 物理地址                                │
│  │ [1..511] │     (未使用, R=0 W=0 X=0)                            │
│  └────┬─────┘                                                       │
│       ▼                                                             │
│  ┌──────────────────────┐                                           │
│  │ PDPT[512]            │  ← g_EptState.Pdpt[]                      │
│  │  [0] → PD#0 的 PA    │                                           │
│  │  [1] → PD#1 的 PA    │                                           │
│  │  ...                  │  每个 PD 覆盖 1GB                         │
│  │ [511] → PD#511 的 PA │  总共覆盖 512 GB                          │
│  └──────┬───────────────┘                                           │
│         │ (每个入口指向一个 PD 页面)                                  │
│         ▼                                                            │
│  ┌─────────────────────────────────────┐                             │
│  │ g_PdPages[i].Entries[512]  (PD)     │  ← EPT_PDE                 │
│  │                                     │                             │
│  │ 默认: LargePage=1 (2MB 大页)        │  ← 恒等映射                 │
│  │   PDE[j] = R=1,W=1,X=1,L=1,        │                             │
│  │            PhysAddr = (i*512+j)*2MB │                             │
│  │                                     │                             │
│  │ Hook 后: LargePage=0               │  ← 已拆分                    │
│  │   PDE[j] → PT页面物理地址           │                             │
│  └──────────────┬──────────────────────┘                             │
│                 │ (拆分后指向 PT)                                    │
│                 ▼                                                    │
│  ┌─────────────────────────────────────┐                             │
│  │ g_SplitPages[idx].Pte[512]   (PT)   │  ← EPT_PTE                 │
│  │                                     │                             │
│  │ PTE[k]: 4KB 粒度                   │                             │
│  │   正常: R=1,W=1,X=1,              │                             │
│  │          PhysAddr = 原始物理页       │                             │
│  │   Hook: R=0,W=0,X=0(或1),         │                             │
│  │          PhysAddr = HookPage的PA   │                             │
│  └─────────────────────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────┘
```

### GPA 位域拆分

```
GPA (Guest Physical Address) 48位:

  47      39 38      30 29      21 20      12 11          0
 ┌─────────┬──────────┬──────────┬──────────┬─────────────┐
 │ PML4 idx│ PDPT idx │  PD idx  │  PT idx  │ Page Offset │
 │  9 bits │  9 bits  │  9 bits  │  9 bits  │  12 bits    │
 └─────────┴──────────┴──────────┴──────────┴─────────────┘
    ①          ②           ③          ④          ⑤
```

### 转换过程详解

假设 Guest 要访问 **GPA = `0x00000000'FFFFF800`**，CPU 硬件执行以下步骤：

#### Step 1: 读取 EPTP（从 VMCS）

```
EPTP (VMCS field 0x201a) = g_EptState.Eptp.Value
  ├─ MemoryType = WB (6)
  ├─ PageWalkLength = 3 (表示4级)
  └─ Pml4PhysAddr  = g_EptState.Pml4Pa >> 12  (PML4 表的物理地址)
```

对应代码 (`ept.c:1012`):
```c
g_EptState.Eptp.Value = 0;
g_EptState.Eptp.MemoryType = EPT_MEMORY_TYPE_WB;          // 6
g_EptState.Eptp.PageWalkLength = EPT_PAGE_WALK_LENGTH_4;   // 3 (表示4级)
g_EptState.Eptp.Pml4PhysAddr = g_EptState.Pml4Pa >> 12;
```

#### Step 2: 第 1 级 — PML4 遍历（位 47:39）

```
PML4 index = GPA[47:39] = 0x000  → PML4[0]

读取 PML4[0]:
  Value = g_EptState.Pml4[0]
  R=1, W=1, X=1
  PhysAddr = VaToPhysical(g_EptState.Pdpt) >> 12   ← PDPT 的物理地址
```

**结果**：得到 PDPT 表的物理基地址。

对应代码 (`ept.c:1001`):
```c
PdptPa = VaToPhysical(g_EptState.Pdpt);
g_EptState.Pml4[0].Value = 0;
g_EptState.Pml4[0].Read = 1;
g_EptState.Pml4[0].Write = 1;
g_EptState.Pml4[0].Execute = 1;
g_EptState.Pml4[0].PhysAddr = PdptPa >> 12;
```

#### Step 3: 第 2 级 — PDPT 遍历（位 38:30）

```
PDPT index = GPA[38:30]

读取 PDPT[i] = g_EptState.Pdpt[i]:
  R=1, W=1, X=1
  LargePage = 0      (不是 1GB 大页)
  PhysAddr = VaToPhysical(&g_PdPages[i]) >> 12   ← PD#i 的物理地址
```

**结果**：得到 PD 表的物理基地址。每个 PD 覆盖 1GB 地址空间。

对应代码 (`ept.c:979`):
```c
for (i = 0; i < MAX_PD_PAGES && i < EPT_PDPTE_COUNT; i++) {
    ULONG64 PdPa = VaToPhysical(&g_PdPages[i]);
    g_EptState.Pdpt[i].Value = 0;
    g_EptState.Pdpt[i].Read = 1;
    g_EptState.Pdpt[i].Write = 1;
    g_EptState.Pdpt[i].Execute = 1;
    g_EptState.Pdpt[i].PhysAddr = PdPa >> 12;
    // ...
}
```

#### Step 4: 第 3 级 — PD 遍历（位 29:21）— **关键分岔点**

```
PD index = GPA[29:21]

读取 PD[pdptIdx][pdIdx] = g_PdPages[pdptIdx].Entries[pdIdx]:

  ════════════════════════════════════════════
  情况 A: 未拆分（默认状态，LargePage = 1）
  ════════════════════════════════════════════
    R=1, W=1, X=1, LargePage=1
    PhysAddr = (pdptIdx*512 + pdIdx) * 2MB >> 12

    → 直接得到 HPA!  (2MB 大页, GPA == HPA, 恒等映射)
    → HPA = PhysAddr << 12 | GPA[20:0]
    → 转换完成! (不需要第4级)

  ════════════════════════════════════════════
  情况 B: 已拆分（Hook 后，LargePage = 0）
  ════════════════════════════════════════════
    R=1, W=1, X=1, LargePage=0
    PhysAddr = g_SplitPages[N].PhysicalAddress >> 12  ← PT 表的物理地址

    需要继续到第 4 级...
```

对应代码 — 初始化为 2MB 大页 (`ept.c:989`):
```c
for (j = 0; j < EPT_PDE_COUNT; j++) {
    PhysAddr = ((ULONG64)i * 512 + j) * (2 * 1024 * 1024);  // 2MB per entry
    g_PdPages[i].Entries[j].Value = 0;
    g_PdPages[i].Entries[j].Read = 1;
    g_PdPages[i].Entries[j].Write = 1;
    g_PdPages[i].Entries[j].Execute = 1;
    g_PdPages[i].Entries[j].LargePage = 1;   // 2MB page
    g_PdPages[i].Entries[j].PhysAddr = PhysAddr >> 12;
}
```

#### Step 5: 第 4 级 — PT 遍历（仅拆分后，位 20:12）

```
PT index = GPA[20:12]

读取 PT[ptIdx] = g_SplitPages[N].Pte[ptIdx]:

  ═══════════════════════════════════════
  情况 B-1: 该 4KB 页未被 Hook
  ═══════════════════════════════════════
    R=1, W=1, X=1
    PhysAddr = Base2MB + ptIdx * 4KB >> 12
    → HPA == GPA  (恒等映射)

  ═══════════════════════════════════════
  情况 B-2: 该 4KB 页已被 Hook！
  ═══════════════════════════════════════
    R=0, W=0, X=1 (或 X=0, 取决于 ExecuteOnlySupported)
    PhysAddr = Hook->HookPagePa >> 12   ← ★ 指向 hook 页面!
    
    → HPA = HookPagePa + Offset   (不是原始物理地址!)
    → 这就是 EPT Hook 的核心: "读/写看原页, 执行看hook页"
    → 如果权限不足 → 触发 EPT Violation VM-Exit → HandleEptViolation()
```

### 完整流程总结图

```
Guest 发起内存访问 (GPA)
        │
        ▼
┌───────────────────────────────────────────────┐
│ Step 1: CPU 从 VMCS 读取 EPTP                │
│         → 得到 PML4 物理基地址               │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 2: PML4[GPA[47:39]]                     │
│         → 得到 PDPT 物理基地址                │
│         (本项目只有 PML4[0] 有效)            │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 3: PDPT[GPA[38:30]]                     │
│         → LargePage?                         │
│           Yes(1GB) → 完成                    │
│           No   → 得到 PD 物理基地址           │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 4: PD[GPA[29:21]]                       │
│         → LargePage?(2MB)                    │
│           Yes → 完成 (恒等映射, HPA==GPA)    │
│           No  → 得到 PT 物理基地址            │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 5: PT[GPA[20:12]]                       │
│         → 4KB 页, 最终 HPA                   │
│         → 权限检查 (R/W/X)                  │
│         权限不足?                            │
│           Yes → EPT Violation VM-Exit!       │
│           No  → 访问 HPA                     │
└───────────────────────────────────────────────┘
```

---

## 4. EptSplitLargePage — 2MB→4KB 拆分过程

以对 GPA `0xFFFF1234` 所在的 2MB 页执行 Hook 为例：

### 拆分前

```
PD[x][y] = {R=1, W=1, X=1, L=1, PA=Base2MB>>12}   ← 2MB 大页
覆盖范围: Base2MB ~ Base2MB + 2MB (512 个 4KB 页)
```

### 拆分过程 (`ept.c:1100`)

```
EptSplitLargePage(PhysicalAddress):
  ① 对齐到 2MB 边界:
     Base2MB = PA & ~(2MB - 1)

  ② 计算索引:
     PdptIndex = (Base2MB >> 30) & 0x1FF    // 1GB per PDPT entry
     PdIndex   = (Base2MB >> 21) & 0x1FF    // 2MB per PD entry

  ③ 分配 g_SplitPages[N] (一个新的 PT 页面, 512个PTE)

  ④ 初始化 512 个 PTE 为恒等映射:
     for i in 0..511:
       PT[i] = {R=1, W=1, X=1, MemoryType=WB, PA=(Base2MB+i*4KB)>>12}

  ⑤ 修改原来的 PDE:
     PD[x][y] = {R=1, W=1, X=1, L=0, PA=SplitPage.PhysAddr>>12}
                                       ^^^
                                       不再是大页, 变成指向 PT 的指针

  ⑥ 插入哈希表 (O(1) 查找):
     EptSplitHashInsert(Base2MB, splitIdx)
```

### 拆分后

```
PD[x][y] → PT[512]:
  GPA Base2MB + 0*4KB  → PT[0]   → HPA Base2MB + 0*4KB     (恒等映射)
  GPA Base2MB + 1*4KB  → PT[1]   → HPA Base2MB + 1*4KB     (恒等映射)
  ...
  GPA Base2MB + N*4KB  → PT[N]   → 可被单独设置权限/指向Hook页!
  ...
  GPA Base2MB + 511*4KB → PT[511] → HPA Base2MB + 511*4KB  (恒等映射)
```

**必须拆分的原因**：只有 4KB 粒度才能对单个页面设置不同权限和指向不同的物理页。

---

## 5. EPT Hook 的权限切换机制

### Execute-Only 模式 (R=0, W=0, X=1)

```
                    ┌─────────────────────────────┐
                    │  Hook 页 (含 JMP 补丁)       │
                    │  权限: X-only               │
                    │  PhysAddr = HookPagePa       │
    ┌──────────┐    └────────────┬────────────────┘
    │ EPT PTE  │────────────────►│
    │          │                 │
    └──────────┘    ┌────────────┴────────────────┐
                    │  原始页 (干净代码)            │
                    │  权限: R+W (临时切换)        │
                    │  PhysAddr = TargetPhysAddr   │
                    └─────────────────────────────┘

执行流程:
  1. Guest 执行到 Hook 地址 → X=1 允许 → 执行 HookPage 上的 JMP
  2. Guest 读取 Hook 地址 (PatchGuard扫描) → R=0 → EPT Violation!
     → HandleEptViolation: 临时切换到原始页 (R=1,W=1,X=0)
     → 开启 MTF (Monitor Trap Flag, 单步)
     → Guest 读到干净的原始代码 (PatchGuard 不会发现 hook)
  3. MTF 触发 → 恢复为 Hook 页 (R=0,W=0,X=1)
```

### 非 Execute-Only 模式 (R=0, W=0, X=0)

```
所有访问都触发 EPT Violation, 通过 Guest RIP 判断意图:

  RIP 在 Hook 页面内? → 执行请求 → 临时 R+W+X 到 Hook 页
  RIP 在其他位置?     → 数据读写 → 临时 R+W+X 到原始页
  → MTF 后恢复 R=0,W=0,X=0
```

---

## 6. 与 x86-64 CR3 页表的对比

| 特性 | x86-64 CR3 页表 (VA→PA) | EPT 页表 (GPA→HPA) |
|------|--------------------------|---------------------|
| **目的** | Guest OS 内部的虚拟地址转换 | Hypervisor 控制的 Guest 物理地址转换 |
| **触发者** | Guest 自身访问内存时 | 每次 Guest 物理内存访问（CPU 自动） |
| **根指针位置** | CR3 寄存器 | VMCS 的 EPTP 字段 |
| **权限位** | U/S, R/W, NX (2位+1位) | R/W/X (3位独立控制) |
| **异常类型** | Page Fault (#PF, 中断14) | EPT Violation / Misconfig (VM-Exit) |
| **管理者** | 操作系统内核 | Hypervisor (VMX root) |
| **Guest 可见?** | 是 (Guest 自己的页表) | 否 (对 Guest 完全透明) |
| **大页支持** | 2MB / 1GB | 2MB / 1GB (相同) |
| **TLB 刷新** | MOV CR3 / INVLPG | INVEPT |
| **代码对应** | Windows 内核管理 | `g_EptState` → PML4 → PDPT → PD → PT |

---

## 7. Per-CPU EPT 隔离

### 为什么需要 Per-CPU

```
问题: CPU0 和 CPU1 同时触发 EPT Violation

  CPU0: 修改共享 PTE → R=1,W=1,X=0 (显示原始页)
  CPU1: 修改共享 PTE → R=0,W=0,X=1 (恢复hook页)
  
  → CPU0 的 MTF 还没触发, PTE 已被 CPU1 改回去!
  → 竞态条件!
```

### Per-CPU 解决方案

```
每个 CPU 拥有独立的:
  PML4[cpu] → PDPT[cpu] → PD[cpu] → PT[cpu]

  CPU0 修改 PT[0][idx] → 只影响 CPU0
  CPU1 修改 PT[1][idx] → 只影响 CPU1
  
  → 彻底消除多核竞态!
```

对应数据结构:
```c
EPT_CPU_STATE  *g_EptCpuStates        // 每CPU的 PML4+PDPT+EPTP
EPT_PER_CPU_PD_PAGE **g_PerCpuPdPages // 每CPU的 PD 页面
PEPT_PER_CPU_SPLIT  *g_PerCpuSplitPages // 每CPU的 PT 页面 (拆分页)
```

---

## 8. AMD NPT (Nested Page Tables) 分析

### 8.1 NPT 概述

NPT 是 **AMD SVM (Secure Virtual Machine)** 虚拟化技术中与 Intel EPT 对等的**第二级地址翻译**机制。核心目标相同：在 Guest 不知情的情况下，将 Guest Physical Address (GPA) 翻译为 Host Physical Address (HPA)。

```
Intel: Guest VA → [Guest CR3] → GPA → [EPT]  → HPA
AMD:   Guest VA → [Guest CR3] → GPA → [NPT]  → HPA
                                       ^^^^^^^^^^
                                       功能完全等价
```

### 8.2 NPT 与 EPT 的相同点

| 相同点 | 说明 |
|--------|------|
| **页表级数** | 都是 4 级：PML4 → PDPT → PD → PT |
| **页表项格式** | 本项目中 NPT 直接复用 EPT 的结构体定义（`EPT_PML4E`, `EPT_PDPTE`, `EPT_PDE`, `EPT_PTE`） |
| **地址位域拆分** | 完全相同：GPA[47:39]=PML4, [38:30]=PDPT, [29:21]=PD, [20:12]=PT, [11:0]=Offset |
| **大页支持** | 都支持 2MB (PDE.LargePage=1) 和 1GB (PDPTE.LargePage=1) 大页 |
| **恒等映射** | 本项目中 EPT 和 NPT 都使用恒等映射 512GB 物理空间 |
| **Hook 原理** | 都是拆分 2MB→4KB 后修改单页 PTE 权限 + 物理地址重定向 |
| **Per-CPU 隔离** | 都需要 Per-CPU 页表防止多核竞态 |
| **TLB 性能代价** | 都有最坏 20 次内存访问的代价（4级 × 5次翻译） |
| **Hash 加速** | 都使用 O(1) 哈希表加速 Hook 查找和 Split Page 查找 |
| **Trampoline 构造** | NPT 复用 EPT 的指令长度解码器 (`EptGetInstructionLength`) 和 RIP-relative 重定位 |

代码证据 — NPT 复用 EPT 类型定义 (`npt.h:21`):
```c
#include "ept.h"    /* Reuse EPT page table structure definitions */
```

### 8.3 NPT 与 EPT 的关键区别

#### 区别一览表

| 特性 | Intel EPT | AMD NPT |
|------|-----------|---------|
| **虚拟化架构** | VT-x (VMX) | AMD-V (SVM) |
| **根指针位置** | VMCS 的 EPTP 字段 | VMCB 的 `nested_cr3` 字段 |
| **根指针格式** | `EPT_POINTER` 联合体（含 MemoryType, PageWalkLength） | 裸物理地址（直接写入 PML4 PA） |
| **Execute-Only** | **支持**（R=0, W=0, X=1）— 需检测 `IA32_VMX_EPT_VPID_CAP` bit 0 | **不支持** — AMD 架构不允许 R=0,X=1 的组合 |
| **违例事件** | EPT Violation (VM-Exit) | #NPF = SVM_EXIT_NPF (0x400) (#VMEXIT) |
| **TLB 刷新** | `INVEPT` 指令（Single-Context / All-Contexts） | VMCB 的 `TlbCtl` 字段（下次 VMRUN 时刷新） |
| **单步恢复** | MTF (Monitor Trap Flag, VMCS 控制位) | RFLAGS.TF (#DB 异常) |
| **内存类型** | EPTP 指定全局 MemoryType + PTE 可设 MemoryType[5:3] | 使用标准 PAT 机制 |

#### 区别详解

##### 区别 1: Execute-Only — 最核心的差异

```
Intel EPT (支持 Execute-Only):
  ┌──────────────────────────────────────────────────────┐
  │ Hook 状态: PTE = { R=0, W=0, X=1, PA=HookPage }    │
  │                                                      │
  │  Guest 执行代码 → X=1 允许 → 直接执行 HookPage     │
  │  Guest 读取代码 → R=0 拒绝 → EPT Violation!         │
  │    → Handler 切换到原始页 → PatchGuard 看到干净代码  │
  │                                                      │
  │  ★ 读和执行可以看到不同的物理页！最佳隐蔽性         │
  └──────────────────────────────────────────────────────┘

AMD NPT (不支持 Execute-Only):
  ┌──────────────────────────────────────────────────────┐
  │ Hook 状态: PTE = { R=1, W=0, X=1, PA=HookPage }    │
  │                                                      │
  │  Guest 执行代码 → X=1 允许 → 直接执行 HookPage     │
  │  Guest 读取代码 → R=1 允许 → 读到 HookPage 内容!   │
  │    → PatchGuard 会看到 JMP 补丁！                   │
  │  Guest 写入代码 → W=0 拒绝 → #NPF!                 │
  │    → Handler 临时切换原始页                         │
  │                                                      │
  │  ★ 读和执行看到同一个页面，隐蔽性略差              │
  └──────────────────────────────────────────────────────┘
```

对应代码对比:
```c
// Intel EPT Hook 权限设置 (ept.c:1544)
Pte->Read = 0;      // 读 → EPT Violation
Pte->Write = 0;     // 写 → EPT Violation
if (g_EptHookState.ExecuteOnlySupported)
    Pte->Execute = 1;   // 执行直接到 HookPage ★
else
    Pte->Execute = 0;   // 不支持时降级

// AMD NPT Hook 权限设置 (npt.c:747)
Pte->Read = 1;      // 读允许 (无法设置 Execute-Only)
Pte->Write = 0;     // 写 → #NPF
Pte->Execute = 1;   // 执行直接到 HookPage
```

##### 区别 2: 根指针配置方式

```
Intel EPT:
  VMCS.EPTP = {
    MemoryType    : 3位  (WB=6)
    PageWalkLength: 3位  (4级=3)
    DirtyAccess   : 1位
    Pml4PhysAddr  : 40位 (PML4 物理地址 >> 12)
  }
  → 通过 VmxWrite(VMCS_CTRL_EPT_POINTER, ...) 写入 VMCS

AMD NPT:
  VMCB.nested_cr3 = g_NptState.Pml4Pa  (裸物理地址, 无额外控制位)
  → 直接写入 VMCB Control Area
```

对应代码:
```c
// Intel: 构造 EPTP 结构体 (ept.c:1013)
g_EptState.Eptp.MemoryType = EPT_MEMORY_TYPE_WB;
g_EptState.Eptp.PageWalkLength = EPT_PAGE_WALK_LENGTH_4;
g_EptState.Eptp.Pml4PhysAddr = g_EptState.Pml4Pa >> 12;

// AMD: 直接返回 PML4 物理地址 (npt.c:358)
ULONG64 NptGetRootPageTablePa(VOID) {
    return g_NptState.Pml4Pa;  // 直接写入 VMCB.nested_cr3
}
```

##### 区别 3: TLB 刷新机制

```
Intel EPT:
  VMX root 模式执行 INVEPT 指令:
    AsmVmxInvept(INVEPT_ALL_CONTEXTS, &Desc);       // 刷新所有 EPTP 上下文
    AsmVmxInvept(INVEPT_SINGLE_CONTEXT, &Desc);     // 只刷当前 EPTP
  → 立即生效

AMD NPT:
  设置 VMCB.TlbCtl 字段:
    Vmcb->Control.TlbCtl = TLB_CONTROL_FLUSH_ALL_ASID;
  → 延迟到下次 VMRUN 时才刷新 (更高效)
```

对应代码:
```c
// Intel (ept.c:2335)
VOID EptInvalidateAllContexts(VOID) {
    INVEPT_DESCRIPTOR Desc = { 0 };
    AsmVmxInvept(INVEPT_ALL_CONTEXTS, &Desc);   // 立即执行硬件指令
}

// AMD (npt.c:1333)
VOID NptInvalidateAll(VOID) {
    for (i = 0; i < g_SvmState.CpuCount; i++) {
        // 标记所有 CPU 的 VMCB, 下次 VMRUN 时刷新
        g_SvmState.CpuContexts[i].VmcbVa->Control.TlbCtl =
            TLB_CONTROL_FLUSH_ALL_ASID;
    }
}
```

##### 区别 4: 单步恢复（Hook 临时放开权限后的恢复）

```
Intel EPT:                                AMD NPT:
  ┌──────────────┐                          ┌──────────────┐
  │ EPT Violation│                          │   #NPF       │
  │ (VM-Exit)    │                          │ (SVM #VMEXIT)│
  └──────┬───────┘                          └──────┬───────┘
         ▼                                         ▼
  放开 PTE 权限                             放开 PTE 权限
  设置 MTF 位                               设置 RFLAGS.TF
  (VMCS 控制位)                             (Guest RFLAGS)
  vmresume                                  vmrun
         │                                         │
         ▼                                         ▼
  Guest 执行 1 条指令                       Guest 执行 1 条指令
         │                                         │
         ▼                                         ▼
  MTF VM-Exit                               #DB 异常 #VMEXIT
  (Exit Reason 37)                          (SVM_EXIT_DB)
  恢复 PTE 为 Hook 状态                    恢复 PTE 为 Hook 状态
  清除 MTF 位                               清除 RFLAGS.TF
```

对应代码:
```c
// Intel: 启用 MTF (ept.c:1974)
ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

// AMD: 启用 TF (npt.c:1127)
Vmcb->Save.Rflags |= (1ULL << 8);  // Set Trap Flag
```

### 8.4 NPT 页表遍历过程

NPT 的 GPA → HPA 遍历过程与 EPT 结构上完全相同，唯一区别是入口点和异常类型：

```
Guest 发起内存访问 (GPA)
        │
        ▼
┌───────────────────────────────────────────────┐
│ Step 1: CPU 从 VMCB.nested_cr3 读取根地址     │  ← 区别: 不是 VMCS EPTP
│         → 得到 PML4 物理基地址               │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 2: PML4[GPA[47:39]]                     │
│         → 得到 PDPT 物理基地址                │  (与 EPT 完全相同)
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 3: PDPT[GPA[38:30]]                     │
│         → 得到 PD 物理基地址                  │  (与 EPT 完全相同)
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 4: PD[GPA[29:21]]                       │
│         → LargePage? Yes → 完成               │  (与 EPT 完全相同)
│           No → 得到 PT 物理基地址             │
└───────────────┬───────────────────────────────┘
                ▼
┌───────────────────────────────────────────────┐
│ Step 5: PT[GPA[20:12]]                       │
│         → 4KB 页, 最终 HPA                   │
│         → 权限检查 (R/W/X)                  │
│         权限不足?                            │
│           Yes → #NPF (SVM_EXIT_NPF)!        │  ← 区别: 不是 EPT Violation
│           No  → 访问 HPA                     │
└───────────────────────────────────────────────┘
```

### 8.5 NPT Hook 流程图

由于 AMD 不支持 Execute-Only，Hook 策略与 EPT 有所不同：

```
                      ┌──────────────────────────────────┐
                      │  初始状态: Hook 已安装            │
                      │  PTE = { R=1, W=0, X=1 }         │
                      │  PhysAddr → HookPage              │
                      └──────────┬───────────────────────┘
                                 │
               ┌─────────────────┼─────────────────┐
               ▼                 ▼                 ▼
        Guest 执行代码    Guest 读取代码    Guest 写入代码
        X=1 → 允许        R=1 → 允许        W=0 → #NPF!
               │                 │                 │
               ▼                 ▼                 ▼
        执行 HookPage     读到 HookPage     NptHandlePageFault():
        上的 JMP 补丁     上的 JMP 补丁       1. 切换到原始页 (RWX)
        → 跳转到我们      (隐蔽性不如EPT)     2. RFLAGS.TF = 1
          的 Hook 函数                         3. 重新执行写指令
                                                      │
                                                      ▼
                                               Guest 执行 1 条指令
                                               (写入成功, 操作原始页)
                                                      │
                                                      ▼
                                               #DB 异常 → SVM #VMEXIT
                                               SvmHandleDbException():
                                                 1. 清除 RFLAGS.TF
                                                 2. PTE 恢复为
                                                    { R=1, W=0, X=1 }
                                                    PhysAddr → HookPage
```

### 8.6 本项目中 EPT / NPT 的代码对称性

本项目同时实现了 Intel EPT 和 AMD NPT，两者的 API 完全对称：

| 功能 | Intel EPT (`ept.c`) | AMD NPT (`npt.c`) |
|------|---------------------|--------------------|
| 初始化 | `EptInitialize()` | `NptInitialize()` |
| 清理 | `EptCleanup()` | `NptCleanup()` |
| 安装 Hook | `EptHookFunction()` | `NptHookFunction()` |
| 移除 Hook | `EptUnhookFunction()` | `NptUnhookFunction()` |
| 移除所有 Hook | `EptUnhookAll()` | `NptUnhookAll()` |
| 违例处理 | `HandleEptViolation()` | `NptHandlePageFault()` |
| 拆分大页 | `EptSplitLargePage()` | `NptSplitLargePage()` |
| PTE 查找 | `EptGetPteForPhysicalAddress()` | `NptGetPteForPhysicalAddress()` |
| Hook 查找 | `EptFindHookByPhysicalAddress()` | `NptFindHookByPhysicalAddress()` |
| TLB 刷新 | `EptInvalidateAllContexts()` | `NptInvalidateAll()` |
| Per-CPU 初始化 | `EptInitPerCpu()` | `NptInitPerCpu()` |
| Per-CPU PTE | `EptGetPerCpuPte()` | `NptGetPerCpuPte()` |
| 单步追踪 | `EptMtfTrackRelaxedPage()` | `NptDbTrackRelaxedPage()` |
| 单步恢复 | `EptMtfGetAndClearRelaxedPage()` | `NptDbGetAndClearRelaxedPage()` |

### 8.7 总结: EPT vs NPT 核心差异速查

```
┌───────────────────────────────────────────────────────────────┐
│                    EPT vs NPT 核心差异                        │
├───────────────────┬──────────────────┬────────────────────────┤
│                   │  Intel EPT       │  AMD NPT               │
├───────────────────┼──────────────────┼────────────────────────┤
│ 虚拟化技术        │  VT-x / VMX      │  AMD-V / SVM           │
│ 根指针            │  VMCS EPTP       │  VMCB nested_cr3       │
│ Execute-Only      │  ✅ 支持          │  ❌ 不支持             │
│ Hook 隐蔽性       │  极高 (读≠执行)  │  中等 (读=执行)        │
│ 违例事件          │  EPT Violation   │  #NPF (Nested PF)      │
│ TLB 刷新          │  INVEPT 指令     │  VMCB.TlbCtl 字段      │
│ 单步机制          │  MTF (VMCS 控制) │  RFLAGS.TF (#DB)       │
│ 页表结构          │  4级, 自定义格式 │  4级, 复用标准 x86 格式│
│ 页表项类型复用    │  EPT_PML4E 等    │  复用 EPT_PML4E 等     │
│ 恒等映射范围      │  512 GB          │  512 GB                │
│ 大页拆分          │  2MB → 4KB       │  2MB → 4KB             │
│ Per-CPU 隔离      │  ✅ 支持          │  ✅ 支持               │
│ Hash 加速         │  ✅ O(1)          │  ✅ O(1)               │
└───────────────────┴──────────────────┴────────────────────────┘

核心结论:
  页表结构和遍历逻辑 → 完全相同
  Hook 拆分和管理    → 完全相同
  关键差异只在:      → Execute-Only / 根指针 / TLB刷新 / 单步恢复
```
