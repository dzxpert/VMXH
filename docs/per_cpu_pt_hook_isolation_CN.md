简体中文 | [English](per_cpu_pt_hook_isolation.md)

# Per-CPU Page Table Hook 页隔离 — 实施细节文档

> **注意（2026-04 更新）**: 文中 `[MAX_PD_PAGES]` / `MAX_PD_PAGES (512)` 等硬编码值已改为运行期变量 `g_EptPdptTotal / g_NptPdptTotal`。Per-CPU PD 数组按 `g_EptPdptTotal` 动态分配；PML4[1..] 的扩展 PDPT 页每 CPU 也有独立副本 (`g_EptCpuExtPdpt / g_NptCpuExtPdpt`)。详见 [BAREMETAL_REVIEW_FIXES.md](./BAREMETAL_REVIEW_FIXES.md) 的 H-2。
>
> 另外：UAF 风险已被同步修复 —— `EptInvalidateAllCpusSync / NptInvalidateAllCpusSync` 通过 IPI 强制所有 CPU（含 HLT/C-state）在释放页前执行 INVEPT / TLB flush（H-5）。

## 1. 设计目标

在多核系统上，EPT/NPT hook 的 **违规 → 单步 → 恢复** 三阶段存在竞争条件：

```
CPU 0: EPT Violation → 放宽 PTE (R+W) → 启用 MTF
CPU 1: EPT Violation → 放宽 PTE (R+W) → 启用 MTF    ← 同一个 PTE!
CPU 0: MTF 触发 → 恢复 PTE (X-Only)                  ← 也恢复了 CPU 1 正在使用的 PTE!
CPU 1: 还在执行放宽后的指令 → PTE 已被 CPU 0 恢复 → 再次 EPT Violation → 死循环/卡死
```

**解决方案**：每个 CPU 拥有自己的 PT（页表级别）副本，用于被 hook 的 2MB 区域。PTE 权限切换仅影响当前 CPU 的地址翻译，不干扰其他 CPU。

**关键约束**：只在 PT 级别做隔离（而非整个页表树），因为 hook 只涉及 4KB PTE 权限翻转，不需要隔离 PML4 和 PDPT 的内容。但为了让 PD entry 指向不同的 PT page，PD 页也需要 per-CPU 副本。

---

## 2. 整体架构

```
        ┌──────────────────────────────────────────────┐
        │  共享模板 (EPT_STATE / NPT_STATE)             │
        │  PML4 → PDPT → PD Pages → Split PT Pages     │
        │  (非 hook 区域所有 CPU 共享)                    │
        └──────────────────────────────────────────────┘

Per-CPU 层 (仅 hook 区域):

  CPU 0:  PML4[0] → PDPT[0]                             CPU 1:  PML4[1] → PDPT[1]
            │                                                      │
            ├─ PDPT[x] → 共享 PD (未 hook 的 GB 区域)               ├─ PDPT[x] → 共享 PD
            │                                                      │
            └─ PDPT[y] → per-CPU PD[0][y]                         └─ PDPT[y] → per-CPU PD[1][y]
                           │                                                     │
                           ├─ PD[z] → per-CPU PT[0]                             ├─ PD[z] → per-CPU PT[1]
                           │   (hook 的 2MB 区域)                                │   (hook 的 2MB 区域)
                           │                                                     │
                           └─ PD[其他] → 共享 PT                                 └─ PD[其他] → 共享 PT
```

**分层隔离**：
- **PML4 + PDPT**: 每 CPU 独立副本（初始化时从模板 clone），用于让 PDPT entry 指向不同的 PD
- **PD pages**: **按需 clone** — 只有包含 hook 的 GB 区域才创建 per-CPU 副本
- **PT (split) pages**: **按需 clone** — 只有包含 hook 的 2MB 区域才创建 per-CPU 副本
- **非 hook 区域**: 所有 CPU 仍然共享相同的 PD/PT pages（通过 PDPT entry 指向共享 PD）

---

## 3. 数据结构

### 3.1 Intel EPT 侧 (`ept.h`)

```c
// Per-CPU EPT 根结构 (ept.h:178-183)
typedef struct _EPT_CPU_STATE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[EPT_PML4E_COUNT];  // 独立 PML4
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[EPT_PDPTE_COUNT];  // 独立 PDPT
    EPT_POINTER Eptp;     // 该 CPU 的 EPTP 值 (写入 VMCS)
    ULONG64     Pml4Pa;   // PML4 的物理地址
} EPT_CPU_STATE, *PEPT_CPU_STATE;

// 全局数组: g_EptCpuStates[g_MaxProcessors]
extern PEPT_CPU_STATE g_EptCpuStates;
```

```c
// Per-CPU split PT page 副本 (ept.c:26-30, 44-48)
typedef struct _EPT_PER_CPU_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[EPT_PTE_COUNT];  // 512 个 4KB PTE
    ULONG64     PhysicalAddress;    // 该页表页的物理地址
    BOOLEAN     Allocated;          // 是否已分配
} EPT_PER_CPU_SPLIT, *PEPT_PER_CPU_SPLIT;

// Per-CPU PD page 副本 (ept.c:59-61)
typedef struct _EPT_PER_CPU_PD_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Entries[EPT_PDE_COUNT];  // 512 个 2MB PDE
} EPT_PER_CPU_PD_PAGE;
```

全局变量：
```c
PEPT_CPU_STATE              g_EptCpuStates     = NULL;  // [g_MaxProcessors] per-CPU EPT root
static PEPT_PER_CPU_SPLIT  *g_PerCpuSplitPages = NULL;  // [g_MaxProcessors] → [MAX_SPLIT_PAGES]
static EPT_PER_CPU_PD_PAGE**g_PerCpuPdPages    = NULL;  // [g_MaxProcessors] → [MAX_PD_PAGES]
static BOOLEAN              g_PerCpuPdAllocated[MAX_PD_PAGES] = {0}; // 哪些 PDPT entry 已隔离
```

### 3.2 AMD NPT 侧 (`npt.h`)

```c
// Per-CPU NPT 根结构 (npt.h:64-68)
typedef struct _NPT_CPU_STATE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[EPT_PML4E_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[EPT_PDPTE_COUNT];
    ULONG64     Pml4Pa;   // 写入 VMCB.nested_cr3
} NPT_CPU_STATE, *PNPT_CPU_STATE;

extern PNPT_CPU_STATE g_NptCpuStates;
```

NPT 侧的 `NPT_PER_CPU_SPLIT` 和 `NPT_PER_CPU_PD_PAGE` 结构与 EPT 侧镜像一致。

---

## 4. 初始化流程

### 4.1 调用链

```
DriverEntry
  └─ VmxInitialize / SvmInitialize
       ├─ EptInitialize / NptInitialize        ← 创建共享模板页表
       ├─ EptInitPerCpu / NptInitPerCpu        ← 创建 per-CPU PML4+PDPT
       └─ 对每个 CPU:
            └─ EptSetupIdentityMap / SvmInitVmcb
                 └─ 写 per-CPU EPTP / nested_cr3 到 VMCS / VMCB
```

### 4.2 `EptInitPerCpu()` (ept.c:1466-1546)

```c
NTSTATUS EptInitPerCpu(VOID)
{
    // 1. 分配 g_EptCpuStates[g_MaxProcessors]  (tag 'tpEC')
    // 2. 分配 g_PerCpuSplitPages[g_MaxProcessors] 指针数组 (tag 'tpES')
    // 3. 分配 g_PerCpuPdPages[g_MaxProcessors] 指针数组 (tag 'tpEP')
    //    (这里只分配指针数组，PD pages 和 split pages 按需分配)
    
    // 4. 对每个 CPU：
    for (i = 0; i < g_MaxProcessors; i++) {
        // Clone PML4 和 PDPT 从共享模板
        RtlCopyMemory(g_EptCpuStates[i].Pml4, g_EptState.Pml4, ...);
        RtlCopyMemory(g_EptCpuStates[i].Pdpt, g_EptState.Pdpt, ...);
        
        // 关键: PML4[0] 指向 **自己的** PDPT
        PdptPa = VaToPhysical(g_EptCpuStates[i].Pdpt);
        g_EptCpuStates[i].Pml4[0].PhysAddr = PdptPa >> 12;
        
        // 构建 per-CPU EPTP
        g_EptCpuStates[i].Eptp.MemoryType = EPT_MEMORY_TYPE_WB;
        g_EptCpuStates[i].Eptp.PageWalkLength = EPT_PAGE_WALK_LENGTH_4;
        g_EptCpuStates[i].Eptp.Pml4PhysAddr = Pml4Pa >> 12;
    }
}
```

> **注意**：此时所有 CPU 的 PDPT entry 仍然指向 **共享** PD pages（与模板相同）。只有在安装 hook 时才会按需创建 per-CPU PD 和 PT pages。

### 4.3 EPTP / nested_cr3 写入

**Intel 侧** — `EptSetupIdentityMap` (ept.c:660-680):
```c
NTSTATUS EptSetupIdentityMap(VMX_CPU_CONTEXT *CpuCtx, VMX_STATE *State)
{
    CpuNum = CpuCtx->ProcessorNumber;
    // 优先使用 per-CPU EPTP，回退到共享
    if (g_EptCpuStates && CpuNum < g_MaxProcessors) {
        VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptCpuStates[CpuNum].Eptp.Value);
    } else {
        VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptState.Eptp.Value);
    }
}
```

**AMD 侧** — `SvmInitVmcb` (svm_init.c:425-434):
```c
NptRootPa = NptGetPerCpuRootPa(CpuNum);
if (NptRootPa == 0) {
    NptRootPa = NptGetRootPageTablePa();  // fallback 到共享
}
Vmcb->Control.NestedCr3 = NptRootPa;
```

---

## 5. Hook 安装时的 per-CPU 设置

### 5.1 `EptHookFunction` 中的 per-CPU 块 (ept.c:1074-1112)

在设置好共享 PTE 权限后，执行以下操作：

```c
if (g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages) {
    ULONG PdptIdx = (PageBase >> 30) & 0x1FF;   // GB 区域索引
    ULONG PdIdx   = (PageBase >> 21) & 0x1FF;   // 2MB 区域索引
    
    // 步骤 1: 确保该 GB 区域的 PD page 已 per-CPU 化
    EptEnsurePerCpuPdForRegion(PdptIdx);
    
    // 步骤 2: 找到对应的 split page 索引
    for (splitIdx = 0; splitIdx < MAX_SPLIT_PAGES; splitIdx++) {
        if (g_SplitPages[splitIdx].InUse &&
            g_SplitPages[splitIdx].BasePhysAddr2MB == (PageBase & ~(2MB - 1))) {
            break;
        }
    }
    
    // 步骤 3: 确保该 split page 已 per-CPU 化
    EptEnsurePerCpuSplitPage(splitIdx, PdptIdx, PdIdx);
    
    // 步骤 4: 将 hook PTE 权限复制到所有 CPU 的私有副本
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        PEPT_PTE CpuPte = EptGetPerCpuPte(cpu, TargetPa);
        if (CpuPte) {
            CpuPte->Read    = Pte->Read;
            CpuPte->Write   = Pte->Write;
            CpuPte->Execute = Pte->Execute;
            CpuPte->PhysAddr = Pte->PhysAddr;
        }
    }
}
```

### 5.2 按需 PD clone — `EptEnsurePerCpuPdForRegion` (ept.c:1592-1629)

```c
static NTSTATUS EptEnsurePerCpuPdForRegion(ULONG PdptIndex)
{
    if (g_PerCpuPdAllocated[PdptIndex]) return STATUS_SUCCESS;  // 已隔离
    
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (!g_PerCpuPdPages[cpu]) {
            // 首次: 分配完整的 MAX_PD_PAGES 个 PD page
            g_PerCpuPdPages[cpu] = ExAllocatePoolWithTag(NonPagedPool,
                sizeof(EPT_PER_CPU_PD_PAGE) * MAX_PD_PAGES, 'tpEP');
            // 从共享 PD pages clone
            RtlCopyMemory(g_PerCpuPdPages[cpu], g_PdPages,
                          sizeof(EPT_PER_CPU_PD_PAGE) * MAX_PD_PAGES);
        }
        // 该 CPU 的 PDPT[PdptIndex] 指向自己的 PD page
        CpuPdPa = VaToPhysical(&g_PerCpuPdPages[cpu][PdptIndex]);
        g_EptCpuStates[cpu].Pdpt[PdptIndex].PhysAddr = CpuPdPa >> 12;
    }
    g_PerCpuPdAllocated[PdptIndex] = TRUE;
}
```

### 5.3 按需 PT clone — `EptEnsurePerCpuSplitPage` (ept.c:1641-1686)

```c
static NTSTATUS EptEnsurePerCpuSplitPage(ULONG splitIdx, ULONG PdptIndex, ULONG PdIndex)
{
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (!g_PerCpuSplitPages[cpu]) {
            // 首次: 分配 MAX_SPLIT_PAGES 个 per-CPU split page
            g_PerCpuSplitPages[cpu] = ExAllocatePoolWithTag(NonPagedPool,
                sizeof(EPT_PER_CPU_SPLIT) * MAX_SPLIT_PAGES, 'tpES');
            RtlZeroMemory(...);
        }
        
        if (!g_PerCpuSplitPages[cpu][splitIdx].Allocated) {
            // Clone 512 个 PTE 从共享 split page
            RtlCopyMemory(g_PerCpuSplitPages[cpu][splitIdx].Pte,
                          g_SplitPages[splitIdx].Pte,
                          sizeof(EPT_PTE) * EPT_PTE_COUNT);
            g_PerCpuSplitPages[cpu][splitIdx].PhysicalAddress =
                VaToPhysical(g_PerCpuSplitPages[cpu][splitIdx].Pte);
            g_PerCpuSplitPages[cpu][splitIdx].Allocated = TRUE;
        }
        
        // 更新该 CPU 的 PD entry 指向自己的 PT page
        CpuPde = &g_PerCpuPdPages[cpu][PdptIndex].Entries[PdIndex];
        CpuPde->Read = 1; CpuPde->Write = 1; CpuPde->Execute = 1;
        CpuPde->LargePage = 0;
        CpuPde->PhysAddr = g_PerCpuSplitPages[cpu][splitIdx].PhysicalAddress >> 12;
    }
}
```

---

## 6. 运行时：EPT Violation / NPF 处理

### 6.1 Intel — `HandleEptViolation` (ept.c:1321-1459)

```c
BOOLEAN HandleEptViolation(PVOID GuestContext)
{
    CpuIndex = KeGetCurrentProcessorNumber();
    Hook = EptFindHookByPhysicalAddress(GuestPhysAddr);
    
    // ★ 核心: 使用 per-CPU PTE
    Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
    if (!Pte) Pte = Hook->TargetPte;  // fallback 到共享
    
    // 后续的 Pte->Read/Write/Execute 修改只影响当前 CPU 的翻译
    if (ExecuteOnlySupported) {
        // Mode A: R=0,W=0,X=1 → 数据访问时临时切换到原始页
        Pte->Read = 1; Pte->Write = 1; Pte->Execute = 0;
        Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
    } else {
        // Mode B: R=0,W=0,X=0 → 根据 RIP 判断执行还是数据访问
        // ... 类似逻辑 ...
    }
    
    EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);  // 记录当前 CPU 放宽了哪个页
    // 启用 MTF
}
```

### 6.2 Intel — `HandleMtf` (vmx_exit.c:518-579)

```c
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    CpuIndex = KeGetCurrentProcessorNumber();
    
    // 禁用 MTF
    ProcBased &= ~PROC_BASED_MONITOR_TRAP_FLAG;
    
    // 获取当前 CPU 放宽的页面
    RelaxedPa = EptMtfGetAndClearRelaxedPage();
    
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (Hook->Active && Hook->TargetPhysicalAddr == RelaxedPa) {
            // ★ 使用 per-CPU PTE 恢复
            PEPT_PTE Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
            if (!Pte) Pte = Hook->TargetPte;  // fallback
            
            if (Pte->Read || Pte->Write) {
                // 恢复到 hook 状态
                Pte->Read = 0; Pte->Write = 0;
                Pte->PhysAddr = Hook->HookPagePa >> 12;
                Pte->Execute = ExecuteOnlySupported ? 1 : 0;
            }
        }
    }
    EptInvalidateAllContexts();
}
```

### 6.3 AMD — `NptHandlePageFault` (npt.c:782-880)

```c
BOOLEAN NptHandlePageFault(PVOID GuestContext)
{
    CpuIdx = KeGetCurrentProcessorNumber();
    Hook = NptFindHookByPhysicalAddress(GuestPhysAddr);
    
    // ★ 使用 per-CPU PTE
    Pte = NptGetPerCpuPte(CpuIdx, Hook->TargetPhysicalAddr);
    if (!Pte) Pte = Hook->TargetPte;
    
    // 写访问: 临时设置 R+W+X + 原始页，启用 TF 单步
    Pte->Read = 1; Pte->Write = 1; Pte->Execute = 1;
    Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
    
    NptDbTrackRelaxedPage(Hook->TargetPhysicalAddr);
    Vmcb->Save.Rflags |= (1ULL << 8);  // Set TF
}
```

### 6.4 AMD — `SvmHandleDbException` (svm_exit.c:403-478)

```c
static BOOLEAN SvmHandleDbException(PGUEST_CONTEXT Ctx)
{
    CpuNum = KeGetCurrentProcessorNumber();
    RelaxedPa = NptDbGetAndClearRelaxedPage();
    
    for (i = 0; i < NPT_MAX_HOOKS; i++) {
        if (Hook->Active && Hook->TargetPhysicalAddr == RelaxedPa) {
            // ★ 使用 per-CPU PTE 恢复
            PEPT_PTE Pte = NptGetPerCpuPte(CpuNum, Hook->TargetPhysicalAddr);
            if (!Pte) Pte = Hook->TargetPte;
            
            if (Pte->Read && Pte->Write && Pte->Execute) {
                // 恢复到 hook 状态: R+X with hook page
                Pte->Read = 1; Pte->Write = 0; Pte->Execute = 1;
                Pte->PhysAddr = Hook->HookPagePa >> 12;
            }
        }
    }
    Vmcb->Save.Rflags &= ~(1ULL << 8);  // Clear TF
    NptInvalidateAll();
}
```

---

## 7. PTE 查找 — `EptGetPerCpuPte` / `NptGetPerCpuPte`

```c
// ept.c:1692-1715
PEPT_PTE EptGetPerCpuPte(ULONG CpuIndex, ULONG64 PhysicalAddress)
{
    if (!g_PerCpuSplitPages || CpuIndex >= g_MaxProcessors ||
        !g_PerCpuSplitPages[CpuIndex]) {
        return NULL;  // per-CPU 未初始化或该 CPU 未分配
    }
    
    Base2MB = PhysicalAddress & ~(2MB - 1);
    PtIndex = (PhysicalAddress >> 12) & 0x1FF;   // 4KB 页表内偏移
    
    // 遍历 split pages 找到匹配的 2MB 区域
    for (i = 0; i < MAX_SPLIT_PAGES; i++) {
        if (g_PerCpuSplitPages[CpuIndex][i].Allocated &&
            g_SplitPages[i].InUse &&
            g_SplitPages[i].BasePhysAddr2MB == Base2MB) {
            return &g_PerCpuSplitPages[CpuIndex][i].Pte[PtIndex];
        }
    }
    return NULL;  // 该地址没有 per-CPU split page → 使用共享 PTE
}
```

---

## 8. Hook 移除时的 per-CPU 清理

### 8.1 `EptUnhookFunction` (ept.c:1166-1187)

当页面上最后一个 hook 移除时：

```c
if (!OtherHooksOnPage) {
    // 恢复共享 PTE
    Hook->TargetPte->Read = 1; ...
    
    // ★ 同步恢复所有 per-CPU PTE
    if (g_EptCpuStates && g_PerCpuSplitPages) {
        for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
            PEPT_PTE CpuPte = EptGetPerCpuPte(cpu, Hook->TargetPhysicalAddr);
            if (CpuPte) {
                CpuPte->Read = 1; CpuPte->Write = 1;
                CpuPte->Execute = 1;
                CpuPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
            }
        }
    }
}
```

### 8.2 `EptUnhookAll` (ept.c:1237-1270) / `NptUnhookAll` (npt.c:699-746)

批量移除时，对每个 active hook 执行相同的 per-CPU PTE 恢复。

---

## 9. 清理流程

### 9.1 `EptCleanupPerCpu` (ept.c:1551-1581)

```c
VOID EptCleanupPerCpu(VOID)
{
    // 释放 per-CPU split page 数组
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (g_PerCpuSplitPages[cpu]) ExFreePoolWithTag(..., 'tpES');
    }
    ExFreePoolWithTag(g_PerCpuSplitPages, 'tpES');
    
    // 释放 per-CPU PD page 数组
    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (g_PerCpuPdPages[cpu]) ExFreePoolWithTag(..., 'tpEP');
    }
    ExFreePoolWithTag(g_PerCpuPdPages, 'tpEP');
    
    // 释放 per-CPU EPT root 数组
    ExFreePoolWithTag(g_EptCpuStates, 'tpEC');
}
```

### 9.2 调用链

```
VmxTerminate / SvmTerminate
  ├─ EptCleanupPerCpu / NptCleanupPerCpu   ← 先释放 per-CPU
  └─ EptCleanup / NptCleanup               ← 再释放共享
```

---

## 10. 内存分配汇总

| 标签 (Pool Tag) | 用途 | 分配时机 | 大小 |
|---|---|---|---|
| `'tpEC'` | `g_EptCpuStates` — per-CPU EPT root (PML4+PDPT+EPTP) | `EptInitPerCpu` | `g_MaxProcessors × sizeof(EPT_CPU_STATE)` |
| `'tpES'` | `g_PerCpuSplitPages` — per-CPU split PT 指针数组 + 实际 PT pages | 指针: `EptInitPerCpu`; 实际: `EptEnsurePerCpuSplitPage` | 指针: `g_MaxProcessors × 8`; 实际: `MAX_SPLIT_PAGES × sizeof(EPT_PER_CPU_SPLIT)` per CPU |
| `'tpEP'` | `g_PerCpuPdPages` — per-CPU PD pages | 指针: `EptInitPerCpu`; 实际: `EptEnsurePerCpuPdForRegion` | 指针: `g_MaxProcessors × 8`; 实际: `MAX_PD_PAGES × sizeof(EPT_PER_CPU_PD_PAGE)` per CPU |
| `'tpNC'` | `g_NptCpuStates` — per-CPU NPT root | `NptInitPerCpu` | `g_MaxProcessors × sizeof(NPT_CPU_STATE)` |
| `'tpNS'` | `g_NptPerCpuSplitPages` — per-CPU NPT split PT | 同 EPT | 同 EPT |
| `'tpNP'` | `g_NptPerCpuPdPages` — per-CPU NPT PD pages | 同 EPT | 同 EPT |

> **按需分配**: `'tpES'`/`'tpEP'` 的 "实际" 分配仅在第一个 hook 安装到对应区域时发生，不装 hook 就不分配。

---

## 11. 容错设计

1. **初始化失败非致命**: `EptInitPerCpu`/`NptInitPerCpu` 返回失败时，仅 `LOG_WARN` 并继续。Hook 仍然可用但回退到共享 PTE（无隔离）。

2. **Fallback 到共享 PTE**: 所有使用 per-CPU PTE 的地方都有 fallback:
   ```c
   Pte = EptGetPerCpuPte(CpuIndex, PA);
   if (!Pte) Pte = Hook->TargetPte;   // ← fallback
   ```

3. **NULL 检查**: 所有 per-CPU 路径都检查 `g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages` 非 NULL。

---

## 12. 涉及文件清单

| 文件 | 修改内容 |
|---|---|
| `ept.h` | 新增 `EPT_CPU_STATE` 结构体; 声明 `EptInitPerCpu`, `EptCleanupPerCpu`, `EptGetPerCpuPte`, `EptGetPerCpuEptp`; `extern g_EptCpuStates` |
| `ept.c` | 新增全局: `g_EptCpuStates`, `g_PerCpuSplitPages`, `g_PerCpuPdPages`, `g_PerCpuPdAllocated`, 及 per-CPU struct 定义; 新增函数: `EptInitPerCpu`, `EptCleanupPerCpu`, `EptEnsurePerCpuPdForRegion`, `EptEnsurePerCpuSplitPage`, `EptGetPerCpuPte`, `EptGetPerCpuEptp`; 修改: `HandleEptViolation` (per-CPU PTE), `EptHookFunction` (per-CPU 设置), `EptUnhookFunction` (per-CPU 恢复), `EptUnhookAll` (per-CPU 恢复), `EptSetupIdentityMap` (per-CPU EPTP) |
| `npt.h` | 新增 `NPT_CPU_STATE` 结构体; 声明 `NptInitPerCpu`, `NptCleanupPerCpu`, `NptGetPerCpuPte`, `NptGetPerCpuRootPa`; `extern g_NptCpuStates` |
| `npt.c` | 镜像 ept.c 的所有 per-CPU 改动; 修改: `NptHandlePageFault`, `NptHookFunction`, `NptUnhookFunction`, `NptUnhookAll` |
| `vmx_exit.c` | 修改 `HandleMtf`: 使用 `EptGetPerCpuPte` 恢复 per-CPU PTE |
| `svm_exit.c` | 修改 `SvmHandleDbException`: 使用 `NptGetPerCpuPte` 恢复 per-CPU PTE |
| `vmx_init.c` | `VmxInitialize` 调用 `EptInitPerCpu`; `VmxTerminate` 调用 `EptCleanupPerCpu` |
| `svm_init.c` | `SvmInitialize` 调用 `NptInitPerCpu`; `SvmTerminate` 调用 `NptCleanupPerCpu`; `SvmInitVmcb` 使用 `NptGetPerCpuRootPa` |

---

## 13. 已知限制 & TODO

1. **Unhook 不释放 per-CPU PD/PT 物理页**: `EptUnhookFunction`/`NptUnhookFunction` 恢复了 per-CPU PTE 权限，但 per-CPU PD page 和 split page 的内存不会被释放回池中。它们直到 `EptCleanupPerCpu` (驱动卸载) 才释放。这对于 hook 数量较少的场景不是问题。

2. **PD pages 全量 clone**: `EptEnsurePerCpuPdForRegion` 首次为某 CPU 分配 PD 时，会一次性 clone 全部 `MAX_PD_PAGES` (512) 个 PD page（≈2MB per CPU）。可以优化为只 clone 需要的那一个 PD page。

3. **`EptGetPerCpuPte` 线性扫描**: 使用 `for (i = 0; i < MAX_SPLIT_PAGES; ...)` 遍历查找匹配的 split page。对于少量 hook（<10）性能无影响，但如果大量 split（接近 128），可考虑哈希表查找。

4. **INVEPT/TLB flush 粒度**: 当前使用 `EptInvalidateAllContexts()` (all-context INVEPT) 和 `NptInvalidateAll()` (全 ASID flush)。可以优化为 single-context INVEPT + per-CPU EPTP 以减少 TLB 抖动。
