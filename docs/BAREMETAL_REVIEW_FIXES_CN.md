简体中文 | [English](BAREMETAL_REVIEW_FIXES.md)

# 裸机运行稳定性 Review 修复记录

本文档汇总 2026-04 对 VMX/SVM 虚拟化与 Hook 引擎裸机运行场景的**代码 Review 发现**及**对应修复**。请与源码注释中以 `H-#` / `M-#` / `L-#` / `C-#` 形式标注的 Fix 标签交叉对照。

修复总数：**17 + 19 补救**（首轮严重 6 + 中等 5 + 低 3 + 跨平台 3；第二轮 Review 补救 19 项）。所有修改对 Intel / AMD 双平台都是幂等或平台专属的；API 改动请见本文末的"重要 API 变更"。

---

## 第二轮 Review（post-2nd-review）补救清单

第一轮修复做完后做了一次更严格的二次 Review，发现若干**功能不完善 / 边界条件未覆盖**的点，全部重做：

### 致命级（会直接 BSOD 或使修复完全无效）

1. **SVM VMSAVE/VMLOAD host state 缺失** — `AsmSvmLaunch` 原版仅 `VMLOAD guest VMCB` 把 FS/GS/TR/LDTR.base、KernelGsBase、SYSCALL MSRs 的 guest 值载入 CPU；VMEXIT 后这些寄存器 **仍是 guest 值**，Windows 内核在第一次 C handler 调用时读 `gs:KPCR` 立即 BSOD。  
   修复：新增独立 `HostVmcbPa`（与 HSAVE 区分）；启动时 `VMSAVE [HostVmcbPa]` 一次；每次 VMEXIT 后 `VMSAVE [guestVmcb] → VMLOAD [hostVmcb] → STGI`（顺序关键，先保存 guest extra、再恢复 host extra），然后才进 C。签名改为 `AsmSvmLaunch(VmcbPa, VmcbVa, HostVmcbPa)`。

2. **`#UD` 注入后错误地又 `HvAdvanceGuestRip`** — `SvmHandleVmmcall` 末尾注入 #UD 然后调 AdvanceRip，导致 Guest 看到的 #UD 的 saved RIP 跳过了 VMMCALL，行为不可预测。  
   修复：`#UD` 是 fault，注入后 **不** AdvanceRip；所有 `HvInjectException + HvAdvanceGuestRip` 组合被拆开。

3. **`EptInvalidateAllCpusSync` 的 CPUID 回调在 teardown 时失效** — 若 CPU 已 VMXOFF，CPUID 不触发 VMEXIT，TLB 不 flush。  
   修复：IPI callback 内**直接** `EptInvalidateAllContexts()`（root-mode INVEPT 合法），并加 `g_VmxState.Initialized` 守卫；SVM 侧因 INVLPGA 无整表刷能力仍使用 CPUID 强迫 VMEXIT/VMRUN 路径，但加 `g_SvmState.Initialized` 守卫避免 teardown 时多余开销。

4. **`NptDbMatchesRelaxedRip` 缺 CR3 核对** — 一个 CPU 上不同进程线程的 #DB 可能 RIP 恰好落在 15 字节窗口，造成误吞。  
   修复：tracker 增加 `g_NptDbRelaxedCr3[]`，write `Pa, Rip, Cr3` 顺序改用 `_WriteBarrier()` 保证 "arm flag (PagePa) 最后写"；读端用 `_ReadBarrier()`；CR3 比较时去 PCID/掩码一致。

5. **`SvmApplyExceptionIntercepts` 的 `CleanBits = 0` 过度保守** — 导致下次 VMRUN 重新加载全部 VMCB state（性能）且对 in-flight VMRUN 有 race。  
   修复：改为 `InterlockedAnd(&CleanBits, ~(1UL << 0))` 只清 INTERCEPTS bit；`InterceptExceptions` 字段 32-bit 对齐原子写；完全移除 lazy-init pattern，改成 `SvmInterceptLockInitialize()` 在 `SvmInitialize` 开始时一次性初始化。

6. **VMCALL/VMMCALL nonce 验证仅检查 CPL** — 没检查 long mode / CS.L / kernel-half RIP；32-bit compat-mode ROP gadget 仍能绕过。  
   修复：抽成 `HvIsAuthenticShutdownCaller(Rcx, Rip, Cpl, Efer, CsL)` 统一检查：nonce、EFER.LMA、CS.L、CPL==0、RIP ≥ 0xFFFF_8000_0000_0000；VMX/SVM 调用相同 helper。

7. **`HandleEptViolation` fixup 用 `EptInvalidateFromGuest`** — 只 bump 代际，当前 CPU VMRESUME 回到同一指令 TLB 还旧，**立即** 再次 violation → 死循环。  
   修复：恢复 `EptInvalidateAllContexts()` 立即刷当前 CPU + 再调 `EptInvalidateFromGuest()` 通知其他 CPU。

8. **VMX/SVM `VMCALL_SUBCMD_READ/WRITE_MEMORY` 路由到已禁用 stub** — Stub 里 `HvAdvanceGuestRip+return TRUE` 让调用者以为成功；应该明确失败。  
   修复：两端的该 subcmd 直接注入 #UD，不调 stub。

### 中级补救

9. **NPT #DB 重注入缺 DR6.BS** — Guest `#DB` handler 读 DR6 区分 TF 单步 vs 硬件断点；硬件不会为"注入"型 #DB 写 DR6。  
   修复：注入前设 `Vmcb->Save.Dr6 = 0xFFFF0FF0 | (1<<14)` (reserved-1 + BS)。

10. **SVM 异常拦截 lazy-init 竞态** — `g_SvmInterceptLockInited` 无 Interlocked 保护。  
    修复：`SvmInterceptLockInitialize()` 在 `SvmInitialize()` 开头同步调用，移除 lazy 分支。

11. **`HandleHlt` Activity-State 约束不全** — 只检查 RFLAGS.IF + STI/MOV-SS shadow；SDM §26.3.1.5 还要求 `VMCS_GUEST_PENDING_DBG_EXCEPTIONS == 0`。  
    修复：加该字段检查，否则保持 Active 态。

12. **AAD_HIDE_EXCEPTIONS 在 VMX 侧从未工作** — VMX `EXCEPTION_BITMAP = 0` 且没有动态更新机制，进程启用 AAD_HIDE_EXCEPTIONS 时 #BP 永远不会 VMEXIT。  
    修复：提供对称的 `VmxSetExceptionInterceptBp / VmxSetExceptionInterceptDb` API，维护全局期望 mask + 每 CPU "applied gen"，VMEXIT handler 顶部 `VmxSyncExceptionBitmap()` lazy-sync（无 IPI，无 VMCS 所有权切换）。

13. **process.c 到 svm.h 的硬依赖** — `ProcessSyncSvmInterceptsAfterConfigChange` 直接调 `SvmSetExceptionInterceptBp` —— 跨模块紧耦合。  
    修复：`process.c` 导出 `ProcessRegisterExceptionHideToggle(Callback)`，SVM/VMX 在各自初始化末尾注册对应 callback，process.c 不再 include svm.h。

14. **`FreeThunk` 时机注释不充分 + 未保证 icache 正确** — 需要写出"IPI 同步后 zero 安全"的 RCU-like 契约。  
    修复：`GenericHookRemove` 路径 `HvUnhookFunction`（内部 `Ept/NptInvalidateAllCpusSync`）→ acquire lock → `FreeThunk` —— 顺序已正确，详细注释固化契约。

15. **SVM DPC 无限等待** — `SvmInitDpcRoutine` 同样用 `NULL` timeout；DPC 挂死时上层 `goto InitFailed` 会释放栈上 `DpcCtx`，corrupted。  
    修复：对齐 VMX 侧：60 s 分片等待，超时 → `KeRemoveQueueDpc`；若 DPC 已开始则**无限等完成**（避免栈破坏，宁可挂死等 OS watchdog）。

16. **`hv_mem.c/SafeReadPhysU64` 把 PA 当指针** — 即便注释说"仅用于 page-table walk"，在 VMX root 仍不安全。  
    修复：改用 `MmGetVirtualForPhysical(Pa)` 获取 OS 映射 VA；`HvGuestVaToPa` 顶部加 `KeGetCurrentIrql() > DISPATCH_LEVEL` 守卫，root mode 误用返回 0。

17. **`g_NptDbRelaxedRip` 失败路径未释放** — `NptInitialize` 有 5 处 early-return，多处仅释放 PagePa 漏了 Rip。  
    修复：每处都加 Rip + Cr3 释放。

18. **VMX Exception Bitmap 不做 per-CPU sync** — 改变全局期望值后必须有方式让每个 CPU 的 VMCS 应用变化；IPI + VMCLEAR/VMPTRLD 太重。  
    修复：lazy-sync 设计（generation counter + VMEXIT 顶部 compare）；无 IPI，零 VMWRITE in 稳态。

19. **`AsmVmxVmcall2` 接口新增** — 支持 2 参数的 nonce VMCALL；SVM 对称加 `AsmSvmVmmcall2`。

---

## 首轮 Review 修复清单



## P0 —— 致命修复（影响功能 / 稳定性）

### C-5 · `AsmSvmLaunch` 缺少真正的 VMRUN 循环 → AMD 平台完全不可用

| 位置 | `driver/svm_asm.asm` |
|------|----------------------|
| 问题 | 原版 `AsmSvmLaunch` 只执行一次 VMRUN 就返回，没有 `call SvmExitHandler`、没有循环。Guest 首次 VMEXIT 后会导致 DPC 误判为 "VMRUN 失败"，立即 `SvmDisableOnCpu` → **SVM 子系统实际上从未工作过**。 |
| 修复 | 重写 `AsmSvmLaunch` 为真正的 blue-pill 循环：分配栈上 `GUEST_CONTEXT` + 独立 anchor slot（VMCB PA/VA），每次 VMEXIT 保存 GP regs → `call SvmExitHandler` → 根据返回值继续 VMRUN 或优雅退出。<br>• 首次 VMRUN 通过 `VMCB.Save.Rip = _SvmLaunchGuest` + `Save.Rsp = current RSP` 让 Guest 从 DPC 自然返回 —— "Windows 成为 Guest"。<br>• 所有 15 个 context-tracked GP 寄存器每次迭代都通过 GUEST_CONTEXT 回传，anchors 保存在栈 slot 而非 CPU 寄存器，从而避免 VMRUN 不保存/恢复 GP regs 的陷阱。 |
| 验证点 | AMD EPYC / Ryzen 裸机上加载驱动后 Guest 应继续正常运行；`SvmExitHandler` 的日志会显示 ExitCode 流（CPUID、CR3 write、NPF 等）。|

### C-1 · SVM 缺少 CR3 Write 拦截 → AAD TSC 补偿失效

| 位置 | `driver/svm_init.c` `SvmSetupVmcb` |
|------|-----------------------------------|
| 修复 | `InterceptCr |= (1 << SVM_INTERCEPT_CR3_WRITE)`。AAD `AadUpdateHwTscOffset` 按进程切换更新 TSC Offset 的逻辑现在在 AMD 上生效。|

### C-2 · SVM HLT 拦截只 AdvanceRip → CPU 100% 占用

| 位置 | `driver/svm_init.c` `SvmSetupVmcb` |
|------|-----------------------------------|
| 修复 | 从 `Intercept` 位图中移除 `SVM_INTERCEPT_HLT`。CPU 硬件直接处理 Guest HLT，进入本地 C1/C2 空闲状态。VMEXIT handler 中的 HLT 处理保留为 defensive fallback。|

### H-5 · `EptUnhookAll` / `NptUnhookAll` UAF（HLT CPU 未刷新 TLB）

| 位置 | `driver/ept.c`、`driver/npt.c` |
|------|--------------------------------|
| 问题 | 卸载 hook 后 `EptInvalidateFromGuest()` 仅递增代际；在 HLT/C-state 的 CPU 不会 VM-Exit，TLB 仍指向将被 `ExFreePool` 的 HookPage → **UAF → BSOD**。 |
| 修复 | 新增 `EptInvalidateAllCpusSync` / `NptInvalidateAllCpusSync`：`KeIpiGenericCall` 在 IPI_LEVEL 广播回调，回调内执行 `__cpuid(0)`（被强制拦截 → 触发 VMEXIT）。回调返回保证所有 CPU 都已在 root mode 执行了 INVEPT / TLB flush。Unhook 释放页前调用这个新 API。|

### M-7 · `hv_mem.c` VMCALL 内存路径在 VMX-root 把 PA 当 HVA 解引用

| 位置 | `driver/hv_mem.c` |
|------|-------------------|
| 修复 | `HvReadGuestMemory` / `HvWriteGuestMemory` / `HvHandleMemoryVmcall` 改为安全 stub（返回 `STATUS_NOT_SUPPORTED`）。原逻辑会在 VMX root 下 `RtlCopyMemory((PVOID)PhysAddr, ...)` + `__try/__except` —— 既错误（root mode 下 host VA != PA）又危险（root mode 下 SEH 不可靠）。用户态路径统一使用 `vmxdrv.c` IOCTL + `MmMapIoSpace`。|

### H-6 · DriverEntry DPC 超时时栈上 DPC 可能仍在队列中

| 位置 | `driver/vmx_init.c` `VmxInitialize` |
|------|-------------------------------------|
| 修复 | 60s 超时分支先尝试 `KeRemoveQueueDpc(&Dpc)`：成功说明 DPC 尚未执行，可安全 unwind；失败说明 DPC 已开始（系统异常），改为 `KeWaitForSingleObject(..., NULL)` 无限等待以避免栈上 `DpcCtx` 被 DPC 回调访问造成内存损坏。|

---

## P1 —— 性能 / 扩展性 / 安全

### M-6 · VMCALL Shutdown 缺乏鉴权 → 任意 Ring-0 代码可解除保护

| 位置 | `driver/vmx_exit.c` `HandleVmcall`、`driver/svm_exit.c` `SvmHandleVmmcall`、`driver/vmxdrv.c` DriverEntry |
|------|---------------------------------------------------------------------------------------------|
| 修复 | DriverEntry 用 `KeQueryPerformanceCounter`/`__rdtsc`/`KeQueryInterruptTime` + Murmur finaliser 生成每次启动随机 64-bit `g_VmcallShutdownNonce`。Shutdown VMCALL 发起方 `AsmVmxVmcall2 / AsmSvmVmmcall2`（新增 2 参数版本）把 nonce 放在 RCX。handler 验证 `RCX == g_VmcallShutdownNonce` + `Guest CPL == 0`，否则注入 `#UD`。Nonce 永不通过 IOCTL / log 暴露出内核模块。|

### C-3 · SVM #DB/#BP 拦截永久开启 → 无关进程性能损耗

| 位置 | `driver/svm_init.c`、`driver/npt.c`、`driver/process.c` |
|------|---------------------------------------------------------|
| 修复 | VMCB 默认 `InterceptExceptions = 0`。引入两个按位元幂等开关：<br>• `SvmSetExceptionInterceptDb(BOOLEAN)` — NPT hook install 成功时置 TRUE，最后一个 hook 卸载时置 FALSE。<br>• `SvmSetExceptionInterceptBp(BOOLEAN)` — `process.c` 每次 Add/Remove/UpdateConfig 聚合所有 target 的 `AAD_HIDE_EXCEPTIONS` 计算。<br>内部 `VMCB.Control.CleanBits = 0` 让下次 VMRUN 重新读取 intercept 位图。|

### L-4 · Hook 点过于接近页尾会跨页覆写

| 位置 | `driver/ept.c` `EptHookFunction`、`driver/npt.c` `NptHookFunction` |
|------|--------------------------------------------------------------------|
| 修复 | 入口检查 `PageOffset + 12 > PAGE_SIZE` 返回 `STATUS_INVALID_PARAMETER`。保护 IOCTL 传入的任意用户态 `TargetAddress`。|

### L-5 · 用户态 Hook 未 `KeStackAttachProcess` → 可能 Hook 错误物理页

| 位置 | `driver/hv_hook.c` `GenericHookInstall` |
|------|----------------------------------------|
| 修复 | `TargetVa < 0x0000_8000_0000_0000`（用户态半区）+ `ProcessId != 0` 时：`PsLookupProcessByProcessId` → `KeStackAttachProcess` → `HvHookFunction` → `KeUnstackDetachProcess` → `ObDereferenceObject`。Kernel 态 VA 不需要 attach。|

### M-2 · `ProcessFindByCr3` mask 不完整

| 位置 | `driver/process.c` |
|------|-------------------|
| 修复 | 使用物理地址掩码 `0x000F_FFFF_FFFF_F000`（bits [51:12]），一次清除低 12 位 PCID、bit 63 "preserve TLB" 以及高位保留位。|

### L-8 · `HandleHlt` 进入 ACTIVE_HLT 未检查 RFLAGS.IF / Interruptibility

| 位置 | `driver/vmx_exit.c` |
|------|---------------------|
| 修复 | 设置 `VMCS_GUEST_ACTIVITY_STATE=HLT` 前检查 `RFLAGS.IF=1 && (Interruptibility & 0x3)==0`。不满足时保持 ACTIVE，避免 `CLI; HLT` 等病态代码触发 VM-Entry 失败。|

### M-8 · `HandleEptViolation` 非 hook 页 fixup 只刷当前 CPU

| 位置 | `driver/ept.c` |
|------|----------------|
| 修复 | 修改共享 PTE 后用 `EptInvalidateFromGuest()` 代际机制（所有 CPU 最终刷新），取代仅对当前 CPU 生效的 `EptInvalidateAllContexts()`。|

---

## P2 —— 质量 / 鲁棒性

### H-3 · Thunk slot 永不回收

| 位置 | `driver/hv_hook.h`、`driver/hv_hook.c` |
|------|----------------------------------------|
| 修复 | `THUNK_PAGE` 加 `SlotBitmap[THUNK_BITMAP_WORDS]`。`AllocateThunk` 搜第一个空闲 bit（支持中间空洞复用）。新增 `FreeThunk(PVOID)` 反查所属页并清对应 bit + 清零 stub 字节。`GenericHookRemove` / `GenericHookRemoveAll` 调用 `FreeThunk`。|

### M-4 · NPT #DB 误吞 Guest 自己的 #DB

| 位置 | `driver/npt.c`、`driver/npt.h`、`driver/svm_exit.c` |
|------|-----------------------------------------------------|
| 修复 | 新增 `g_NptDbRelaxedRip[cpu]`，`NptDbTrackRelaxedPage` 同时记录放宽时 `Vmcb->Save.Rip`。添加 `NptDbMatchesRelaxedRip(CurrentRip)` 检查 `CurrentRip - Recorded <= 15`（x86 最大指令长度）。`SvmHandleDbException` 在 `NptDbGetAndClearRelaxedPage` 前先调用 match 检查；不匹配则直接重注入 #DB，不碰 PTE 放宽状态。|

### L-1 · `ProcessResolveOffsets` 可能命中 UserDirectoryTableBase

| 位置 | `driver/process.c` |
|------|-------------------|
| 修复 | 扫描收集**所有**匹配 offset（最多 8 个），优先选最小值（DirectoryTableBase 历史上位于 EPROCESS 前部，UserDirectoryTableBase 为 KPTI 补丁新增），`ValidateDtbOffset` 做最终验证。|

---

## H-2 · 动态扩展 PD 数量（支持 > 512GB 物理内存）

上一轮已实现，此处作为清单完整性记录：

| 位置 | `driver/ept.c`、`driver/ept.h`、`driver/npt.c`、`driver/npt.h` |
|------|-----------------------------------------------------------------|
| 关键点 | `MmGetPhysicalMemoryRanges()` 启动时探测上限 → `g_EptPdptTotal` / `g_NptPdptTotal` 运行时确定；PML4[1..] 动态分配额外 PDPT 页；per-CPU 扩展 PDPT 页相应管理；`EptPaToFlatPdptIdx` / `NptPaToFlatPdptIdx` 统一扁平索引消除 `(PA>>30)&0x1FF` 截断；`HandleEptViolation` 对超出映射的 GPA 直接 fatal-shutdown VMX 避免死循环。 |

---

## 后续建议

1. **硬件验证**：在真实裸机 Intel（VT-x）+ AMD（SVM-V）平台上进行压力测试，重点关注：
   - 多核 + 频繁 hook/unhook 循环（`EptInvalidateAllCpusSync` 的 IPI 开销）
   - 长时间空闲（HLT / C-state）下的 TLB 一致性
   - `> 512GB` 服务器的 EPT/NPT 扩展覆盖
   - AMD 平台：首次 VMRUN 后 Windows 的 `ntoskrnl!KxSwapIdtEntry` / `KeInitializeIdtEntry` / 任何访问 `gs:KPCR` 的代码路径 —— 用来验证 Host VMCB 保存/恢复是正确的
2. **Driver Verifier**：启用 "Special Pool", "DPC Checking", "Low Resource Simulation" 运行 24h。
3. **压力工具**：建议 stress test 套件 —— 并发 `InstallHook/RemoveHook` + SSDT Monitor 全开 + WinDbg 附加 Guest。
4. **未处理的已知限制**（见代码注释）：
   - NPT + Intel execute-only 不支持的平台 Mode B 性能退化（REP 前缀指令 MTF 慢路径）
   - VMCALL 内存操作路径禁用（见 M-7 解释）；用户态一律走 IOCTL。

---

## 重要 API 变更（post-2nd-review）

| 变更 | 类型 | 说明 |
|------|------|------|
| `AsmSvmLaunch` | **签名变更** | `(VmcbPa, VmcbVa)` → `(VmcbPa, VmcbVa, HostVmcbPa)` — 新增 Host VMCB 物理地址用于 VMSAVE/VMLOAD host state |
| `SVM_CPU_CONTEXT::HostVmcbVa/HostVmcbPa` | 新字段 | 独立于 `HostSaveAreaVa/Pa`（硬件 HSAVE）；`SvmAllocateCpuContext` / `SvmFreeCpuContext` 同步更新 |
| `AsmVmxVmcall2` / `AsmSvmVmmcall2` | 新 API | 2 参数 VMCALL，用于 nonce 认证 |
| `HvIsAuthenticShutdownCaller(Rcx, Rip, Cpl, Efer, CsL)` | 新 helper | 统一的 shutdown VMCALL 认证 |
| `VmxSetExceptionInterceptDb/Bp`, `VmxSyncExceptionBitmap` | 新 API | VMX 侧动态异常拦截（原本缺失） |
| `SvmSetExceptionInterceptDb/Bp`, `SvmInterceptLockInitialize` | 新 API | SVM 侧无竞态初始化版本 |
| `ProcessRegisterExceptionHideToggle(Callback)` | 新 API | 解耦 process.c 与 SVM/VMX 后端 |
| `ProcessAnyTargetHasExceptionHiding()` | 新 API | 查询当前是否需要 #BP 拦截 |
| `NptDbMatchesRelaxedRip` | 语义改变 | 现在同时比对 CR3 + RIP 15-byte 窗口；内部使用 `NptDbSnapshotRelaxedTracker` 带 memory barrier |
| `EptInvalidateAllCpusSync` / `NptInvalidateAllCpusSync` | 实现改变 | 行为等价，但 IPI callback 现在直接 INVEPT/做 VMEXIT，不再依赖 CPUID-VMEXIT-CheckPending 间接路径 |
| `HvGuestVaToPa` | 行为改变 | 内部 `SafeReadPhysU64` 改用 `MmGetVirtualForPhysical`；顶部 `KeGetCurrentIrql` 守卫防止 VMX root 误用 |
| `HvHandleMemoryVmcall` | **已禁用** | VMCALL_SUBCMD_READ/WRITE_MEMORY 现直接注入 #UD；用户态请使用 IOCTL |
| `g_VmcallShutdownNonce` | 新全局 | 每次启动随机化；shutdown VMCALL 必须携带 |

Review / 修复提交人：Hypervisor 维护团队 · 2026-04（二次 Review：2026-04-18）
