# VMX Hypervisor Toolbox

基于 Intel VT-x (VMX) 和 AMD SVM 的 Windows x64 Hypervisor 工具箱。通过在操作系统下方插入一层轻量级 Type-2 Hypervisor，提供多种运行在 Ring -1 层面的底层能力，包括反反调试、绕过 PatchGuard 的内核 Hook 框架、基于物理内存直接访问的进程内存读写等，且后续将持续扩展更多基于 VMX 的高级功能。

**支持双平台**: 自动检测 CPU 厂商 (Intel/AMD)，选择对应的虚拟化后端。

---

## 许可协议（License）

> ⚠️ **重要：本项目采用自定义许可协议，非 MIT/BSD/GPL 等开源标准协议。**
>
> - ✅ **允许** 个人学习、研究、私人实验、安全研究、学术用途（非营利）。
> - ❌ **禁止** 任何形式的商业使用（含公司内部使用、付费产品集成、SaaS 服务、外挂／反外挂产品、AI 训练数据等），**除非事先获得作者书面同意**。
> - 🚫 **绝对禁止** 用于任何非法或恶意破坏目的，包括但不限于：未授权入侵、恶意软件／勒索软件／Rootkit、数据窃取、隐私侵犯、跟踪监控、欺诈与金融犯罪、DDoS／僵尸网络、侵害未成年人、非法商品服务平台，以及其他一切违反法律的行为。此项禁止 **对个人使用同样适用**，不可协商、不可豁免。违者自动失去一切使用权，并将依《刑法》《网络安全法》《数据安全法》《个人信息保护法》及同等境外法律承担民刑事责任；作者保留配合执法机关调查的权利。
> - 🛡️ **合法安全研究例外**：仅针对自有系统或获得书面授权的系统，以善意、负责任披露、最小必要损害为前提开展研究——具体条件详见 [`LICENSE`](LICENSE) 第 4A.3 节。
> - 📜 完整条款见根目录 [`LICENSE`](LICENSE) 文件（中英双语，英文为正式文本）。
> - 📬 商业授权洽谈：请通过本仓库 Issues 或 README 末尾列出的联系渠道联络作者。
>
> 使用、下载、编译、修改或分发本软件即视为您接受 [`LICENSE`](LICENSE) 全部条款。违反协议将自动终止您的使用权，并可能承担侵权法律责任。

> **2026-04 稳定性 Review（两轮）**: 完成了针对裸机运行的全面代码 Review + 一次更严格的二次 Review，合计修复 **36 项**跨级别问题（首轮 17 + 二次补救 19，含 SVM VMSAVE/VMLOAD host-state 缺失致 BSOD、AAD VMX 侧从未工作、nonce 认证不完备等致命 bug），详见 [docs/BAREMETAL_REVIEW_FIXES.md](docs/BAREMETAL_REVIEW_FIXES.md)。重要 API 变化：<br>• `AsmSvmLaunch` 签名为 `(VmcbPa, VmcbVa, HostVmcbPa)`，Host VMCB 用于 VMSAVE/VMLOAD 保护 host extra-state。<br>• Shutdown VMCALL/VMMCALL 现需要 `g_VmcallShutdownNonce` + long-mode + CS.L + kernel-RIP 完整认证。<br>• `VmxSetExceptionInterceptBp/Db` 新 API — VMX 侧 AAD_HIDE_EXCEPTIONS 现在真正工作。<br>• `ProcessRegisterExceptionHideToggle` 解耦 process 模块与 SVM/VMX 后端。<br>• VMCALL 内存操作路径已**注入 #UD 失败**；用户态必须使用 IOCTL。<br>• EPT/NPT 身份映射现动态扩展支持 > 512GB 物理内存（`g_EptPdptTotal / g_NptPdptTotal`）。

---

## 目录

- [项目概述](#项目概述)
  - [核心能力](#核心能力)
  - [设计理念](#设计理念)
- [系统架构](#系统架构)
- [项目结构](#项目结构)
- [核心技术细节](#核心技术细节)
  - [VMX 初始化流程](#vmx-初始化流程)
  - [VMCS 配置](#vmcs-配置)
  - [VM-Exit 处理框架](#vm-exit-处理框架)
  - [EPT 引擎与 Hook 机制](#ept-引擎与-hook-机制)
  - [进程跟踪与 EPROCESS 动态偏移发现](#进程跟踪与-eprocess-动态偏移发现)
  - [反反调试引擎](#反反调试引擎)
  - [MSR 拦截](#msr-拦截)
  - [日志系统](#日志系统)
- [AMD SVM 技术细节](#amd-svm-技术细节)
- [虚拟化隐藏](#虚拟化隐藏)
- [Per-CPU EPT/NPT Hook 页隔离](#per-cpu-eptnpt-hook-页隔离)
- [Hypervisor 内存读写](#hypervisor-内存读写)
- [后加载虚拟化与内存连续性](#后加载虚拟化与内存连续性)
- [通用 EPT/NPT Hook 框架](#通用-eptnpt-hook-框架)
- [SSDT 监控与 Hook 框架](#ssdt-监控与-hook-框架)
- [Shadow SSDT (Win32k) 监控与 Hook 框架](#shadow-ssdt-win32k-监控与-hook-框架)
- [反反调试能力清单](#反反调试能力清单)
- [用户态控制程序](#用户态控制程序)
  - [反反调试命令](#反反调试命令)
  - [Hook 框架命令](#hook-框架命令)
  - [内存读写命令](#内存读写命令)
  - [SSDT 命令](#ssdt-命令)
  - [Shadow SSDT 命令](#shadow-ssdt-命令)
  - [典型使用场景](#典型使用场景)
- [驱动与用户态通信协议](#驱动与用户态通信协议)
- [数据流分析](#数据流分析)
- [模块依赖关系](#模块依赖关系)
- [编译与部署](#编译与部署)
- [后续规划](#后续规划)
- [关键风险与注意事项](#关键风险与注意事项)

---

## 项目概述

| 属性 | 说明 |
|------|------|
| 平台 | Windows 10/11 x64 |
| CPU | Intel (VT-x/VMX/EPT) 和 AMD (SVM/NPT) |
| 架构 | Type-2 Hypervisor (寄生式, Blue Pill) + hv_ops 抽象层 |
| 运行环境 | 仅支持裸机 (bare metal) 运行 |
| 语言 | C + x64 MASM |
| 编译工具 | WDK 7600 (GRMWDK_EN_7600_1) |
| 核心功能 | 反反调试 / 内核 Hook 框架 / 进程内存读写 / 更多扩展中 |
| 工作原理 | 运行时加载到已运行的 OS 之下, 通过 VMX non-root 模式拦截敏感操作 |

### 核心能力

| 模块 | 能力 | 技术原理 |
|------|------|---------|
| **反反调试** | 使调试器对目标进程完全不可见 | 拦截 PEB/NtQuery/DR/RDTSC/CPUID 等检测，返回伪造结果 |
| **内核 Hook 框架** | 运行时 Hook 任意内核/用户态函数，绕过 PatchGuard | EPT/NPT Execute-Only 页分离 —— 读取看原始代码，执行走 Hook 代码 |
| **进程内存读写** | 直接读写任意进程内存，绕过一切内核回调和反作弊 Hook | CR3 页表遍历 → 物理地址 → MmMapIoSpace 直接访问 |
| **SSDT 监控与 Hook** | 发现、转储、按名称/索引 Hook 任意 SSDT 函数，支持全量/过滤监控 | 磁盘映射 ntoskrnl.exe (SEC_IMAGE) 获取无污染 SSDT 地址，复用 EPT Hook 框架 |
| **Shadow SSDT (Win32k) Hook** | 发现、转储、Hook NtUser*/NtGdi* 函数，支持全量/过滤监控 | KTHREAD 偏移扫描定位 KeServiceDescriptorTableShadow，Session 上下文中解析 win32k |
| **虚拟化隐藏** | 对 Guest 完全隐藏 Hypervisor 存在 | 拦截 CPUID/MSR/VMX/SVM 指令，伪装为裸机环境 |
| **Per-CPU EPT/NPT 隔离** | 多核 Hook 零竞争条件 | 每 CPU 独立 EPT/NPT 页表链，PTE 权限切换互不干扰 |
| **更多扩展** | 后续持续增加基于 VMX 的高级功能 | — |

### 设计理念

本项目不是一个单一用途的工具，而是一个 **基于 VMX/SVM 的可扩展底层能力平台**：

- **Ring -1 执行**: 所有功能运行在 Hypervisor 层面，高于操作系统内核，不受 PatchGuard、反作弊驱动等内核保护机制约束
- **双平台统一**: 通过 hv_ops 抽象层屏蔽 Intel/AMD 差异，所有上层功能对两个平台完全共用
- **模块化扩展**: 每个功能模块（反反调试、Hook、内存读写）独立实现，后续可方便地继续扩展新能力（如 SSDT 监控、虚拟化保护、驱动通信隐藏等）
- **CLI 统一入口**: 所有功能通过同一个 `VMXToolbox.exe` 命令行工具控制

---

## 系统架构

```
+---------------------------------------------------+
|                  用户态 (Ring 3)                    |
|                                                     |
|   VMXToolbox.exe (CLI)                                  |
|   +-- 反反调试命令  (--pid --hide-*)                |
|   +-- Hook 框架命令 (--install-hook --list-hooks)   |
|   +-- 内存读写命令  (--read-mem --write-mem)        |
|      |                                              |
|      | DeviceIoControl                              |
+------+----------------------------------------------+
|      v              内核态 (Ring 0)                  |
|                                                     |
|   VMXToolboxDrv.sys (内核驱动)                              |
|   +-----------------------------------------------+ |
|   | DriverEntry / CPU Detection / IOCTL Dispatch   | |
|   +-----------------------------------------------+ |
|   |            hv_ops 抽象层 (hv_ops.h)             | |
|   |     +------------------+-------------------+   | |
|   |     |   Intel VMX      |    AMD SVM        |   | |
|   |     |  (vmx_init.c)    |  (svm_init.c)     |   | |
|   |     |  (vmx_exit.c)    |  (svm_exit.c)     |   | |
|   |     |  (vmx_asm.asm)   |  (svm_asm.asm)    |   | |
|   |     |  (ept.c)         |  (npt.c)          |   | |
|   |     +------------------+-------------------+   | |
|   +-----------------------------------------------+ |
|   | Anti-Anti | Hook      | Memory   | Process    | |
|   | Debug     | Framework | R/W      | Tracking   | |
|   | (anti_*.c)| (hv_hook*)| (hv_mem*)| (process.c)| |
|   +-----------------------------------------------+ |
|   | SSDT Monitor & Hook  (ssdt.c)                  | |
|   | (发现 / 解析 / 名称 / Hook / 监控)             | |
|   +-----------------------------------------------+ |
|   | Shadow SSDT (Win32k) Monitor & Hook            | |
|   | (shadow_ssdt.c - NtUser*/NtGdi* Hook/监控)     | |
|   +-----------------------------------------------+ |
+-----------------------------------------------------+
|              Hardware Virtualization                  |
|   Intel VT-x: VMCS | EPT | MSR Bitmap               |
|   AMD SVM:    VMCB | NPT | MSRPM | IOPM             |
+-----------------------------------------------------+
```

### 双平台抽象架构 (hv_ops)

```
反反调试引擎 / VM-Exit 处理 / EPT/NPT Hook
         |
    hv_ops 抽象接口 (g_HvOps)
    /                        \
vmx_backend                 svm_backend
(现有 VMX 代码)             (新增 SVM 代码)
- VMCS read/write           - VMCB field access
- VMLAUNCH/VMRESUME         - VMRUN/VMLOAD/VMSAVE
- EPT + Execute-Only        - NPT + Read+Execute
- INVEPT                    - ASID Flush
- MTF single-step           - RFLAGS.TF single-step
    |                           |
    |                           |
    v                           v
 VMREAD/VMWRITE              VMCB 直接
 (Intel 原生)               内存读写
```

---

## 项目结构

```
VMXToolbox/
+-- common/
|   +-- shared.h              IOCTL 码, AAD_HIDE_* 标志, 共享数据结构
+-- driver/                    内核驱动 (VMXToolboxDrv.sys)
|   +-- hv_ops.h              [新增] Hypervisor 抽象层接口 (HV_OPS 结构体)
|   +-- hv_detect.h           [新增] CPU 厂商检测接口
|   +-- hv_detect.c           [新增] CPU 厂商检测 (Intel/AMD) + 能力探测
|   +-- vmx.h                 VMX 核心定义 (VMCS 编码, Exit Reason, 控制位)
|   +-- vmxdrv.c              驱动入口, CPU 检测, 后端选择, IOCTL 处理
|   +-- vmx_init.c            VMX 初始化 + HV_OPS 后端注册
|   +-- vmx_exit.c            VMX VM-Exit 主分发器
|   +-- vmx_asm.asm           Intel x64 汇编 (VMLAUNCH/VMRESUME/INVEPT)
|   +-- ept.h                 EPT 数据结构定义
|   +-- ept.c                 EPT 恒等映射, Hook 引擎, Violation 处理
|   +-- svm.h                 [新增] SVM 核心定义 (VMCB, Exit Codes, Intercepts)
|   +-- svm_init.c            [新增] SVM 初始化 + HV_OPS 后端注册
|   +-- svm_exit.c            [新增] SVM #VMEXIT 分发器
|   +-- svm_asm.asm           [新增] AMD x64 汇编 (VMRUN/VMLOAD/VMSAVE/CLGI/STGI)
|   +-- npt.h                 [新增] NPT 结构定义
|   +-- npt.c                 [新增] NPT 恒等映射 + Hook 引擎 (AMD 版 EPT)
|   +-- hv_mem.h              [新增] Hypervisor 内存读写接口 (页表遍历, VMCALL 定义)
|   +-- hv_mem.c              [新增] Guest 页表遍历 + 物理内存直接读写引擎
|   +-- hv_hook.h             [新增] 通用 Hook 框架接口 (动态 Thunk, 规则, 事件日志)
|   +-- hv_hook.c             [新增] Hook 框架核心 (Install/Remove/Decide/PostCall)
|   +-- hv_hook_asm.asm       [新增] Hook ASM dispatcher (参数保存/恢复/Trampoline 调用)
|   +-- ssdt.h               [新增] SSDT 监控框架接口 (状态结构, API 声明)
|   +-- ssdt.c               [新增] SSDT 发现/解析/名称解析/Hook/监控 全部实现
|   +-- shadow_ssdt.h       [新增] Shadow SSDT (Win32k) 框架接口
|   +-- shadow_ssdt.c       [新增] Shadow SSDT 发现/Win32k解析/NtUser*/NtGdi* Hook
|   +-- process.h             进程跟踪接口
|   +-- process.c             进程跟踪实现, EPROCESS 动态偏移发现
|   +-- anti_anti_debug.h     反反调试引擎接口
|   +-- anti_anti_debug.c     反反调试核心 (通过 hv_ops 抽象, 双平台共用)
|   +-- msr.c                 MSR 拦截 (通过 hv_ops 抽象)
|   +-- log.h                 日志接口
|   +-- log.c                 日志实现
+-- client/                    用户态控制程序 (VMXToolbox.exe)
|   +-- main.c                CLI 入口, 参数解析, 命令分发
|   +-- driver_comm.h         驱动通信接口
|   +-- driver_comm.c         DeviceIoControl 封装
+-- scripts/
|   +-- do_build.bat          一键编译脚本
|   +-- build.bat             编译说明脚本
|   +-- sign_test.bat         测试签名脚本
+-- readme.md                  本文档
```

---

## 核心技术细节

### VMX 初始化流程

**文件**: `vmx_init.c`

初始化分为全局准备和每核心虚拟化两个阶段:

#### 1. 全局准备

```
VmxInitialize()
  +-- VmxCheckCapabilities()      读取能力 MSR, 确认 EPT/VPID 支持
  |     +-- IA32_VMX_BASIC        获取 VMCS Revision ID, True Controls 支持
  |     +-- IA32_VMX_PROCBASED_CTLS   主处理器控制能力
  |     +-- IA32_VMX_PROCBASED_CTLS2  二级处理器控制能力 (EPT, VPID)
  |     +-- IA32_VMX_EPT_VPID_CAP    EPT/VPID 能力
  +-- VmxAllocateCpuContext() x N  为每个逻辑核分配:
  |     +-- VMXON Region (4KB, 物理连续, 页对齐)
  |     +-- VMCS Region  (4KB, 物理连续, 页对齐)
  |     +-- MSR Bitmap   (4KB, 物理连续)
  |     +-- Host Stack    (32KB, NonPagedPool)
  +-- EptInitialize()             构建 EPT 恒等映射
```

#### 2. VMX 支持检测

```c
VmxIsSupported():
  1. CPUID.1:ECX[5] == 1     // VMX 位
  2. IA32_FEATURE_CONTROL.Lock == 1 && VMXON_ENABLED == 1
```

#### 3. 控制字段调整

遵循 Intel SDM Vol. 3C, Section 31.5.1:

```c
VmxAdjustControls(Requested, Capability):
  Low32  = Capability & 0xFFFFFFFF   // 必须为 1 的位
  High32 = Capability >> 32          // 允许为 1 的位
  Result = (Requested | Low32) & High32
```

#### 4. 每核心启用

```
VmxEnableOnCpu():
  1. 保存原始 CR4
  2. CR4 |= VMXE (bit 13)
  3. 调整 CR0 满足 VMX fixed bits
  4. VMXON (使用 VMXON Region 物理地址)
```

### VMCS 配置

**文件**: `vmx_init.c` - `VmxSetupVmcs()`

VMCS 配置是整个 Hypervisor 的核心, 决定了哪些事件会触发 VM-Exit:

#### VM-Execution Controls

| 控制类别 | 启用的位 | 用途 |
|---------|---------|------|
| **Pin-Based** | NMI Exiting | 拦截 NMI |
| **Primary Proc** | Use MSR Bitmaps | 选择性拦截 MSR 访问 |
| | Use I/O Bitmaps | I/O 端口拦截控制 (全零=无 I/O 退出) |
| | Secondary Controls | 启用二级控制 |
| | CR3 Load Exiting | 监控进程切换 (CR3 写入) |
| | MOV-DR Exiting | 拦截调试寄存器访问 |
| | Use TSC Offsetting | 硬件 TSC 偏移 (反时间检测) |
| **Secondary Proc** | Enable EPT | 启用扩展页表 |
| | Enable RDTSCP | 允许 RDTSCP 指令 (拦截处理) |
| | Enable VPID | 虚拟处理器标识 (TLB 优化) |
| | Enable INVPCID | 允许 INVPCID 指令 |
| | Enable XSAVES | 允许 XSAVES/XRSTORS 指令 |
| **Exception Bitmap** | #DB (bit 1) | 拦截调试异常 |
| | #BP (bit 3) | 拦截断点异常 |

#### Guest State (镜像当前 CPU)

- 段寄存器: CS/SS/DS/ES/FS/GS/TR/LDTR (Selector, Base, Limit, AccessRights)
- 控制寄存器: CR0, CR3, CR4
- 描述符表: GDTR, IDTR (Base + Limit)
- MSR: IA32_DEBUGCTL, IA32_EFER, SYSENTER_CS/ESP/EIP
- RFLAGS, DR7, VMCS Link Pointer (0xFFFFFFFFFFFFFFFF)

#### Host State (VM-Exit 恢复目标)

- Host RSP: 指向 Host Stack 顶部 (32KB, 16 字节对齐 - 8)
- Host RIP: 指向 `AsmVmxExitHandler` (汇编入口)
- 段选择子: RPL 清零 (& 0xFFF8)
- CR4.VMXE: 保持置位
- IA32_EFER: VM-Exit 时自动保存/加载

#### CR0/CR4 Guest-Host Mask 与 Read Shadow

```c
// CR0: 拦截 VMX Fixed Bits (PE, NE, PG 等必须为 1 的位)
// Guest 修改这些位时触发 VM-Exit → HandleCrAccess 应用 Fixed0/Fixed1 调整
// 防止 Guest 写入违反 VMX 约束的 CR0 值导致 VM-Entry 失败
ULONG64 Cr0Fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
VmxWrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, Cr0Fixed0);
VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, Cr0 & Cr0Fixed0);

// CR4: 仅拦截 VMXE 位, 对 Guest 隐藏 VMX 操作
VmxWrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMXE);
VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, Cr4 & ~CR4_VMXE);
```

### VM-Exit 处理框架

**文件**: `vmx_asm.asm` (汇编入口) + `vmx_exit.c` (C 分发器)

#### 汇编入口 (`AsmVmxExitHandler`)

VM-Exit 发生时 CPU 自动跳转到 Host RIP, 即此函数:

```
1. sub rsp, 128          // 分配 GUEST_CONTEXT (16 个寄存器 x 8 字节)
2. 保存 RAX~R15 到栈     // 按 GUEST_CONTEXT 结构布局
3. mov rcx, rsp          // 第一参数 = PGUEST_CONTEXT
4. sub rsp, 28h          // x64 Shadow Space
5. call VmxExitHandler   // 调用 C 分发器
6. add rsp, 28h
7. if AL != 0:           // 继续 Guest
     恢复 RAX~R15
     add rsp, 128
     vmresume            // 恢复 Guest 执行
   else:                 // 关闭 VMX (IRETQ 方式)
     vmread Guest RSP/RIP/RFLAGS/CS/SS  // vmxoff 前读取
     vmxoff                              // 退出 VMX 操作
     在 Guest 栈上构建 IRETQ 帧         // [RIP, CS, RFLAGS, RSP, SS]
     恢复 RAX~R15
     mov rsp, Guest 栈
     iretq               // 原子恢复 CS:RIP + SS:RSP + RFLAGS
```

#### C 分发器 (`VmxExitHandler`)

```c
BOOLEAN VmxExitHandler(PGUEST_CONTEXT GuestContext) {
    GuestContext->Rsp = VmxRead(VMCS_GUEST_RSP);  // 同步 Guest RSP
    ExitReason = VmxRead(VMCS_EXIT_REASON) & 0xFFFF;
    InterlockedIncrement64(&CpuContext->ExitCount);

    switch (ExitReason) {
        case EXIT_REASON_CPUID:          -> AadHandleCpuid() (含 0x4CAFE000 后门)
        case EXIT_REASON_RDMSR:          -> HandleRdmsrImpl()
        case EXIT_REASON_WRMSR:          -> HandleWrmsrImpl()
        case EXIT_REASON_CR_ACCESS:      -> HandleCrAccess() (CR0 Fixed Bits 保护)
        case EXIT_REASON_DR_ACCESS:      -> AadHandleDrAccess()
        case EXIT_REASON_EXCEPTION_NMI:  -> HandleException() (NMI 重注入)
        case EXIT_REASON_EPT_VIOLATION:  -> HandleEptViolation()
        case EXIT_REASON_MTF:            -> HandleMtf() (per-CPU hook 恢复)
        case EXIT_REASON_VMCALL:         -> HandleVmcall() (关闭/内存读写)
        case EXIT_REASON_XSETBV:         -> HandleXsetbv() (XCR0 验证)
        case EXIT_REASON_HLT:           -> Activity State = HLT
        case EXIT_REASON_IO:            -> I/O 直通模拟
        ...
    }

    // IDT-Vectoring 事件重注入 (防止 Guest 丢失异常)
    if (IDT_VECTORING_INFO.Valid && !VMENTRY_INT_INFO.Valid)
        重注入原始 IDT 事件;

    VmxWrite(VMCS_GUEST_RSP, GuestContext->Rsp);  // 写回 Guest RSP
    return TRUE;  // VMRESUME
    return FALSE; // VMXOFF (IRETQ 恢复)
}
```

#### Exit Reason 处理策略

| Exit Reason | 策略 | 说明 |
|-------------|------|------|
| CPUID | 后门 + 修改返回值 | 0x4CAFE000 后门, 清除 VMX/Hypervisor 位 |
| RDMSR/WRMSR | 代理执行 + 伪造 | 修改 IA32_DEBUGCTL 返回值 |
| CR3 Load | 透传 + 记录 | 监控进程切换 |
| CR0 Write | Fixed Bits 调整 | 应用 VMX CR0 Fixed0/Fixed1 约束 |
| DR Access | 伪造读取 / 允许写入 | DR0-3=0, DR7=0x400 |
| Exception/NMI | 重注入 / NMI-window | NMI 始终重注入, 异常传递给 Guest |
| EPT Violation | 页面切换 + MTF | Execute-Only Hook 核心 |
| MTF | 恢复 EPT 权限 | Hook 读写后恢复 Execute-Only |
| VMCALL | 控制通道 | 0xDEADCAFE = 关闭, 内存读写 |
| HLT | Activity State = HLT | Guest 安全休眠 |
| XSETBV | 验证 + 执行 | XCR0 合法性检查 |
| I/O | 直通执行 | 模拟 IN/OUT (must-be-1 位强制) |
| IDT-Vectoring | 自动重注入 | 防止 VM-Exit 丢失 Guest 异常 |

### EPT 引擎与 Hook 机制

**文件**: `ept.h` + `ept.c`

EPT (Extended Page Tables) 是本项目最核心的技术, 实现了透明的函数 Hook。

#### EPT 页表层级

```
EPT 4 级页表 (恒等映射 512GB 物理地址空间):

PML4[0] ──> PDPT[512] ──> PD[512][512] ──> 2MB Large Pages
                                |
                         EptSplitLargePage()
                                |
                                v
                          PT[512] ──> 4KB Pages (用于 Hook)
```

#### 恒等映射构建

```c
EptInitialize():
  1. 分配 512 个 PD 页 (每个覆盖 1GB)
  2. 每个 PD 页含 512 个 2MB Large Page 条目
  3. 总覆盖: 512 PD x 512 条目 x 2MB = 512GB
  4. PML4[0] -> PDPT -> PD (Read+Write+Execute)
  5. EPTP = WB 内存类型 + 4 级页走 + PML4 物理地址
```

#### 2MB -> 4KB 分裂

当需要对某个 4KB 页面设置不同权限时, 必须先将包含它的 2MB 大页拆分:

```c
EptSplitLargePage(PhysicalAddress):
  1. 计算 2MB 对齐基址
  2. 从预分配的 Split Page 池中取一个空闲页
  3. 填充 512 个 PTE, 每个映射 4KB (R+W+X, WB)
  4. 更新 PDE: LargePage=0, 指向新 PT 页
```

预分配的 Split Page 池大小: `MAX_SPLIT_PAGES = 32`

#### Execute-Only Hook 机制

这是整个项目最精妙的设计 -- 利用 EPT 的 R/W/X 权限分离实现**不可检测**的函数 Hook:

```
                    +------------------+
                    |   目标函数页面    |
                    |   (原始代码)      |
                    +--------+---------+
                             |
                    EptHookFunction()
                             |
              +--------------+--------------+
              |                             |
     +--------v--------+         +---------v--------+
     |   原始页 (备份)   |         |   Hook 页 (修改)  |
     |   原始字节内容    |         |   JMP HookFunc    |
     |                  |         |   (14 字节 abs)   |
     +--------+---------+         +---------+--------+
              |                             |
              |    EPT PTE 配置:             |
              |    Execute-Only -> Hook 页   |
              |    Read/Write  -> 原始页     |
              |                             |
     +--------v---------+        +---------v--------+
     | 反调试代码读取时:  |        | CPU 执行时:       |
     | 看到未修改的原始   |        | 执行 JMP 到       |
     | 字节 (完整性检查   |        | Hook 函数         |
     | 通过)             |        |                   |
     +------------------+        +-------------------+
```

#### Hook 安装流程

```c
EptHookFunction(TargetVa, HookFunction, &OriginalFunction):
  1. 翻译 VA -> PA (MmGetPhysicalAddress)
  2. 拆分 2MB 大页 (EptSplitLargePage)
  3. 获取目标 4KB 页的 PTE
  4. 分配并拷贝原始页内容
  5. 分配 Hook 页, 写入 14 字节绝对跳转:
       FF 25 00000000           // JMP QWORD PTR [RIP+0]
       <8 字节 HookFunction 地址>
  6. 构建 Trampoline (调用原函数):
       <原始字节 (14 bytes)>
       FF 25 00000000
       <8 字节 TargetVa+14 地址>
  7. 设置 PTE:
       Read=0, Write=0, Execute=1
       PhysAddr = Hook 页物理地址
  8. INVEPT 刷新 TLB
```

#### EPT Violation 处理

```c
HandleEptViolation():
  读取: GuestPhysAddr, ExitQualification

  if 读/写访问:
    // 反调试代码在读取函数字节 (完整性检查)
    PTE -> Read=1, Write=1, Execute=0, PhysAddr=原始页
    启用 MTF (Monitor Trap Flag)
    // 执行一条读/写指令后触发 MTF VM-Exit

  if 执行访问:
    // 恢复为执行 Hook 页
    PTE -> Read=0, Write=0, Execute=1, PhysAddr=Hook页

HandleMtf():
  // 读/写指令执行完毕, 恢复 Execute-Only
  关闭 MTF
  遍历所有 Hook:
    PTE -> Read=0, Write=0, Execute=1, PhysAddr=Hook页
  INVEPT
```

### 进程跟踪与 EPROCESS 动态偏移发现

**文件**: `process.h` + `process.c`

#### EPROCESS 偏移动态发现

`EPROCESS.DirectoryTableBase` 的偏移因 Windows 版本而异。本项目通过**运行时扫描**自动确定:

```c
ProcessResolveOffsets():
  // 方法 1: CR3 扫描 (最可靠)
  CurrentProcess = PsGetCurrentProcess()
  CurrentCr3 = __readcr3()
  for offset = 0 to 0x700 step 8:
    value = *(ULONG64*)(EPROCESS + offset)
    if (value & ~0xFFF) == (CurrentCr3 & ~0xFFF):
      if ValidateDtbOffset(offset):
        -> 找到! offset 就是 DirectoryTableBase 偏移

  // 方法 2: 已知偏移表 (回退)
  尝试: 0x028 (Win10/11), 0x018 (Win7/8), 0x02C (Insider)
  对每个偏移用 ValidateDtbOffset() 验证
```

验证逻辑:

```c
ValidateDtbOffset(offset):
  1. 读取 System 进程 EPROCESS 在该偏移处的值
  2. 与当前 CR3 比较 (mask 掉 PCID 低 12 位)
  3. 检查值非零且在有效物理地址范围内 (< 2^48)
```

#### CR3 进程识别

在 VM-Exit handler 中通过 CR3 快速识别目标进程:

```c
ProcessFindByCr3(Cr3):
  Cr3Masked = Cr3 & ~0xFFF    // 去掉 PCID 位
  for i = 0 to MAX_TARGET_PROCESSES:
    if Targets[i].Active && (Targets[i].Cr3 & ~0xFFF) == Cr3Masked:
      return &Targets[i]
  return NULL
```

**设计考量**:
- 线性扫描 (MAX_TARGET_PROCESSES=16), 无锁读取
- 在 VM-Exit handler 的高 IRQL 下安全执行
- PCID (Process Context Identifier) 位 mask 保证兼容性

### 反反调试引擎

**文件**: `anti_anti_debug.h` + `anti_anti_debug.c`

#### 功能概览

反反调试引擎分两层工作:

1. **VM-Exit Handler 层**: 拦截 CPUID / DR / RDTSC / 异常
2. **EPT Hook 层**: 拦截 Nt* 内核 API 调用

#### EPT Hook 的四个 Nt API

**1. NtQueryInformationProcess** (最重要)

```c
HookNtQueryInformationProcess():
  调用原函数获取真实结果
  if 是目标进程 && AAD_HIDE_DEBUGGER:
    switch (InformationClass):
      ProcessDebugPort (0x07):
        -> 改为 0 (无调试端口)
      ProcessDebugObjectHandle (0x1E):
        -> 返回 STATUS_PORT_NOT_SET
      ProcessDebugFlags (0x1F):
        -> 改为 1 (未被调试)
```

**2. NtQuerySystemInformation**

```c
HookNtQuerySystemInformation():
  调用原函数
  if 是目标进程 && AAD_HIDE_SYSINFO:
    if class == SystemKernelDebuggerInformation (0x23):
      KernelDebuggerEnabled = FALSE
      KernelDebuggerNotPresent = TRUE
```

**3. NtSetInformationThread**

```c
HookNtSetInformationThread():
  if 是目标进程 && class == ThreadHideFromDebugger (0x11):
    return STATUS_SUCCESS   // 假装成功, 实际不执行
  else:
    调用原函数
```

**4. NtClose**

```c
HookNtClose():
  if 是目标进程:
    __try { 调用原函数 }
    __except { 吞掉异常 }   // 防止 INVALID_HANDLE 异常泄露调试状态
```

#### 调试寄存器伪造 (DR0-DR7)

```c
AadHandleDrAccess():
  Exit Qualification 解析:
    DrNumber  = bits[2:0]    // DR 编号
    Direction = bit[4]       // 0=写入DR, 1=读取DR
    GpReg     = bits[11:8]   // 通用寄存器编号

  if 是目标进程 && AAD_HIDE_HWBP:
    if 读取 DR:
      DR0-DR3 -> 返回 0           (隐藏硬件断点地址)
      DR6     -> 返回 0xFFFF0FF0  (清除断点命中标志)
      DR7     -> 返回 0x400       (默认值, 无断点启用)
    if 写入 DR:
      正常写入 (断点仍然工作, 只是读取时隐藏)
  else:
    正常执行 DR 操作
```

#### RDTSC/RDTSCP 时间补偿

```c
AadHandleRdtsc():
  RealTsc = __rdtsc()
  if 是目标进程 && AAD_HIDE_TIMING:
    RealTsc -= CpuContext->TscOffset   // 减去累计调试暂停时间
  GuestContext->RAX = RealTsc 低32位
  GuestContext->RDX = RealTsc 高32位

// TSC 偏移管理:
AadNotifyDebugPause():  记录暂停开始时的 TSC
AadNotifyDebugResume(): TscOffset += (当前TSC - 暂停开始TSC)
```

#### CPUID 隐藏

```c
AadHandleCpuid():
  // CPUID 后门：快速检测 Hypervisor 是否活跃
  if Leaf == 0x4CAFE000:
    EAX = 0x564D5854 ("VMXT"), EBX=ECX=EDX=0
    return   // 不执行真实 CPUID

  执行真实 CPUID
  if 是目标进程 && AAD_HIDE_CPUID:
    Leaf 1:
      ECX &= ~(1 << 31)       // 清除 Hypervisor Present 位
    Leaf 0x40000000~0x400000FF:
      EAX=EBX=ECX=EDX = 0     // 伪装为裸机
```

#### 异常行为标准化

```c
AadHandleException():
  读取中断信息: Vector, Type, ErrorCode
  // 无论是否目标进程, 都重新注入异常到 Guest
  // 让 Guest 的 SEH/VEH 正常处理
  // 这确保了 INT 2D, INT 3 等的行为与非调试环境一致

  VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, InjectInfo)
```

### MSR 拦截

**文件**: `msr.c`

#### MSR Bitmap 布局

```
4KB Bitmap:
  [0x000..0x3FF]  Read bitmap  for MSR 0x00000000 - 0x00001FFF
  [0x400..0x7FF]  Read bitmap  for MSR 0xC0000000 - 0xC0001FFF
  [0x800..0xBFF]  Write bitmap for MSR 0x00000000 - 0x00001FFF
  [0xC00..0xFFF]  Write bitmap for MSR 0xC0000000 - 0xC0001FFF

bit = 1 -> 该 MSR 访问触发 VM-Exit
bit = 0 -> 直接透传 (不 VM-Exit)
```

默认全部透传, 仅拦截 `IA32_DEBUGCTL` (0x01D9):

```c
MsrBitmapInitialize():
  RtlZeroMemory(bitmap, 4096)     // 全部透传
  SetBit(IA32_DEBUGCTL, Read+Write)  // 拦截调试控制 MSR
```

#### IA32_DEBUGCTL 伪造

```c
HandleRdmsrImpl():
  if MSR == IA32_DEBUGCTL && 是目标进程:
    Value &= ~0x43    // 清除:
                      //   Bit 0 (LBR): Last Branch Record
                      //   Bit 1 (BTF): Single-Step on Branches
                      //   Bit 6 (TR):  Trace Messages
```

### 日志系统

**文件**: `log.h` + `log.c`

#### 设计原则

Hypervisor 日志面临一个核心挑战：**VMX root 模式下不能调用 `DbgPrintEx`**。原因是 `DbgPrintEx` 内部使用自旋锁和 `INT 3` 触发调试器中断，而 VMX root 模式运行在 Host 栈（32KB `ExAllocatePool` 分配的内存）上，不是 Windows 线程内核栈——SEH 异常链无效，`INT 3` 导致递归 VM-Exit 或死锁。

解决方案：**统一的 Lock-free Ring Buffer + Flush Thread 架构**。

#### Lock-free Ring Buffer

```
8192 entries, 每条 256 字节

                   Lock-free 写入 (InterlockedIncrement)
                            |
+---+---+---+---+---+---+---+---+
| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | ... [8192 entries]
+---+---+---+---+---+---+---+---+
          ^                   ^                ^
          |                   |                |
      FlushIndex         ReadIndex        WriteIndex

Ready[i] = 0: 空槽位或正在写入
Ready[i] = 1: 数据已完整写入, 可安全读取
```

**无锁发布协议** (Multi-writer safe)：
```
写入者 (LogWrite, 任意 IRQL / VMX root 均安全):
  1. InterlockedIncrement(&WriteIndex)    — 原子占位
  2. 填写 Entry (Level, Pid, Timestamp, Message)
  3. InterlockedExchange(&Ready[Idx], 1)  — RELEASE 屏障, 发布

读取者 (Flush Thread / LogRead):
  1. 检查 Ready[Idx] == 1                 — ACQUIRE 屏障
  2. 读取 Entry 全部字段 (保证完整)
  3. InterlockedExchange(&Ready[Idx], 0)  — 释放槽位
```

全程零自旋锁、零 IRQL 操作、纯 `Interlocked*` 原子操作。

#### Flush Thread (System Thread)

```
LogFlushThreadRoutine():
  运行级别: PASSIVE_LEVEL (普通内核线程栈)
  轮询间隔: 5ms
  
  loop:
    KeWaitForSingleObject(StopEvent, 5ms timeout)
    while (FlushIndex < WriteIndex):
      if Ready[Idx] == 1:
        DbgPrintEx(...)    ← 在 PASSIVE_LEVEL 安全调用
        Ready[Idx] = 0
        FlushIndex++
      else:
        break              ← 写入者尚未完成, 下次再来
```

日志从写入到显示在 WinDbg 的延迟约 **5ms**（Flush Thread 轮询间隔）。

#### 统一宏接口

```c
/* 普通上下文 (DriverEntry, IOCTL handler 等) */
LOG_ERROR(fmt, ...)     // → LogWrite → Ring Buffer
LOG_WARN(fmt, ...)
LOG_INFO(fmt, ...)
LOG_DEBUG(fmt, ...)

/* VMX root 模式 (VM-Exit handler 内部) — 与上面完全相同 */
VMXROOT_LOG_ERROR(fmt, ...)  // → LogWrite → Ring Buffer
VMXROOT_LOG_WARN(fmt, ...)
VMXROOT_LOG_INFO(fmt, ...)
VMXROOT_LOG_DEBUG(fmt, ...)
```

两组宏最终都调用同一个 `LogWrite()`，统一走 Ring Buffer 路径。Flush Thread 负责所有 `DbgPrintEx` 输出。

#### 输出过滤

| 级别 | 值 | WinDbg 输出 | Ring Buffer | 用途 |
|------|---|------------|-------------|------|
| ERROR | 0 | ✅ (Flush Thread) | ✅ | 致命错误 |
| WARN  | 1 | ✅ (Flush Thread) | ✅ | 警告信息 |
| INFO  | 2 | ✅ (Flush Thread) | ✅ | 常规信息 (驱动加载, Hook 安装等) |
| DEBUG | 3 | ❌ (仅 Ring Buffer) | ✅ | 调试信息 (高频, 通过 IOCTL 读取) |

#### 用户态读取

通过 `IOCTL_VMX_GET_LOG` 读取 Ring Buffer 中的条目，使用独立的 `ReadIndex`（与 Flush Thread 的 `FlushIndex` 互不干扰）。

---

## AMD SVM 技术细节

### SVM 概述

AMD SVM (Secure Virtual Machine) 是 AMD 的硬件虚拟化技术，等价于 Intel VT-x。核心差异：

| 概念 | Intel VMX | AMD SVM |
|------|-----------|---------|
| 控制结构 | VMCS (通过 vmread/vmwrite) | VMCB (直接内存访问) |
| 进入 Guest | VMLAUNCH / VMRESUME | VMRUN |
| 状态保存 | 自动 (VMCS fields) | VMSAVE / VMLOAD |
| 二级页表 | EPT (Extended Page Tables) | NPT (Nested Page Tables) |
| TLB 管理 | INVEPT / INVVPID | ASID + TLB Control |
| 中断控制 | External-Interrupt Exiting | GIF (Global Interrupt Flag) |
| 单步调试 | MTF (Monitor Trap Flag) | RFLAGS.TF + #DB 拦截 |
| Execute-Only 页 | 支持 | **不支持** |
| 指令长度 | Exit Instruction Length | NRIP Save (Next RIP) |

### VMCB (Virtual Machine Control Block)

VMCB 是 4KB 页面，包含两个区域：

```
+---------------------------+
| Control Area (0x000-0x3FF)|  拦截配置、退出信息、NPT 设置
|   intercept_cr/dr/excps   |
|   intercept (64-bit)      |
|   iopm_base_pa            |
|   msrpm_base_pa           |
|   tsc_offset              |
|   asid                    |
|   exit_code / exit_info   |
|   nested_ctl / nested_cr3 |
|   event_inj               |
|   next_rip                |
+---------------------------+
| Save Area (0x400-0xFFF)   |  Guest CPU 状态
|   段寄存器 (ES~TR)         |
|   CR0/CR2/CR3/CR4         |
|   DR6/DR7                 |
|   RFLAGS/RIP/RSP/RAX      |
|   EFER/STAR/LSTAR/CSTAR   |
|   SYSENTER_CS/ESP/EIP     |
|   G_PAT/DBGCTL            |
+---------------------------+
```

### SVM VMRUN 循环

```
SvmEnableOnCpu():
  1. EFER |= SVME (bit 12)        启用 SVM
  2. MSR_VM_HSAVE_PA = host_save   设置 host 状态保存区

VMRUN 循环 (svm_asm.asm):
  保存 host callee-saved 寄存器
  加载 guest GP 寄存器
  RAX = VMCB 物理地址
  VMLOAD                           加载 guest 段寄存器等
  VMRUN                            进入 guest, #VMEXIT 时返回
  VMSAVE                           保存 guest 段寄存器等
  保存 guest GP 寄存器
  恢复 host callee-saved 寄存器
  调用 SvmExitHandler()            C 分发器
```

### NPT vs EPT Hook 策略

| 特性 | Intel EPT | AMD NPT |
|------|-----------|---------|
| Execute-Only | 支持 (R=0, W=0, X=1) | **不支持** |
| Hook 默认映射 | Execute-Only → Hook 页 | Read+Execute → Hook 页 |
| 读取时 | EPT Violation → 原始页 | 直接看到 Hook 页 |
| 写入时 | EPT Violation → 原始页 + MTF | NPF → 原始页 + TF |
| 完整性检查抗性 | 极高 (读取看原始) | 中等 (读取看 Hook) |
| 单步恢复 | MTF VM-Exit | #DB Exception |

NPT Hook 具体策略：

```
Hook 安装:
  PTE -> Read=1, Write=0, Execute=1, PhysAddr=Hook页
  (执行和读取走 Hook 页，写入触发 NPF)

写入触发 NPF:
  PTE -> Read=1, Write=1, Execute=1, PhysAddr=原始页
  RFLAGS.TF = 1 (设置 Trap Flag)
  重新执行写入指令

#DB Exception (单步完成):
  PTE -> Read=1, Write=0, Execute=1, PhysAddr=Hook页
  RFLAGS.TF = 0
  TLB Flush (ASID 切换)
```

### SVM 反反调试能力

SVM 后端提供与 VMX 完全相同的反反调试能力：

| 功能 | VMX 实现 | SVM 实现 |
|------|---------|---------|
| DR 寄存器伪造 | MOV-DR Exiting | DR Read/Write Intercept |
| CPUID 隐藏 | CPUID 无条件 Exit | CPUID Intercept |
| RDTSC 补偿 | RDTSC Exiting | RDTSC Intercept |
| 异常标准化 | Exception Bitmap | Exception Intercept |
| API Hook | EPT Execute-Only | NPT Read+Execute |
| MSR 伪造 | MSR Bitmap (4KB) | MSRPM (8KB) |

---

```

---

## 虚拟化隐藏

### 背景

为了阻止 Guest 内软件（包括反作弊驱动的虚拟化检测、以及反调试代码的 Hypervisor 探测），我们在 VM-Exit handler 中对 **CPUID / MSR / VMX 指令 / SVM 指令** 进行全面拦截，使 Guest 认为自己运行在无虚拟化能力的裸机上。

### 修改影响方向

```
VMXToolbox Hypervisor                  ← 修改发生在这里
        ↓ VM-Exit handler 修改返回给 Guest 的值
Guest OS + 应用                        ← 看到伪造的裸机环境
```

**所有修改只影响 Hypervisor→Guest 方向**。

### CPUID 隐藏

**文件**: `anti_anti_debug.c` — `AadHandleCpuid()`

**CPUID 后门** (对所有进程无条件生效)：

| Leaf | 返回值 | 目的 |
|------|--------|------|
| `CPUID(0x4CAFE000)` | `EAX=0x564D5854` ("VMXT") | 快速检测 Hypervisor 是否活跃 |

```c
// 用户态/内核态检测代码示例:
int info[4];
__cpuid(info, 0x4CAFE000);
if (info[0] == 0x564D5854) printf("Hypervisor active!\n");
```

**虚拟化隐藏** (对所有进程无条件生效)：

| Leaf | 修改 | 目的 |
|------|------|------|
| `CPUID.1:ECX` | 清除 bit 31 (Hypervisor Present) | 隐藏 Hypervisor 存在 |
| `CPUID.1:ECX` | 清除 bit 5 (VMX) | 隐藏 Intel VT-x 支持 |
| `CPUID.0x80000001:ECX` | 清除 bit 2 (SVM) | 隐藏 AMD-V 支持 |
| `CPUID.0x8000000A` | 返回全零 | 隐藏 SVM 特性叶（NASID/NPT 支持等） |
| `CPUID.0x40000000~0x40000006` | 返回全零 | 隐藏 Hypervisor 厂商字符串和接口叶 |

```c
if (Leaf == 1) {
    CpuInfo[2] &= ~(1 << CPUID_HYPERVISOR_BIT);   /* Hide hypervisor present */
    CpuInfo[2] &= ~(1 << 5);                       /* Hide VMX (Intel VT-x) */
}
else if (Leaf == 0x80000001) {
    CpuInfo[2] &= ~(1 << 2);                       /* Hide SVM (AMD-V) */
}
else if (Leaf == 0x8000000A) {
    CpuInfo[0] = CpuInfo[1] = CpuInfo[2] = CpuInfo[3] = 0;
}
else if (Leaf >= 0x40000000 && Leaf <= 0x40000006) {
    CpuInfo[0] = CpuInfo[1] = CpuInfo[2] = CpuInfo[3] = 0;
}
```

**安全性说明**：`__cpuidex()` 先执行真实 CPUID（由 L0 返回），修改发生在 VM-Exit handler 中，仅改变返回给 L2 Guest 的结果。L0 完全不知道我们修改了什么。

### MSR 拦截 — 虚拟化能力隐藏

**文件**: `msr.c`

#### MSR Bitmap 配置

在 `MsrBitmapInitialize()` 中拦截以下 MSR：

| MSR 范围 | 名称 | 拦截模式 |
|----------|------|---------|
| `0x003A` | IA32_FEATURE_CONTROL | 读+写 |
| `0x0480~0x0491` | IA32_VMX_BASIC ~ IA32_VMX_VMFUNC | 读+写 |
| `0xC0010114` | MSR_VM_CR (AMD) | 读+写 (SVM MSRPM) |
| `0xC0010117` | MSR_VM_HSAVE_PA (AMD) | 读+写 (SVM MSRPM) |

#### RDMSR 伪造策略

| MSR | 返回值 | 含义 |
|-----|--------|------|
| `0x0480~0x0491` (VMX MSRs) | 全零 | VMX 不可用 |
| `0x003A` (IA32_FEATURE_CONTROL) | `1` (Lock=1, VMXON=0) | VMX 被 BIOS 锁定禁用 |
| `0xC0010114` (MSR_VM_CR) | 真实值 \| SVMDIS \| LOCK | SVM 被禁用并锁定 |
| `0xC0010117` (MSR_VM_HSAVE_PA) | `0` | SVM Host Save Area 未配置 |

#### WRMSR 阻止策略

所有虚拟化相关 MSR 的写入操作均注入 `#GP(0)`，模拟裸机行为（VMX MSR 只读；IA32_FEATURE_CONTROL 写入锁定后 #GP；VM_CR 锁定后 #GP）。

### VMX 指令拦截

**文件**: `vmx_exit.c`

Guest 尝试执行任何 VMX 指令时（即使 CPUID 已隐藏 VMX 位），CPU 会无条件触发 VM-Exit。我们对所有 VMX 指令注入 `#UD`（Undefined Opcode），与 VMX 被禁用时的 CPU 行为一致：

```c
case EXIT_REASON_VMCLEAR:
case EXIT_REASON_VMLAUNCH:
case EXIT_REASON_VMPTRLD:
case EXIT_REASON_VMPTRST:
case EXIT_REASON_VMREAD:
case EXIT_REASON_VMRESUME:
case EXIT_REASON_VMWRITE:
case EXIT_REASON_VMXOFF:
case EXIT_REASON_VMXON:
case EXIT_REASON_INVEPT:
case EXIT_REASON_INVVPID:
    /* Inject #UD (vector 6) */
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO, INTERRUPT_INFO_VALID |
             (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) | 6);
    break;
```

### SVM 指令拦截

**文件**: `svm_exit.c`

AMD SVM 后端同样拦截所有 SVM 管理指令并注入 `#UD`：

- `VMRUN` / `VMLOAD` / `VMSAVE`
- `STGI` / `CLGI`
- `SKINIT` / `INVLPGA`

### 安全性总结

| 修改点 | 影响方向 | 对外层 HV 影响 | 说明 |
|--------|---------|--------------|------|
| CPUID 隐藏 VMX/SVM 位 | L1→L2 | ❌ 无 | 只修改给 Guest 的返回值 |
| MSR bitmap 拦截 | L1→L2 | ❌ 无 | 只控制 Guest 的 MSR 访问 |
| RDMSR 伪造 | L1→L2 | ❌ 无 | 只在 Exit handler 中修改 |
| WRMSR 阻止 (#GP) | L1→L2 | ❌ 无 | 只对 Guest 注入 #GP |
| VMX 指令 → #UD | L1→L2 | ❌ 无 | 只拦截 Guest 的 VMX 指令 |
| SVM 指令 → #UD | L1→L2 | ❌ 无 | 只拦截 Guest 的 SVM 指令 |

**初始化安全**：`VmxCheckCapabilities()` 和 `SvmCheckCapabilities()` 中的 `__readmsr(MSR_IA32_VMX_BASIC)` 等调用在 `DriverEntry` 中执行，此时 VMX/SVM 还未启动，MSR Bitmap 还未生效，不受影响。

---

---

## Per-CPU EPT/NPT Hook 页隔离

### 背景问题

在多核系统上，EPT/NPT Hook 的 **违规 → 单步 → 恢复** 三阶段存在竞争条件：

```
CPU 0: EPT Violation → 放宽 PTE (R+W) → 启用 MTF
CPU 1: EPT Violation → 放宽 PTE (R+W) → 启用 MTF    ← 同一个 PTE!
CPU 0: MTF 触发 → 恢复 PTE (X-Only)                  ← 也恢复了 CPU 1 正在使用的 PTE!
CPU 1: 还在执行放宽后的指令 → PTE 已被 CPU 0 恢复 → 再次 EPT Violation → 死循环/卡死
```

### 解决方案

每个 CPU 拥有独立的 EPT/NPT 页表链（PML4 → PDPT → PD → PT），使得 PTE 权限切换仅影响当前 CPU 的地址翻译。

**关键约束**：只在 PT 级别做隔离，非 Hook 区域所有 CPU 仍共享相同的 PD/PT pages。

### 整体架构

```
        ┌──────────────────────────────────────────────┐
        │  共享模板 (EPT_STATE / NPT_STATE)             │
        │  PML4 → PDPT → PD Pages → Split PT Pages     │
        │  (非 Hook 区域所有 CPU 共享)                    │
        └──────────────────────────────────────────────┘

Per-CPU 层 (仅 Hook 区域):

  CPU 0:  PML4[0] → PDPT[0]                CPU 1:  PML4[1] → PDPT[1]
            │                                        │
            ├─ PDPT[x] → 共享 PD (未 hook)           ├─ PDPT[x] → 共享 PD
            │                                        │
            └─ PDPT[y] → per-CPU PD[0][y]           └─ PDPT[y] → per-CPU PD[1][y]
                           │                                       │
                           ├─ PD[z] → per-CPU PT[0]              ├─ PD[z] → per-CPU PT[1]
                           │   (hook 的 2MB 区域)                 │   (hook 的 2MB 区域)
                           │                                      │
                           └─ PD[其他] → 共享 PT                  └─ PD[其他] → 共享 PT
```

**分层隔离策略**：
- **PML4 + PDPT**: 每 CPU 独立副本（初始化时从模板 clone），用于让 PDPT entry 指向不同的 PD
- **PD pages**: **按需 clone** — 只有包含 Hook 的 GB 区域才创建 per-CPU 副本
- **PT (split) pages**: **按需 clone** — 只有包含 Hook 的 2MB 区域才创建 per-CPU 副本
- **非 Hook 区域**: 所有 CPU 共享相同的 PD/PT pages

### 数据结构

```c
// Per-CPU EPT 根结构 (ept.h)
typedef struct _EPT_CPU_STATE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[512];  // 独立 PML4
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[512];  // 独立 PDPT
    EPT_POINTER Eptp;     // 该 CPU 的 EPTP 值 (写入 VMCS)
    ULONG64     Pml4Pa;   // PML4 的物理地址
} EPT_CPU_STATE;

// Per-CPU split PT page 副本 (ept.c)
typedef struct _EPT_PER_CPU_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[512];  // 512 个 4KB PTE
    ULONG64     PhysicalAddress;    // 该页表页的物理地址
    BOOLEAN     Allocated;          // 是否已分配
} EPT_PER_CPU_SPLIT;

// 全局数组
PEPT_CPU_STATE   g_EptCpuStates;                // [g_MaxProcessors] per-CPU EPT root
PEPT_PER_CPU_SPLIT  *g_PerCpuSplitPages;        // [g_MaxProcessors] → [MAX_SPLIT_PAGES]
EPT_PER_CPU_PD_PAGE **g_PerCpuPdPages;          // [g_MaxProcessors] → [MAX_PD_PAGES]
```

AMD NPT 侧 (`npt.h`/`npt.c`) 结构与 Intel EPT 完全镜像。

### 初始化流程

```
DriverEntry
  └─ VmxInitialize / SvmInitialize
       ├─ EptInitialize / NptInitialize        ← 创建共享模板页表
       ├─ EptInitPerCpu / NptInitPerCpu        ← 创建 per-CPU PML4+PDPT
       └─ 对每个 CPU:
            └─ EptSetupIdentityMap / SvmInitVmcb
                 └─ 写 per-CPU EPTP / nested_cr3 到 VMCS / VMCB
```

`EptInitPerCpu()` 为每个 CPU clone PML4 和 PDPT，并将 PML4[0] 指向各自的 PDPT。此时所有 CPU 的 PDPT entry 仍指向共享 PD pages，只有 Hook 安装时才按需创建 per-CPU PD 和 PT pages。

### Hook 安装时的 Per-CPU 设置

```c
// EptHookFunction() 中的 per-CPU 块 (ept.c)
if (g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages) {
    // 1. 确保该 GB 区域的 PD page 已 per-CPU 化
    EptEnsurePerCpuPdForRegion(PdptIdx);

    // 2. 确保该 2MB 区域的 split PT page 已 per-CPU 化
    EptEnsurePerCpuSplitPage(splitIdx, PdptIdx, PdIdx);

    // 3. 将 hook PTE 权限复制到所有 CPU 的私有副本
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

### 运行时：EPT Violation / NPF 处理

核心变化：使用 **per-CPU PTE** 替代共享 PTE，消除多核竞争。

**Intel EPT (ept.c — HandleEptViolation)**:

```c
CpuIndex = KeGetCurrentProcessorNumber();
Hook = EptFindHookByPhysicalAddress(GuestPhysAddr);

// ★ 核心: 使用 per-CPU PTE
Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
if (!Pte) Pte = Hook->TargetPte;  // fallback 到共享

// 后续的 Pte->Read/Write/Execute 修改只影响当前 CPU 的翻译
// 启用 MTF 单步, 通过 EptMtfTrackRelaxedPage() 记录当前 CPU 放宽了哪个页
```

**Intel MTF 恢复 (vmx_exit.c — HandleMtf)**:

```c
CpuIndex = KeGetCurrentProcessorNumber();
RelaxedPa = EptMtfGetAndClearRelaxedPage();  // 获取当前 CPU 放宽的页面

// ★ 使用 per-CPU PTE 恢复 (只恢复当前 CPU)
PEPT_PTE Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
Pte->Read = 0; Pte->Write = 0; Pte->Execute = 1;  // 恢复到 hook 状态
Pte->PhysAddr = Hook->HookPagePa >> 12;
EptInvalidateSingleContext(CpuEptp);  // 仅刷新当前 CPU 的 TLB
```

**AMD NPT** 侧的 `NptHandlePageFault` 和 `SvmHandleDbException` 采用相同策略。

### INVEPT 优化

Per-CPU 隔离后，PTE 修改只影响当前 CPU，因此使用 **INVEPT SINGLE_CONTEXT** 替代 ALL_CONTEXTS，避免不必要的跨 CPU TLB 刷新：

```c
ULONG64 CpuEptp = EptGetPerCpuEptp(CpuIndex);
if (CpuEptp)
    EptInvalidateSingleContext(CpuEptp);
else
    EptInvalidateAllContexts();  // fallback
```

### 内存分配汇总

| Pool Tag | 用途 | 分配时机 | 大小 |
|----------|------|---------|------|
| `'tpEC'` | per-CPU EPT root (PML4+PDPT+EPTP) | `EptInitPerCpu` | `CPUs × sizeof(EPT_CPU_STATE)` |
| `'tpES'` | per-CPU split PT pages | 按需: `EptEnsurePerCpuSplitPage` | `MAX_SPLIT_PAGES × sizeof(EPT_PER_CPU_SPLIT)` per CPU |
| `'tpEP'` | per-CPU PD pages | 按需: `EptEnsurePerCpuPdForRegion` | `MAX_PD_PAGES × sizeof(EPT_PER_CPU_PD_PAGE)` per CPU |
| `'tpNC'` / `'tpNS'` / `'tpNP'` | AMD NPT 侧 (镜像) | 同 EPT | 同 EPT |

> **按需分配**: split PT 和 PD pages 仅在 Hook 安装到对应区域时分配，不装 Hook 就不分配。

### 容错设计

1. **初始化失败非致命**: `EptInitPerCpu`/`NptInitPerCpu` 返回失败时仅 `LOG_WARN` 并继续，Hook 回退到共享 PTE（无隔离）
2. **Fallback 到共享 PTE**: 所有使用 per-CPU PTE 的地方都有 fallback: `if (!Pte) Pte = Hook->TargetPte;`
3. **NULL 检查**: 所有 per-CPU 路径检查 `g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages` 非 NULL

---

## Hypervisor 内存读写

### 概述

**文件**: `hv_mem.h` + `hv_mem.c` + `vmxdrv.c` (IOCTL handlers)

利用 Hypervisor 运行在 Ring -1 的特权，直接通过物理内存访问读写任意 Guest 进程的虚拟地址空间。**完全绕过 Guest 内所有软件层面的保护**，包括反作弊驱动的内存保护机制。

### 为什么能绕过反作弊驱动

```
Ring -1  ┃  VMXToolbox (Hypervisor)        ← 内存读写在这里执行
━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Ring 0   ┃  反作弊驱动 (EAC/BE/VGK)          ← 它的保护全在这里
         ┃  Windows 内核
━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Ring 3   ┃  游戏进程
```

反作弊驱动能监控的所有操作都在 Guest 内部:

| 反作弊手段 | 为什么失效 |
|-----------|-----------|
| `ObRegisterCallbacks` 剥离句柄权限 | 不用 `OpenProcess`，不走句柄 |
| Hook `NtReadVirtualMemory` | 不调任何内存读写 API |
| 监控 `KeStackAttachProcess` | 不需要 Attach 到目标进程 |
| 扫描可疑驱动调用栈 | 读写在 Ring -1 完成，Guest 看不到 |
| 检测 `MmCopyVirtualMemory` | 不调用此函数 |

### 工作原理

```
用户态请求: 读取游戏进程 PID=1234 地址 0x7FF612340000 的 4096 字节

IOCTL_VMX_READ_MEMORY
  |
  v
[内核驱动] HandleIoctlReadMemory()
  |
  +-- 1. PID → CR3: PsLookupProcessByProcessId(1234)
  |       读取 EPROCESS + DirectoryTableBase 偏移
  |       得到目标进程 CR3 = 0x1A3000
  |
  +-- 2. 遍历 Guest 4 级页表 (VA → PA 翻译):
  |       CR3(0x1A3000) → PML4[index] → PDPT → PD → PT
  |       0x7FF612340000 → 物理地址 0x3F8A5000
  |
  +-- 3. 映射物理内存并复制:
  |       MmMapIoSpace(0x3F8A5000, PAGE_SIZE)
  |       RtlCopyMemory(输出缓冲区, 映射地址, 4096)
  |       MmUnmapIoSpace()
  |
  +-- 4. 返回数据给用户态
```

### Guest 页表遍历 (4 级)

```
CR3 (DirectoryTableBase)
 |
 +--[PML4 Index = VA[47:39]]--> PML4E
                                  |
                  +--[PDPT Index = VA[38:30]]--> PDPTE
                                                   |
                                                   +-- 如果 PS=1: 1GB 大页, PA = PDPTE[51:30] | VA[29:0]
                                                   |
                                   +--[PD Index = VA[29:21]]--> PDE
                                                                  |
                                                                  +-- 如果 PS=1: 2MB 大页, PA = PDE[51:21] | VA[20:0]
                                                                  |
                                                  +--[PT Index = VA[20:12]]--> PTE
                                                                                 |
                                                                                 +--> PA = PTE[51:12] | VA[11:0]
```

关键实现 (`KernelGuestVaToPa`):
- 每一级通过 `MmMapIoSpace` 映射物理页表页
- 读取对应 index 的页表项
- 检查 Present 位和 Large Page 位
- 处理 4KB / 2MB / 1GB 三种页面大小
- 跨页读写时自动拆分为多次单页操作

### IOCTL 接口

#### `IOCTL_VMX_READ_MEMORY` (0x807)

从目标进程读取内存。

```c
// 请求结构
typedef struct _VMX_MEMORY_REQUEST {
    ULONG       Pid;                /* 目标进程 ID */
    ULONG       Size;               /* 字节数 (最大 64KB) */
    ULONG64     VirtualAddress;     /* 目标进程中的虚拟地址 */
} VMX_MEMORY_REQUEST;

// 用法
VMX_MEMORY_REQUEST req;
req.Pid = 1234;
req.Size = 4096;
req.VirtualAddress = 0x7FF612340000;

BYTE buffer[4096];
DeviceIoControl(hDevice, IOCTL_VMX_READ_MEMORY,
    &req, sizeof(req),          // 输入: 请求头
    buffer, sizeof(buffer),     // 输出: 读取到的数据
    &bytesReturned, NULL);
```

#### `IOCTL_VMX_WRITE_MEMORY` (0x808)

向目标进程写入内存。

```c
// 输入布局: [VMX_MEMORY_REQUEST 头部][要写入的数据...]
// 总 InputBufferLength = sizeof(VMX_MEMORY_REQUEST) + Size

// 示例: 向目标地址写入一个 int 值
BYTE packet[sizeof(VMX_MEMORY_REQUEST) + sizeof(int)];
VMX_MEMORY_REQUEST *hdr = (VMX_MEMORY_REQUEST *)packet;
hdr->Pid = 1234;
hdr->Size = sizeof(int);
hdr->VirtualAddress = 0x7FF612340000;
*(int *)(packet + sizeof(VMX_MEMORY_REQUEST)) = 99999;  // 要写入的值

DeviceIoControl(hDevice, IOCTL_VMX_WRITE_MEMORY,
    packet, sizeof(packet),     // 输入: 头部 + 数据
    NULL, 0,                    // 无输出
    &bytesReturned, NULL);
```

### VMCALL 内存操作接口 (备用路径)

除了 IOCTL → 内核直接物理内存访问的路径外，还实现了 VMCALL 路径，可从 Guest 内核触发 Hypervisor 在 Ring -1 中执行读写：

```
VMCALL 约定:
  RAX = 0xCAFE0001  (VMCALL_MAGIC | READ_MEMORY)
  RAX = 0xCAFE0002  (VMCALL_MAGIC | WRITE_MEMORY)
  RDX = VMCALL_MEM_PARAMS 结构体的 Guest 虚拟地址

typedef struct _VMCALL_MEM_PARAMS {
    ULONG64     TargetCr3;      /* 目标进程 CR3 */
    ULONG64     TargetVa;       /* 目标虚拟地址 */
    ULONG64     BufferVa;       /* 调用者缓冲区地址 */
    ULONG       Size;           /* 字节数 */
    NTSTATUS    Status;         /* [out] 返回状态 */
} VMCALL_MEM_PARAMS;
```

VMCALL 路径中，Hypervisor 利用 EPT/NPT 恒等映射 (Guest PA == Host VA) 直接以指针方式访问物理内存，连 `MmMapIoSpace` 都不需要。

### 使用场景

```bash
# 场景 1: 读取目标进程的 PE 头 (MZ header)
VMXToolbox.exe --read-mem 1234 7FF600000000 64

# 场景 2: 读取指定大小的内存区域
VMXToolbox.exe --read-mem 1234 7FF612345678 128

# 场景 3: 写入 NOP sled (4 字节), 自动读回验证
VMXToolbox.exe --write-mem 1234 7FF600001000 90909090

# 场景 4: 写入 INT3 断点
VMXToolbox.exe --write-mem 1234 7FF600001000 CC

# 场景 5: 大块内存转储 (Hex+ASCII 格式)
VMXToolbox.exe --dump-mem 1234 7FF600000000 4096

# 场景 6: 配合反反调试一起使用
VMXToolbox.exe --pid 1234 --hide-all              # 先隐藏调试器
VMXToolbox.exe --read-mem 1234 7FF600000000 256   # 再读内存

# 场景 7: 读取内核内存 (System 进程, PID=4)
VMXToolbox.exe --read-mem 4 FFFFF78000000000 64
```

### 安全限制

| 限制 | 说明 |
|------|------|
| 单次最大 64KB | `VMX_MEM_MAX_SIZE = 64 * 1024`，更大的读写需拆分多次 IOCTL |
| 页面必须 Present | 未映射 (换出到磁盘) 的页面无法读取，返回 `STATUS_INVALID_ADDRESS` |
| 跨页自动处理 | 读写跨越 4KB 页面边界时自动拆分为多次物理页访问 |
| 不触发缺页 | 与 `ReadProcessMemory` 不同，不会触发 Guest 的 Page Fault |

---

## 后加载虚拟化与内存连续性

### 核心问题

VMXToolbox 是**寄生式 Hypervisor** (Blue Pill / late-launch)，在操作系统和目标进程都已经运行之后才加载。一个自然的疑问是：

> 进程已经运行了，大量内存已经分配在物理 DRAM 上，此时才启用虚拟化（EPT/NPT），这些已存在的内存怎么办？需要搬移吗？

**答案：不需要搬移任何一个字节。物理内存原封不动，只是在 CPU 的地址翻译管线上加了一层透明的映射。**

### 虚拟化前后的地址翻译对比

**启用前** — 正常运行，CPU 做一次翻译：

```
进程虚拟地址              [Guest CR3 页表]              物理 DRAM
0x7FF612340000  ─────────────────────────>  PA 0x3F8A5000  ────>  实际内存芯片
                                                                  (数据在这里)
                   唯一的翻译层
                   由 Windows 内存管理器维护
```

**启用后** — CPU 做两次翻译，但第二次是透明的：

```
进程虚拟地址          [Guest CR3 页表]        [EPT/NPT]            物理 DRAM
0x7FF612340000  ───────────────>  GPA 0x3F8A5000  ──────────>  HPA 0x3F8A5000
                                                                    |
                  这层完全没变         这层是新加的                     |
                  Windows 不知道       恒等映射: GPA == HPA            v
                  页表内容一模一样     输出 = 输入                 同一块 DRAM
                                                                数据原封不动
```

**关键点**：EPT/NPT 的恒等映射使得 `GPA == HPA`，第二层翻译等于没翻译。CPU 最终访问的仍然是同一块物理内存。

### 恒等映射如何保证无缝衔接

看 `ept.c` / `npt.c` 的初始化代码：

```c
// 覆盖 512GB 物理地址空间, 每个 2MB 区域映射到自身
for (i = 0; i < 512; i++) {            // 512 个 PDPT entry, 每个 1GB
    for (j = 0; j < 512; j++) {        // 512 个 PD entry, 每个 2MB
        PhysAddr = (i * 512 + j) * 2MB;

        PD[i][j].Read    = 1;          // 允许读
        PD[i][j].Write   = 1;          // 允许写
        PD[i][j].Execute = 1;          // 允许执行
        PD[i][j].LargePage = 1;        // 2MB 大页
        PD[i][j].PhysAddr = PhysAddr;  // ★ 指向自己! GPA == HPA
    }
}
```

| GPA 范围 | HPA 范围 | 效果 |
|----------|----------|------|
| 0x00000000 ~ 0x001FFFFF | 0x00000000 ~ 0x001FFFFF | 前 2MB，原样映射 |
| 0x00200000 ~ 0x003FFFFF | 0x00200000 ~ 0x003FFFFF | 第 2 个 2MB |
| ... | ... | ... |
| 0x3F800000 ~ 0x3F9FFFFF | 0x3F800000 ~ 0x3F9FFFFF | 包含游戏数据的某个 2MB 块 |
| ... | ... | ... |
| 到 512GB | 相同 | 全覆盖 |

**每一个物理地址都映射到它自己**，所以任何已经存在的内存——不管是进程代码段、数据段、堆、栈、内核代码——在虚拟化启用前后访问到的都是同一块 DRAM，内容完全不变。

### 完整的启用时间线

```
时间线
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

T0: 系统正常运行, 游戏进程已经在跑
    ──────────────────────────────────────────────────────
    物理 DRAM 布局 (简化):
    [0x00000000] OS 内核代码/数据
    [0x10000000] 其他进程
    [0x3F8A5000] ← 游戏代码页 (VA 0x7FF612340000 通过 CR3 映射到这里)
    [0x52100000] ← 游戏数据页 (血量/金币在这里)
    [0x8A200000] ← 游戏堆内存
    ...

    地址翻译: VA ──[CR3 页表]──> PA  (一层)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

T1: 用户执行 IOCTL_VMX_INIT, 驱动开始初始化
    ──────────────────────────────────────────────────────
    1. EptInitialize() / NptInitialize()
       在内核内存中构建 EPT/NPT 页表
       这些页表本身占用约 10MB 物理内存 (PD pages + split pool)
       ★ 但页表内容是恒等映射, 不影响任何现有数据

    2. 每个 CPU 核心:
       VmxEnableOnCpu():
         CR4 |= VMXE          // 启用 VMX 操作
         VMXON                 // 进入 VMX root 模式
       VmxSetupVmcs():
         Guest CR3 = 当前 CR3  // ★ Guest 页表就是现有页表, 不变
         Guest RIP = 下一条指令 // ★ 从当前位置继续执行
         Guest RSP = 当前 RSP
         EPTP = EPT 页表地址   // 插入 EPT 翻译层
         VMLAUNCH               // 当前 CPU 进入 Guest 模式

    ★ VMLAUNCH 之后, 这个 CPU 上所有代码 (包括 OS 内核和所有进程)
      都在 VMX non-root (Guest) 模式下运行, 但它们完全不知道!

    物理 DRAM 布局: 完全没变!
    [0x3F8A5000] ← 仍然是游戏代码页, 内容一模一样
    [0x52100000] ← 仍然是游戏数据页, 血量/金币一模一样

    地址翻译: VA ──[CR3 页表]──> GPA ──[EPT 恒等映射]──> HPA=GPA  (两层, 但等效一层)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

T2: 虚拟化已启用, 游戏继续运行
    ──────────────────────────────────────────────────────
    游戏代码: MOV EAX, [血量地址]
      VA → CR3 页表 → GPA 0x52100XXX → EPT → HPA 0x52100XXX → 读到真实血量
                                         ↑
                                    恒等映射, 完全透明

    Windows 内存管理: 正常工作, 完全不知道 Hypervisor 存在
      - 分配新页: 照常操作 (EPT 恒等映射覆盖了所有物理地址)
      - 页面换出: 照常操作 (修改 Guest CR3 页表, EPT 不受影响)
      - 进程创建: 照常操作

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

T3: 用户通过 IOCTL_VMX_READ_MEMORY 读取游戏内存
    ──────────────────────────────────────────────────────
    驱动拿到游戏 CR3, 自己遍历页表:
      游戏 VA → 遍历游戏 CR3 → GPA 0x52100XXX
      MmMapIoSpace(0x52100XXX) → 直接读到真实数据

    ★ 这个过程中:
      - 游戏不知道 (没有调用任何游戏地址空间的 API)
      - 反作弊驱动不知道 (没有 OpenProcess / ReadProcessMemory)
      - Windows 不知道 (只是映射了一下物理地址)
```

### 为什么 Windows 和所有 Guest 软件毫无感知

| 方面 | 为什么无感 |
|------|-----------|
| **Guest 页表未修改** | VMCS/VMCB 的 Guest CR3 = 真实 CR3，Windows 内存管理继续用它自己的页表 |
| **物理内存未搬移** | EPT/NPT 恒等映射，GPA==HPA，物理数据纹丝不动 |
| **指令执行无中断** | VMLAUNCH 时 Guest RIP = 当前 RIP，从下一条指令无缝继续 |
| **时间无跳变** | TSC 连续递增，VMLAUNCH 本身只花几百个时钟周期 |
| **性能影响极小** | EPT/NPT 有硬件 TLB 缓存 (EPTP-tagged)，大部分访问不需要二次遍历 |
| **新分配的内存** | 也自动覆盖，因为恒等映射覆盖了整个 512GB 物理空间 |

### EPT/NPT 性能开销

```
无虚拟化:    VA → CR3 (4级遍历, 约 4 次内存访问, TLB 命中则 0 次)
有虚拟化:    VA → CR3 (4级) × EPT (4级) = 最坏 24 次内存访问
             但 EPT TLB (VPID-tagged) 缓存后, 实际开销约 1-5%

实测: Hypervisor 启用后, 游戏帧率下降通常 < 3%
     (VM-Exit 处理是主要开销, 不是 EPT 遍历)
```

### 与传统虚拟机的根本区别

```
传统虚拟机 (VirtualBox / VMware / Hyper-V):
  先创建空虚拟机 → 安装 OS → 分配虚拟硬盘 → 物理内存是从主机"借"的
  Guest 物理地址空间是虚构的, EPT 映射到主机分配的真实页面
  GPA ≠ HPA (Guest 认为自己的 PA 0x0 实际可能在 HPA 0x7000000000)

VMXToolbox (Blue Pill):
  OS 已经在跑 → 在它下面塞一层 → 恒等映射
  Guest 物理地址空间就是真实物理地址空间
  GPA == HPA (整个 512GB 一一对应)
  Guest 从来没有"搬进虚拟机", 它一直在原地, 只是脚下多了一层透明地板
```

一句话总结：**VMXToolbox 不创建虚拟环境，而是把现实变成虚拟环境——所有东西都在原地，只是 CPU 多了一层你看不见的翻译。**

---

## 通用 EPT/NPT Hook 框架

**文件**: `hv_hook.h` + `hv_hook.c` + `hv_hook_asm.asm`

利用 EPT/NPT 页表权限分离，实现对任意内核/用户态函数的无感知 Hook。PatchGuard 无法检测，因为内核代码页的物理内存从未被修改。

### 核心特性

| 特性 | 说明 |
|------|------|
| 动态安装/卸载 | 通过 IOCTL 在运行时安装和移除 Hook |
| 无数量上限 | 动态分配 Thunk 页，每页 170 个 Hook，按需增长 |
| 按名称 Hook | 传入函数名（如 `NtCreateFile`），自动解析地址 |
| 按地址 Hook | 直接指定内核或用户态虚拟地址 |
| PID 过滤 | Hook 可设为全局或仅对指定进程生效 |
| 4 种动作 | PASSTHROUGH（计数）、LOG（日志）、BLOCK（拦截）、MODIFY_RETVAL（改返回值） |
| 事件日志 | 512 条环形缓冲区，记录每次 Hook 触发的详细信息 |
| PatchGuard 安全 | EPT Execute-Only 机制，读取看原始代码，执行走 Hook 代码 |

### IOCTL 接口

| IOCTL | 功能 |
|-------|------|
| `IOCTL_VMX_INSTALL_HOOK` (0x809) | 安装 Hook（输入函数名/地址+规则，返回 HookId） |
| `IOCTL_VMX_REMOVE_HOOK` (0x80A) | 移除 Hook（输入 HookId） |
| `IOCTL_VMX_LIST_HOOKS` (0x80B) | 查询所有活跃 Hook 及命中次数 |
| `IOCTL_VMX_GET_HOOK_EVENTS` (0x80C) | 读取 Hook 事件日志 |

### 用法示例

**CLI 命令行方式** (通过 VMXToolbox.exe):

```bash
# Hook NtCreateFile, 记录所有调用
VMXToolbox.exe --install-hook NtCreateFile --action 1 --hook-log

# Block ObRegisterCallbacks for PID 1234, return ACCESS_DENIED
VMXToolbox.exe --install-hook ObRegisterCallbacks --action 2 --block-retval C0000022 --hook-pid 1234

# 修改 NtClose 返回值为 STATUS_SUCCESS
VMXToolbox.exe --install-hook NtClose --action 3 --new-retval 0

# 按地址 Hook 非导出函数
VMXToolbox.exe --install-hook-addr FFFFF80012345678 --action 1 --hook-log

# 查看 Hook 列表和事件
VMXToolbox.exe --list-hooks
VMXToolbox.exe --hook-events

# 移除 Hook
VMXToolbox.exe --remove-hook 1
```

**C 代码方式** (直接调用 IOCTL):

```c
// Hook NtCreateFile, 记录所有调用
VMX_HOOK_REQUEST req = {0};
VMX_HOOK_RESPONSE resp = {0};
req.ByName = TRUE;
wcscpy(req.FunctionName, L"NtCreateFile");
req.Rule.Action = HOOK_ACTION_LOG_ONLY;
req.Rule.LogEnabled = TRUE;
DeviceIoControl(hDev, IOCTL_VMX_INSTALL_HOOK, &req, sizeof(req), &resp, sizeof(resp), &ret, NULL);

// Block ObRegisterCallbacks for PID 1234, return ACCESS_DENIED
req.ByName = TRUE;
wcscpy(req.FunctionName, L"ObRegisterCallbacks");
req.Rule.Action = HOOK_ACTION_BLOCK;
req.Rule.BlockReturnValue = 0xC0000022;  // STATUS_ACCESS_DENIED
req.Rule.TargetPid = 1234;
DeviceIoControl(hDev, IOCTL_VMX_INSTALL_HOOK, &req, sizeof(req), &resp, sizeof(resp), &ret, NULL);
```

> **详细技术文档**: 完整的架构设计、ASM dispatcher 流程、Thunk 机制、HOOK_DECISION 结构布局等，请参阅 **[hook_framework.md](hook_framework.md)**

---

## SSDT 监控与 Hook 框架

**文件**: `ssdt.h` + `ssdt.c`

提供对 Windows x64 SSDT (System Service Descriptor Table) 的完整发现、解析、名称解析、按索引/名称 Hook、以及全量/过滤监控能力。所有实际 Hook 操作完全复用现有 `GenericHookInstall()` EPT/NPT 框架。

### 设计定位

SSDT 模块是一个**薄协调层**：

- **发现与解析**: 负责 KiServiceTable 定位、SSDT 条目解码、Nt* 函数名称解析
- **syscall index ↔ hookId 映射**: 维护 `SSDT_HOOK_MAPPING` 链表，跟踪哪些 syscall 被 Hook 了
- **实际 Hook**: 完全委托给 `GenericHookInstall()` / `GenericHookRemove()`（Thunk 生成、EPT 分页、决策逻辑、事件日志等均已就绪）

### 两级 SSDT 发现与地址解析

SSDT 地址的可信度直接决定了 Hook 目标的正确性。框架采用**两级策略**，优先从磁盘获取无污染数据：

#### Tier 1: 从磁盘映射 ntoskrnl.exe 解析（首选）

```
SsdtGetNtoskrnlBase()
  → ZwQuerySystemInformation(SystemModuleInformation)
  → 获取 ntoskrnl 加载基址 + 磁盘路径

SsdtMapNtoskrnlFromDisk()
  → ZwOpenFile(ntoskrnl.exe)
  → ZwCreateSection(SEC_IMAGE)    ← 关键：按 PE 节对齐展开
  → ZwMapViewOfSection()          ← 映射到内核地址空间

SsdtDiscoverAndResolveFromDisk()
  → 遍历映射 PE 导出表，找到 KeServiceDescriptorTable
  → 读取 .Base (未重定位值 = PreferredBase + TableRva)
  → TableRva = .Base - PreferredBase
  → 读取 .Limit → ServiceCount
  → 直接从 MapBase + TableRva 读取 LONG 数组
  → 重定位: FuncVA = NtoskrnlBase + TableRva + (entry >> 4)
```

**为什么用 SEC_IMAGE?**

| 对比项 | ZwReadFile (原始文件) | ZwCreateSection(SEC_IMAGE) |
|--------|----------------------|----------------------------|
| 内存布局 | 文件原始字节 (raw) | 按 PE 节对齐展开 (virtual) |
| RVA 使用 | 需手动 RVA→文件偏移转换 | **RVA 直接当偏移用** |
| 内存消耗 | 需分配整个文件大小的 NonPagedPool (~10MB) | 按需分页 |
| 辅助函数 | 需要 Section Header 遍历 | **不需要** |

**为什么从磁盘获取比从内存获取更安全?**

- 磁盘上的 ntoskrnl.exe 受 Windows 文件保护 (WFP/WRP) 守护，且具有微软数字签名
- 即使某个 rootkit 在 PatchGuard 激活前的极短窗口内篡改了内存中的 KiServiceTable，磁盘数据仍然是微软原版的
- 所有读取的字节来自经过签名验证的 PE 文件，零内存数据被信任（唯一使用的内存值是 `NtoskrnlBase`，来自 `ZwQuerySystemInformation` 这一可信内核 API）

#### Tier 2: 从内存导出符号解析（回退）

```
SsdtDiscoverAndResolveFromMemory()
  → MmGetSystemRoutineAddress(L"KeServiceDescriptorTable")
  → 读取 .Base (已重定位 = 真实 KiServiceTable VA) + .Limit
  → 直接从内存 KiServiceTable 读取 LONG 条目数组
  → FuncVA = KiServiceTableVa + (entry >> 4)
```

`KeServiceDescriptorTable` 是 ntoskrnl 在所有 x64 Windows 版本上导出的符号，`KSERVICE_TABLE_DESCRIPTOR` 结构布局从未变过。在 PatchGuard 保护下，内存中的表同样可靠。

此方式仅在磁盘方案失败时使用（如虚拟化环境中无法访问宿主文件系统等极端情况）。

### SSDT 条目格式 (x64)

```c
// KiServiceTable 是 LONG 数组，每个条目编码为：
LONG entry = KiServiceTable[index];

ULONG64 FunctionVA = KiServiceTableVA + (entry >> 4);   // 高 28 位 = 相对偏移
ULONG   ArgCount   = entry & 0xF;                       // 低 4 位 = 参数个数
```

### 名称解析

通过遍历内存中 ntoskrnl PE 导出表，匹配 `Nt*` 前缀的导出函数地址到 SSDT 条目地址：

```
SsdtPopulateNames()
  → 读取 ntoskrnl PE 导出目录
  → 遍历所有 Nt* 导出 (跳过 Zw* 前缀)
  → 计算 FuncVA = NtoskrnlBase + FuncRva
  → 在 ResolvedAddresses[] 数组中匹配
  → 匹配成功 → 存入 NameCache[index]
```

`SsdtFindIndexByName()` 先查 NameCache，未命中时 fallback 到 `MmGetSystemRoutineAddress` 解析后地址匹配。

### Hook 操作

SSDT Hook 完全复用现有 `GenericHookInstall()` 框架：

```
SsdtHookByIndex(Index, Rule)
  1. 查重 (spinlock 保护的 SSDT_HOOK_MAPPING 链表)
  2. FuncVa = ResolvedAddresses[Index]
  3. 调用 GenericHookInstall(FuncVa, 0/*kernel*/, Name, Rule, &HookId)
     → 分配 Thunk → EPT 页分离 → 安装完成
  4. 创建 SSDT_HOOK_MAPPING 节点记录 Index ↔ HookId

SsdtHookByName(Name, Rule)
  → SsdtFindIndexByName(Name) → SsdtHookByIndex(Index)
```

Hook 事件通过现有 512 条环形缓冲区自动记录，`--hook-events` 即可查看。

### 监控模式

| 模式 | 说明 |
|------|------|
| `SSDT_MONITOR_OFF` | 停止监控，移除所有监控 Hook |
| `SSDT_MONITOR_ALL` | 对全部 ~460 个 syscall 安装 LOG_ONLY Hook |
| `SSDT_MONITOR_FILTERED` | 仅对指定的 syscall index 列表安装 Hook |

监控 Hook 被标记为 `IsMonitorHook=TRUE`，`SsdtStopMonitoring()` 只移除监控创建的 Hook，不影响用户手动安装的 SSDT Hook。

### 生命周期

```
SsdtInitialize()
  → 读取 LSTAR (诊断信息)
  → SsdtGetNtoskrnlBase() (获取加载基址 + 磁盘路径)
  → Tier 1: SsdtMapNtoskrnlFromDisk() + SsdtDiscoverAndResolveFromDisk() + SsdtUnmapFileImage()
  → 失败 → Tier 2: SsdtDiscoverAndResolveFromMemory()
  → SsdtPopulateNames() (名称解析，best-effort)
  → Initialized = TRUE

SsdtCleanup()       [在 DriverUnload 中，GenericHookCleanup 之前调用]
  → SsdtStopMonitoring()
  → SsdtUnhookAll()
  → SsdtUnmapFileImage()
```

---

## Shadow SSDT (Win32k) 监控与 Hook 框架

**文件**: `shadow_ssdt.h` + `shadow_ssdt.c`

将 SSDT 模块的架构扩展到 **Win32k Shadow SSDT**（`W32pServiceTable`），覆盖 `NtUser*`/`NtGdi*` 系统调用。Shadow SSDT 条目格式与普通 SSDT 完全一致（`LONG` 数组，`entry >> 4` 得偏移），EPT Hook 机制完全通用。

### 核心挑战与解决方案

| 挑战 | 解决方案 |
|------|---------|
| `KeServiceDescriptorTableShadow` 未导出 | 从 KTHREAD.ServiceTable 间接获取 |
| KTHREAD.ServiceTable 偏移随 Windows 版本变化 | QWORD 扫描 System 进程线程动态发现 |
| win32k.sys 是 per-Session 映射 | 使用 `KeStackAttachProcess` 到 GUI 进程上下文 |
| Win10+ 将 win32k 拆分为三个模块 | 枚举所有 win32k* 模块，遍历多导出表解析名称 |

### KTHREAD.ServiceTable 偏移动态发现

```
KthreadResolveServiceTableOffset()
  1. 获取 KeServiceDescriptorTable 地址 (MmGetSystemRoutineAddress)
  2. 枚举 PID=4 (System) 的线程 → KTHREAD*
     (System 线程永远不会初始化 win32k, ServiceTable 必定指向 KeServiceDescriptorTable)
  3. QWORD 扫描 KTHREAD 前 0x400 字节:
     for (Offset = 0; Offset < 0x400; Offset += 8)
         if (*(QWORD*)(KTHREAD + Offset) == KeServiceDescriptorTable)
             → Candidate = Offset
  4. 用第二个 System 线程交叉验证同一偏移
```

### KeServiceDescriptorTableShadow 获取

```
ShadowSsdtDiscover()
  1. 枚举所有进程所有线程:
     for each Thread:
         Value = *(QWORD*)(Thread + ServiceTableOffset)
         if (Value != KeServiceDescriptorTable && IsKernelAddress(Value)):
             ShadowCandidate = Value, GuiPid = 该进程 PID
             break
  2. 三重验证:
     - Shadow[0].Base == KeServiceDescriptorTable[0].Base
     - Shadow[0].Limit == KeServiceDescriptorTable[0].Limit
     - Shadow[1].Limit ∈ (0, SHADOW_SSDT_MAX_SERVICES)
  3. PsLookupProcessByProcessId(GuiPid) → 持有引用用于后续 Attach
```

### Win32k 模块发现 + 名称解析

```
ShadowSsdtGetWin32kModules()
  → ZwQuerySystemInformation(SystemModuleInformation)
  → 匹配文件名含 "win32k" 的模块 (支持 win32kbase/win32kfull/win32k)

ShadowSsdtPopulateNames()
  → KeStackAttachProcess(GuiProcess)
  → for each win32k module:
      遍历 PE 导出表, 匹配 NtUser*/NtGdi* 名称
      与 ResolvedAddresses[] 中的 VA 匹配 → NameCache[index]
  → KeUnstackDetachProcess()
```

### Shadow SSDT 条目解析

```
ShadowSsdtResolveAllAddresses()
  → KeStackAttachProcess(GuiProcess)
  → Table = (PLONG)W32pServiceTableVa
  → for (i = 0; i < ServiceCount; i++):
        FuncVa = W32pServiceTableVa + (Table[i] >> 4)
        ResolvedAddresses[i] = FuncVa
  → KeUnstackDetachProcess()
```

### Hook 操作

Hook 安装时需要在 GUI 进程上下文中执行，确保 win32k VA→PA 映射有效：

```c
ShadowSsdtHookByIndex(Index, Rule, &HookId)
  → 查重 (spinlock)
  → FuncVa = ResolvedAddresses[Index]
  → KeStackAttachProcess(GuiProcess)
  → GenericHookInstall(FuncVa, 0, Name, Rule, &HookId)
  → KeUnstackDetachProcess()
  → 创建 SSDT_HOOK_MAPPING 节点
```

### 生命周期

```
ShadowSsdtInitialize()    [需要 SSDT 模块先初始化]
  → KthreadResolveServiceTableOffset()
  → ShadowSsdtDiscover()
  → ShadowSsdtGetWin32kModules()
  → ShadowSsdtResolveAllAddresses()
  → ShadowSsdtPopulateNames()
  → Initialized = TRUE

ShadowSsdtCleanup()       [在 DriverUnload 中, SsdtCleanup 之前调用]
  → ShadowSsdtStopMonitoring()
  → ShadowSsdtUnhookAll()
  → ObDereferenceObject(GuiProcess)
```

---

## 反反调试能力清单

| 优先级 | 检测手段 | 拦截方式 | 功能标志 |
|--------|---------|---------|---------|
| **P0** | `IsDebuggerPresent` / PEB.BeingDebugged | EPT Hook NtQueryInformationProcess | `AAD_HIDE_DEBUGGER` |
| **P0** | `CheckRemoteDebuggerPresent` | 同上 (底层调用 NtQueryInformationProcess) | `AAD_HIDE_DEBUGGER` |
| **P0** | `NtQueryInformationProcess` (DebugPort/DebugObjectHandle/DebugFlags) | EPT Hook | `AAD_HIDE_DEBUGGER` |
| **P0** | DR0-DR7 硬件断点检测 | MOV-DR Exiting + 返回伪值 | `AAD_HIDE_HWBP` |
| **P0** | RDTSC/RDTSCP 时间差检测 | RDTSC Exiting + TSC Offset 补偿 | `AAD_HIDE_TIMING` |
| **P1** | CPUID Hypervisor 检测 (ECX[31]) | CPUID 无条件 Exit + 清除位 | `AAD_HIDE_CPUID` |
| **P1** | `NtQuerySystemInformation` (KernelDebugger) | EPT Hook | `AAD_HIDE_SYSINFO` |
| **P1** | INT 2D / INT 3 异常行为差异 | Exception Bitmap + 标准化注入 | `AAD_HIDE_EXCEPTIONS` |
| **P2** | `NtClose` 无效句柄异常 | EPT Hook + 异常抑制 | `AAD_HIDE_NTCLOSE` |
| **P2** | `NtSetInformationThread` (ThreadHideFromDebugger) | EPT Hook + 阻断 | `AAD_HIDE_THREADINFO` |

---

## 用户态控制程序

**文件**: `client/main.c` + `client/driver_comm.c`

所有功能通过同一个 `VMXToolbox.exe` CLI 工具统一控制。

### 反反调试命令

```
VMXToolbox.exe --pid <PID> [选项]        设置目标进程
VMXToolbox.exe --pid <PID> --remove      移除目标进程
VMXToolbox.exe --status                  查询 VMX 状态
VMXToolbox.exe --stop                    停止 VMX 引擎
VMXToolbox.exe --log                     显示拦截日志
```

隐藏选项:

```
--hide-debugger     隐藏调试器存在 (PEB, NtQuery*)
--hide-hwbp         隐藏硬件断点 (DR0-DR7)
--hide-timing       对抗时间检测 (RDTSC 补偿)
--hide-cpuid        隐藏 Hypervisor (CPUID)
--hide-sysinfo      伪造系统信息 (KernelDebugger)
--hide-exceptions   标准化异常行为 (INT 2D/3)
--hide-ntclose      抑制 NtClose 异常
--hide-threadinfo   阻断 ThreadHideFromDebugger
--hide-all          启用以上全部功能
```

### Hook 框架命令

```
VMXToolbox.exe --install-hook <name>         按导出名 Hook 内核函数
VMXToolbox.exe --install-hook-addr <hex>     按虚拟地址 Hook 函数
VMXToolbox.exe --remove-hook <id>            按 ID 移除 Hook
VMXToolbox.exe --list-hooks                  列出所有活跃 Hook
VMXToolbox.exe --hook-events                 显示 Hook 事件日志
```

Hook 选项 (配合 `--install-hook` / `--install-hook-addr` 使用):

```
--action <0-3>       Hook 动作: 0=穿透计数 1=日志 2=拦截 3=修改返回值
--hook-pid <PID>     PID 过滤 (0=全局, 默认=0)
--block-retval <hex> 拦截时返回值 (action=2)
--new-retval <hex>   修改后返回值 (action=3)
--hook-log           启用事件日志记录
```

### 内存读写命令

```
VMXToolbox.exe --read-mem <PID> <addr> [size]   读取目标进程内存 (默认 64 字节)
VMXToolbox.exe --write-mem <PID> <addr> <hex>   写入十六进制字节到目标进程
VMXToolbox.exe --dump-mem <PID> <addr> <size>   Hex+ASCII 大块内存转储
```

### SSDT 命令

```
VMXToolbox.exe --ssdt-init                          初始化 SSDT 发现
VMXToolbox.exe --ssdt-dump [start] [count]          转储 SSDT 表条目
VMXToolbox.exe --ssdt-hook <index|NtName>           Hook SSDT 函数 (配合 --action, --hook-pid 等)
VMXToolbox.exe --ssdt-unhook <index|hookid:N>       按 syscall index 或 hookid:N 移除 Hook
VMXToolbox.exe --ssdt-unhook-all                    移除全部 SSDT Hook
VMXToolbox.exe --ssdt-list                          列出活跃 SSDT Hook
VMXToolbox.exe --ssdt-monitor <off|all|filtered>    设置 SSDT 监控模式
VMXToolbox.exe --ssdt-filter <idx1,idx2,...>        指定监控的 syscall index 列表
```

### Shadow SSDT 命令

```
VMXToolbox.exe --shadow-ssdt-init                          初始化 Shadow SSDT 发现
VMXToolbox.exe --shadow-ssdt-dump [start] [count]          转储 Shadow SSDT 表条目
VMXToolbox.exe --shadow-ssdt-hook <index|NtUserName>       Hook Shadow SSDT 函数 (配合 --action, --hook-pid 等)
VMXToolbox.exe --shadow-ssdt-unhook <index|hookid:N>       按 index 或 hookid:N 移除 Hook
VMXToolbox.exe --shadow-ssdt-unhook-all                    移除全部 Shadow SSDT Hook
VMXToolbox.exe --shadow-ssdt-list                          列出活跃 Shadow SSDT Hook
VMXToolbox.exe --shadow-ssdt-monitor <off|all|filtered>    设置 Shadow SSDT 监控模式
VMXToolbox.exe --shadow-ssdt-filter <idx1,idx2,...>        指定监控的 Shadow SSDT index 列表
```

### 典型使用场景

```bash
# ===================== 反反调试 =====================

# 1. 对 PID 1234 启用全部反反调试
VMXToolbox.exe --pid 1234 --hide-all

# 2. 仅隐藏调试器和硬件断点
VMXToolbox.exe --pid 1234 --hide-debugger --hide-hwbp

# 3. 查看 VMX 状态
VMXToolbox.exe --status

# 4. 查看拦截日志
VMXToolbox.exe --log

# 5. 移除保护
VMXToolbox.exe --pid 1234 --remove

# ===================== 内核 Hook =====================

# 6. 监控 NtOpenProcess 调用 (全局, 记录日志)
VMXToolbox.exe --install-hook NtOpenProcess --action 1 --hook-log

# 7. 拦截 NtQuerySystemInformation, 返回 STATUS_ACCESS_DENIED
VMXToolbox.exe --install-hook NtQuerySystemInformation --action 2 --block-retval C0000022

# 8. 修改 NtClose 返回值为 STATUS_SUCCESS, 仅对 PID 1234
VMXToolbox.exe --install-hook NtClose --action 3 --new-retval 0 --hook-pid 1234

# 9. 按地址安装 Hook
VMXToolbox.exe --install-hook-addr FFFFF80012345678 --action 1 --hook-log

# 10. 查看活跃 Hook 列表 / 事件日志
VMXToolbox.exe --list-hooks
VMXToolbox.exe --hook-events

# 11. 移除 Hook
VMXToolbox.exe --remove-hook 1

# ===================== 内存读写 =====================

# 12. 读取目标进程 PE 头 (默认 64 字节)
VMXToolbox.exe --read-mem 1234 7FF600000000

# 13. 读取 128 字节
VMXToolbox.exe --read-mem 1234 7FF600000000 128

# 14. 写入 NOP sled + 自动验证
VMXToolbox.exe --write-mem 1234 7FF600001000 90909090

# 15. 写入 INT3 断点
VMXToolbox.exe --write-mem 1234 7FF600001000 CC

# 16. 大块内存转储 (256 字节)
VMXToolbox.exe --dump-mem 1234 7FF600000000 256

# 17. 读取内核内存 (System 进程 PID=4)
VMXToolbox.exe --read-mem 4 FFFFF78000000000 64

# ===================== 通用 =====================

# 18. 停止 VMX 引擎
VMXToolbox.exe --stop

# ===================== SSDT 监控 =====================

# 19. 初始化 SSDT 发现
VMXToolbox.exe --ssdt-init

# 20. 转储前 20 条 SSDT 条目
VMXToolbox.exe --ssdt-dump 0 20

# 21. 按函数名 Hook SSDT (记录日志)
VMXToolbox.exe --ssdt-hook NtOpenProcess --action 1 --hook-log

# 22. 按 syscall index Hook SSDT (拦截, 返回 STATUS_ACCESS_DENIED)
VMXToolbox.exe --ssdt-hook 38 --action 2 --block-retval 0xC0000022

# 23. 查看 SSDT Hook 事件 (复用现有 --hook-events)
VMXToolbox.exe --hook-events

# 24. 列出活跃 SSDT Hook
VMXToolbox.exe --ssdt-list

# 25. 全量监控所有 syscall (仅对 PID 1234)
VMXToolbox.exe --ssdt-monitor all --hook-pid 1234

# 26. 过滤监控指定 syscall index
VMXToolbox.exe --ssdt-monitor filtered --ssdt-filter 35,38,55 --hook-pid 1234

# 27. 停止监控
VMXToolbox.exe --ssdt-monitor off

# 28. 按 syscall index 移除 Hook
VMXToolbox.exe --ssdt-unhook 38

# 29. 按 hookId 移除 Hook
VMXToolbox.exe --ssdt-unhook hookid:5

# 30. 移除全部 SSDT Hook
VMXToolbox.exe --ssdt-unhook-all

# ===================== Shadow SSDT (Win32k) 监控 =====================

# 31. 初始化 Shadow SSDT 发现 (需要先 --ssdt-init)
VMXToolbox.exe --shadow-ssdt-init

# 32. 转储前 20 条 Shadow SSDT 条目
VMXToolbox.exe --shadow-ssdt-dump 0 20

# 33. 按函数名 Hook NtUserGetForegroundWindow (记录日志)
VMXToolbox.exe --shadow-ssdt-hook NtUserGetForegroundWindow --action 1 --hook-log

# 34. 按 index 拦截 Shadow SSDT 函数, 返回 NULL
VMXToolbox.exe --shadow-ssdt-hook 10 --action 2 --block-retval 0

# 35. 查看 Shadow SSDT Hook 事件 (复用现有 --hook-events)
VMXToolbox.exe --hook-events

# 36. 列出活跃 Shadow SSDT Hook
VMXToolbox.exe --shadow-ssdt-list

# 37. 全量监控所有 Win32k syscall (仅对 PID 1234)
VMXToolbox.exe --shadow-ssdt-monitor all --hook-pid 1234

# 38. 过滤监控指定 Shadow SSDT index
VMXToolbox.exe --shadow-ssdt-monitor filtered --shadow-ssdt-filter 10,20,30 --hook-pid 1234

# 39. 停止 Shadow SSDT 监控
VMXToolbox.exe --shadow-ssdt-monitor off

# 40. 移除全部 Shadow SSDT Hook
VMXToolbox.exe --shadow-ssdt-unhook-all
```

---

## 驱动与用户态通信协议

通过 `DeviceIoControl` 和自定义 IOCTL 码通信:

| IOCTL | 方向 | 输入结构 | 输出结构 | 功能 |
|-------|------|---------|---------|------|
| `IOCTL_VMX_INIT` (0x800) | -> | 无 | 无 | 初始化 VMX |
| `IOCTL_VMX_SET_TARGET` (0x801) | -> | `VMX_TARGET_INFO` (PID+Flags) | 无 | 添加目标进程 |
| `IOCTL_VMX_REMOVE_TARGET` (0x802) | -> | `VMX_REMOVE_TARGET` (PID) | 无 | 移除目标进程 |
| `IOCTL_VMX_SET_CONFIG` (0x803) | -> | `VMX_CONFIG_INFO` (PID+Flags) | 无 | 更新配置 |
| `IOCTL_VMX_GET_LOG` (0x804) | <- | 无 | `VMX_LOG_BUFFER` | 读取日志 |
| `IOCTL_VMX_STOP` (0x805) | -> | 无 | 无 | 停止 VMX |
| `IOCTL_VMX_QUERY_STATUS` (0x806) | <- | 无 | `VMX_STATUS` | 查询状态 |
| `IOCTL_VMX_READ_MEMORY` (0x807) | <-> | `VMX_MEMORY_REQUEST` (PID+VA+Size) | Raw bytes | 读取目标进程内存 (物理内存直接访问) |
| `IOCTL_VMX_WRITE_MEMORY` (0x808) | -> | `VMX_MEMORY_REQUEST` + payload | 无 | 写入目标进程内存 (物理内存直接访问) |
| `IOCTL_VMX_INSTALL_HOOK` (0x809) | <-> | `VMX_HOOK_REQUEST` (名称/地址+规则) | `VMX_HOOK_RESPONSE` (HookId) | 安装 Hook |
| `IOCTL_VMX_REMOVE_HOOK` (0x80A) | -> | `VMX_UNHOOK_REQUEST` (HookId) | 无 | 移除 Hook |
| `IOCTL_VMX_LIST_HOOKS` (0x80B) | <- | 无 | `VMX_HOOK_LIST` | 查询所有活跃 Hook |
| `IOCTL_VMX_GET_HOOK_EVENTS` (0x80C) | <- | 无 | `VMX_HOOK_EVENT_BUFFER` | 读取 Hook 事件日志 |
| `IOCTL_VMX_SSDT_INIT` (0x80D) | <- | 无 | `VMX_SSDT_INIT_RESPONSE` | 初始化 SSDT 发现 |
| `IOCTL_VMX_SSDT_DUMP` (0x80E) | <-> | `VMX_SSDT_DUMP_REQUEST` (Start+Count) | `VMX_SSDT_DUMP_RESPONSE` | 转储 SSDT 条目 |
| `IOCTL_VMX_SSDT_HOOK` (0x80F) | <-> | `VMX_SSDT_HOOK_REQUEST` (Index/Name+Rule) | `VMX_SSDT_HOOK_RESPONSE` | Hook SSDT 函数 |
| `IOCTL_VMX_SSDT_UNHOOK` (0x810) | -> | `VMX_SSDT_UNHOOK_REQUEST` (HookId/Index) | 无 | 移除 SSDT Hook |
| `IOCTL_VMX_SSDT_UNHOOK_ALL` (0x811) | -> | 无 | 无 | 移除全部 SSDT Hook |
| `IOCTL_VMX_SSDT_LIST_HOOKS` (0x812) | <- | 无 | `VMX_SSDT_HOOK_LIST` | 查询活跃 SSDT Hook |
| `IOCTL_VMX_SSDT_MONITOR` (0x813) | -> | `VMX_SSDT_MONITOR_REQUEST` (Mode+PID+Filter) | 无 | 设置 SSDT 监控模式 |
| `IOCTL_VMX_SHADOW_SSDT_INIT` (0x814) | <- | 无 | `VMX_SHADOW_SSDT_INIT_RESPONSE` | 初始化 Shadow SSDT 发现 |
| `IOCTL_VMX_SHADOW_SSDT_DUMP` (0x815) | <-> | `VMX_SHADOW_SSDT_DUMP_REQUEST` (Start+Count) | `VMX_SHADOW_SSDT_DUMP_RESPONSE` | 转储 Shadow SSDT 条目 |
| `IOCTL_VMX_SHADOW_SSDT_HOOK` (0x816) | <-> | `VMX_SHADOW_SSDT_HOOK_REQUEST` (Index/Name+Rule) | `VMX_SHADOW_SSDT_HOOK_RESPONSE` | Hook Shadow SSDT 函数 |
| `IOCTL_VMX_SHADOW_SSDT_UNHOOK` (0x817) | -> | `VMX_SHADOW_SSDT_UNHOOK_REQUEST` (HookId/Index) | 无 | 移除 Shadow SSDT Hook |
| `IOCTL_VMX_SHADOW_SSDT_UNHOOK_ALL` (0x818) | -> | 无 | 无 | 移除全部 Shadow SSDT Hook |
| `IOCTL_VMX_SHADOW_SSDT_LIST_HOOKS` (0x819) | <- | 无 | `VMX_SHADOW_SSDT_HOOK_LIST` | 查询活跃 Shadow SSDT Hook |
| `IOCTL_VMX_SHADOW_SSDT_MONITOR` (0x81A) | -> | `VMX_SHADOW_SSDT_MONITOR_REQUEST` (Mode+PID+Filter) | 无 | 设置 Shadow SSDT 监控模式 |

### 关键数据结构

```c
// 添加目标进程
typedef struct _VMX_TARGET_INFO {
    ULONG   Pid;     // 进程 ID
    ULONG   Flags;   // AAD_HIDE_* 位掩码
} VMX_TARGET_INFO;

// 查询状态
typedef struct _VMX_STATUS {
    BOOLEAN VmxActive;       // VMX 是否运行
    ULONG   ActiveTargets;   // 受保护进程数
    ULONG   TotalExits;      // 累计 VM-Exit 次数
    ULONG   CpuCount;        // 虚拟化的 CPU 数
} VMX_STATUS;

// 日志条目
typedef struct _VMX_LOG_ENTRY {
    ULONG       Level;       // 0=Error, 1=Warn, 2=Info, 3=Debug
    ULONG       Pid;         // 源进程 ID
    LARGE_INTEGER Timestamp; // 内核时间戳
    CHAR        Message[256];
} VMX_LOG_ENTRY;

// 内存读写请求
typedef struct _VMX_MEMORY_REQUEST {
    ULONG       Pid;             // 目标进程 ID
    ULONG       Size;            // 字节数 (最大 64KB)
    ULONG64     VirtualAddress;  // 目标虚拟地址
} VMX_MEMORY_REQUEST;

// Hook 规则
typedef struct _HOOK_RULE {
    ULONG       Action;             // 0=穿透 1=日志 2=拦截 3=改返回值
    ULONG       TargetPid;          // 0=全局, >0=指定PID
    ULONG64     BlockReturnValue;   // 拦截时返回值
    ULONG64     NewReturnValue;     // 修改后返回值
    BOOLEAN     LogEnabled;         // 是否写入事件日志
} HOOK_RULE;

// 安装 Hook 请求
typedef struct _VMX_HOOK_REQUEST {
    BOOLEAN     ByName;             // TRUE=按名称, FALSE=按地址
    WCHAR       FunctionName[128];  // 内核导出名
    ULONG64     TargetAddress;      // 直接虚拟地址
    ULONG       ProcessId;          // 0=内核 Hook
    HOOK_RULE   Rule;
} VMX_HOOK_REQUEST;

// Hook 事件日志
typedef struct _HOOK_EVENT {
    ULONG       HookId;             // 触发的 Hook ID
    ULONG       ProcessId;          // 调用者进程 ID
    ULONG64     Timestamp;          // 内核时间戳
    ULONG64     ReturnAddress;      // 调用者返回地址
    ULONG64     FinalRetVal;        // 最终返回值
    ULONG       ActionTaken;        // 执行的动作
} HOOK_EVENT;

// SSDT 条目信息
typedef struct _SSDT_ENTRY_INFO {
    ULONG       SyscallIndex;       // Syscall 编号
    ULONG       ArgCount;           // 参数个数 (entry & 0xF)
    LONG        RawOffset;          // SSDT 表原始条目
    ULONG64     FunctionVa;         // 解析后的函数虚拟地址
    WCHAR       FunctionName[128];  // Nt* 函数名 (可能为空)
} SSDT_ENTRY_INFO;

// SSDT Hook 请求
typedef struct _VMX_SSDT_HOOK_REQUEST {
    BOOLEAN     ByName;             // TRUE=按名称, FALSE=按 index
    ULONG       SyscallIndex;       // ByName=FALSE 时使用
    WCHAR       FunctionName[128];  // ByName=TRUE 时使用
    HOOK_RULE   Rule;               // 复用现有 HOOK_RULE
} VMX_SSDT_HOOK_REQUEST;

// SSDT 监控请求
typedef struct _VMX_SSDT_MONITOR_REQUEST {
    ULONG       Mode;               // SSDT_MONITOR_OFF/ALL/FILTERED
    ULONG       TargetPid;          // 0=全局
    ULONG       FilterCount;        // FilterIndices 有效个数
    ULONG       FilterIndices[64];  // FILTERED 模式下的 syscall index 列表
} VMX_SSDT_MONITOR_REQUEST;
```

---

## 数据流分析

### 初始化流程

```
用户: VMXToolbox.exe --pid 1234 --hide-all
  |
  v
DriverOpen() -> CreateFile("\\\\.\\VmxDbg")
  |
  v
DriverInitVmx() -> IOCTL_VMX_INIT
  |
  v
[内核] HandleIoctlInit()
  +-- VmxInitialize()
       +-- VmxCheckCapabilities()     // 读能力 MSR
       +-- VmxAllocateCpuContext() x N // 分配内存
       +-- EptInitialize()            // 构建 EPT 恒等映射
  |
  v
DriverSetTarget(1234, AAD_HIDE_ALL) -> IOCTL_VMX_SET_TARGET
  |
  v
[内核] HandleIoctlSetTarget()
  +-- ProcessAddTarget(1234, 0xFFFFFFFF)
       +-- GetProcessCr3(1234)        // PsLookupProcessByProcessId
       |    +-- 读取 EPROCESS + 动态偏移
       +-- 存入 TARGET_PROCESS 数组
```

### VM-Exit 处理流程 (以 CPUID 为例)

```
[Guest] 目标进程执行 CPUID 指令
  |
  v
[CPU] VM-Exit (reason = EXIT_REASON_CPUID)
  |
  v
[Host] AsmVmxExitHandler
  +-- 保存 16 个通用寄存器
  +-- call VmxExitHandler(PGUEST_CONTEXT)
       |
       +-- HandleCpuid() -> AadHandleCpuid()
            +-- GuestCr3 = VmxRead(VMCS_GUEST_CR3)
            +-- __cpuidex(CpuInfo, Leaf, SubLeaf)  // 执行真实 CPUID
            +-- IsFeatureEnabled(GuestCr3, AAD_HIDE_CPUID)?
            |     +-- ProcessFindByCr3(GuestCr3)
            |     +-- 检查 Flags & AAD_HIDE_CPUID
            +-- if Leaf == 1:
            |     CpuInfo[ECX] &= ~(1 << 31)  // 清除 Hypervisor Present
            +-- if Leaf == 0x40000000~0x400000FF:
            |     CpuInfo = {0, 0, 0, 0}       // 返回全零
            +-- GuestContext->RAX/RBX/RCX/RDX = CpuInfo
            +-- VmxAdvanceGuestRip()
            +-- return TRUE
  |
  +-- 恢复通用寄存器
  +-- VMRESUME -> Guest 继续执行
```

### EPT Hook 数据流 (以 NtQueryInformationProcess 为例)

```
[Guest] 目标进程调用 NtQueryInformationProcess
  |
  v
[CPU] 执行到 ntoskrnl!NtQueryInformationProcess 地址
  |
  v
[EPT] PTE = Execute-Only, PhysAddr = Hook 页
  -> 执行 Hook 页上的 JMP 指令
  |
  v
[Host] HookNtQueryInformationProcess()
  +-- 调用 Trampoline (原函数)
  |     +-- 执行原始 14 字节
  |     +-- JMP 到 NtQueryInformationProcess + 14
  |     +-- 原函数正常执行并返回
  +-- CurrentCr3 = __readcr3()
  +-- Target = ProcessFindByCr3(CurrentCr3)
  +-- if Target && AAD_HIDE_DEBUGGER:
  |     switch (InformationClass):
  |       ProcessDebugPort:       *Output = 0
  |       ProcessDebugObjectHandle: return STATUS_PORT_NOT_SET
  |       ProcessDebugFlags:      *Output = 1
  +-- return Status
  |
  v
[Guest] 目标进程收到 "未被调试" 的结果

---

如果反调试代码读取 NtQueryInformationProcess 的函数字节做完整性检查:

[Guest] MOV RAX, [NtQueryInformationProcess]   // 读取函数字节
  |
  v
[EPT] PTE = Execute-Only, 读取触发 EPT Violation
  |
  v
[Host] HandleEptViolation()
  +-- PTE -> Read=1, Write=1, Execute=0, PhysAddr=原始页
  +-- 启用 MTF
  +-- 返回 (不推进 RIP, 重新执行读取指令)
  |
  v
[Guest] 读取到原始未修改的函数字节 (完整性检查通过!)
  |
  v
[CPU] MTF VM-Exit (单步完成)
  |
  v
[Host] HandleMtf()
  +-- PTE -> Read=0, Write=0, Execute=1, PhysAddr=Hook页
  +-- 关闭 MTF
  +-- INVEPT
```

### 内存读写数据流 (绕过反作弊)

```
[用户态] DeviceIoControl(IOCTL_VMX_READ_MEMORY, {Pid=1234, VA=0x7FF6xxx, Size=4096})
  |
  v
[内核驱动] HandleIoctlReadMemory()
  |
  +-- ResolvePidToCr3(1234)
  |     +-- PsLookupProcessByProcessId()
  |     +-- 读取 EPROCESS[DirectoryTableBase]
  |     +-- 得到 TargetCr3 = 0x1A3000
  |
  +-- KernelCopyProcessMemory(TargetCr3, 0x7FF6xxx, buffer, 4096, READ)
       |
       +-- while (还有字节未处理):
            |
            +-- KernelGuestVaToPa(0x1A3000, currentVA)
            |     |
            |     +-- MmMapIoSpace(CR3基址)  → 读 PML4E
            |     +-- MmMapIoSpace(PML4E指向) → 读 PDPTE
            |     +-- MmMapIoSpace(PDPTE指向) → 读 PDE
            |     +-- MmMapIoSpace(PDE指向)   → 读 PTE
            |     +-- 得到物理地址 = 0x3F8A5000
            |
            +-- MmMapIoSpace(0x3F8A5000, 4096)
            +-- RtlCopyMemory(buffer, 映射地址 + offset, chunkSize)
            +-- MmUnmapIoSpace()

  *** 全程未调用: OpenProcess / NtReadVirtualMemory / KeStackAttachProcess ***
  *** 反作弊驱动的 ObCallback / SSDT Hook / 调用栈检查 全部无效 ***
```

写入流程完全对称，只是 `RtlCopyMemory` 方向相反。

---

## 模块依赖关系

```
vmxdrv.c (驱动入口)
+-- hv_ops.h (抽象层接口)
+-- hv_detect.h/c (CPU 厂商检测 + VMX/SVM 能力探测)
+-- hv_mem.h/c (物理内存读写引擎, Guest 页表遍历)
+-- hv_hook.h/c (通用 Hook 框架, 动态 Thunk, 规则引擎)
|   +-- hv_hook_asm.asm (ASM dispatcher)
+-- log.h/c (日志)
+-- process.h/c (进程跟踪)
+-- vmx.h + vmx_init.c (Intel VMX 后端)
|   +-- ept.h/c (EPT)
|   +-- vmx_asm.asm (VMLAUNCH)
+-- svm.h + svm_init.c (AMD SVM 后端)
|   +-- npt.h/c (NPT)
|   +-- svm_asm.asm (VMRUN)
+-- vmx_exit.c (Intel Exit 分发)
+-- svm_exit.c (AMD Exit 分发)
|   +-- hv_mem.h/c (VMCALL 内存操作处理)
|   +-- anti_anti_debug.h/c (反反调试, 双平台共用)
|   |   +-- hv_ops 宏 (HvReadGuestCr3, HvAdvanceGuestRip, ...)
|   |   +-- process.h/c (进程查找)
|   +-- msr.c (MSR 处理, 通过 hv_ops)
+-- shared.h (IOCTL 定义)

client/main.c (用户态 CLI)
+-- driver_comm.h/c (驱动通信)
+-- shared.h (共享定义)
```

---

## 编译与部署

### 编译环境

- **WDK**: GRMWDK_EN_7600_1.ISO (Windows DDK 7600.16385.1)
- **安装路径**: `C:\WinDDK\7600.16385.1`（默认路径，`do_build.bat` 中硬编码此路径）
- **目标**: x64 Checked Build, Windows 7 Target
- **无需额外配置**: `do_build.bat` 脚本内自包含完整的 WDK 环境变量设置，无需手动打开 WDK 命令行

### 编译方法

**方法 1: 使用 do_build.bat 一键编译（推荐）**

`scripts\do_build.bat` 是一个自包含的编译脚本，内部完整配置了 WDK 7600 的所有环境变量（Include / Lib / PATH / 编译目标等），直接双击或在任意命令行中运行即可：

```cmd
:: 直接运行（无需打开 WDK 命令行环境）
<项目根目录>\scripts\do_build.bat
```

脚本会自动完成以下步骤：

1. 设置 WDK 7600 编译环境（`BASEDIR=C:\WinDDK\7600.16385.1`）
2. 配置 AMD64 目标平台、Checked Build、Win7 Target
3. 设置 Include 路径（`inc\api` + `inc\crt` + `inc\ddk`）
4. 设置 Lib 路径（`lib\win7\amd64`）
5. 设置编译器路径（`bin\x86\amd64` 交叉编译工具链）
6. 切换到项目根目录
7. 执行 `build.exe -cZg`（-c 全量编译，-Z 不跳过错误，-g 彩色输出）

预期编译输出：

```
BUILD: Compile and Link for AMD64
BUILD: Examining <项目根目录> directory tree for files to compile.
    <项目根目录>
    <项目根目录>\driver
    <项目根目录>\client
BUILD: Compiling <项目根目录>\driver directory
Compiling - driver\vmxdrv.c
Compiling - driver\vmx_init.c
...
Assembling - driver\vmx_asm.asm
Assembling - driver\svm_asm.asm
Assembling - driver\hv_hook_asm.asm
BUILD: Linking for <项目根目录>\driver directory
Linking Executable - driver\...\VMXToolboxDrv.sys
BUILD: Compiling and Linking <项目根目录>\client directory
Compiling - client\main.c
Compiling - client\driver_comm.c
Linking Executable - client\...\VMXToolbox.exe
BUILD: Done

    23 files compiled
    2 executables built
```

> **注意**: 如果 WDK 安装路径不是默认的 `C:\WinDDK\7600.16385.1`，需修改 `do_build.bat` 第 6 行的 `BASEDIR` 变量。

**方法 2: 使用 WDK 命令行环境手动编译**

```cmd
:: 打开 WDK 命令行环境
C:\Windows\System32\cmd.exe /k C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1\ chk x64 WIN7

:: 切换到项目目录
cd /d <项目根目录>

:: 编译
build -cZg
```

### 编译产出

| 文件 | 路径 |
|------|------|
| VMXToolboxDrv.sys | `driver\objchk_win7_amd64\amd64\VMXToolboxDrv.sys` |
| VMXToolbox.exe | `client\objchk_win7_amd64\amd64\VMXToolbox.exe` |

### 部署步骤

```cmd
:: 1. 启用测试签名 (需管理员权限, 需重启)
bcdedit /set testsigning on

:: 2. 加载驱动
sc create VMXToolboxDrv type=kernel binPath="<项目根目录>\driver\objchk_win7_amd64\amd64\VMXToolboxDrv.sys"
sc start VMXToolboxDrv

:: 3. 使用控制程序
VMXToolbox.exe --pid <TARGET_PID> --hide-all
VMXToolbox.exe --install-hook NtOpenProcess --action 1 --hook-log
VMXToolbox.exe --read-mem <TARGET_PID> 7FF600000000 64

:: 4. 卸载驱动
sc stop VMXToolboxDrv
sc delete VMXToolboxDrv
```

---

## 后续规划

本项目作为基于 VMX/SVM 的可扩展平台，后续将持续增加更多底层能力：

| 方向 | 功能 | 状态 |
|------|------|------|
| 反反调试 | PEB/NtQuery/DR/RDTSC/CPUID 等全套反检测 | ✅ 已完成 |
| 内核 Hook | EPT/NPT 绕过 PatchGuard 的通用 Hook 框架 | ✅ 已完成 |
| 内存读写 | 物理内存直接访问，绕过一切内核回调 | ✅ 已完成 |
| SSDT 监控 | 磁盘映像解析 SSDT + EPT Hook 监控/拦截/过滤 syscall | ✅ 已完成 |
| Shadow SSDT | Win32k Shadow SSDT 发现 + NtUser*/NtGdi* Hook/监控 | ✅ 已完成 |
| 裸机运行 | 仅支持裸机环境 | ✅ |
| 驱动隐藏 | 隐藏自身驱动对象，防止枚举 | 📋 规划中 |
| 虚拟化保护 | 对目标进程代码段进行 VMX 级别加密保护 | 📋 规划中 |
| 通信隐藏 | 基于 VMCALL 的隐蔽驱动通信通道 | 📋 规划中 |

---

## 关键风险与注意事项

| 风险 | 说明 | 应对措施 |
|------|------|---------|
| **蓝屏 (BSOD)** | VMX 代码中任何错误都可能导致蓝屏 | 在虚拟机中测试, 双机调试 |
| **PatchGuard** | Windows 内核补丁保护可能检测异常 | EPT Hook 不修改内核代码, 通常不触发 |
| **HVCI** | Hypervisor-protected Code Integrity 阻止自定义 Hypervisor | 需关闭 HVCI |
| **驱动签名** | Windows 10+ 要求驱动签名 | 开发阶段使用 testsigning, 生产需 EV 证书 |
| **EPROCESS 偏移** | 不同 Windows 版本偏移不同 | 已实现动态发现, 覆盖 Win7~Win11 |
| **多核同步** | VM-Exit handler 在各核心并行运行 | 使用原子操作和 Spin Lock |
| **进程退出** | 目标进程退出后 CR3 可能被复用 | 需要进程退出通知机制 (TODO) |
