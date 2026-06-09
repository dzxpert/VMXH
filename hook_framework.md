[简体中文](hook_framework_CN.md) | English

# Generic EPT/NPT Hook Framework - Technical Documentation

> **April 2026 Update**: Following a stability review, the following behaviors have been fixed/optimized:
> - **Thunk slot reclamation**: Thunks are now reclaimed via a `SlotBitmap` after a `GENERIC_HOOK_ENTRY` is uninstalled (fixes H-3).
> - **User-mode Hook**: Automatically call `KeStackAttachProcess` when `TargetVa < 0x8000_0000_0000_0000` and `ProcessId != 0` (fixes L-5).
> - **Cross-page protection**: Hook installation is rejected if the hook point is less than 12 bytes away from the end of the page (fixes L-4).
> - **SVM #DB interception**: Enabled only when NPT hooks are active, and automatically disabled when all hooks are uninstalled (fixes C-3).
> - **Cross-CPU TLB flush**: Uses `EptInvalidateAllCpusSync / NptInvalidateAllCpusSync` (IPI broadcast) after uninstalling a hook to avoid Use-After-Free (UAF) caused by HLT CPUs (fixes H-5).
> 
> See [docs/BAREMETAL_REVIEW_FIXES.md](docs/BAREMETAL_REVIEW_FIXES.md) for details.

## Overview

The generic hook framework manages Intel EPT / AMD NPT page tables to provide dynamic, user-controlled function hooking capabilities. Since kernel code pages are never physically modified, hooks are completely invisible to PatchGuard and any guest-level integrity checks.

**Core Capabilities:**
- Hook any kernel function by name (automatically resolved via `MmGetSystemRoutineAddress`)
- Hook any explicit virtual address (VA) (kernel-mode or user-mode)
- Dynamically install/remove at runtime via IOCTL
- No fixed upper limit on the number of hooks (dynamic thunk page allocation)
- Predefined actions: Passthrough, Log Only, Block (interception), Modify Return Value
- Filtering by process PID
- Event log ring buffer for monitoring hook activities

---

## Architecture

```
User-mode (VMXToolbox.exe)
  |  IOCTL_VMX_INSTALL_HOOK   (Function name or VA + Action rules)
  |  IOCTL_VMX_REMOVE_HOOK    (Hook ID)
  |  IOCTL_VMX_LIST_HOOKS     (Query active hooks)
  |  IOCTL_VMX_GET_HOOK_EVENTS (Read event logs)
  v
vmxdrv.c (IOCTL Handler)
  |  MmGetSystemRoutineAddress() resolves Name -> VA
  |  GenericHookInstall() -> Allocates Thunk + EPT Hook
  v
hv_hook.c (Hook Framework Core)
  |  Dynamic Thunk page allocation
  |  Hook entry linked-list management
  |  GenericHookDecide() - C decision function
  |  GenericHookPostCall() - Log recording
  v
hv_hook_asm.asm (ASM Dispatcher)
  |  Save original parameters (RCX/RDX/R8/R9 + stack parameters 5-8)
  |  Call GenericHookDecide() to get the action
  |  Call trampoline (original function) or block
  |  Call GenericHookPostCall() to log the event
  |  Return to the original caller
  v
EPT/NPT Engine
  |  Execute-Only page splitting (Intel) / R=0,W=0,X=0 fallback (when Execute-Only is not supported)
  |  12-byte MOV+JMP -> Thunk stub
  |  Per-CPU PT isolation: Independent PTE switching per CPU to eliminate multi-core race conditions
  |  MTF/TF single-step restoration (optimized with INVEPT SINGLE_CONTEXT)
  |  O(1) Hash table lookups for Hooks and Split Pages
```

---

## Core Mechanism: Thunk Stubs

### The Problem

EPT Hook replaces the function entry point with a 14-byte JMP to a single address. If all hooks jumped to the same dispatcher, the dispatcher would have no way of knowing which hook was triggered.

### Solution: Independent Thunk Stubs Per Hook

Each hook is allocated a unique 24-byte thunk stub that sets R10 to the Hook ID before jumping to the shared dispatcher:

```
Thunk for Hook #5:                Thunk for Hook #42:
  mov r10, 5                      mov r10, 42
  jmp AsmGenericHookDispatcher    jmp AsmGenericHookDispatcher
```

R10 is a volatile register in the Windows x64 ABI (not used for parameter passing), so setting it does not affect the original RCX/RDX/R8/R9 parameters of the function.

### Thunk Binary Layout (24 Bytes)

```
Offset    Bytes                          Instruction
+0:       49 BA [8-byte Hook ID]         mov r10, <hook_id>     (10 bytes)
+10:      FF 25 00000000                 jmp [rip+0]            (6 bytes)
+16:      [8-byte dispatcher address]    Absolute jump target   (8 bytes)
```

### Dynamic Thunk Pages

Thunks are allocated from dynamically growing pages:

```
THUNK_PAGE (Linked-list node)
  |-- CodeBase: 4KB executable page (NonPagedPool)
  |-- Capacity: 170 thunks per page (4096 / 24 = 170)
  |-- UsedCount: Current number of allocated thunks
  |-- Next: Pointer to the next THUNK_PAGE

Allocation Flow:
  1. Search existing pages to find a page where UsedCount < Capacity.
  2. If all pages are full, allocate a new 4KB page and insert it at the head of the list.
  3. Write the thunk bytes at CodeBase + (UsedCount * 24).
  4. Increment UsedCount.
  5. Return the thunk code address.

No fixed upper limit - allocate new pages on demand.
Page 1: Hooks 1-170, Page 2: Hooks 171-340, and so on.
```

---

## ASM Dispatcher Flow

When any hooked function is called, the execution flow is as follows:

```
Original Caller
  |
  | CALL NtCreateFile (now jumps to the Thunk via EPT)
  v
Thunk_N:
  mov r10, N                         ; Set Hook ID
  jmp AsmGenericHookDispatcher       ; Jump to the shared dispatcher
  |
  v
AsmGenericHookDispatcher:

  Phase 1 - Save State:
    push rbp; mov rbp,rsp; sub rsp, 0C0h
    Save RCX/RDX/R8/R9 to local variables       ; Original parameters 1-4
    Copy [rbp+30h..+48h] to local variables     ; Original parameters 5-8
    Save [rbp+08h] as CallerRetAddr             ; Who called the hooked function

  Phase 2 - Decision:
    call GenericHookDecide(R10, CallerRetAddr, &Decision)
    |
    |  GenericHookDecide() (C code):
    |    FindHookById(R10) -> GENERIC_HOOK_ENTRY
    |    Check PID filtering (Rule.TargetPid vs PsGetCurrentProcessId)
    |    InterlockedIncrement64(&HitCount)
    |    Fill HOOK_DECISION:
    |      .Action = Rule.Action
    |      .Trampoline = Pointer to the original function
    |      .BlockReturnValue / NewReturnValue
    |      .ShouldLog
    |
    If Decision.Action == BLOCK -> Jump to _do_block

  Phase 3 - Call Original Function:
    Restore RCX/RDX/R8/R9 from saved local variables
    Copy saved parameters 5-8 to [rsp+20h..+38h]
    call Decision.Trampoline            ; Call original function
    Save RAX (Return Value)
    If MODIFY_RETVAL: RAX = Decision.NewReturnValue

  Phase 4 - Post-Call Processing:
    call GenericHookPostCall(HookId, Action, FinalRetVal, CallerAddr, ShouldLog)
    |
    |  If ShouldLog:
    |    Write HOOK_EVENT to the ring buffer
    |    (HookId, PID, Timestamp, CallerAddr, RetVal, Action)

  Cleanup:
    mov rax, FinalRetVal
    mov rsp,rbp; pop rbp; ret           ; Return to the original caller

  _do_block:
    RAX = Decision.BlockReturnValue
    -> Phase 4 (Log) -> Cleanup
```

### Parameter Forwarding

The dispatcher supports functions with up to 12 parameters:
- Parameters 1-4: Saved/restored via RCX/RDX/R8/R9 registers.
- Parameters 5-8: Copied from the original stack frame to the trampoline call stack frame.
- Parameters 9+: Remain on the stack above our stack frame (never touched, naturally forwarded).

---

## HOOK_DECISION Structure

The ASM and C code share this structure. The offsets must match exactly:

```c
typedef struct _HOOK_DECISION {
    ULONG       Action;             /* +0x00: HOOK_ACTION_* */
    ULONG       Pad0;              /* +0x04: Alignment padding */
    ULONG64     BlockReturnValue;  /* +0x08: Return value when blocked */
    ULONG64     NewReturnValue;    /* +0x10: New value when return value is modified */
    PVOID       Trampoline;        /* +0x18: Original function entry point */
    BOOLEAN     ShouldLog;         /* +0x20: Whether to write to event log */
    UCHAR       Pad1[7];           /* +0x21: Alignment padding */
} HOOK_DECISION;  /* Total: 0x28 = 40 bytes */
```

ASM directly references these offsets:
```asm
mov eax, [rbp-90h]         ; Decision.Action      (+0x00)
mov rax, [rbp-90h+08h]     ; Decision.BlockRetVal (+0x08)
mov rax, [rbp-90h+10h]     ; Decision.NewRetVal   (+0x10)
mov rax, [rbp-90h+18h]     ; Decision.Trampoline  (+0x18)
movzx eax, byte ptr [rbp-90h+20h] ; Decision.ShouldLog (+0x20)
```

---

## Hook Actions

| Action | Value | Behavior | Use Cases |
|------|-----|------|----------|
| `HOOK_ACTION_PASSTHROUGH` | 0 | Calls the original function without modification. Counts hits only. | Performance monitoring |
| `HOOK_ACTION_LOG_ONLY` | 1 | Calls the original function, logging every invocation. | Function call tracing |
| `HOOK_ACTION_BLOCK` | 2 | Skips the original function, returning `BlockReturnValue`. | Access denial, API interception |
| `HOOK_ACTION_MODIFY_RETVAL` | 3 | Calls the original function, overwriting RAX with `NewReturnValue`. | Return value spoofing |

### PID Filtering

Each hook has a `TargetPid` field:
- `TargetPid = 0`: Trigger hook for all processes (global)
- `TargetPid = 1234`: Trigger hook only for PID 1234, passthrough for all other processes

This check is implemented in `GenericHookDecide()` using `PsGetCurrentProcessId()`.

---

## IOCTL Interface

### IOCTL_VMX_INSTALL_HOOK (0x809)

Installs a new hook.

**Input:** `VMX_HOOK_REQUEST`
```c
typedef struct _VMX_HOOK_REQUEST {
    BOOLEAN     ByName;                          /* TRUE = Resolve by name */
    WCHAR       FunctionName[128];               /* e.g., L"NtCreateFile" */
    ULONG64     TargetAddress;                   /* Direct VA (when !ByName) */
    ULONG       ProcessId;                       /* 0 = Kernel */
    HOOK_RULE   Rule;                            /* Action + parameters */
} VMX_HOOK_REQUEST;

typedef struct _HOOK_RULE {
    ULONG       Action;             /* HOOK_ACTION_* */
    ULONG       TargetPid;          /* 0 = Global, >0 = Specific PID */
    ULONG64     BlockReturnValue;   /* Used for BLOCK action */
    ULONG64     NewReturnValue;     /* Used for MODIFY_RETVAL action */
    BOOLEAN     LogEnabled;         /* Enable event logging */
} HOOK_RULE;
```

**Output:** `VMX_HOOK_RESPONSE`
```c
typedef struct _VMX_HOOK_RESPONSE {
    ULONG       HookId;             /* Unique ID for subsequent operations */
    ULONG64     ResolvedAddress;    /* The actual hooked VA */
} VMX_HOOK_RESPONSE;
```

**Example (C User-mode Code):**
```c
VMX_HOOK_REQUEST req = {0};
VMX_HOOK_RESPONSE resp = {0};
DWORD ret;

req.ByName = TRUE;
wcscpy(req.FunctionName, L"NtCreateFile");
req.Rule.Action = HOOK_ACTION_LOG_ONLY;
req.Rule.LogEnabled = TRUE;

DeviceIoControl(hDev, IOCTL_VMX_INSTALL_HOOK,
    &req, sizeof(req), &resp, sizeof(resp), &ret, NULL);

printf("Hook installed: ID=%u, Address=0x%llX\n", resp.HookId, resp.ResolvedAddress);
```

### IOCTL_VMX_REMOVE_HOOK (0x80A)

Removes a hook by ID.

**Input:** `VMX_UNHOOK_REQUEST`
```c
typedef struct _VMX_UNHOOK_REQUEST {
    ULONG HookId;
} VMX_UNHOOK_REQUEST;
```

### IOCTL_VMX_LIST_HOOKS (0x80B)

Lists all active hooks.

**Output:** `VMX_HOOK_LIST` (variable length)
```c
typedef struct _VMX_HOOK_LIST {
    ULONG           Count;
    VMX_HOOK_INFO   Hooks[1];  /* Variable-length array */
} VMX_HOOK_LIST;

typedef struct _VMX_HOOK_INFO {
    ULONG       HookId;
    BOOLEAN     Active;
    ULONG64     TargetAddress;
    ULONG       ProcessId;
    HOOK_RULE   Rule;
    ULONG64     HitCount;          /* Trigger count for this hook */
    WCHAR       FunctionName[128];
} VMX_HOOK_INFO;
```

### IOCTL_VMX_GET_HOOK_EVENTS (0x80C)

Reads hook event log entries.

**Output:** `VMX_HOOK_EVENT_BUFFER` (variable length)
```c
typedef struct _VMX_HOOK_EVENT_BUFFER {
    ULONG       Count;
    HOOK_EVENT  Events[1];
} VMX_HOOK_EVENT_BUFFER;

typedef struct _HOOK_EVENT {
    ULONG       HookId;
    ULONG       ProcessId;
    ULONG64     Timestamp;
    ULONG64     ReturnAddress;  /* Who called the hooked function */
    ULONG64     FinalRetVal;    /* Value returned to the caller */
    ULONG       ActionTaken;    /* Executed HOOK_ACTION_* */
} HOOK_EVENT;
```

The ring buffer holds 512 entries. When the buffer is full, the oldest entries are overwritten.

---

## Installation Flow (Internal)

```
User: IOCTL_VMX_INSTALL_HOOK { ByName=TRUE, Name="NtCreateFile", Action=LOG }
  |
  v
HandleIoctlInstallHook():
  |
  +-- MmGetSystemRoutineAddress(L"NtCreateFile")
  |   -> TargetVa = 0xFFFFF80012345678
  |
  +-- GenericHookInstall(TargetVa, 0, "NtCreateFile", &Rule, &HookId)
       |
       +-- NextHookId++ -> HookId = 5
       |
       +-- AllocateThunk(5)
       |     Search thunk pages for a free slot
       |     If all are full: Allocate a new 4KB executable page
       |     Write 24-byte thunk: mov r10,5; jmp AsmGenericHookDispatcher
       |     -> ThunkAddr = 0xFFFFXXXXXXXX
       |
       +-- HvHookFunction(0xFFFFF80012345678, ThunkAddr, &Trampoline)
       |     |
       |     +-- EPT Engine:
       |           1. VA -> PA translation
       |           2. Split 2MB page into 4KB pages (O(1) hash table tracks split pages)
       |           3. Copy original page -> OriginalPage
       |           4. Copy original page -> HookPage
       |           5. Patch HookPage: MOV RAX,imm64 + JMP RAX (12 bytes)
       |           6. Construct trampoline: Instruction length decoding -> Full instruction copy -> RIP-relative relocation fixes
       |           7. EPT PTE:
       |              - If Execute-Only supported: R=0,W=0,X=1 -> HookPage
       |              - Fallback if unsupported: R=0,W=0,X=0 + RIP intent detection
       |           8. Per-CPU PT isolation: Clone PD+PT to all CPUs
       |           9. INVEPT SINGLE_CONTEXT flushes current CPU TLB
       |
       +-- Allocate GENERIC_HOOK_ENTRY (NonPagedPool)
       |     .HookId = 5
       |     .TargetVirtualAddress = 0xFFFFF80012345678
       |     .FunctionName = "NtCreateFile"
       |     .Rule = { LOG_ONLY, LogEnabled=TRUE }
       |     .Trampoline = <EPT trampoline pointer>
       |     .ThunkAddress = ThunkAddr
       |
       +-- Link entry to HookListHead
       |
       +-- Return HookId=5
```

---

## Runtime Hook Trigger Flow

```
[Guest] Any process calls NtCreateFile(...)
  |
  +-- CPU fetches instruction from NtCreateFile entry point
  |
  +-- [EPT] PTE permissions depend on Execute-Only support:
  |   Mode A (Supported): R=0,W=0,X=1, Physical Address = HookPage
  |   Mode B (Unsupported): R=0,W=0,X=0, distinguish execution/read via RIP detection
  |   HookPage contains: MOV RAX,imm64; JMP RAX (12-byte absolute JMP)
  |
  v
[Thunk_5]
  mov r10, 5                           ; "I am Hook #5"
  jmp AsmGenericHookDispatcher         ; Shared entry point
  |
  v
[AsmGenericHookDispatcher]
  |
  +-- Save RCX/RDX/R8/R9, stack parameters 5-8, caller return address
  |
  +-- call GenericHookDecide(5, CallerRetAddr, &Decision)
  |     |
  |     +-- FindHookById(5) -> Entry for NtCreateFile
  |     +-- Rule.TargetPid == 0 -> No PID filtering, process all processes
  |     +-- InterlockedIncrement64(&HitCount)
  |     +-- Decision = { LOG_ONLY, Trampoline=<Original>, ShouldLog=TRUE }
  |
  +-- Restore all parameters
  +-- call Decision.Trampoline         ; Run the real NtCreateFile
  |     |
  |     +-- [EPT Trampoline]:
  |           Execute original 14 bytes
  |           JMP to NtCreateFile+14
  |           Real NtCreateFile runs to completion
  |           Returns NTSTATUS in RAX
  |
  +-- RAX = original return value (e.g., STATUS_SUCCESS)
  |
  +-- call GenericHookPostCall(5, LOG_ONLY, RAX, CallerAddr, TRUE)
  |     |
  |     +-- HookLogEvent():
  |           Write to ring buffer:
  |           { HookId=5, PID=CurrentProcess, Timestamp, CallerAddr, RetVal, LOG_ONLY }
  |
  +-- ret   ; Return original RAX to the caller
  |
  v
[Guest] Caller receives NtCreateFile result, completely unaware of the hook
```

---

## Why PatchGuard Cannot Detect It

```
What PatchGuard checks:             What actually happens:

Read NtCreateFile bytes:            EPT Violation -> Presents OriginalPage
  Expected: Original prologue        Seen: Unmodified original bytes     [Pass]

Calculate ntoskrnl page hash:       All reads route through OriginalPage
  Expected: Known hash value         Hash value: Unchanged               [Pass]

Check SSDT entries:                 SSDT is not modified
  Expected: Within ntoskrnl range    All entries unchanged               [Pass]

Check IDT entries:                 IDT is not modified
  Expected: Within ntoskrnl range    All entries unchanged               [Pass]

Key Trick: EPT presents different physical pages for reads vs execution
  - Read/Write: OriginalPage (unmodified)   -> Integrity checks pass
  - Execute: HookPage (with JMP)            -> Hooks are triggered upon call
```

---

## Data Structures Overview

```
GENERIC_HOOK_STATE (Global Singleton)
  |
  +-- HookListHead -> GENERIC_HOOK_ENTRY -> GENERIC_HOOK_ENTRY -> ... -> NULL
  |                    .HookId = 1          .HookId = 5
  |                    .TargetVA = ...       .TargetVA = ...
  |                    .Rule = {...}         .Rule = {...}
  |                    .Trampoline = ...     .Trampoline = ...
  |
  +-- ThunkPageHead -> THUNK_PAGE -> THUNK_PAGE -> ... -> NULL
  |                    .CodeBase = [4KB executable page]
  |                    .UsedCount = 42
  |                    .Capacity = 170
  |
  +-- EventRing[512]   (Ring buffer of HOOK_EVENT entries)
  +-- EventWriteIndex, EventReadIndex, EventCount
```

---

## Files

| File | Description |
|------|------|
| `driver/hv_hook.h` | Framework header: all structures and function declarations |
| `driver/hv_hook.c` | Core implementation: initialization, installation, removal, decision-making, logging |
| `driver/hv_hook_asm.asm` | ASM dispatcher: saving/restoring parameters, trampoline calls |
| `driver/ept.c` | EPT engine: Per-CPU isolation, O(1) hash tables, instruction decoding, RIP relocation, Violation handling |
| `driver/ept.h` | EPT structures: EPT_CPU_STATE, hash constants, Per-CPU function declarations |
| `driver/npt.c` | NPT engine (AMD): Similar Per-CPU isolation implementation |
| `driver/npt.h` | NPT structures: NPT_CPU_STATE, Per-CPU function declarations |
| `common/shared.h` | IOCTL codes (0x809-0x80C) and shared structures |
| `driver/vmxdrv.c` | IOCTL handlers for install/remove/list/events |

---

## Limitations

| Limitation | Details |
|------|------|
| 12-byte minimum prologue | Hooked functions must have at least 12 bytes of intact instructions before any short jump target (instruction decoder automatically aligns boundaries) |
| Stack parameters 9+ not explicitly copied | Parameters 9-12+ rely on stack frame layout compatibility (works in practice) |
| Thunk pages not reclaimed | Freed hooks leave gaps in thunk pages; pages are only freed during cleanup |
| Event ring buffer overflow | When the ring buffer (512 entries) is full, the oldest events are silently overwritten |
| User-mode Hooks | Requires target process CR3 resolution; kernel-mode hooks are fully supported |
| RIP-relative relocation range | RIP-relative instructions cannot be relocated if the distance between the trampoline and the original location exceeds ±2GB, causing hook installation to be rejected |

---

## Per-CPU EPT/NPT Hook Page Isolation

### Problem: Multi-core Race Conditions

EPT Hook works by temporarily relaxing PTE permissions during an EPT Violation to execute a single instruction (MTF single-step) and then restoring them. When multiple CPUs trigger the same hook simultaneously, race conditions occur on the shared PTE:

```
CPU 0: EPT Violation → Relax PTE (R+W) → Enable MTF
CPU 1: EPT Violation → Relax PTE (R+W) → Enable MTF    ← Same PTE!
CPU 0: MTF triggers → Restore PTE (X-Only)             ← Also restores CPU 1's PTE!
CPU 1: Still executing → PTE restored → EPT Violation again → Infinite loop
```

### Solution: Per-CPU Independent PTs

```
        ┌──────────────────────────────────────────────┐
        │  Shared Template (EPT_STATE)                  │
        │  PML4 → PDPT → PD Pages → Split PT Pages     │
        │  (Shared by all CPUs for non-hooked areas)   │
        └──────────────────────────────────────────────┘

Per-CPU Layer (cloned on demand only for hooked areas):

  CPU 0:  PML4[0] → PDPT[0]                      CPU 1:  PML4[1] → PDPT[1]
            │                                               │
            ├─ PDPT[x] → Shared PD (non-hooked GB regions)  ├─ PDPT[x] → Shared PD
            │                                               │
            └─ PDPT[y] → per-CPU PD[0][y]                  └─ PDPT[y] → per-CPU PD[1][y]
                           │                                               │
                           └─ PD[z] → per-CPU PT[0]                       └─ PD[z] → per-CPU PT[1]
                                (Independent 4KB PTEs)                          (Independent 4KB PTEs)
```

**Layered Isolation Strategy:**

| Level | Isolation Strategy | Reason |
|------|---------|------|
| PML4 | Independent copy per CPU | Allows PML4[0] to point to respective PDPTs |
| PDPT | Independent copy per CPU | Allows PDPT entries to point to respective PD pages |
| PD | **Cloned on demand** | Per-CPU PD pages are created only for GB regions containing hooks |
| PT (split) | **Cloned on demand** | Per-CPU PT pages are created only for 2MB regions containing hooks |
| Non-hooked areas | Shared by all CPUs | Points to shared PD pages via PDPT entries |

### Core Data Structures

```c
/* Per-CPU EPT root structure */
typedef struct _EPT_CPU_STATE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[512];   /* Independent PML4 */
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[512];   /* Independent PDPT */
    EPT_POINTER Eptp;      /* EPTP value for this CPU (written to VMCS) */
    ULONG64     Pml4Pa;
} EPT_CPU_STATE;

/* Per-CPU PT page copy */
typedef struct _EPT_PER_CPU_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[512];      /* Independent PTE array */
    ULONG64     PhysicalAddress;   /* Physical address of this per-CPU PTE array */
    BOOLEAN     Allocated;         /* Whether it has been allocated */
} EPT_PER_CPU_SPLIT;

/* Per-CPU PD page copy */
typedef struct _EPT_PER_CPU_PD_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Entries[512];
} EPT_PER_CPU_PD_PAGE;
```

### Initialization Flow

```
EptInitPerCpu()  (Called after EptInitialize)
  |
  +-- Allocate g_EptCpuStates[g_MaxProcessors]
  +-- Allocate pointer array g_PerCpuSplitPages[g_MaxProcessors]
  +-- Allocate pointer array g_PerCpuPdPages[g_MaxProcessors]
  |
  +-- For each CPU:
       +-- Clone PML4 and PDPT (from shared template)
       +-- PML4[0].PhysAddr = Physical address of this CPU's PDPT
       +-- Build independent EPTP value
       |
       PDPT entries initially still point to shared PD pages (no memory wasted for non-hooked regions)
```

### Per-CPU Setup During Hook Installation

```
EptHookFunction()
  |
  +-- ... Normal hook installation (page splitting, HookPage creation, trampoline construction) ...
  |
  +-- Per-CPU Isolation Setup:
       |
       +-- EptEnsurePerCpuPdForRegion(PdptIndex)
       |     For each CPU: Clone shared PD page -> per-CPU PD page
       |     Update the CPU's PDPT[PdptIndex] to point to its own PD page
       |
       +-- EptEnsurePerCpuSplitPage(splitIdx, PdptIndex, PdIndex)
       |     For each CPU: Clone shared split PT page -> per-CPU PT page
       |     Update the CPU's PD[PdptIndex].Entries[PdIndex] to point to its own PT page
       |
       +-- Copy hook PTE permissions to all per-CPU PTs:
             for (cpu = 0; cpu < N; cpu++):
                 CpuPte = EptGetPerCpuPte(cpu, TargetPA)
                 CpuPte->Read/Write/Execute/PhysAddr = Same as shared PTE
```

### Runtime EPT Violation Handling (Per-CPU PTE)

```
HandleEptViolation()
  |
  +-- CpuIndex = KeGetCurrentProcessorNumber()
  |
  +-- Pte = EptGetPerCpuPte(CpuIndex, HookPA)  // Get private PTE for this CPU
  |   If per-CPU is unavailable: Fall back to shared PTE
  |
  +-- Modify Pte permissions (affects current CPU only):
  |     Mode A: R=1,W=1,X=0 (Data access) or R=0,W=0,X=1 (Execute)
  |     Mode B: R=1,W=1,X=1 + RIP detection to select HookPage/OriginalPage
  |
  +-- INVEPT SINGLE_CONTEXT(Current CPU's EPTP)  // Flush current CPU only
  |   (No longer use ALL_CONTEXTS to affect all CPUs)
  |
  +-- EptMtfTrackRelaxedPage(HookPA)  // Track relaxed page for current CPU
  +-- Enable MTF

HandleMtf()
  |
  +-- Pa = EptMtfGetAndClearRelaxedPage()  // Get tracked page for this CPU
  +-- Restore this CPU's PTE to hook permissions
  +-- INVEPT SINGLE_CONTEXT
  +-- Disable MTF
  |
  // PTEs of other CPUs are unaffected → No race conditions
```

### Memory Overhead

| Component | Size | When Allocated |
|------|------|---------|
| EPT_CPU_STATE (PML4+PDPT+EPTP) | ~8KB × Number of CPUs | EptInitPerCpu() |
| Per-CPU PD pages | ~2MB × Number of CPUs | Cloned on demand during first hook installation |
| Per-CPU Split PT pages | ~4KB × Number of CPUs × Number of hooked 2MB regions | Cloned on demand during first hook installation |

> **Example**: 4-CPU system, 3 hooks distributed across 2 different 2MB regions:
> - EPT_CPU_STATE: 4 × 8KB = 32KB
> - Per-CPU PD: 4 × 2MB = 8MB (one-time, covering all PDPT indices)
> - Per-CPU PT: 4 × 2 × 4KB = 32KB
> - **Total extra overhead**: ~8.06MB

---

## Execute-Only Fallback (Mode A / Mode B)

EPT Hooks rely on page permission separation to distinguish between execution and data access. Mode A is used on platforms that support hardware Execute-Only; otherwise, Mode B is used.

### Mode A: Execute-Only (R=0, W=0, X=1)

```
PTE Settings: Read=0, Write=0, Execute=1, PhysAddr = HookPage

Guest reads/writes NtCreateFile bytes:
  → EPT Violation (Data access)
  → Handler: Switch to OriginalPage (R+W, X=0) + Enable MTF
  → MTF Restoration: Switch back to HookPage (X-only)
  → PatchGuard/Integrity check sees original unmodified code ✓

Guest executes NtCreateFile:
  → Directly hits HookPage (X=1, no Violation)
  → MOV RAX,ThunkAddr; JMP RAX → Thunk → Dispatcher
```

**Pros**: Zero violations on the execution path (no extra performance overhead).

### Mode B: Access Denied (R=0, W=0, X=0)

```
PTE Settings: Read=0, Write=0, Execute=0, PhysAddr = HookPage

Any Guest access:
  → EPT Violation (All access types)
  → Handler: Check Guest RIP
    |
    +-- RIP is inside target page → Execution intent
    |   → Temporarily set R+W+X, PhysAddr = HookPage + Enable MTF
    |   → Execute JMP patch → Enter Thunk
    |
    +-- RIP is outside page → Data read/write intent
        → Temporarily set R+W+X, PhysAddr = OriginalPage + Enable MTF
        → Reads unmodified original code (PatchGuard safe)

  MTF Restoration: Switch back to R=0, W=0, X=0
```

**RIP Detection Principle**: Uses Guest CR3 page table traversal to translate Guest RIP VA to PA, and compares its 4KB page frame with the target page frame.

```c
/* VMX root-safe Guest VA → PA translation (does not rely on Windows APIs) */
ULONG64 RipPa = EptGuestVaToPa(GuestCr3, GuestRip);
if ((RipPa & PAGE_MASK_4KB) == HookTargetPhysicalAddr) {
    /* Execution: Present HookPage */
} else {
    /* Data Access: Present OriginalPage */
}
```

### Auto-Detection

```c
/* Detect Execute-Only support in EptInitialize() */
ULONG64 EptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
g_EptHookState.ExecuteOnlySupported = (EptVpidCap & 1) != 0;
/* Some CPU models might not support this bit → automatic fallback to Mode B */
```

---

## O(1) Hash Table Lookup Optimization

EPT Violation handling runs on the critical path in VMX root mode, and latency directly impacts guest performance. The original implementation used a linear scan O(n), which has been optimized to an O(1) open-addressing hash table.

### Hook Lookup Hash Table

```
Purpose: HandleEptViolation() → EptFindHookByPhysicalAddress()
Key:     Page Physical Address (PA >> 12)
Value:   Hook array index
Size:    2048 buckets (≤1024 hooks, load factor ≤ 0.5)
Hash:    Knuth multiplicative hash (PFN × 2654435761 >> shift)
Conflict: Linear probing + EPT_HOOK_HASH_EMPTY sentinel

Operations:
  Insert - EptHookFunction() : O(1)
  Lookup - EptFindHookByPhysicalAddress() : O(1) expected
  Delete - EptUnhookFunction() : O(n) rebuild (not hot path)
```

### Split Page Lookup Hash Table

```
Purpose: EptGetPteForPhysicalAddress() / EptGetPerCpuPte()
Key:     2MB-aligned base address (Base2MB >> 21)
Value:   g_SplitPages[] array index
Size:    256 buckets (≤128 split pages, load factor ≤ 0.5)
Hash:    Same Knuth multiplicative hash as above

Inserted in EptSplitLargePage(), cleared in EptCleanup().
```

### Performance Comparison

| Operation | Old Scheme | New Scheme |
|------|--------|--------|
| Hook Lookup (Every EPT Violation) | O(1024) linear scan | O(1) hash lookup |
| Split page Lookup (Every PTE operation) | O(128) linear scan | O(1) hash lookup |
| Hook Removal (Not hot path) | O(1) | O(n) hash rebuild |

---

## Secure Trampoline Construction

The trampoline is used to call the original function after a hook is triggered. The construction process involves three key components:

### Instruction Length Decoder

`EptGetInstructionLength()` is a minimal x86-64 instruction length decoder that covers a common subset of instructions typically found in function prologues:

```
Supported Instruction Categories:
  - Register operations: MOV, LEA, XOR, AND, OR, SUB, ADD, CMP, TEST
  - Stack operations: PUSH reg/imm, POP reg
  - Flow control: JMP rel8/rel32, Jcc rel8/rel32, CALL rel32, RET
  - Prefixes: REX (0x40-0x4F), Operand size (0x66), Address size (0x67)
  - Two-byte: 0F xx (CMOVcc, SETcc, MOVZX, MOVSX, NOP, Jcc rel32)
  - Group 1/3/5: 80/81/83, F6/F7, FF series

Instructions processing:
  1. Skip prefix bytes (REX, 66, 67, segment overrides, LOCK/REP).
  2. Identify 1-byte/2-byte opcode.
  3. If ModRM present: Decode Mod, RM, SIB, Displacement.
  4. Accumulate immediate size.
  5. Return total length (0 = failed to decode → reject hook).
```

**Safety Guarantee**: The decoder loops until the accumulated bytes are ≥ 12 (JMP patch size), ensuring that the trampoline only contains complete instructions.

### RIP-Relative Instruction Detection and Relocation

```c
/* Detect RIP-relative addressing: ModRM Mod=00, RM=101 */
BOOLEAN EptIsRipRelativeInstruction(Code, InsnLen, &DispOffset);

/* Relocate disp32: new_disp = target - (TrampolineVA + InsnLen) */
BOOLEAN EptRelocateRipRelativeInstruction(TrampolineInsn, InsnLen,
    DispOffset, OriginalVA, TrampolineVA);
```

```
Original Location (OriginalVA = 0xFFFFF800`12345678):
  LEA RAX, [RIP+0x1234]
  → Target Absolute Address = 0xFFFFF800`12345678 + InsnLen + 0x1234

Trampoline Location (TrampolineVA = 0xFFFFABCD`00001000):
  LEA RAX, [RIP+NewDisp]
  → NewDisp = Target Absolute Address - (TrampolineVA + InsnLen)
  → If |NewDisp| > 2GB → Relocation fails → Reject hook installation
```

### Trampoline Overall Structure

```
Trampoline (max 64 bytes):
  +0:      [Original Instruction 1]      (RIP-relative fixed)
  +N1:     [Original Instruction 2]      (RIP-relative fixed)
  ...
  +Nk:     [Original Instruction k]      (Total ≥ 12 bytes of complete instructions)
  +Total:  FF 25 00000000                JMP [RIP+0]
  +Total+6: [8-byte absolute address]     → TargetVA + Total (Jump back after the patched section)
```

---

## Shared Page Support (Multiple Hooks in Same Page)

When multiple hooks are installed on the same 4KB physical page (e.g., adjacent functions in the same module), they share the HookPage and OriginalPage:

```
EptHookFunction(FuncA) → First hook, allocates HookPage + OriginalPage
  Hook[0].OwnsPages = TRUE
  Writes JMP → ThunkA at offset A on HookPage

EptHookFunction(FuncB, same page) → Detects PageOwner
  Hook[1].OwnsPages = FALSE
  Reuses Hook[0]'s HookPage/OriginalPage
  Writes JMP → ThunkB at offset B on HookPage (does not overwrite JMP at offset A)

EptUnhookFunction(FuncA):
  Restores original bytes at offset A on HookPage
  Detects FuncB is still on the same page → Does not free HookPage/OriginalPage
  Transfers OwnsPages to Hook[1]

EptUnhookFunction(FuncB):
  Restores original bytes at offset B on HookPage
  No other hooks on the same page → Restores EPT PTE to the original page → INVEPT → Frees pages
```

**Ownership Transfer Rule**: When removing a page owner, if there are other hooks on the same page, transfer `OwnsPages = TRUE` to another hook.

---

## INVEPT Optimization

### Old Scheme: INVEPT ALL_CONTEXTS

Every PTE modification flushes the TLBs of all EPTP contexts on all CPUs.

### New Scheme: INVEPT SINGLE_CONTEXT

After Per-CPU isolation, a PTE modification only affects the page table of the current CPU. Using SINGLE_CONTEXT to flush the current CPU's EPTP context is sufficient:

```c
ULONG64 CpuEptp = EptGetPerCpuEptp(CpuIndex);
if (CpuEptp)
    EptInvalidateSingleContext(CpuEptp);  /* Flush current CPU only */
else
    EptInvalidateAllContexts();           /* Fallback */
```

### Cross-CPU Flushing (During Hook Installation/Removal)

Hook installation and removal modify PTEs for all CPUs, so a global flush is still required. This is achieved using a generation counter mechanism:

```
EptInvalidateFromGuest():
  InterlockedIncrement(&g_EptInveptGeneration)

Every VM-Exit:
  EptCheckPendingInvept():
    if (g_EptInveptCpuGen[CPU] != g_EptInveptGeneration):
      g_EptInveptCpuGen[CPU] = g_EptInveptGeneration
      INVEPT ALL_CONTEXTS
```

---

## Two-Phase Unhook (Preventing UAF)

When removing hooks, it must be guaranteed that no CPU's TLB still references the HookPage/OriginalPage to be freed:

```
EptUnhookAll():
  Pass 1: Traverse all hooks, restore EPT PTE → Original Physical Address (R+W+X)
          Restore all per-CPU PTEs as well
          !! Do not free any pages yet !!

  INVEPT: EptInvalidateFromGuest() → All CPUs eventually execute INVEPT

  Pass 2: Traverse all hooks, free HookPage/OriginalPage/Trampoline

  // The order of Pass 1 → INVEPT → Pass 2 ensures no UAF window exists.
  // If pages were freed directly in Pass 1, stale TLBs on other CPUs might still translate the old pages → Use-After-Free
```
