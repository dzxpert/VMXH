/*
 * hv_hook.h - VMX Anti-Anti-Debug Hypervisor
 * Universal EPT/NPT Hook Framework
 *
 * Provides dynamic, user-controllable function hooking via EPT/NPT.
 * Hooks are invisible to PatchGuard (kernel code pages never modified).
 * Supports unlimited hooks via dynamic thunk allocation.
 */

#ifndef _HV_HOOK_H_
#define _HV_HOOK_H_

#include <ntddk.h>
#include "../common/shared.h"

/* ========================================================================= */
/*  Thunk Stub Layout                                                        */
/* ========================================================================= */

/*
 * Each thunk stub is 24 bytes:
 *   +0:  49 BA [8-byte index]    ; mov r10, <hook_id>     (10 bytes)
 *   +10: FF 25 00000000          ; jmp [rip+0]            (6 bytes)
 *   +16: [8-byte dispatcher]     ; absolute address        (8 bytes)
 *
 * R10 is volatile in Win x64 ABI (not used for params), safe to clobber.
 * RCX/RDX/R8/R9 + stack args remain intact for the original function.
 */
#define THUNK_STUB_SIZE         24
#define THUNKS_PER_PAGE         (0x1000 / THUNK_STUB_SIZE)   /* 170 per 4KB page */

/* H-3: bitmap size for slot allocation — one bit per slot, rounded up */
#define THUNK_BITMAP_WORDS      ((THUNKS_PER_PAGE + 63) / 64)

/* ========================================================================= */
/*  Thunk Page (dynamically allocated, linked list)                          */
/* ========================================================================= */

typedef struct _THUNK_PAGE {
    struct _THUNK_PAGE *Next;           /* Linked list */
    PVOID               CodeBase;       /* 4KB executable page */
    ULONG               Capacity;       /* THUNKS_PER_PAGE */
    ULONG               UsedCount;      /* Slots currently in use */
    ULONG               BaseId;         /* First hook ID ever assigned here */

    /*
     * H-3: bitmap of allocated slots (bit set = slot in use).  Together
     * with UsedCount this lets GenericHookRemove return a slot so it can
     * be re-used by future AllocateThunk calls.  Previously slots were
     * allocated strictly append-only and never recycled, so long-running
     * systems with frequent hook/unhook (e.g. SSDT monitor toggles)
     * leaked thunk pages over time.
     */
    ULONG64             SlotBitmap[THUNK_BITMAP_WORDS];
} THUNK_PAGE, *PTHUNK_PAGE;

/* ========================================================================= */
/*  Hook Decision (shared between ASM and C, offsets must match exactly)     */
/* ========================================================================= */

typedef struct _HOOK_DECISION {
    ULONG       Action;             /* +0x00: HOOK_ACTION_* */
    ULONG       Pad0;              /* +0x04: alignment */
    ULONG64     BlockReturnValue;  /* +0x08 */
    ULONG64     NewReturnValue;    /* +0x10 */
    PVOID       Trampoline;        /* +0x18 */
    BOOLEAN     ShouldLog;         /* +0x20 */
    UCHAR       Pad1[7];           /* +0x21 */
} HOOK_DECISION, *PHOOK_DECISION;
/* Total: 0x28 = 40 bytes */

/* ========================================================================= */
/*  Generic Hook Entry (dynamic linked list node)                            */
/* ========================================================================= */

typedef struct _GENERIC_HOOK_ENTRY {
    struct _GENERIC_HOOK_ENTRY *Next;   /* Linked list */
    BOOLEAN     Active;
    ULONG       HookId;                /* Unique, monotonically increasing */

    /* Target */
    ULONG64     TargetVirtualAddress;
    ULONG       ProcessId;             /* 0 = kernel/global */
    WCHAR       FunctionName[HOOK_MAX_NAME_LEN];

    /* Rule */
    HOOK_RULE   Rule;

    /* EPT/NPT trampoline (calls original function) */
    PVOID       Trampoline;

    /* Thunk address (the EPT hook JMP target) */
    PVOID       ThunkAddress;

    /* Statistics */
    volatile LONG64 HitCount;

} GENERIC_HOOK_ENTRY, *PGENERIC_HOOK_ENTRY;

/* ========================================================================= */
/*  Global Hook Framework State                                              */
/* ========================================================================= */

typedef struct _GENERIC_HOOK_STATE {
    /* Hook entries (linked list, dynamically allocated) */
    PGENERIC_HOOK_ENTRY HookListHead;
    ULONG               HookCount;
    ULONG               NextHookId;     /* Auto-increment ID */
    KSPIN_LOCK          Lock;

    /* Thunk pages (linked list, each page holds THUNKS_PER_PAGE stubs) */
    PTHUNK_PAGE         ThunkPageHead;
    ULONG               ThunkPageCount;

    /* Hook event ring buffer */
    HOOK_EVENT          EventRing[HOOK_EVENT_RING_SIZE];
    volatile LONG       EventWriteIndex;
    volatile LONG       EventReadIndex;
    volatile LONG       EventCount;
    KSPIN_LOCK          EventLock;

    BOOLEAN             Initialized;

} GENERIC_HOOK_STATE, *PGENERIC_HOOK_STATE;

extern GENERIC_HOOK_STATE g_GenericHookState;

/* ========================================================================= */
/*  Public API                                                               */
/* ========================================================================= */

/* Lifecycle */
NTSTATUS    GenericHookInit(VOID);
VOID        GenericHookCleanup(VOID);

/* Install/remove hooks */
NTSTATUS    GenericHookInstall(
    ULONG64     TargetVa,
    ULONG       ProcessId,
    const WCHAR *FunctionName,
    PHOOK_RULE  Rule,
    PULONG      OutHookId
);
NTSTATUS    GenericHookRemove(ULONG HookId);
VOID        GenericHookRemoveAll(VOID);

/* Query */
NTSTATUS    GenericHookGetInfo(ULONG HookId, PVMX_HOOK_INFO OutInfo);
ULONG       GenericHookGetCount(VOID);

/* C helpers called from ASM dispatcher */
VOID NTAPI  GenericHookDecide(
    ULONG64         HookIndex,
    ULONG64         CallerRetAddr,
    PHOOK_DECISION  OutDecision
);

VOID NTAPI  GenericHookPostCall(
    ULONG64     HookIndex,
    ULONG       Action,
    ULONG64     FinalRetVal,
    ULONG64     CallerRetAddr,
    ULONG64     ShouldLog
);

/* Event log */
VOID        HookLogEvent(ULONG HookId, ULONG Pid, ULONG64 CallerAddr,
                          ULONG64 FinalRetVal, ULONG ActionTaken);
ULONG       HookLogRead(PHOOK_EVENT OutputBuffer, ULONG MaxEntries);

/* ASM entry point (hv_hook_asm.asm) */
extern VOID AsmGenericHookDispatcher(VOID);

#endif /* _HV_HOOK_H_ */
