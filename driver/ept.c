/*
 * ept.c - VMX Anti-Anti-Debug Hypervisor
 * Extended Page Tables: identity mapping, hook engine, violation handler
 */

#include "ept.h"
#include "vmx.h"
#include "log.h"

/* ========================================================================= */
/*  Forward declarations for per-CPU helpers (defined later in this file)     */
/* ========================================================================= */
static NTSTATUS EptEnsurePerCpuPdForRegion(ULONG PdptIndex);
static NTSTATUS EptEnsurePerCpuSplitPage(ULONG splitIdx, ULONG PdptIndex, ULONG PdIndex);

/* ========================================================================= */
/*  Constants (needed before global array declarations)                      */
/* ========================================================================= */

/* Pool of split page tables (for 2MB -> 4KB splitting) */
#define MAX_SPLIT_PAGES     128

/* Page directory pages - we need one PD per PDPT entry (512 entries) */
/* For simplicity, we pre-allocate for the first 512GB of physical memory */
/* Each PD covers 1GB and has 512 entries of 2MB each */
#define MAX_PD_PAGES    512

/* ========================================================================= */
/*  Globals                                                                  */
/* ========================================================================= */

EPT_STATE       g_EptState = { 0 };
EPT_HOOK_STATE  g_EptHookState = { 0 };
PEPT_CPU_STATE  g_EptCpuStates = NULL;     /* per-CPU EPT root array */

/*
 * Per-CPU split page tracking.
 * Each CPU gets its own copy of the PT page for hooked 2MB regions,
 * allowing independent PTE permission toggling during EPT violation → MTF.
 *
 * g_PerCpuSplitPages[cpu][splitIdx] is the per-CPU copy of g_SplitPages[splitIdx].
 * Only populated when a hook is installed on that split page.
 */
typedef struct _EPT_PER_CPU_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[EPT_PTE_COUNT];
    ULONG64     PhysicalAddress;    /* PA of this per-CPU PTE array */
    BOOLEAN     Allocated;          /* TRUE if this per-CPU copy exists */
} EPT_PER_CPU_SPLIT, *PEPT_PER_CPU_SPLIT;

/* [g_MaxProcessors][MAX_SPLIT_PAGES] — allocated on demand */
static PEPT_PER_CPU_SPLIT *g_PerCpuSplitPages = NULL;

/*
 * Per-CPU PD pages for PDPT entries that contain hooked 2MB regions.
 * g_PerCpuPdPages[cpu] is an array of PD pages (one per PDPT entry).
 * Only PDPT entries containing hooks get per-CPU PD pages.
 * g_PerCpuPdAllocated[pdptIdx] tracks which PDPT entries have been split.
 */
typedef struct _EPT_PER_CPU_PD_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Entries[EPT_PDE_COUNT];
} EPT_PER_CPU_PD_PAGE;

static EPT_PER_CPU_PD_PAGE **g_PerCpuPdPages = NULL;  /* [g_MaxProcessors] -> allocated PD */
static BOOLEAN g_PerCpuPdAllocated[MAX_PD_PAGES] = { 0 };  /* which PDPT entries are per-CPU */

/*
 * Global flag: Guest code sets this after modifying EPT PTEs.
 * Each CPU checks it at every VM-Exit and executes INVEPT if non-zero.
 *
 * We use a generation counter instead of a simple flag: the Guest
 * increments it, and each CPU tracks the last generation it has seen.
 * This way every CPU eventually executes INVEPT, not just the first
 * one to notice the change.
 */
volatile LONG   g_EptInveptGeneration = 0;
static PLONG    g_EptInveptCpuGen = NULL;  /* per-CPU last-seen generation (dynamic) */

/*
 * Per-CPU tracking of which physical page was temporarily made permissive
 * by the EPT violation handler. The MTF handler reads and clears this to
 * know which page to restore, avoiding a multi-core race condition.
 */
static volatile ULONG64 *g_MtfRelaxedPagePa = NULL;  /* dynamic [g_MaxProcessors] */

/*
 * EptMtfTrackRelaxedPage - Record which physical page this CPU just made
 * permissive (called from HandleEptViolation).
 */
VOID EptMtfTrackRelaxedPage(ULONG64 PagePhysicalAddr)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    if (g_MtfRelaxedPagePa && CpuIndex < g_MaxProcessors) {
        g_MtfRelaxedPagePa[CpuIndex] = PagePhysicalAddr;
    }
}

/*
 * EptMtfGetAndClearRelaxedPage - Get and clear the relaxed page for this CPU.
 * Called from HandleMtf in vmx_exit.c.
 * Returns 0 if no page was recorded (shouldn't happen normally).
 */
ULONG64 EptMtfGetAndClearRelaxedPage(VOID)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    ULONG64 Pa = 0;
    if (g_MtfRelaxedPagePa && CpuIndex < g_MaxProcessors) {
        Pa = g_MtfRelaxedPagePa[CpuIndex];
        g_MtfRelaxedPagePa[CpuIndex] = 0;
    }
    return Pa;
}

/*
 * Dynamically allocated page directory and page table pages.
 * For a full identity map we use 2MB large pages by default,
 * and split to 4KB only when we need fine-grained EPT hooks.
 */

typedef struct _EPT_SPLIT_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PTE Pte[EPT_PTE_COUNT];
    ULONG64     PhysicalAddress;    /* PA of this PTE array */
    ULONG64     BasePhysAddr2MB;    /* The 2MB region this covers */
    BOOLEAN     InUse;
} EPT_SPLIT_PAGE, *PEPT_SPLIT_PAGE;

static EPT_SPLIT_PAGE  *g_SplitPages = NULL;
static ULONG            g_SplitPageCount = 0;

/*
 * BUG FIX (Issue #3+5+6): Split page hash table for O(1) lookup.
 *
 * Maps (Base2MB >> 21) → split page index in g_SplitPages[].
 * Avoids the O(n) linear scan in EptGetPteForPhysicalAddress() and
 * EptGetPerCpuPte(), which are called multiple times per EPT violation.
 *
 * Open-addressing with linear probing, EPT_SPLIT_HASH_EMPTY sentinel.
 * Maintained by EptSplitLargePage (insert) and EptCleanup (clear).
 *
 * Hash table entries: [hash_slot] = { Base2MB, splitIdx }
 * We store the full Base2MB key for collision verification.
 */
typedef struct _EPT_SPLIT_HASH_ENTRY {
    ULONG64 Base2MB;        /* Key: 2MB-aligned physical address */
    ULONG   SplitIdx;       /* Value: index into g_SplitPages[] */
} EPT_SPLIT_HASH_ENTRY;

static EPT_SPLIT_HASH_ENTRY g_SplitHashTable[EPT_SPLIT_HASH_SIZE];

/*
 * Hash function for 4KB page physical address → hook hash table slot.
 * Uses the page frame number (PA >> 12) and a simple multiplicative hash
 * to distribute entries across EPT_HOOK_HASH_SIZE buckets.
 */
static __forceinline ULONG EptHookHashFn(ULONG64 PagePa)
{
    ULONG64 Pfn = PagePa >> 12;
    /* Knuth multiplicative hash: spread bits using golden ratio constant */
    return (ULONG)((Pfn * 2654435761ULL) >> (32 - EPT_HOOK_HASH_BITS)) & (EPT_HOOK_HASH_SIZE - 1);
}

/*
 * Hash function for 2MB base physical address → split page hash table slot.
 */
static __forceinline ULONG EptSplitHashFn(ULONG64 Base2MB)
{
    ULONG64 Idx2MB = Base2MB >> 21;
    return (ULONG)((Idx2MB * 2654435761ULL) >> (32 - EPT_SPLIT_HASH_BITS)) & (EPT_SPLIT_HASH_SIZE - 1);
}

/*
 * EptSplitHashLookup - O(1) lookup of split page index by 2MB base address.
 * Returns the split page index, or EPT_SPLIT_HASH_EMPTY if not found.
 */
static __forceinline ULONG EptSplitHashLookup(ULONG64 Base2MB)
{
    ULONG Slot = EptSplitHashFn(Base2MB);
    ULONG i;
    for (i = 0; i < EPT_SPLIT_HASH_SIZE; i++) {
        ULONG Idx = (Slot + i) & (EPT_SPLIT_HASH_SIZE - 1);
        if (g_SplitHashTable[Idx].SplitIdx == EPT_SPLIT_HASH_EMPTY)
            return EPT_SPLIT_HASH_EMPTY;  /* Empty slot → not found */
        if (g_SplitHashTable[Idx].Base2MB == Base2MB)
            return g_SplitHashTable[Idx].SplitIdx;
    }
    return EPT_SPLIT_HASH_EMPTY;  /* Table full (shouldn't happen) */
}

/*
 * EptSplitHashInsert - Insert a (Base2MB → splitIdx) mapping.
 */
static __forceinline VOID EptSplitHashInsert(ULONG64 Base2MB, ULONG SplitIdx)
{
    ULONG Slot = EptSplitHashFn(Base2MB);
    ULONG i;
    for (i = 0; i < EPT_SPLIT_HASH_SIZE; i++) {
        ULONG Idx = (Slot + i) & (EPT_SPLIT_HASH_SIZE - 1);
        if (g_SplitHashTable[Idx].SplitIdx == EPT_SPLIT_HASH_EMPTY) {
            g_SplitHashTable[Idx].Base2MB = Base2MB;
            g_SplitHashTable[Idx].SplitIdx = SplitIdx;
            return;
        }
    }
    /* Table full — should never happen with 256 slots and 128 max splits */
}

/*
 * EptHookHashRebuild - Rebuild the hook hash table from scratch.
 *
 * Called after removing a hook entry. Open-addressing hash tables cannot
 * simply mark a slot as empty on deletion (it breaks probe chains), so
 * we rebuild the entire table. This is O(n) but only runs on the
 * unhook path (guest mode, non-hot-path), not on every EPT violation.
 *
 * Must be called with g_EptHookState.Lock held.
 */
static VOID EptHookHashRebuild(VOID)
{
    ULONG i;

    /* Clear all slots */
    for (i = 0; i < EPT_HOOK_HASH_SIZE; i++)
        g_EptHookState.HookHashTable[i] = EPT_HOOK_HASH_EMPTY;

    /* Re-insert all active hooks */
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active) {
            ULONG Slot = EptHookHashFn(g_EptHookState.Hooks[i].TargetPhysicalAddr);
            ULONG j;
            for (j = 0; j < EPT_HOOK_HASH_SIZE; j++) {
                ULONG Idx = (Slot + j) & (EPT_HOOK_HASH_SIZE - 1);
                if (g_EptHookState.HookHashTable[Idx] == EPT_HOOK_HASH_EMPTY) {
                    g_EptHookState.HookHashTable[Idx] = i;
                    break;
                }
            }
        }
    }
}

typedef struct _EPT_PD_PAGE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Entries[EPT_PDE_COUNT];
} EPT_PD_PAGE;

static EPT_PD_PAGE  *g_PdPages = NULL;

/* ========================================================================= */
/*  Internal Helpers                                                         */
/* ========================================================================= */

static ULONG64 VaToPhysical(PVOID Va)
{
    PHYSICAL_ADDRESS Pa = MmGetPhysicalAddress(Va);
    return Pa.QuadPart;
}

/*
 * EptGuestVaToPa - Walk the Guest's page tables to translate a Guest VA
 * to a Guest PA.  Safe to call from VMX root mode (no Windows API dependency).
 *
 * BUG FIX (Issue #4): The original code used MmGetPhysicalAddress() in VMX
 * root mode (HandleEptViolation Mode B path), which is a Windows kernel API
 * that may not be safe to call at arbitrary points in VMX root. This function
 * directly walks the Guest's CR3 page tables using physical memory access
 * through our EPT identity map.
 *
 * Since we have an identity-mapped EPT, Guest Physical Address == Host Physical
 * Address, and kernel VA for low physical memory is accessible. We use
 * MmGetVirtualForPhysical-like logic but operate on the raw page table entries.
 *
 * Parameters:
 *   GuestCr3:       Guest CR3 value (from VMCS)
 *   GuestVa:        Guest virtual address to translate
 *
 * Returns: Guest physical address, or 0 if translation fails.
 */
static ULONG64 EptGuestVaToPa(ULONG64 GuestCr3, ULONG64 GuestVa)
{
    ULONG64 TablePa, Entry;
    PULONG64 TableVa;
    PHYSICAL_ADDRESS PhysAddr;

    /* PML4 */
    TablePa = GuestCr3 & 0x000FFFFFFFFFF000ULL;
    PhysAddr.QuadPart = (LONGLONG)(TablePa + (((GuestVa >> 39) & 0x1FF) * 8));
    TableVa = (PULONG64)MmGetVirtualForPhysical(PhysAddr);
    if (!TableVa) return 0;
    Entry = *TableVa;
    if (!(Entry & 1)) return 0;  /* Not present */

    /* PDPT */
    TablePa = Entry & 0x000FFFFFFFFFF000ULL;
    PhysAddr.QuadPart = (LONGLONG)(TablePa + (((GuestVa >> 30) & 0x1FF) * 8));
    TableVa = (PULONG64)MmGetVirtualForPhysical(PhysAddr);
    if (!TableVa) return 0;
    Entry = *TableVa;
    if (!(Entry & 1)) return 0;
    if (Entry & (1ULL << 7))  /* 1GB page */
        return (Entry & 0x000FFFFFC0000000ULL) | (GuestVa & 0x3FFFFFFF);

    /* PD */
    TablePa = Entry & 0x000FFFFFFFFFF000ULL;
    PhysAddr.QuadPart = (LONGLONG)(TablePa + (((GuestVa >> 21) & 0x1FF) * 8));
    TableVa = (PULONG64)MmGetVirtualForPhysical(PhysAddr);
    if (!TableVa) return 0;
    Entry = *TableVa;
    if (!(Entry & 1)) return 0;
    if (Entry & (1ULL << 7))  /* 2MB page */
        return (Entry & 0x000FFFFFFFE00000ULL) | (GuestVa & 0x1FFFFF);

    /* PT */
    TablePa = Entry & 0x000FFFFFFFFFF000ULL;
    PhysAddr.QuadPart = (LONGLONG)(TablePa + (((GuestVa >> 12) & 0x1FF) * 8));
    TableVa = (PULONG64)MmGetVirtualForPhysical(PhysAddr);
    if (!TableVa) return 0;
    Entry = *TableVa;
    if (!(Entry & 1)) return 0;

    return (Entry & 0x000FFFFFFFFFF000ULL) | (GuestVa & 0xFFF);
}

/* ========================================================================= */
/*  RIP-Relative Instruction Detection and Relocation                        */
/* ========================================================================= */

/*
 * EptIsRipRelativeInstruction - Check if an instruction uses RIP-relative addressing.
 *
 * In x64, ModRM with Mod=00 and RM=101 (5) encodes RIP-relative disp32.
 * Common patterns:
 *   - LEA r, [RIP+disp32]   (0x8D + ModRM)
 *   - MOV r, [RIP+disp32]   (0x8B + ModRM)
 *   - MOV [RIP+disp32], r   (0x89 + ModRM)
 *   - CMP r, [RIP+disp32]   (0x3B + ModRM)
 *   - CALL [RIP+disp32]     (0xFF /2 + ModRM)
 *   - JMP [RIP+disp32]      (0xFF /4 + ModRM)
 *   - 0F xx [RIP+disp32]    (two-byte opcode variants)
 *
 * Returns TRUE if the instruction has RIP-relative addressing, with:
 *   *pDispOffset = byte offset of the disp32 field within the instruction
 *   *pInsnLen    = total instruction length
 *
 * This allows the caller to fix up the displacement when relocating the
 * instruction to a different VA (trampoline).
 */
BOOLEAN EptIsRipRelativeInstruction(
    PUCHAR  Code,
    ULONG   InsnLen,
    PULONG  pDispOffset
)
{
    ULONG Pos = 0;
    UCHAR b;
    BOOLEAN HasRex = FALSE;
    BOOLEAN OperandSize66 = FALSE;
    BOOLEAN IsTwoByte = FALSE;
    UCHAR Opcode;
    UCHAR ModRM;
    UCHAR Mod, RM;
    ULONG ImmSize = 0;

    if (InsnLen == 0) return FALSE;

    /* Skip prefixes */
    for (;;) {
        if (Pos >= InsnLen) return FALSE;
        b = Code[Pos];

        /* Legacy prefixes */
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) {
            Pos++; continue;
        }
        if (b == 0x66) { OperandSize66 = TRUE; Pos++; continue; }
        if (b == 0x67) { Pos++; continue; }

        /* REX prefix */
        if (b >= 0x40 && b <= 0x4F) {
            HasRex = TRUE;
            Pos++;
            break;
        }
        break;
    }

    if (Pos >= InsnLen) return FALSE;
    Opcode = Code[Pos++];

    /* Two-byte opcode */
    if (Opcode == 0x0F) {
        if (Pos >= InsnLen) return FALSE;
        IsTwoByte = TRUE;
        Opcode = Code[Pos++];

        /* Two-byte opcodes with ModRM that may use RIP-relative */
        /* 0F 1F, 0F B6, 0F B7, 0F BE, 0F BF, 0F 40-4F, 0F 90-9F, 0F AF */
        /* 0F 80-8F are Jcc rel32 (no ModRM), skip */
        if (Opcode == 0x1F || Opcode == 0xB6 || Opcode == 0xB7 ||
            Opcode == 0xBE || Opcode == 0xBF || Opcode == 0xAF ||
            Opcode == 0x20 || Opcode == 0x22 ||
            (Opcode >= 0x40 && Opcode <= 0x4F) ||
            (Opcode >= 0x90 && Opcode <= 0x9F)) {
            ImmSize = 0;
            goto check_modrm;
        }
        return FALSE;  /* No ModRM or not a RIP-relative candidate */
    }

    /* One-byte opcodes with ModRM that may use RIP-relative */
    /* ALU ops: 00-03, 08-0B, 10-13, 18-1B, 20-23, 28-2B, 30-33, 38-3B */
    if ((Opcode & 0xC0) == 0x00 && (Opcode & 0x07) <= 0x03) {
        ImmSize = 0;
        goto check_modrm;
    }

    /* Group 1: 80, 81, 83 */
    if (Opcode == 0x80) { ImmSize = 1; goto check_modrm; }
    if (Opcode == 0x81) { ImmSize = OperandSize66 ? 2 : 4; goto check_modrm; }
    if (Opcode == 0x83) { ImmSize = 1; goto check_modrm; }

    /* TEST r/m, r (84/85) */
    if (Opcode == 0x84 || Opcode == 0x85) { ImmSize = 0; goto check_modrm; }

    /* MOV r/m,r / MOV r,r/m (88-8B) */
    if (Opcode >= 0x88 && Opcode <= 0x8B) { ImmSize = 0; goto check_modrm; }

    /* LEA (8D) */
    if (Opcode == 0x8D) { ImmSize = 0; goto check_modrm; }

    /* MOV r/m, imm (C6, C7) */
    if (Opcode == 0xC6) { ImmSize = 1; goto check_modrm; }
    if (Opcode == 0xC7) { ImmSize = OperandSize66 ? 2 : 4; goto check_modrm; }

    /* XCHG r/m, r (86/87) */
    if (Opcode == 0x86 || Opcode == 0x87) { ImmSize = 0; goto check_modrm; }

    /* Group 5: FF */
    if (Opcode == 0xFF) { ImmSize = 0; goto check_modrm; }

    /* Group 3: F6, F7 */
    if (Opcode == 0xF6) {
        if (Pos < InsnLen && (((Code[Pos] >> 3) & 7) == 0))
            ImmSize = 1;
        else
            ImmSize = 0;
        goto check_modrm;
    }
    if (Opcode == 0xF7) {
        if (Pos < InsnLen && (((Code[Pos] >> 3) & 7) == 0))
            ImmSize = OperandSize66 ? 2 : 4;
        else
            ImmSize = 0;
        goto check_modrm;
    }

    /* Shift/rotate: D0-D3, C0, C1 */
    if (Opcode == 0xD0 || Opcode == 0xD1 || Opcode == 0xD2 || Opcode == 0xD3) {
        ImmSize = 0; goto check_modrm;
    }
    if (Opcode == 0xC0 || Opcode == 0xC1) { ImmSize = 1; goto check_modrm; }

    return FALSE;

check_modrm:
    if (Pos >= InsnLen) return FALSE;
    ModRM = Code[Pos];
    Mod = (ModRM >> 6) & 3;
    RM = ModRM & 7;

    /* RIP-relative: Mod=00, RM=101 (and NOT register-direct which is Mod=11) */
    if (Mod == 0 && RM == 5) {
        /* The disp32 starts at Pos+1 (right after ModRM) */
        *pDispOffset = Pos + 1;
        return TRUE;
    }

    return FALSE;
}

/*
 * EptRelocateRipRelativeInstruction - Fix up a RIP-relative instruction
 * that has been copied from OriginalVA to TrampolineVA.
 *
 * The disp32 field is adjusted so the instruction still references
 * the same absolute address from its new location.
 *
 * Returns TRUE on success, FALSE if the offset doesn't fit in 32 bits.
 */
BOOLEAN EptRelocateRipRelativeInstruction(
    PUCHAR  TrampolineInsn,
    ULONG   InsnLen,
    ULONG   DispOffset,
    ULONG64 OriginalVA,
    ULONG64 TrampolineVA
)
{
    LONG    OrigDisp;
    LONG64  OrigTargetAddr;
    LONG64  NewDisp64;

    /* Read the original disp32 */
    OrigDisp = *(PLONG)(TrampolineInsn + DispOffset);

    /* Calculate the absolute target address from the original location.
     * RIP-relative addressing: target = RIP_after_insn + disp32
     * where RIP_after_insn = OriginalVA + InsnLen */
    OrigTargetAddr = (LONG64)(OriginalVA + InsnLen) + OrigDisp;

    /* Calculate what the new disp32 should be from the trampoline location.
     * new_disp = target - (TrampolineVA + InsnLen) */
    NewDisp64 = OrigTargetAddr - (LONG64)(TrampolineVA + InsnLen);

    /* Check if new displacement fits in 32 bits (signed) */
    if (NewDisp64 > 0x7FFFFFFFLL || NewDisp64 < -0x80000000LL) {
        return FALSE;  /* Cannot relocate: target too far away */
    }

    /* Patch the displacement */
    *(PLONG)(TrampolineInsn + DispOffset) = (LONG)NewDisp64;
    return TRUE;
}

/* ========================================================================= */
/*  Minimal x64 Instruction Length Decoder                                   */
/* ========================================================================= */

/*
 * EptGetInstructionLength - Determine the length of a single x86-64 instruction.
 *
 * This is a minimal decoder sufficient for typical function prologues
 * (MOV, PUSH, SUB, LEA, XOR, CMP, TEST, JMP, CALL, NOP, etc.).
 * Returns 0 if the instruction cannot be decoded (unknown/unsupported).
 *
 * We only need to handle the first ~20 bytes of kernel function prologues,
 * which use a very limited subset of the x86-64 ISA.
 */
ULONG EptGetInstructionLength(PUCHAR Code)
{
    ULONG   Pos = 0;
    BOOLEAN HasRex = FALSE;
    BOOLEAN OperandSize66 = FALSE;
    BOOLEAN AddressSize67 = FALSE;
    UCHAR   Rex = 0;
    UCHAR   Opcode;
    UCHAR   ModRM;
    UCHAR   Mod, RM;
    BOOLEAN HasModRM = FALSE;
    ULONG   ImmSize = 0;
    UCHAR   b;
    UCHAR   Op2;
    UCHAR   Group;
    UCHAR   SubOp;
    UCHAR   SIB;
    UCHAR   SibBase;
    UCHAR   EffRM;

    /* Limit: x86-64 instructions are at most 15 bytes */
    #define MAX_INSN_LEN 15

    /* ---- Prefixes ---- */
    for (;;) {
        if (Pos >= MAX_INSN_LEN) return 0;
        b = Code[Pos];

        /* Legacy prefixes */
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||  /* LOCK, REPNZ, REP */
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) {                 /* Segment overrides */
            Pos++;
            continue;
        }
        if (b == 0x66) { OperandSize66 = TRUE; Pos++; continue; }
        if (b == 0x67) { AddressSize67 = TRUE; Pos++; continue; }

        /* REX prefix: 0x40..0x4F */
        if (b >= 0x40 && b <= 0x4F) {
            HasRex = TRUE;
            Rex = b;
            Pos++;
            break;  /* REX must be immediately before opcode */
        }
        break;  /* Not a prefix */
    }

    if (Pos >= MAX_INSN_LEN) return 0;
    Opcode = Code[Pos++];

    /* ---- Two-byte opcode (0F xx) ---- */
    if (Opcode == 0x0F) {
        if (Pos >= MAX_INSN_LEN) return 0;
        Op2 = Code[Pos++];

        /* 0F 80..8F: Jcc rel32 (6 bytes total) */
        if (Op2 >= 0x80 && Op2 <= 0x8F) {
            return Pos + 4;
        }

        /* 0F 1F /0: multi-byte NOP with ModRM */
        if (Op2 == 0x1F) {
            HasModRM = TRUE;
            ImmSize = 0;
            goto decode_modrm;
        }

        /* 0F B6, 0F B7: MOVZX; 0F BE, 0F BF: MOVSX — all have ModRM */
        if (Op2 == 0xB6 || Op2 == 0xB7 || Op2 == 0xBE || Op2 == 0xBF) {
            HasModRM = TRUE;
            ImmSize = 0;
            goto decode_modrm;
        }

        /* 0F 05: SYSCALL (2 bytes) */
        if (Op2 == 0x05) return Pos;

        /* 0F 20, 0F 22: MOV CR,reg / MOV reg,CR - ModRM but no displacement typically */
        if (Op2 == 0x20 || Op2 == 0x22) {
            HasModRM = TRUE;
            ImmSize = 0;
            goto decode_modrm;
        }

        /* 0F 40..4F: CMOVcc - ModRM */
        if (Op2 >= 0x40 && Op2 <= 0x4F) {
            HasModRM = TRUE;
            ImmSize = 0;
            goto decode_modrm;
        }

        /* 0F 90..9F: SETcc - ModRM */
        if (Op2 >= 0x90 && Op2 <= 0x9F) {
            HasModRM = TRUE;
            ImmSize = 0;
            goto decode_modrm;
        }

        /* 0F AF: IMUL r, r/m - ModRM */
        if (Op2 == 0xAF) {
            HasModRM = TRUE;
            ImmSize = 0;
            goto decode_modrm;
        }

        /* Unrecognized two-byte opcode */
        return 0;
    }

    /* ---- One-byte opcodes ---- */

    /* NOP (0x90) */
    if (Opcode == 0x90) return Pos;

    /* RET near (0xC3) */
    if (Opcode == 0xC3) return Pos;

    /* RET near with imm16 (0xC2) */
    if (Opcode == 0xC2) return Pos + 2;

    /* INT3 (0xCC) */
    if (Opcode == 0xCC) return Pos;

    /* INT imm8 (0xCD) */
    if (Opcode == 0xCD) return Pos + 1;

    /* PUSH reg (50+r) / POP reg (58+r) */
    if ((Opcode >= 0x50 && Opcode <= 0x57) ||
        (Opcode >= 0x58 && Opcode <= 0x5F)) {
        return Pos;
    }

    /* MOV reg, imm32/64 (B8+r): 32-bit default, 64-bit with REX.W */
    if (Opcode >= 0xB8 && Opcode <= 0xBF) {
        if (HasRex && (Rex & 0x08)) {
            return Pos + 8;  /* REX.W → MOV reg, imm64 */
        }
        return Pos + 4;     /* MOV reg, imm32 */
    }

    /* MOV reg, imm8 (B0+r) */
    if (Opcode >= 0xB0 && Opcode <= 0xB7) {
        return Pos + 1;
    }

    /* Short JMP rel8 (0xEB) */
    if (Opcode == 0xEB) return Pos + 1;

    /* Short Jcc rel8 (0x70..0x7F) */
    if (Opcode >= 0x70 && Opcode <= 0x7F) return Pos + 1;

    /* CALL rel32 (0xE8), JMP rel32 (0xE9) */
    if (Opcode == 0xE8 || Opcode == 0xE9) return Pos + 4;

    /* PUSH imm8 (0x6A) */
    if (Opcode == 0x6A) return Pos + 1;

    /* PUSH imm32 (0x68) */
    if (Opcode == 0x68) return Pos + 4;

    /* 
     * ALU ops with ModRM: ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
     * 00..05 (ADD), 08..0D (OR), 10..15 (ADC), 18..1D (SBB),
     * 20..25 (AND), 28..2D (SUB), 30..35 (XOR), 38..3D (CMP)
     */
    {
        Group = Opcode & 0xFE;  /* Strip direction bit for grouping */
        /* Check if in ALU range: 0x00-0x05, 0x08-0x0D, 0x10-0x15, etc. */
        if ((Opcode & 0xC0) == 0x00 && (Opcode & 0x07) <= 0x05 && ((Opcode >> 3) & 7) <= 7) {
            SubOp = Opcode & 0x07;
            if (SubOp <= 3) {
                /* r/m, r  or  r, r/m  (with ModRM, no immediate) */
                HasModRM = TRUE;
                ImmSize = 0;
                goto decode_modrm;
            } else if (SubOp == 4) {
                /* AL, imm8 */
                return Pos + 1;
            } else if (SubOp == 5) {
                /* rAX, imm32 */
                return Pos + 4;
            }
        }
    }

    /* Group 1: 80/81/83 with ModRM + imm */
    if (Opcode == 0x80) { HasModRM = TRUE; ImmSize = 1; goto decode_modrm; }
    if (Opcode == 0x81) { HasModRM = TRUE; ImmSize = OperandSize66 ? 2 : 4; goto decode_modrm; }
    if (Opcode == 0x83) { HasModRM = TRUE; ImmSize = 1; goto decode_modrm; }

    /* TEST r/m8, r8 (0x84); TEST r/m, r (0x85) */
    if (Opcode == 0x84 || Opcode == 0x85) {
        HasModRM = TRUE; ImmSize = 0; goto decode_modrm;
    }

    /* MOV r/m, r (0x88/0x89); MOV r, r/m (0x8A/0x8B) */
    if (Opcode >= 0x88 && Opcode <= 0x8B) {
        HasModRM = TRUE; ImmSize = 0; goto decode_modrm;
    }

    /* LEA r, m (0x8D) */
    if (Opcode == 0x8D) {
        HasModRM = TRUE; ImmSize = 0; goto decode_modrm;
    }

    /* MOV r/m, imm (0xC6 = byte, 0xC7 = dword) */
    if (Opcode == 0xC6) { HasModRM = TRUE; ImmSize = 1; goto decode_modrm; }
    if (Opcode == 0xC7) {
        HasModRM = TRUE;
        ImmSize = OperandSize66 ? 2 : 4;
        goto decode_modrm;
    }

    /* XCHG r/m, r (0x86/0x87) */
    if (Opcode == 0x86 || Opcode == 0x87) {
        HasModRM = TRUE; ImmSize = 0; goto decode_modrm;
    }

    /* Group 5: FF /0..6 (INC/DEC/CALL/JMP/PUSH) */
    if (Opcode == 0xFF) {
        HasModRM = TRUE; ImmSize = 0; goto decode_modrm;
    }

    /* Group 3: F6 (byte) / F7 (dword) - TEST/NOT/NEG/MUL/DIV */
    if (Opcode == 0xF6) {
        /* F6 /0 has imm8, others don't */
        if (Pos >= MAX_INSN_LEN) return 0;
        ModRM = Code[Pos];
        if (((ModRM >> 3) & 7) == 0) { /* TEST r/m8, imm8 */
            HasModRM = TRUE; ImmSize = 1; goto decode_modrm;
        }
        HasModRM = TRUE; ImmSize = 0; goto decode_modrm;
    }
    if (Opcode == 0xF7) {
        if (Pos >= MAX_INSN_LEN) return 0;
        ModRM = Code[Pos];
        if (((ModRM >> 3) & 7) == 0) { /* TEST r/m, imm32 */
            HasModRM = TRUE; ImmSize = OperandSize66 ? 2 : 4; goto decode_modrm;
        }
        HasModRM = TRUE; ImmSize = 0; goto decode_modrm;
    }

    /* Shift/rotate group: D0/D1/D2/D3/C0/C1 */
    if (Opcode == 0xD0 || Opcode == 0xD1 || Opcode == 0xD2 || Opcode == 0xD3) {
        HasModRM = TRUE; ImmSize = 0; goto decode_modrm;
    }
    if (Opcode == 0xC0) { HasModRM = TRUE; ImmSize = 1; goto decode_modrm; }
    if (Opcode == 0xC1) { HasModRM = TRUE; ImmSize = 1; goto decode_modrm; }

    /* MOVS/STOS/etc. string ops (single byte) */
    if (Opcode == 0xA4 || Opcode == 0xA5 ||  /* MOVS */
        Opcode == 0xAA || Opcode == 0xAB ||  /* STOS */
        Opcode == 0xAC || Opcode == 0xAD ||  /* LODS */
        Opcode == 0xA6 || Opcode == 0xA7 ||  /* CMPS */
        Opcode == 0xAE || Opcode == 0xAF) {  /* SCAS */
        return Pos;
    }

    /* TEST AL, imm8 (0xA8); TEST rAX, imm32 (0xA9) */
    if (Opcode == 0xA8) return Pos + 1;
    if (Opcode == 0xA9) return Pos + (OperandSize66 ? 2 : 4);

    /* LEAVE (0xC9) */
    if (Opcode == 0xC9) return Pos;

    /* CLC/STC/CLI/STI/CLD/STD */
    if (Opcode == 0xF8 || Opcode == 0xF9 || Opcode == 0xFA ||
        Opcode == 0xFB || Opcode == 0xFC || Opcode == 0xFD) {
        return Pos;
    }

    /* XCHG rAX, r (91..97) */
    if (Opcode >= 0x91 && Opcode <= 0x97) return Pos;

    /* CDQ/CQO (0x99), CBW/CWDE/CDQE (0x98) */
    if (Opcode == 0x98 || Opcode == 0x99) return Pos;

    /* Unknown opcode */
    return 0;

decode_modrm:
    /* ---- Decode ModRM ---- */
    if (Pos >= MAX_INSN_LEN) return 0;
    ModRM = Code[Pos++];
    Mod = (ModRM >> 6) & 3;
    RM  = ModRM & 7;

    /* In 64-bit mode, check if REX.B extends RM */
    {
        EffRM = RM;

        if (Mod == 3) {
            /* Register direct - no displacement, no SIB */
            return Pos + ImmSize;
        }

        /* SIB byte present if RM == 4 (and Mod != 3) */
        if (RM == 4) {
            if (Pos >= MAX_INSN_LEN) return 0;
            SIB = Code[Pos++];
            SibBase = SIB & 7;

            /* SIB base == 5 with Mod == 0 → disp32 (no base register) */
            if (Mod == 0 && SibBase == 5) {
                return Pos + 4 + ImmSize;
            }
        }

        if (Mod == 0) {
            /* RIP-relative: RM == 5, Mod == 0 → disp32 */
            if (RM == 5) {
                return Pos + 4 + ImmSize;
            }
            /* No displacement */
            return Pos + ImmSize;
        }

        if (Mod == 1) {
            /* disp8 */
            return Pos + 1 + ImmSize;
        }

        if (Mod == 2) {
            /* disp32 */
            return Pos + 4 + ImmSize;
        }
    }

    return 0;  /* Should not reach here */

    #undef MAX_INSN_LEN
}

/* ========================================================================= */
/*  EPT Identity Map Setup                                                   */
/* ========================================================================= */

NTSTATUS EptInitialize(VOID)
{
    ULONG i, j;
    ULONG64 PhysAddr;
    ULONG64 PdptPa;

    if (g_EptState.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_EptState, sizeof(EPT_STATE));
    RtlZeroMemory(&g_EptHookState, sizeof(EPT_HOOK_STATE));
    KeInitializeSpinLock(&g_EptHookState.Lock);

    /*
     * BUG FIX (Issue #3+5+6): Initialize hash tables for O(1) lookups.
     * Hook hash table: fill with EPT_HOOK_HASH_EMPTY sentinel.
     * Split page hash table: fill with EPT_SPLIT_HASH_EMPTY sentinel.
     */
    {
        ULONG htIdx;
        for (htIdx = 0; htIdx < EPT_HOOK_HASH_SIZE; htIdx++)
            g_EptHookState.HookHashTable[htIdx] = EPT_HOOK_HASH_EMPTY;
        for (htIdx = 0; htIdx < EPT_SPLIT_HASH_SIZE; htIdx++)
            g_SplitHashTable[htIdx].SplitIdx = EPT_SPLIT_HASH_EMPTY;
    }

    /* Allocate per-CPU tracking arrays (dynamic based on g_MaxProcessors) */
    if (g_MaxProcessors > 0) {
        g_EptInveptCpuGen = (PLONG)ExAllocatePoolWithTag(
            NonPagedPool, g_MaxProcessors * sizeof(LONG), 'tpeC');
        g_MtfRelaxedPagePa = (volatile ULONG64 *)ExAllocatePoolWithTag(
            NonPagedPool, g_MaxProcessors * sizeof(ULONG64), 'tpeM');

        if (!g_EptInveptCpuGen || !g_MtfRelaxedPagePa) {
            LOG_ERROR("Failed to allocate EPT per-CPU tracking arrays");
            if (g_EptInveptCpuGen) { ExFreePoolWithTag(g_EptInveptCpuGen, 'tpeC'); g_EptInveptCpuGen = NULL; }
            if (g_MtfRelaxedPagePa) { ExFreePoolWithTag((PVOID)g_MtfRelaxedPagePa, 'tpeM'); g_MtfRelaxedPagePa = NULL; }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(g_EptInveptCpuGen, g_MaxProcessors * sizeof(LONG));
        RtlZeroMemory((PVOID)g_MtfRelaxedPagePa, g_MaxProcessors * sizeof(ULONG64));
    }

    /*
     * Detect Execute-Only EPT support (IA32_VMX_EPT_VPID_CAP bit 0).
     * Many nested hypervisors (VMware, Hyper-V) do NOT expose this bit,
     * which means R=0,W=0,X=1 causes EPT Misconfiguration instead of
     * working as an execute-only page.  When unsupported, we fall back
     * to R=1,W=0,X=1 (read+execute) for hook pages.
     */
    {
        ULONG64 EptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
        g_EptHookState.ExecuteOnlySupported = (EptVpidCap & 1) != 0;

        LOG_INFO("EPT Execute-Only pages: %s",
                 g_EptHookState.ExecuteOnlySupported ? "supported" : "NOT supported (fallback to R+X)");
    }

    /*
     * Allocate Page Directory pages.
     * We map the first 512GB using 2MB large pages (512 PDs * 512 entries * 2MB = 512GB).
     */
    g_PdPages = (EPT_PD_PAGE *)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(EPT_PD_PAGE) * MAX_PD_PAGES,
        VMX_TAG
    );
    if (!g_PdPages) {
        LOG_ERROR("Failed to allocate EPT page directory pages");
        /*
         * BUG FIX (Review Issue #4): Free per-CPU tracking arrays on failure.
         * Previously leaked g_EptInveptCpuGen and g_MtfRelaxedPagePa.
         */
        if (g_EptInveptCpuGen) { ExFreePoolWithTag(g_EptInveptCpuGen, 'tpeC'); g_EptInveptCpuGen = NULL; }
        if (g_MtfRelaxedPagePa) { ExFreePoolWithTag((PVOID)g_MtfRelaxedPagePa, 'tpeM'); g_MtfRelaxedPagePa = NULL; }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_PdPages, sizeof(EPT_PD_PAGE) * MAX_PD_PAGES);

    /* Allocate split page pool */
    g_SplitPages = (EPT_SPLIT_PAGE *)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(EPT_SPLIT_PAGE) * MAX_SPLIT_PAGES,
        VMX_TAG
    );
    if (!g_SplitPages) {
        LOG_ERROR("Failed to allocate EPT split page pool");
        ExFreePoolWithTag(g_PdPages, VMX_TAG);
        if (g_EptInveptCpuGen) { ExFreePoolWithTag(g_EptInveptCpuGen, 'tpeC'); g_EptInveptCpuGen = NULL; }
        if (g_MtfRelaxedPagePa) { ExFreePoolWithTag((PVOID)g_MtfRelaxedPagePa, 'tpeM'); g_MtfRelaxedPagePa = NULL; }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_SplitPages, sizeof(EPT_SPLIT_PAGE) * MAX_SPLIT_PAGES);

    /*
     * Build identity-mapped EPT using 2MB large pages.
     *
     * PML4 -> PDPT -> PD (2MB entries)
     *
     * We map the first 512GB of physical address space.
     */

    /* Setup PDPT entries - each points to a PD page */
    for (i = 0; i < MAX_PD_PAGES && i < EPT_PDPTE_COUNT; i++) {
        ULONG64 PdPa = VaToPhysical(&g_PdPages[i]);

        g_EptState.Pdpt[i].Value = 0;
        g_EptState.Pdpt[i].Read = 1;
        g_EptState.Pdpt[i].Write = 1;
        g_EptState.Pdpt[i].Execute = 1;
        g_EptState.Pdpt[i].PhysAddr = PdPa >> 12;

        /* Setup PD entries - each is a 2MB large page */
        for (j = 0; j < EPT_PDE_COUNT; j++) {
            PhysAddr = ((ULONG64)i * 512 + j) * (2 * 1024 * 1024); /* 2MB per entry */

            g_PdPages[i].Entries[j].Value = 0;
            g_PdPages[i].Entries[j].Read = 1;
            g_PdPages[i].Entries[j].Write = 1;
            g_PdPages[i].Entries[j].Execute = 1;
            g_PdPages[i].Entries[j].LargePage = 1;  /* 2MB page */
            g_PdPages[i].Entries[j].PhysAddr = PhysAddr >> 12;
        }
    }

    /* Setup PML4[0] to point to our PDPT */
    PdptPa = VaToPhysical(g_EptState.Pdpt);
    g_EptState.Pml4[0].Value = 0;
    g_EptState.Pml4[0].Read = 1;
    g_EptState.Pml4[0].Write = 1;
    g_EptState.Pml4[0].Execute = 1;
    g_EptState.Pml4[0].PhysAddr = PdptPa >> 12;

    /* Store PML4 physical address */
    g_EptState.Pml4Pa = VaToPhysical(g_EptState.Pml4);

    /* Build EPTP */
    g_EptState.Eptp.Value = 0;
    g_EptState.Eptp.MemoryType = EPT_MEMORY_TYPE_WB;
    g_EptState.Eptp.PageWalkLength = EPT_PAGE_WALK_LENGTH_4;
    g_EptState.Eptp.DirtyAccess = 0; /* Can enable if supported */
    g_EptState.Eptp.Pml4PhysAddr = g_EptState.Pml4Pa >> 12;

    g_EptState.Initialized = TRUE;
    g_EptHookState.Initialized = TRUE;

    LOG_INFO("EPT initialized: identity map for 512GB, EPTP=0x%llX", g_EptState.Eptp.Value);
    return STATUS_SUCCESS;
}

VOID EptCleanup(VOID)
{
    /* Unhook everything first */
    EptUnhookAll();

    if (g_SplitPages) {
        ExFreePoolWithTag(g_SplitPages, VMX_TAG);
        g_SplitPages = NULL;
    }

    /*
     * BUG FIX: Reset split hash table after freeing split pages.
     * If the driver is re-initialized without a full reload, stale hash
     * entries would point to freed memory, causing dangling pointer lookups.
     */
    {
        ULONG htIdx;
        for (htIdx = 0; htIdx < EPT_SPLIT_HASH_SIZE; htIdx++)
            g_SplitHashTable[htIdx].SplitIdx = EPT_SPLIT_HASH_EMPTY;
    }
    if (g_PdPages) {
        ExFreePoolWithTag(g_PdPages, VMX_TAG);
        g_PdPages = NULL;
    }

    /* Free per-CPU tracking arrays */
    if (g_EptInveptCpuGen) {
        ExFreePoolWithTag(g_EptInveptCpuGen, 'tpeC');
        g_EptInveptCpuGen = NULL;
    }
    if (g_MtfRelaxedPagePa) {
        ExFreePoolWithTag((PVOID)g_MtfRelaxedPagePa, 'tpeM');
        g_MtfRelaxedPagePa = NULL;
    }

    g_EptState.Initialized = FALSE;
    g_EptHookState.Initialized = FALSE;

    LOG_INFO("EPT cleaned up");
}

/*
 * Set up EPT for a specific CPU's VMCS
 */
NTSTATUS EptSetupIdentityMap(struct _VMX_CPU_CONTEXT *CpuCtx, struct _VMX_STATE *State)
{
    ULONG CpuNum;

    UNREFERENCED_PARAMETER(State);

    if (!g_EptState.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    CpuNum = CpuCtx->ProcessorNumber;

    /* Use per-CPU EPTP if available, otherwise fall back to shared */
    if (g_EptCpuStates && CpuNum < g_MaxProcessors) {
        VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptCpuStates[CpuNum].Eptp.Value);
    } else {
        VmxWrite(VMCS_CTRL_EPT_POINTER, g_EptState.Eptp.Value);
    }

    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  2MB -> 4KB Page Splitting                                                */
/* ========================================================================= */

/*
 * Split a 2MB large page into 512 4KB pages.
 * Required for fine-grained EPT permission control (hooks).
 */
VOID EptSplitLargePage(ULONG64 PhysicalAddress)
{
    ULONG64     Base2MB;
    ULONG       PdptIndex, PdIndex;
    PEPT_PDE    TargetPde;
    PEPT_SPLIT_PAGE SplitPage = NULL;
    ULONG       i;
    ULONG       splitIdx = (ULONG)-1;  /* saved split page index for hash table */

    /* Align to 2MB boundary */
    Base2MB = PhysicalAddress & ~((2ULL * 1024 * 1024) - 1);

    /* Calculate indices */
    PdptIndex = (ULONG)((Base2MB >> 30) & 0x1FF);   /* 1GB per PDPT entry */
    PdIndex   = (ULONG)((Base2MB >> 21) & 0x1FF);   /* 2MB per PD entry */

    if (PdptIndex >= MAX_PD_PAGES) {
        LOG_ERROR("EPT split: address 0x%llX is beyond mapped range", PhysicalAddress);
        return;
    }

    TargetPde = &g_PdPages[PdptIndex].Entries[PdIndex];

    /* Check if already split */
    if (!TargetPde->LargePage) {
        LOG_DEBUG("EPT: 2MB page at 0x%llX already split", Base2MB);
        return;
    }

    /* Find a free split page */
    for (i = 0; i < MAX_SPLIT_PAGES; i++) {
        if (!g_SplitPages[i].InUse) {
            SplitPage = &g_SplitPages[i];
            splitIdx = i;
            break;
        }
    }

    if (!SplitPage) {
        LOG_ERROR("EPT split: no free split pages available");
        return;
    }

    /* Initialize 512 PTEs mapping the same 2MB region as 4KB pages */
    for (i = 0; i < EPT_PTE_COUNT; i++) {
        ULONG64 PagePa = Base2MB + (ULONG64)i * PAGE_SIZE;

        SplitPage->Pte[i].Value = 0;
        SplitPage->Pte[i].Read = 1;
        SplitPage->Pte[i].Write = 1;
        SplitPage->Pte[i].Execute = 1;
        SplitPage->Pte[i].MemoryType = EPT_MEMORY_TYPE_WB;
        SplitPage->Pte[i].PhysAddr = PagePa >> 12;
    }

    SplitPage->PhysicalAddress = VaToPhysical(SplitPage->Pte);
    SplitPage->BasePhysAddr2MB = Base2MB;
    SplitPage->InUse = TRUE;
    g_SplitPageCount++;

    /*
     * BUG FIX (Issue #3+5+6): Insert into split page hash table for O(1)
     * lookup by Base2MB in EptGetPteForPhysicalAddress / EptGetPerCpuPte.
     */
    EptSplitHashInsert(Base2MB, splitIdx);

    /* Update PDE: change from 2MB large page to pointer to PT */
    TargetPde->Value = 0;
    TargetPde->Read = 1;
    TargetPde->Write = 1;
    TargetPde->Execute = 1;
    TargetPde->LargePage = 0;   /* No longer a large page */
    TargetPde->PhysAddr = SplitPage->PhysicalAddress >> 12;

    LOG_INFO("EPT: Split 2MB page at 0x%llX into 4KB pages", Base2MB);
}

/* ========================================================================= */
/*  EPT PTE Lookup                                                           */
/* ========================================================================= */

PEPT_PTE EptGetPteForPhysicalAddress(ULONG64 PhysicalAddress)
{
    ULONG64     Base2MB;
    ULONG       PdptIndex, PdIndex, PtIndex;
    PEPT_PDE    Pde;
    ULONG       splitIdx;

    Base2MB = PhysicalAddress & ~((2ULL * 1024 * 1024) - 1);
    PdptIndex = (ULONG)((PhysicalAddress >> 30) & 0x1FF);
    PdIndex   = (ULONG)((PhysicalAddress >> 21) & 0x1FF);
    PtIndex   = (ULONG)((PhysicalAddress >> 12) & 0x1FF);

    if (PdptIndex >= MAX_PD_PAGES) {
        return NULL;
    }

    Pde = &g_PdPages[PdptIndex].Entries[PdIndex];

    /* If it's still a 2MB page, we need to split first */
    if (Pde->LargePage) {
        return NULL;  /* Caller should split first */
    }

    /*
     * BUG FIX (Issue #3+5+6): O(1) hash table lookup instead of O(n) scan.
     * The old code linearly scanned all MAX_SPLIT_PAGES (128) entries.
     */
    splitIdx = EptSplitHashLookup(Base2MB);
    if (splitIdx != EPT_SPLIT_HASH_EMPTY && splitIdx < MAX_SPLIT_PAGES) {
        return &g_SplitPages[splitIdx].Pte[PtIndex];
    }

    return NULL;
}

/* ========================================================================= */
/*  EPT Hook Engine                                                          */
/* ========================================================================= */

/*
 * Install an EPT hook on a function.
 *
 * This works by:
 * 1. Splitting the 2MB page containing the target into 4KB pages
 * 2. Creating a "hook page" - copy of original page with a JMP at the hook point
 * 3. Setting the EPT PTE to Execute-Only pointing to hook page
 * 4. Reads/writes see original page, execution sees hook page
 *
 * TargetVa:          Virtual address of the function to hook (kernel VA)
 * HookFunction:      Our replacement function
 * OriginalFunction:  [out] Pointer to trampoline for calling original
 */
NTSTATUS EptHookFunction(ULONG64 TargetVa, PVOID HookFunction, PVOID *OriginalFunction)
{
    KIRQL               OldIrql;
    PEPT_HOOK_ENTRY     Hook = NULL;
    PEPT_HOOK_ENTRY     PageOwner = NULL;
    ULONG64             TargetPa;
    ULONG64             PageBase;
    ULONG               PageOffset;
    PEPT_PTE            Pte;
    PHYSICAL_ADDRESS    PhysAddr;
    ULONG               i;
    PVOID               TargetPageVa;
    PUCHAR              HookPoint;
    PUCHAR              Trampoline;

    if (!g_EptHookState.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    /* Translate target VA to PA */
    PhysAddr = MmGetPhysicalAddress((PVOID)TargetVa);
    TargetPa = PhysAddr.QuadPart;

    if (TargetPa == 0) {
        LOG_ERROR("EPT Hook: Failed to get PA for VA 0x%llX", TargetVa);
        return STATUS_INVALID_ADDRESS;
    }

    PageBase = TargetPa & PAGE_MASK_4KB;
    PageOffset = (ULONG)(TargetPa & 0xFFF);

    KeAcquireSpinLock(&g_EptHookState.Lock, &OldIrql);

    /* Check for duplicate hook */
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active &&
            g_EptHookState.Hooks[i].TargetVirtualAddr == TargetVa) {
            KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
            LOG_WARN("EPT Hook: Already hooked at VA 0x%llX", TargetVa);
            return STATUS_ALREADY_REGISTERED;
        }
    }

    /*
     * Check if another hook already exists on the same physical page.
     * If so, we share its HookPage and OriginalPage instead of allocating new ones.
     */
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (g_EptHookState.Hooks[i].Active &&
            g_EptHookState.Hooks[i].TargetPhysicalAddr == PageBase &&
            g_EptHookState.Hooks[i].OwnsPages)
        {
            PageOwner = &g_EptHookState.Hooks[i];
            break;
        }
    }

    /* Find free hook slot */
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        if (!g_EptHookState.Hooks[i].Active) {
            Hook = &g_EptHookState.Hooks[i];
            break;
        }
    }

    if (!Hook) {
        KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
        LOG_ERROR("EPT Hook: No free hook slots");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Split the 2MB page to 4KB if needed */
    EptSplitLargePage(TargetPa);

    /*
     * BUG FIX: After splitting a 2MB page into 4KB pages, other CPUs may
     * still have stale TLB entries pointing to the old 2MB PDE.  If they
     * access memory in this range before seeing the new 4KB PTEs, the CPU
     * will detect an EPT Misconfiguration (the old PDE format doesn't match
     * the new PT) and trigger HandleEptMisconfig → VMX shutdown → BSOD.
     *
     * Fix: Invalidate EPT TLB immediately after page split so all CPUs
     * pick up the new page table structure before any further accesses.
     */
    EptInvalidateFromGuest();

    /* Get the PTE for this specific 4KB page */
    Pte = EptGetPteForPhysicalAddress(TargetPa);
    if (!Pte) {
        KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
        LOG_ERROR("EPT Hook: Failed to get PTE for PA 0x%llX", TargetPa);
        return STATUS_UNSUCCESSFUL;
    }

    if (PageOwner) {
        /*
         * Shared page path: another hook already owns the pages for this
         * physical page. Reuse its HookPage/OriginalPage and just add
         * our JMP patch at our offset.
         */
        Hook->OriginalPageVa = PageOwner->OriginalPageVa;
        Hook->HookPageVa     = PageOwner->HookPageVa;
        Hook->HookPagePa     = PageOwner->HookPagePa;
        Hook->OwnsPages       = FALSE;
    } else {
        /*
         * First hook on this page: allocate fresh copies.
         */
        Hook->OriginalPageVa = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, VMX_TAG);
        if (!Hook->OriginalPageVa) {
            KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Hook->HookPageVa = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, VMX_TAG);
        if (!Hook->HookPageVa) {
            ExFreePoolWithTag(Hook->OriginalPageVa, VMX_TAG);
            KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /*
         * Copy the original page content.
         * Both OriginalPage (for EPT R/W violations) and HookPage (base for patches)
         * start as copies of the original code page.
         */
        TargetPageVa = (PVOID)(TargetVa & PAGE_MASK_4KB);
        RtlCopyMemory(Hook->OriginalPageVa, TargetPageVa, PAGE_SIZE);
        RtlCopyMemory(Hook->HookPageVa, TargetPageVa, PAGE_SIZE);

        Hook->HookPagePa = VaToPhysical(Hook->HookPageVa);
        Hook->OwnsPages   = TRUE;
    }

    /* Allocate trampoline (always per-hook, not shared) */
    Hook->TrampolineVa = ExAllocatePoolWithTag(NonPagedPool, EPT_TRAMPOLINE_SIZE, VMX_TAG);
    if (!Hook->TrampolineVa) {
        if (Hook->OwnsPages) {
            ExFreePoolWithTag(Hook->HookPageVa, VMX_TAG);
            ExFreePoolWithTag(Hook->OriginalPageVa, VMX_TAG);
        }
        KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /*
     * Save original bytes at hook point.
     * We need at least 12 bytes for our JMP (48 B8 [imm64] FF E0).
     * However, we must NOT cut an instruction in half — that would
     * cause the trampoline to execute a truncated instruction → #UD → BSOD.
     *
     * Use a simple x64 instruction length decoder to find the minimum
     * number of complete instructions that cover >= 12 bytes.
     */
    {
        ULONG TotalLen = 0;
        PUCHAR Code = (PUCHAR)TargetVa;
        while (TotalLen < 12) {
            ULONG InsnLen = EptGetInstructionLength(Code + TotalLen);
            if (InsnLen == 0) {
                /* Unknown instruction — bail out with safe default */
                LOG_ERROR("EPT Hook: Cannot decode instruction at VA 0x%llX + 0x%X",
                          TargetVa, TotalLen);
                if (Hook->OwnsPages) {
                    ExFreePoolWithTag(Hook->HookPageVa, VMX_TAG);
                    ExFreePoolWithTag(Hook->OriginalPageVa, VMX_TAG);
                }
                ExFreePoolWithTag(Hook->TrampolineVa, VMX_TAG);
                KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
                return STATUS_UNSUCCESSFUL;
            }
            if (TotalLen + InsnLen > sizeof(((EPT_HOOK_ENTRY*)0)->OriginalBytes)) {
                /*
                 * Next instruction would overflow OriginalBytes buffer.
                 * This means the function prologue has unusually long
                 * instructions — refuse to hook rather than corrupt memory.
                 */
                LOG_ERROR("EPT Hook: OriginalBytes overflow at VA 0x%llX "
                          "(TotalLen=%u + InsnLen=%u > %u)",
                          TargetVa, TotalLen, InsnLen,
                          (ULONG)sizeof(((EPT_HOOK_ENTRY*)0)->OriginalBytes));
                if (Hook->OwnsPages) {
                    ExFreePoolWithTag(Hook->HookPageVa, VMX_TAG);
                    ExFreePoolWithTag(Hook->OriginalPageVa, VMX_TAG);
                }
                ExFreePoolWithTag(Hook->TrampolineVa, VMX_TAG);
                KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
                return STATUS_BUFFER_TOO_SMALL;
            }
            TotalLen += InsnLen;
        }
        Hook->OriginalBytesSize = TotalLen;
    }
    RtlCopyMemory(Hook->OriginalBytes, (PVOID)TargetVa, Hook->OriginalBytesSize);

    /*
     * Patch the shared HookPage at our offset with a JMP to our hook function.
     * Using: 48 B8 [imm64] + FF E0  (MOV RAX, imm64; JMP RAX)
     * This is a 12-byte absolute JMP that encodes the target as an immediate,
     * avoiding any data read from the page.  The old FF 25 encoding performed
     * a RIP-relative memory read of the 8-byte target address, which caused an
     * EPT violation on execute-only pages (R=0,W=0,X=1) and resulted in an
     * infinite EPT-violation loop where the hook never fired.
     *
     * Clobbering RAX is safe: we are at function entry, RAX is volatile, and
     * the hook dispatcher does not depend on RAX's incoming value.
     *
     * Because the HookPage is shared, each hook on the same page accumulates
     * its JMP patch at a different offset — they don't overwrite each other.
     */
    HookPoint = (PUCHAR)Hook->HookPageVa + PageOffset;
    HookPoint[0] = 0x48;                                /* REX.W prefix       */
    HookPoint[1] = 0xB8;                                /* MOV RAX, imm64     */
    *(PULONG64)(HookPoint + 2) = (ULONG64)HookFunction; /* 8-byte immediate   */
    HookPoint[10] = 0xFF;                               /* JMP RAX            */
    HookPoint[11] = 0xE0;

    /*
     * Build trampoline: original bytes + JMP back to (Target + OriginalBytesSize)
     *
     * BUG FIX (Issue #2): After copying original bytes to the trampoline,
     * scan each instruction for RIP-relative addressing (ModRM Mod=00 RM=101).
     * If found, fix up the disp32 so it still points to the original target
     * from the trampoline's different VA.  If relocation fails (target too far),
     * refuse to hook rather than execute broken instructions.
     */
    Trampoline = (PUCHAR)Hook->TrampolineVa;
    RtlCopyMemory(Trampoline, Hook->OriginalBytes, Hook->OriginalBytesSize);

    /* Relocate RIP-relative instructions in trampoline */
    {
        ULONG TrampolineOffset = 0;
        ULONG64 TrampolineBaseVa = (ULONG64)Hook->TrampolineVa;
        while (TrampolineOffset < Hook->OriginalBytesSize) {
            ULONG InsnLen = EptGetInstructionLength(Trampoline + TrampolineOffset);
            if (InsnLen == 0) break;  /* Already validated above, shouldn't happen */

            {
                ULONG DispOffset = 0;
                if (EptIsRipRelativeInstruction(Trampoline + TrampolineOffset, InsnLen, &DispOffset)) {
                    ULONG64 OrigInsnVa = TargetVa + TrampolineOffset;
                    ULONG64 TrampolineInsnVa = TrampolineBaseVa + TrampolineOffset;

                    if (!EptRelocateRipRelativeInstruction(
                            Trampoline + TrampolineOffset,
                            InsnLen, DispOffset,
                            OrigInsnVa, TrampolineInsnVa)) {
                        LOG_ERROR("EPT Hook: RIP-relative relocation failed at VA 0x%llX "
                                  "(trampoline too far from target)", OrigInsnVa);
                        if (Hook->OwnsPages) {
                            ExFreePoolWithTag(Hook->HookPageVa, VMX_TAG);
                            ExFreePoolWithTag(Hook->OriginalPageVa, VMX_TAG);
                        }
                        ExFreePoolWithTag(Hook->TrampolineVa, VMX_TAG);
                        KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
                        return STATUS_UNSUCCESSFUL;
                    }
                    LOG_DEBUG("EPT Hook: Relocated RIP-relative insn at VA 0x%llX +%u (disp offset %u)",
                              TargetVa, TrampolineOffset, DispOffset);
                }
            }
            TrampolineOffset += InsnLen;
        }
    }

    Trampoline[Hook->OriginalBytesSize + 0] = 0xFF;
    Trampoline[Hook->OriginalBytesSize + 1] = 0x25;
    *(PULONG)(Trampoline + Hook->OriginalBytesSize + 2) = 0;
    *(PULONG64)(Trampoline + Hook->OriginalBytesSize + 6) = TargetVa + Hook->OriginalBytesSize;

    /* Fill in hook entry */
    Hook->TargetVirtualAddr = TargetVa;
    Hook->TargetPhysicalAddr = PageBase;
    Hook->TargetPageOffset = PageOffset;
    Hook->HookFunction = HookFunction;
    Hook->TargetPte = Pte;
    Hook->Active = TRUE;
    g_EptHookState.HookCount++;

    /*
     * BUG FIX (Issue #3+5+6): Insert into hook hash table for O(1) lookup.
     * We use the hook array index (Hook - &Hooks[0]) as the value.
     */
    {
        ULONG hookArrayIdx = (ULONG)(Hook - g_EptHookState.Hooks);
        ULONG htSlot = EptHookHashFn(PageBase);
        ULONG htI;
        for (htI = 0; htI < EPT_HOOK_HASH_SIZE; htI++) {
            ULONG htIdx = (htSlot + htI) & (EPT_HOOK_HASH_SIZE - 1);
            if (g_EptHookState.HookHashTable[htIdx] == EPT_HOOK_HASH_EMPTY) {
                g_EptHookState.HookHashTable[htIdx] = hookArrayIdx;
                break;
            }
        }
    }

    /*
     * Set EPT PTE pointing to the (shared) hook page.
     *
     * If Execute-Only is supported: R=0, W=0, X=1 (hook page)
     *   - Reads/writes cause EPT violation -> we show original page
     *   - Execution goes to hook page -> our JMP gets executed
     *   - Most stealthy: integrity scans read original code
     *
     * If Execute-Only is NOT supported: R=0, W=0, X=0 (hook page)
     *   - ALL accesses cause EPT violation
     *   - In the handler, check Guest RIP to distinguish:
     *     * RIP is within this page -> execution -> temporarily R+W+X with hook page + MTF
     *     * RIP is elsewhere -> read/write -> temporarily R+W+X with original page + MTF
     *   - PatchGuard reads see original (unpatched) code
     */
    Pte->Read = 0;
    Pte->Write = 0;
    Pte->PhysAddr = Hook->HookPagePa >> 12;

    if (g_EptHookState.ExecuteOnlySupported) {
        Pte->Execute = 1;
    } else {
        Pte->Execute = 0;
    }

    /*
     * Per-CPU hook page isolation:
     * Clone the PD and split PT page for this 2MB region to all CPUs,
     * then replicate the same PTE permissions on each CPU's private copy.
     */
    if (g_EptCpuStates && g_PerCpuSplitPages && g_PerCpuPdPages) {
        ULONG PdptIdx = (ULONG)((PageBase >> 30) & 0x1FF);
        ULONG PdIdx   = (ULONG)((PageBase >> 21) & 0x1FF);
        ULONG splitIdx, cpu;
        NTSTATUS PerCpuStatus;

        /* Ensure per-CPU PD page for this region */
        PerCpuStatus = EptEnsurePerCpuPdForRegion(PdptIdx);
        if (NT_SUCCESS(PerCpuStatus)) {
            /*
             * BUG FIX (Issue #3+5+6): Use hash lookup for split page index
             * instead of O(n) linear scan.
             */
            splitIdx = EptSplitHashLookup(PageBase & ~((2ULL * 1024 * 1024) - 1));
            if (splitIdx != EPT_SPLIT_HASH_EMPTY && splitIdx < MAX_SPLIT_PAGES) {
                PerCpuStatus = EptEnsurePerCpuSplitPage(splitIdx, PdptIdx, PdIdx);
                if (NT_SUCCESS(PerCpuStatus)) {
                    /* Replicate hook PTE permissions to all per-CPU copies */
                    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
                        PEPT_PTE CpuPte = EptGetPerCpuPte(cpu, TargetPa);
                        if (CpuPte) {
                            CpuPte->Read = Pte->Read;
                            CpuPte->Write = Pte->Write;
                            CpuPte->Execute = Pte->Execute;
                            CpuPte->PhysAddr = Pte->PhysAddr;
                        }
                    }
                    LOG_INFO("Per-CPU PT isolation set up for hook at PA=0x%llX", PageBase);
                }
            }
        }
    }

    /* Return trampoline as the "original function" */
    if (OriginalFunction) {
        *OriginalFunction = Hook->TrampolineVa;
    }

    KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);

    /* Invalidate EPT TLB via VMCALL (we're in Guest/non-root mode) */
    EptInvalidateFromGuest();

    LOG_INFO("EPT Hook installed: VA=0x%llX -> Hook=0x%p, Trampoline=0x%p%s",
             TargetVa, HookFunction, Hook->TrampolineVa,
             PageOwner ? " (shared page)" : "");

    return STATUS_SUCCESS;
}

NTSTATUS EptUnhookFunction(ULONG64 TargetVa)
{
    KIRQL   OldIrql;
    ULONG   i;

    KeAcquireSpinLock(&g_EptHookState.Lock, &OldIrql);

    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        PEPT_HOOK_ENTRY Hook = &g_EptHookState.Hooks[i];

        if (Hook->Active && Hook->TargetVirtualAddr == TargetVa) {
            ULONG64 PageBase = Hook->TargetPhysicalAddr;
            BOOLEAN OtherHooksOnPage = FALSE;
            ULONG   j;

            /*
             * Restore original bytes on the shared HookPage so this
             * function's JMP patch is removed while other patches survive.
             */
            if (Hook->HookPageVa) {
                PUCHAR HookPoint = (PUCHAR)Hook->HookPageVa + Hook->TargetPageOffset;
                RtlCopyMemory(HookPoint, Hook->OriginalBytes, Hook->OriginalBytesSize);
            }

            /* Check if other active hooks share this page */
            for (j = 0; j < MAX_EPT_HOOKS; j++) {
                if (j != i &&
                    g_EptHookState.Hooks[j].Active &&
                    g_EptHookState.Hooks[j].TargetPhysicalAddr == PageBase)
                {
                    OtherHooksOnPage = TRUE;
                    break;
                }
            }

            if (!OtherHooksOnPage) {
                /*
                 * BUG FIX (Review Issue #2): Two-pass single-function unhook.
                 *
                 * Same UAF pattern as was fixed in EptUnhookAll:
                 * Pass 1: Restore EPT PTEs to original physical address (RWX).
                 * Then flush TLB (INVEPT) before freeing pages, so stale TLB
                 * entries on other CPUs won't reference freed memory.
                 */
                PVOID FreeOriginalPage = Hook->OwnsPages ? Hook->OriginalPageVa : NULL;
                PVOID FreeHookPage     = Hook->OwnsPages ? Hook->HookPageVa : NULL;

                /* Pass 1: Restore EPT mapping */
                if (Hook->TargetPte) {
                    Hook->TargetPte->Read = 1;
                    Hook->TargetPte->Write = 1;
                    Hook->TargetPte->Execute = 1;
                    Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
                }

                /* Also restore all per-CPU PTEs for this page */
                if (g_EptCpuStates && g_PerCpuSplitPages) {
                    ULONG cpu;
                    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
                        PEPT_PTE CpuPte = EptGetPerCpuPte(cpu, Hook->TargetPhysicalAddr);
                        if (CpuPte) {
                            CpuPte->Read = 1;
                            CpuPte->Write = 1;
                            CpuPte->Execute = 1;
                            CpuPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
                        }
                    }
                }

                /* Trampoline is always per-hook */
                if (Hook->TrampolineVa) ExFreePoolWithTag(Hook->TrampolineVa, VMX_TAG);

                RtlZeroMemory(Hook, sizeof(EPT_HOOK_ENTRY));
                g_EptHookState.HookCount--;
                EptHookHashRebuild();

                KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);

                /* TLB flush BEFORE freeing pages — prevents UAF from stale TLB */
                EptInvalidateFromGuest();

                /* Pass 2: Now safe to free pages */
                if (FreeOriginalPage) ExFreePoolWithTag(FreeOriginalPage, VMX_TAG);
                if (FreeHookPage)     ExFreePoolWithTag(FreeHookPage, VMX_TAG);
            } else {
                if (Hook->OwnsPages) {
                    /*
                     * This hook owns the pages but other hooks still need them.
                     * Transfer ownership to another hook on the same page.
                     */
                    PEPT_HOOK_ENTRY NewOwner = &g_EptHookState.Hooks[j];
                    NewOwner->OwnsPages = TRUE;
                    /* NewOwner already points to the same pages */
                }

                /* Trampoline is always per-hook */
                if (Hook->TrampolineVa) ExFreePoolWithTag(Hook->TrampolineVa, VMX_TAG);

                RtlZeroMemory(Hook, sizeof(EPT_HOOK_ENTRY));
                g_EptHookState.HookCount--;

                /*
                 * BUG FIX (Issue #3+5+6): Rebuild hook hash table after removal.
                 * Open-addressing deletion requires rehashing to maintain probe chains.
                 */
                EptHookHashRebuild();

                KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);

                EptInvalidateFromGuest();
            }

            LOG_INFO("EPT Hook removed: VA=0x%llX", TargetVa);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);
    return STATUS_NOT_FOUND;
}

VOID EptUnhookAll(VOID)
{
    KIRQL   OldIrql;
    ULONG   i;

    if (!g_EptHookState.Initialized) {
        return;
    }

    KeAcquireSpinLock(&g_EptHookState.Lock, &OldIrql);

    /*
     * BUG FIX (Issue #7 + #10): Two-pass unhook to avoid UAF and missing INVEPT.
     *
     * Pass 1: Restore all EPT PTEs to original physical addresses (RWX).
     *         Do NOT free any pages yet — other CPUs may still have stale TLB
     *         entries pointing to HookPage/OriginalPage. Freeing here would
     *         create a use-after-free window.
     *
     * Then: INVEPT to flush all stale TLB entries across all CPUs.
     *
     * Pass 2: Now safe to free HookPage/OriginalPage/Trampoline memory
     *         since no CPU can reference them via stale TLB entries.
     */

    /* Pass 1: Restore all PTEs */
    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        PEPT_HOOK_ENTRY Hook = &g_EptHookState.Hooks[i];

        if (Hook->Active) {
            /* Restore shared EPT mapping (safe to do multiple times for same PTE) */
            if (Hook->TargetPte) {
                Hook->TargetPte->Read = 1;
                Hook->TargetPte->Write = 1;
                Hook->TargetPte->Execute = 1;
                Hook->TargetPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
            }

            /* Also restore all per-CPU PTEs for this page */
            if (g_EptCpuStates && g_PerCpuSplitPages) {
                ULONG cpu;
                for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
                    PEPT_PTE CpuPte = EptGetPerCpuPte(cpu, Hook->TargetPhysicalAddr);
                    if (CpuPte) {
                        CpuPte->Read = 1;
                        CpuPte->Write = 1;
                        CpuPte->Execute = 1;
                        CpuPte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
                    }
                }
            }
        }
    }

    KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);

    /*
     * Flush EPT TLB on all CPUs BEFORE freeing any pages.
     * This ensures no CPU still has stale TLB entries pointing to
     * pages we're about to free.
     */
    EptInvalidateFromGuest();

    /* Pass 2: Free memory (safe now that TLB is flushed) */
    KeAcquireSpinLock(&g_EptHookState.Lock, &OldIrql);

    for (i = 0; i < MAX_EPT_HOOKS; i++) {
        PEPT_HOOK_ENTRY Hook = &g_EptHookState.Hooks[i];

        if (Hook->Active) {
            /* Only page owners free the shared pages */
            if (Hook->OwnsPages) {
                if (Hook->OriginalPageVa) ExFreePoolWithTag(Hook->OriginalPageVa, VMX_TAG);
                if (Hook->HookPageVa)     ExFreePoolWithTag(Hook->HookPageVa, VMX_TAG);
            }

            /* Trampoline is always per-hook */
            if (Hook->TrampolineVa) ExFreePoolWithTag(Hook->TrampolineVa, VMX_TAG);

            RtlZeroMemory(Hook, sizeof(EPT_HOOK_ENTRY));
        }
    }

    g_EptHookState.HookCount = 0;

    /*
     * BUG FIX (Issue #3+5+6): Clear hook hash table — all hooks removed.
     */
    {
        ULONG htIdx;
        for (htIdx = 0; htIdx < EPT_HOOK_HASH_SIZE; htIdx++)
            g_EptHookState.HookHashTable[htIdx] = EPT_HOOK_HASH_EMPTY;
    }

    KeReleaseSpinLock(&g_EptHookState.Lock, OldIrql);

    LOG_INFO("All EPT hooks removed");
}

/* ========================================================================= */
/*  EPT Hook Lookup                                                          */
/* ========================================================================= */

/*
 * BUG FIX (Issue #3+5+6): O(1) hook lookup using hash table.
 *
 * The old implementation linearly scanned all MAX_EPT_HOOKS (1024)
 * entries — called on every EPT violation in VMX root mode where
 * latency directly impacts guest performance.
 *
 * Now uses an open-addressing hash table (PagePA >> 12 → hook index)
 * maintained by EptHookFunction/EptUnhookFunction/EptUnhookAll.
 */
PEPT_HOOK_ENTRY EptFindHookByPhysicalAddress(ULONG64 PhysicalAddress)
{
    ULONG64 PagePa = PhysicalAddress & PAGE_MASK_4KB;
    ULONG Slot = EptHookHashFn(PagePa);
    ULONG i;

    for (i = 0; i < EPT_HOOK_HASH_SIZE; i++) {
        ULONG Idx = (Slot + i) & (EPT_HOOK_HASH_SIZE - 1);
        ULONG HookIdx = g_EptHookState.HookHashTable[Idx];

        if (HookIdx == EPT_HOOK_HASH_EMPTY)
            return NULL;  /* Empty slot → no matching hook exists */

        if (HookIdx < MAX_EPT_HOOKS &&
            g_EptHookState.Hooks[HookIdx].Active &&
            g_EptHookState.Hooks[HookIdx].TargetPhysicalAddr == PagePa) {
            return &g_EptHookState.Hooks[HookIdx];
        }
    }

    return NULL;
}

/* ========================================================================= */
/*  EPT Violation Handler                                                    */
/* ========================================================================= */

/*
 * Called from VM-Exit dispatcher when an EPT violation occurs.
 *
 * Strategy depends on Execute-Only support:
 *
 * (A) Execute-Only supported (R=0,W=0,X=1 hook page):
 *   - READ/WRITE violation: switch to original page (RW, no X), enable MTF
 *   - EXEC violation: switch back to hook page (X-only)
 *
 * (B) Execute-Only NOT supported (R=0,W=0,X=0 hook page):
 *   - ALL accesses fault; handler checks Guest RIP:
 *     * RIP within hooked page -> execution -> show hook page (RWX) + MTF
 *     * RIP elsewhere -> data access -> show original page (RWX) + MTF
 *   - PatchGuard reads always see original (unpatched) code
 */
BOOLEAN HandleEptViolation(PVOID GuestContext)
{
    ULONG64 GuestPhysAddr;
    ULONG64 ExitQualification;
    PEPT_HOOK_ENTRY Hook;
    BOOLEAN IsRead, IsWrite, IsExec;
    PEPT_PTE Pte;
    ULONG64 ProcBased;
    ULONG   CpuIndex;

    UNREFERENCED_PARAMETER(GuestContext);

    GuestPhysAddr = VmxRead(VMCS_GUEST_PHYSICAL_ADDRESS);
    ExitQualification = VmxRead(VMCS_EXIT_QUALIFICATION);
    CpuIndex = KeGetCurrentProcessorNumber();

    IsRead  = (ExitQualification & EPT_VIOLATION_READ) != 0;
    IsWrite = (ExitQualification & EPT_VIOLATION_WRITE) != 0;
    IsExec  = (ExitQualification & EPT_VIOLATION_EXEC) != 0;

    /* Find the hook for this physical address */
    Hook = EptFindHookByPhysicalAddress(GuestPhysAddr);

    if (!Hook) {
        /*
         * EPT violation on a non-hooked page.
         * This shouldn't happen with our identity map.
         * Log and try to fix by setting RWX.
         */
        LOG_WARN("EPT violation on non-hooked page: GPA=0x%llX, Qual=0x%llX",
                 GuestPhysAddr, ExitQualification);

        Pte = EptGetPerCpuPte(CpuIndex, GuestPhysAddr);
        if (!Pte) Pte = EptGetPteForPhysicalAddress(GuestPhysAddr);
        if (Pte) {
            Pte->Read = 1;
            Pte->Write = 1;
            Pte->Execute = 1;
            EptInvalidateAllContexts();
        }

        return TRUE;
    }

    /*
     * Per-CPU hook page isolation: use this CPU's private PTE if available.
     * This eliminates the multi-core race condition where two CPUs
     * simultaneously toggle the same shared PTE, causing one CPU's
     * MTF restore to undo the other's temporary relaxation.
     *
     * Each CPU has its own EPT PML4 → PDPT → PD → PT chain for hooked
     * regions, so modifying this CPU's PTE only affects this CPU's
     * address translation.
     */
    Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
    if (!Pte) {
        /* Fallback to shared PTE if per-CPU not available */
        Pte = Hook->TargetPte;
    }

    if (g_EptHookState.ExecuteOnlySupported) {
        /*
         * Mode A: Execute-Only (R=0,W=0,X=1)
         * EPT hardware distinguishes exec from data access.
         */
        if (IsRead || IsWrite) {
            /* Data access: show original page (on THIS CPU only) */
            Pte->Read = 1;
            Pte->Write = 1;
            Pte->Execute = 0;
            Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;

            /*
             * BUG FIX (Issue #11): Use INVEPT SINGLE_CONTEXT instead of
             * ALL_CONTEXTS. Since we modified only this CPU's per-CPU PTE,
             * we only need to flush this CPU's EPT TLB. INVEPT ALL_CONTEXTS
             * unnecessarily flushes all EPTP contexts including other CPUs'.
             */
            {
                ULONG64 CpuEptp = EptGetPerCpuEptp(CpuIndex);
                if (CpuEptp)
                    EptInvalidateSingleContext(CpuEptp);
                else
                    EptInvalidateAllContexts();
            }

            /* Track which page this CPU relaxed (for per-CPU MTF restore) */
            EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);

            ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

        } else if (IsExec) {
            /* Exec after MTF restored RW mode: switch back to X-only hook page */
            Pte->Read = 0;
            Pte->Write = 0;
            Pte->Execute = 1;
            Pte->PhysAddr = Hook->HookPagePa >> 12;

            {
                ULONG64 CpuEptp = EptGetPerCpuEptp(CpuIndex);
                if (CpuEptp)
                    EptInvalidateSingleContext(CpuEptp);
                else
                    EptInvalidateAllContexts();
            }
        }
    } else {
        /*
         * Mode B: No Execute-Only (R=0,W=0,X=0)
         * ALL accesses fault.  Check Guest RIP to determine intent:
         *   - RIP physical page == hooked page -> instruction fetch
         *     -> show hook page (R+W+X) so JMP patch executes
         *   - RIP elsewhere -> data read/write (e.g. PatchGuard scan)
         *     -> show original page (R+W+X) so scanner sees clean code
         * Then MTF to restore R=0,W=0,X=0 after one instruction.
         */
        {
            ULONG64 GuestRipPagePa;
            ULONG64 GuestRip = VmxRead(VMCS_GUEST_RIP);
            ULONG64 GuestCr3 = VmxRead(VMCS_GUEST_CR3);

            /*
             * BUG FIX (Issue #4): Use custom page table walk instead of
             * MmGetPhysicalAddress() which is a Windows kernel API that
             * should not be called from VMX root mode.
             *
             * EptGuestVaToPa walks the Guest's CR3 page tables directly
             * using MmGetVirtualForPhysical (which is safe at any IRQL
             * for identity-mapped physical memory).
             * If the translation fails (returns 0), assume data access to be safe.
             */
            {
                ULONG64 RipPa = EptGuestVaToPa(GuestCr3, GuestRip);
                GuestRipPagePa = RipPa & PAGE_MASK_4KB;
            }

            Pte->Read = 1;
            Pte->Write = 1;
            Pte->Execute = 1;

            if (GuestRipPagePa == Hook->TargetPhysicalAddr) {
                /* Execution: use hook page (with JMP patch) */
                Pte->PhysAddr = Hook->HookPagePa >> 12;
            } else {
                /* Data access: use original page (clean code) */
                Pte->PhysAddr = Hook->TargetPhysicalAddr >> 12;
            }

            /*
             * BUG FIX (Issue #11): INVEPT SINGLE_CONTEXT for per-CPU PTE changes.
             */
            {
                ULONG64 CpuEptp = EptGetPerCpuEptp(CpuIndex);
                if (CpuEptp)
                    EptInvalidateSingleContext(CpuEptp);
                else
                    EptInvalidateAllContexts();
            }

            /* Track which page this CPU relaxed (for per-CPU MTF restore) */
            EptMtfTrackRelaxedPage(Hook->TargetPhysicalAddr);

            ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased |= PROC_BASED_MONITOR_TRAP_FLAG;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
        }
    }

    /* Don't advance RIP - re-execute the faulting instruction */
    return TRUE;
}

/* ========================================================================= */
/*  Per-CPU EPT Management (Hook Page Isolation)                             */
/* ========================================================================= */

/*
 * EptInitPerCpu - Allocate per-CPU EPT root structures.
 *
 * Each CPU gets its own PML4 → PDPT, initially cloned from the shared
 * template in g_EptState.  The per-CPU PDPT entries point to the shared
 * PD pages (same as the template).  When a hook is installed, the
 * relevant PD entries are cloned per-CPU on demand.
 *
 * Must be called AFTER EptInitialize() and g_MaxProcessors is set.
 */
NTSTATUS EptInitPerCpu(VOID)
{
    ULONG i;

    if (!g_EptState.Initialized || g_MaxProcessors == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    /* Allocate per-CPU EPT root array */
    g_EptCpuStates = (PEPT_CPU_STATE)ExAllocatePoolWithTag(
        NonPagedPool,
        g_MaxProcessors * sizeof(EPT_CPU_STATE),
        'tpEC');
    if (!g_EptCpuStates) {
        LOG_ERROR("Failed to allocate per-CPU EPT states for %u CPUs", g_MaxProcessors);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_EptCpuStates, g_MaxProcessors * sizeof(EPT_CPU_STATE));

    /* Allocate per-CPU split page pointer array [g_MaxProcessors] */
    g_PerCpuSplitPages = (PEPT_PER_CPU_SPLIT *)ExAllocatePoolWithTag(
        NonPagedPool,
        g_MaxProcessors * sizeof(PEPT_PER_CPU_SPLIT),
        'tpES');
    if (!g_PerCpuSplitPages) {
        ExFreePoolWithTag(g_EptCpuStates, 'tpEC');
        g_EptCpuStates = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_PerCpuSplitPages, g_MaxProcessors * sizeof(PEPT_PER_CPU_SPLIT));

    /* Allocate per-CPU PD page pointer array [g_MaxProcessors] */
    g_PerCpuPdPages = (EPT_PER_CPU_PD_PAGE **)ExAllocatePoolWithTag(
        NonPagedPool,
        g_MaxProcessors * sizeof(EPT_PER_CPU_PD_PAGE *),
        'tpEP');
    if (!g_PerCpuPdPages) {
        ExFreePoolWithTag(g_PerCpuSplitPages, 'tpES');
        g_PerCpuSplitPages = NULL;
        ExFreePoolWithTag(g_EptCpuStates, 'tpEC');
        g_EptCpuStates = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_PerCpuPdPages, g_MaxProcessors * sizeof(EPT_PER_CPU_PD_PAGE *));

    /* Initialize each CPU's EPT root (clone from shared template) */
    for (i = 0; i < g_MaxProcessors; i++) {
        ULONG64 PdptPa;

        /* Clone PML4 from template */
        RtlCopyMemory(g_EptCpuStates[i].Pml4, g_EptState.Pml4, sizeof(g_EptState.Pml4));

        /* Clone PDPT from template */
        RtlCopyMemory(g_EptCpuStates[i].Pdpt, g_EptState.Pdpt, sizeof(g_EptState.Pdpt));

        /* Update PML4[0] to point to this CPU's PDPT */
        PdptPa = VaToPhysical(g_EptCpuStates[i].Pdpt);
        g_EptCpuStates[i].Pml4[0].PhysAddr = PdptPa >> 12;

        /* Set up per-CPU EPTP */
        g_EptCpuStates[i].Pml4Pa = VaToPhysical(g_EptCpuStates[i].Pml4);
        g_EptCpuStates[i].Eptp.Value = 0;
        g_EptCpuStates[i].Eptp.MemoryType = EPT_MEMORY_TYPE_WB;
        g_EptCpuStates[i].Eptp.PageWalkLength = EPT_PAGE_WALK_LENGTH_4;
        g_EptCpuStates[i].Eptp.Pml4PhysAddr = g_EptCpuStates[i].Pml4Pa >> 12;
    }

    RtlZeroMemory(g_PerCpuPdAllocated, sizeof(g_PerCpuPdAllocated));

    LOG_INFO("Per-CPU EPT initialized for %u CPUs", g_MaxProcessors);
    return STATUS_SUCCESS;
}

/*
 * EptCleanupPerCpu - Free all per-CPU EPT structures.
 */
VOID EptCleanupPerCpu(VOID)
{
    ULONG cpu, idx;

    if (g_PerCpuSplitPages) {
        for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
            if (g_PerCpuSplitPages[cpu]) {
                ExFreePoolWithTag(g_PerCpuSplitPages[cpu], 'tpES');
            }
        }
        ExFreePoolWithTag(g_PerCpuSplitPages, 'tpES');
        g_PerCpuSplitPages = NULL;
    }

    if (g_PerCpuPdPages) {
        for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
            if (g_PerCpuPdPages[cpu]) {
                ExFreePoolWithTag(g_PerCpuPdPages[cpu], 'tpEP');
            }
        }
        ExFreePoolWithTag(g_PerCpuPdPages, 'tpEP');
        g_PerCpuPdPages = NULL;
    }

    if (g_EptCpuStates) {
        ExFreePoolWithTag(g_EptCpuStates, 'tpEC');
        g_EptCpuStates = NULL;
    }

    LOG_INFO("Per-CPU EPT cleaned up");
}

/*
 * EptEnsurePerCpuPdForRegion - Ensure per-CPU PD page exists for a PDPT entry.
 *
 * When a hook is installed on a 2MB region, we need each CPU to have its
 * own PD page so that the PD entry (pointing to the split PT) is independent.
 * This clones the shared PD page for the given PDPT index to all CPUs.
 *
 * Must be called with g_EptHookState.Lock held.
 */
static NTSTATUS EptEnsurePerCpuPdForRegion(ULONG PdptIndex)
{
    ULONG cpu;

    if (PdptIndex >= MAX_PD_PAGES) return STATUS_INVALID_PARAMETER;
    if (g_PerCpuPdAllocated[PdptIndex]) return STATUS_SUCCESS;  /* already done */

    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (!g_PerCpuPdPages[cpu]) {
            /* First time for this CPU - allocate the full PD pages array.
             * We allocate MAX_PD_PAGES pointers but only fill ones that
             * actually need per-CPU isolation. Actually, simpler: allocate
             * a single contiguous PD page for this PDPT index per CPU. */
            g_PerCpuPdPages[cpu] = (EPT_PER_CPU_PD_PAGE *)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(EPT_PER_CPU_PD_PAGE) * MAX_PD_PAGES,
                'tpEP');
            if (!g_PerCpuPdPages[cpu]) {
                LOG_ERROR("Failed to allocate per-CPU PD pages for CPU %u", cpu);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            /* Initialize from shared PD pages */
            RtlCopyMemory(g_PerCpuPdPages[cpu], g_PdPages,
                          sizeof(EPT_PER_CPU_PD_PAGE) * MAX_PD_PAGES);
        }

        /* Point this CPU's PDPT entry to its own PD page */
        {
            ULONG64 CpuPdPa = VaToPhysical(&g_PerCpuPdPages[cpu][PdptIndex]);

            g_EptCpuStates[cpu].Pdpt[PdptIndex].PhysAddr = CpuPdPa >> 12;
        }
    }

    g_PerCpuPdAllocated[PdptIndex] = TRUE;
    LOG_INFO("Per-CPU PD allocated for PDPT index %u", PdptIndex);
    return STATUS_SUCCESS;
}

/*
 * EptEnsurePerCpuSplitPage - Ensure per-CPU split PT page exists.
 *
 * When a 2MB region is split for hooks, each CPU needs its own copy of
 * the 512-entry PT page so that individual PTE toggles are independent.
 * This clones the shared split page to all CPUs.
 *
 * Must be called with g_EptHookState.Lock held.
 * splitIdx: index into g_SplitPages[].
 */
static NTSTATUS EptEnsurePerCpuSplitPage(ULONG splitIdx, ULONG PdptIndex, ULONG PdIndex)
{
    ULONG cpu;

    if (splitIdx >= MAX_SPLIT_PAGES) return STATUS_INVALID_PARAMETER;

    for (cpu = 0; cpu < g_MaxProcessors; cpu++) {
        if (!g_PerCpuSplitPages[cpu]) {
            /* Allocate per-CPU split page array for this CPU */
            g_PerCpuSplitPages[cpu] = (PEPT_PER_CPU_SPLIT)ExAllocatePoolWithTag(
                NonPagedPool,
                sizeof(EPT_PER_CPU_SPLIT) * MAX_SPLIT_PAGES,
                'tpES');
            if (!g_PerCpuSplitPages[cpu]) {
                LOG_ERROR("Failed to allocate per-CPU split pages for CPU %u", cpu);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(g_PerCpuSplitPages[cpu],
                          sizeof(EPT_PER_CPU_SPLIT) * MAX_SPLIT_PAGES);
        }

        if (!g_PerCpuSplitPages[cpu][splitIdx].Allocated) {
            /* Clone PT entries from shared split page */
            RtlCopyMemory(g_PerCpuSplitPages[cpu][splitIdx].Pte,
                          g_SplitPages[splitIdx].Pte,
                          sizeof(EPT_PTE) * EPT_PTE_COUNT);
            g_PerCpuSplitPages[cpu][splitIdx].PhysicalAddress =
                VaToPhysical(g_PerCpuSplitPages[cpu][splitIdx].Pte);
            g_PerCpuSplitPages[cpu][splitIdx].Allocated = TRUE;
        }

        /* Update this CPU's PD entry to point to its own PT page */
        if (g_PerCpuPdPages[cpu]) {
            PEPT_PDE CpuPde = &g_PerCpuPdPages[cpu][PdptIndex].Entries[PdIndex];
            CpuPde->Value = 0;
            CpuPde->Read = 1;
            CpuPde->Write = 1;
            CpuPde->Execute = 1;
            CpuPde->LargePage = 0;
            CpuPde->PhysAddr = g_PerCpuSplitPages[cpu][splitIdx].PhysicalAddress >> 12;
        }
    }

    LOG_INFO("Per-CPU split page %u cloned (PD[%u][%u])", splitIdx, PdptIndex, PdIndex);
    return STATUS_SUCCESS;
}

/*
 * EptGetPerCpuPte - Get the per-CPU PTE for a physical address.
 * Returns the PTE from the calling CPU's private split page.
 *
 * BUG FIX (Issue #3+5+6): O(1) hash lookup instead of O(n) linear scan.
 */
PEPT_PTE EptGetPerCpuPte(ULONG CpuIndex, ULONG64 PhysicalAddress)
{
    ULONG64 Base2MB;
    ULONG   PtIndex;
    ULONG   splitIdx;

    if (!g_PerCpuSplitPages || CpuIndex >= g_MaxProcessors ||
        !g_PerCpuSplitPages[CpuIndex]) {
        return NULL;
    }

    Base2MB = PhysicalAddress & ~((2ULL * 1024 * 1024) - 1);
    PtIndex = (ULONG)((PhysicalAddress >> 12) & 0x1FF);

    splitIdx = EptSplitHashLookup(Base2MB);
    if (splitIdx != EPT_SPLIT_HASH_EMPTY && splitIdx < MAX_SPLIT_PAGES &&
        g_PerCpuSplitPages[CpuIndex][splitIdx].Allocated) {
        return &g_PerCpuSplitPages[CpuIndex][splitIdx].Pte[PtIndex];
    }

    return NULL;
}

/*
 * EptGetPerCpuEptp - Get the EPTP value for a specific CPU.
 * Returns 0 if per-CPU EPT is not initialized.
 */
ULONG64 EptGetPerCpuEptp(ULONG CpuIndex)
{
    if (g_EptCpuStates && CpuIndex < g_MaxProcessors) {
        return g_EptCpuStates[CpuIndex].Eptp.Value;
    }
    return 0;
}

/* ========================================================================= */
/*  INVEPT Wrappers                                                          */
/* ========================================================================= */

/*
 * EptInvalidateAllContexts - Execute INVEPT (all contexts).
 * Must ONLY be called from VMX root mode (VM-Exit handlers).
 */
VOID EptInvalidateAllContexts(VOID)
{
    INVEPT_DESCRIPTOR Desc = { 0 };
    AsmVmxInvept(INVEPT_ALL_CONTEXTS, &Desc);
}

VOID EptInvalidateSingleContext(ULONG64 Eptp)
{
    INVEPT_DESCRIPTOR Desc = { 0 };
    Desc.EptPointer = Eptp;
    AsmVmxInvept(INVEPT_SINGLE_CONTEXT, &Desc);
}

/*
 * EptInvalidateFromGuest - Request EPT TLB flush from Guest (VMX non-root).
 *
 * Bumps a generation counter. Each CPU compares its last-seen generation
 * at every VM-Exit and executes INVEPT if behind.  This ensures all CPUs
 * eventually flush, without relying on VMCALL (which VMware nested
 * virtualization intercepts).
 */
VOID EptInvalidateFromGuest(VOID)
{
    InterlockedIncrement(&g_EptInveptGeneration);
}

/*
 * EptCheckPendingInvept - Check and execute pending INVEPT.
 *
 * Called at the top of every VM-Exit handler (VMX root mode).
 * Compares the current CPU's last-seen generation with the global
 * generation counter.  If behind, executes INVEPT and updates.
 */
VOID EptCheckPendingInvept(VOID)
{
    ULONG CpuIndex = KeGetCurrentProcessorNumber();
    LONG  CurrentGen = g_EptInveptGeneration;

    if (g_EptInveptCpuGen && CpuIndex < g_MaxProcessors && g_EptInveptCpuGen[CpuIndex] != CurrentGen) {
        g_EptInveptCpuGen[CpuIndex] = CurrentGen;
        EptInvalidateAllContexts();
    }
}
