/*
 * vmx_exit.c - VMX Anti-Anti-Debug Hypervisor
 * VM-Exit main dispatcher and individual exit handlers
 */

#include "vmx.h"
#include "ept.h"
#include "hv_ops.h"
#include "hv_mem.h"
#include "hv_hypercall.h"
#include "log.h"
#include "process.h"
#include "anti_anti_debug.h"
#include "../common/shared.h"

/* ========================================================================= */
/*  Forward Declarations                                                     */
/* ========================================================================= */

static BOOLEAN HandleCpuid(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleRdmsr(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleWrmsr(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleCrAccess(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleDrAccess(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleException(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleXsetbv(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleInvd(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleVmcall(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleEptViol(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleEptMisconfig(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleInvlpg(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleWbinvd(PGUEST_CONTEXT Ctx);
static BOOLEAN HandleTripleFault(PGUEST_CONTEXT Ctx);

/* MSR handlers from msr.c */
extern BOOLEAN HandleRdmsrImpl(PGUEST_CONTEXT Ctx);
extern BOOLEAN HandleWrmsrImpl(PGUEST_CONTEXT Ctx);

/* Helper: get GP register value by index */
static ULONG64 GetGpRegValue(PGUEST_CONTEXT Ctx, ULONG RegIndex);
static VOID    SetGpRegValue(PGUEST_CONTEXT Ctx, ULONG RegIndex, ULONG64 Value);

/* =========================================================================
 * PRODUCTION-GRADE NMI DISCRIMINATION SYSTEM
 *
 * Goal: Distinguish real hardware NMIs from virtualization-artifact NMIs
 * in nested virtualization environments (L0=VMware, L1=Our Driver).
 *
 * Real hardware NMIs MUST be forwarded to Guest OS (KiNmiInterrupt).
 * Virtualization artifacts MUST be silently dropped to prevent loops.
 *
 * Architecture: Hash Map with multi-slot per-CPU injection tracking.
 *
 *   When we inject an NMI to Guest: compute fingerprint → store in map slot.
 *   When an NMI VM-Exit arrives:   compute fingerprint → lookup map.
 *     Match found (echo) → drop as artifact.
 *     No match           → inject to Guest and record in map.
 *
 * Discrimination signals (all deterministic):
 *   Signal A — Echo match via hash fingerprint correlation
 *   Signal B — Exit Qualification bit 11 (IRET unblocking)
 *   Signal C — IDT Vectoring Info field validity
 *   Signal D — Guest RIP stasis detection
 * ======================================================================== */

/*
 * NMI Fingerprint — compact hash representing a specific injection event.
 * Composed from Guest execution context at the moment of injection.
 */
typedef struct _NMI_FINGERPRINT {
    ULONG64 GuestRip;      /* Guest RIP at injection / arrival time       */
    ULONG64 GuestRsp;      /* Guest RSP at injection / arrival time       */
} NMI_FINGERPRINT, *PNMI_FINGERPRINT;

/*
 * Injection Map Slot — one entry per pending injection awaiting echo.
 * Each CPU has NMI_MAP_SLOTS slots for concurrent injection tracking.
 */
#define NMI_MAP_SLOTS              4        /* max concurrent injections  */
#define NMI_ECHO_MAX_TSC_CYCLES    10000000 /* ~3.3ms @3GHz echo window  */
#define NMI_RIP_STASIS_THRESHOLD   128      /* bytes ± tolerance          */

typedef enum _NMI_SLOT_STATUS {
    NMI_SLOT_FREE     = 0,  /* available for reuse                       */
    NMI_SLOT_PENDING  = 1,  /* injected, waiting for echo                */
    NMI_SLOT_MATCHED  = 2,  /* echo received and correlated              */
    NMI_SLOT_EXPIRED  = 3,  /* timeout, echo never arrived               */
} NMI_SLOT_STATUS;

typedef struct _NMI_INJECTION_SLOT {
    volatile NMI_FINGERPRINT Fp;          /* fingerprint at injection time  */
    volatile LONG64        InjectedAtTsc; /* TSC timestamp at injection     */
    volatile LONG          InjectionSeq;  /* global sequence number         */
    volatile NMI_SLOT_STATUS Status;      /* slot lifecycle state           */
} NMI_INJECTION_SLOT;

/* Per-CPU injection map: tracks our NMI injections for echo correlation. */
static volatile NMI_INJECTION_SLOT g_NmiInjectionMap[64][NMI_MAP_SLOTS];

/* Global monotonic injection counter — unique ID per injection. */
static volatile LONG g_NmiGlobalSeq = 0;

/* Diagnostic counters — per-CPU visibility into discrimination behavior. */
static volatile LONG64 g_DiagNmiTimestamp[64] = { 0 };
static volatile LONG   g_DiagNmiTotalCount[64] = { 0 };
static volatile LONG   g_DiagNmiDroppedCount[64] = { 0 };

/* Signal D: Last known Guest RIP after NMI handling (stasis detection). */
static volatile ULONG64 g_DiagNmiLastGuestRipAfterNmi[64] = { 0 };

/* DIAGNOSTIC (Phase 3): External interrupt vector frequency - FILE-SCOPE */
static volatile LONG g_DiagExtIntVectorCount[256] = { 0 };

/* =========================================================================
 * NMI Fingerprint & Map Helper Functions
 *
 * These operate on per-CPU data only — no locks needed since VM-Exits
 * on a given vCPU are strictly serialized by hardware.
 * ======================================================================== */

/*
 * NmiComputeHash — compute a 64-bit hash from NMI fingerprint.
 *
 * Uses xorshift-mix for good distribution with minimal CPU cost.
 * The hash is used to select a slot in the injection map (modulo NMI_MAP_SLOTS).
 */
static ULONG64 NmiComputeHash(PNMI_FINGERPRINT Fp)
{
    ULONG64 h = Fp->GuestRip;
    h ^= Fp->GuestRsp;
    h ^= (h >> 33) * 0xff51afd7ed558ccdULL;
    h ^= (h >> 33) * 0xc4ceb9fe1a85ec53ULL;
    h ^= (h >> 33);
    return h;
}

/*
 * NmiFindFreeOrOldestSlot — find a slot for new injection record.
 *
 * Strategy:
 *   1. Return first FREE slot if any (ideal case).
 *   2. Return the EXPIRED or MATCHED slot (safe to overwrite).
 *   3. Last resort: all slots are PENDING — evict the OLDEST injection
 *      (lowest InjectionSeq) because its echo is most likely already lost
 *      or will arrive soonest. This minimizes the window for a missed echo.
 */
static ULONG NmiFindFreeOrOldestSlot(ULONG CpuIdx)
{
    ULONG i;
    ULONG candidate = 0;
    LONG  oldestSeq = 0x7FFFFFFF;  /* MAX LONG for initial comparison */

    if (CpuIdx >= 64) CpuIdx = 0;

    for (i = 0; i < NMI_MAP_SLOTS; i++) {
        volatile NMI_INJECTION_SLOT *S = &g_NmiInjectionMap[CpuIdx][i];
        if (S->Status == NMI_SLOT_FREE) {
            return i;  /* ideal: empty slot */
        }
        /* Prefer non-pending slots for eviction */
        if (S->Status != NMI_SLOT_PENDING) {
            candidate = i;  /* EXPIRED or MATCHED → safe immediate reuse */
        }
        /*
         * Track oldest PENDING slot for worst-case eviction.
         * If all slots are PENDING, we'll evict the one with the lowest
         * sequence number (injected longest ago). The lost echo risk is
         * acceptable because 4+ concurrent pending injections are extremely
         * rare in practice.
         */
        if (S->Status == NMI_SLOT_PENDING && S->InjectionSeq < oldestSeq) {
            oldestSeq = S->InjectionSeq;
            candidate = i;
        }
    }

    /*
     * DIAGNOSTIC v2: Log slot allocation type for map capacity analysis.
     * Helps verify Fix #4 (seq-based eviction) is working correctly:
     *   - "free"     → normal operation, plenty of room
     *   - "expired"  → echo didn't arrive within window (expected occasionally)
     *   - "matched"  → reuse after successful correlation
     *   - "evict"    → all slots PENDING, evicted oldest (Fix #4)
     *
     * Throttled to first 50 calls per CPU to avoid log flooding.
     */
    {
        static volatile LONG s_SlotLogCount[64] = { 0 };
        volatile NMI_INJECTION_SLOT *ChosenSlot = &g_NmiInjectionMap[CpuIdx][candidate];
        const CHAR *slotType;
        LONG logN;

        switch (ChosenSlot->Status) {
        case NMI_SLOT_FREE:     slotType = "free"; break;
        case NMI_SLOT_EXPIRED:  slotType = "expired"; break;
        case NMI_SLOT_MATCHED:  slotType = "matched"; break;
        default:                slotType = "evict(pending)"; break;
        }

        logN = (CpuIdx < 64)
             ? InterlockedIncrement(&s_SlotLogCount[CpuIdx]) : 0;

        if (logN <= 50 || (logN % 200 == 0)) {
            LOG_INFO("NMI SLOT-ALLOC CPU%u #%ld: slot=%u type=%s old_seq=%d",
                     CpuIdx, (LONG)logN, candidate,
                     slotType, (int)(oldestSeq == 0x7FFFFFFF ? -1 : oldestSeq));
        }
    }

    return candidate;  /* best available slot (free/expired/oldest-pending) */
}

/*
 * NmiRecordInjection — store a new injection fingerprint into the map.
 *
 * Called when we write an NMI to VMCS_ENTRY_INT_INFO. Records the
 * injection context so the echo can be correlated later.
 */
static VOID NmiRecordInjection(ULONG CpuIdx, PNMI_FINGERPRINT Fp, LONG64 Tsc)
{
    ULONG SlotIdx;
    volatile NMI_INJECTION_SLOT *Slot;

    if (CpuIdx >= 64) CpuIdx = 0;

    SlotIdx = NmiFindFreeOrOldestSlot(CpuIdx);
    Slot = &g_NmiInjectionMap[CpuIdx][SlotIdx];

    Slot->Fp.GuestRip     = Fp->GuestRip;
    Slot->Fp.GuestRsp     = Fp->GuestRsp;
    Slot->InjectedAtTsc    = Tsc;
    Slot->InjectionSeq     = InterlockedIncrement(&g_NmiGlobalSeq);
    Slot->Status           = NMI_SLOT_PENDING;

    /*
     * DIAGNOSTIC v2: Log injection recording for echo correlation verification.
     * Shows which slot was allocated (free vs evicted), the sequence number,
     * and the fingerprint. On the next NMI exit, look for ECHO-MATCH with
     * the same seq to confirm the full inject→echo→drop cycle works.
     */
    {
        LONG LocalTotal = (CpuIdx < 64) ? g_DiagNmiTotalCount[CpuIdx] : 0;
        if (LocalTotal <= 30 || (LocalTotal % 500 == 0)) {
            LOG_INFO("NMI RECORD-INJECT CPU%u #%ld: slot=%u seq=%d "
                     "rip=0x%llX rsp=0x%llX tsc=%lld",
                     CpuIdx, (LONG)LocalTotal, SlotIdx,
                     (int)Slot->InjectionSeq,
                     Fp->GuestRip, Fp->GuestRsp, Tsc);
        }
    }
}

/*
 * NmiLookupEcho — search map for an echo match of the current NMI.
 *
 * For each PENDING slot, check:
 *   1. RIP proximity (within ±NMI_RIP_STASIS_THRESHOLD bytes)
 *   2. TSC elapsed within echo window (<NMI_ECHO_MAX_TSC_CYCLES)
 *
 * If matched: consumes the slot (sets MATCHED), returns TRUE.
 * If no match: returns FALSE (this is an independent NMI).
 */
static BOOLEAN NmiLookupEcho(ULONG CpuIdx,
                              PNMI_FINGERPRINT CurrentFp,
                              LONG64 CurrentTsc,
                              LONG *MatchedSeqOut)
{
    ULONG i;

    if (CpuIdx >= 64) CpuIdx = 0;
    if (MatchedSeqOut) *MatchedSeqOut = -1;

    for (i = 0; i < NMI_MAP_SLOTS; i++) {
        volatile NMI_INJECTION_SLOT *Slot = &g_NmiInjectionMap[CpuIdx][i];

        if (Slot->Status != NMI_SLOT_PENDING) {
            continue;
        }

        /* Check RIP proximity: echo should arrive at nearly same RIP */
        {
            LONG64 RipDelta = (LONG64)(CurrentFp->GuestRip - Slot->Fp.GuestRip);
            if (RipDelta <= -NMI_RIP_STASIS_THRESHOLD ||
                RipDelta >=  NMI_RIP_STASIS_THRESHOLD) {
                continue;  /* RIP moved too far → not our echo */
            }
        }

        /*
         * FIX v2: RSP correlation check — prevents false positive on
         * independent HW NMIs that arrive while Guest RIP happens to be
         * within ±128 bytes of a recent injection point.
         *
         * An echo returns with nearly identical RSP (NMI stack frame is
         * tiny: just flags/CS/RIP pushed by hardware). An independent HW
         * NMI arriving during normal execution typically has a very
         * different RSP (deep in some kernel call chain).
         *
         * Tolerance: ±256 bytes (generous for NMI stack variance).
         */
#define NMI_RSP_CORRELATION_THRESHOLD   256
        {
            LONG64 RspDelta = (LONG64)(CurrentFp->GuestRsp - Slot->Fp.GuestRsp);
            if (RspDelta <= -NMI_RSP_CORRELATION_THRESHOLD ||
                RspDelta >=  NMI_RSP_CORRELATION_THRESHOLD) {
                /*
                 * DIAGNOSTIC v2: Log RSP mismatch to verify Fix #1 is working.
                 * This proves an independent HW NMI was saved from being falsely
                 * identified as an echo by the RSP guard.
                 *
                 * Uses g_DiagNmiTotalCount[CpuIdx] for throttling (available
                 * since function already has CpuIdx).
                 */
                LONG LocalTotal = (CpuIdx < 64) ? g_DiagNmiTotalCount[CpuIdx] : 0;
                if (LocalTotal <= 30 || (LocalTotal % 500 == 0)) {
                    LOG_WARN("NMI SIGNAL-A [RSP-guard] CPU%u #%ld: "
                             "slot=%u seq=%d rip_ok(delta=%lld) "
                             "rsp_rejected(inj_rsp=0x%llX cur_rsp=0x%llX rsp_delta=%lld)",
                             CpuIdx, (LONG)LocalTotal, i,
                             (int)Slot->InjectionSeq,
                             (LONG64)(CurrentFp->GuestRip - Slot->Fp.GuestRip),
                             Slot->Fp.GuestRsp, CurrentFp->GuestRsp, RspDelta);
                }
                continue;  /* RSP differs too much → independent NMI, not echo */
            }
        }

        /* Check time window: echo must arrive within latency limit */
        {
            LONG64 TscElapsed = CurrentTsc - Slot->InjectedAtTsc;
            if ((ULONG64)TscElapsed >= (ULONG64)NMI_ECHO_MAX_TSC_CYCLES) {
                /*
                 * DIAGNOSTIC v2: Log slot expiration.
                 * An echo never arrived for this injection — either the echo
                 * was consumed by another signal (B/C/D) or it genuinely
                 * didn't come back (rare but possible in VMware).
                 */
                LONG LocalTotal2 = (CpuIdx < 64) ? g_DiagNmiTotalCount[CpuIdx] : 0;
                if (LocalTotal2 <= 30 || (LocalTotal2 % 500 == 0)) {
                    LOG_WARN("NMI SLOT-EXPIRE CPU%u #%ld: slot=%u seq=%d "
                             "tsc_elapsed=%lld > max=%ld rip=0x%llX",
                             CpuIdx, (LONG)LocalTotal2, i,
                             (int)Slot->InjectionSeq,
                             TscElapsed, (LONG)NMI_ECHO_MAX_TSC_CYCLES,
                             Slot->Fp.GuestRip);
                }
                Slot->Status = NMI_SLOT_EXPIRED;
                continue;
            }
        }

        /* === ECHO MATCH FOUND === */
        Slot->Status = NMI_SLOT_MATCHED;
        if (MatchedSeqOut) *MatchedSeqOut = Slot->InjectionSeq;

        LOG_WARN("NMI ECHO-MATCH CPU%u: seq=%d current_rip=0x%llX "
                 "inj_rip=0x%llX rip_delta=%lld rsp_delta=%lld tsc_elapsed=%lld",
                 CpuIdx, (int)Slot->InjectionSeq,
                 CurrentFp->GuestRip, Slot->Fp.GuestRip,
                 (LONG64)(CurrentFp->GuestRip - Slot->Fp.GuestRip),
                 (LONG64)(CurrentFp->GuestRsp - Slot->Fp.GuestRsp),
                 CurrentTsc - Slot->InjectedAtTsc);

        return TRUE;
    }

    return FALSE;  /* no echo match found */
}

/* ========================================================================= */
/*  Main VM-Exit Handler (called from ASM)                                   */
/* ========================================================================= */

/*
 * VmxExitHandler - Main VM-Exit dispatch function
 *
 * Called from AsmVmxExitHandler after guest GP registers are saved.
 * Returns TRUE to resume guest, FALSE to shut down VMX.
 */
BOOLEAN VmxExitHandler(PGUEST_CONTEXT GuestContext)
{
    ULONG   ExitReason;
    ULONG   CpuIndex;
    BOOLEAN Result = TRUE;

    /*
     * DIAGNOSTIC: Per-CPU early exit counting with rapid-fire detection.
     *
     * When VM-Exits fire at extremely high frequency (e.g., millions per
     * second due to unhandled UNCONDITIONAL_IO_EXIT), the VMware host
     * becomes unresponsive because each exit involves a VMEXIT → handler →
     * VMRESUME round-trip overhead.
     *
     * Fix: Track per-CPU exit count. If >10000 exits occur with no
     * "quiet period" (i.e., rapid-fire), forcefully shut down VMX.
     * This counter is checked BEFORE any logging to avoid recursion.
     *
     * Note: Uses static volatiles — safe because each CPU only accesses
     * its own data (partitioned by CpuIndex).
     *
     * Declared here (before any statements) for C89 compatibility
     * required by WDK 7.1 (MSVC 2008).
     */
    static volatile LONG64 s_EarlyExitCount[64] = { 0 };
    static volatile LONG64 s_LastReportedCount[64] = { 0 };

    /*
     * CRITICAL: Sync Guest RSP from VMCS into GuestContext at VM-Exit entry.
     *
     * The ASM stub saves GP registers to the stack-based GUEST_CONTEXT, but
     * RSP in that struct is a placeholder — it holds the Host stack pointer
     * at the time of the push, NOT the Guest RSP. The real Guest RSP lives
     * in VMCS_GUEST_RSP.
     *
     * By syncing it here (like HyperDbg does in VmxVmexitHandler), ALL
     * subsequent handlers can use GpRegs[4] / GuestContext->Rsp directly
     * without needing special-case code for RegIndex==4.
     *
     * On VM-Exit completion, we write back the (potentially modified) value
     * to VMCS_GUEST_RSP before VMRESUME.
     */
    GuestContext->Rsp = VmxRead(VMCS_GUEST_RSP);

    ExitReason = (ULONG)VmxRead(VMCS_EXIT_REASON);
    CpuIndex = KeGetCurrentProcessorNumber();

    /* Increment exit counter */
    if (CpuIndex < g_MaxProcessors) {
        LONG64 Count = InterlockedIncrement64(&g_VmxState.CpuContexts[CpuIndex].ExitCount);

        /*
         * HEARTBEAT DIAGNOSTIC: Log every 10000th exit per-CPU.
         * This creates a timeline showing what exit reasons appear
         * over time. When VMware freezes, the last heartbeat message
         * in WinDbg tells us exactly where the system got stuck.
         *
         * Also includes rapid-fire detection at 100K intervals.
         */
        if (CpuIndex < 64) {
            s_EarlyExitCount[CpuIndex] = Count;

            /*
             * Heartbeat: Log periodically FOREVER (no upper bound).
             * - Every 100 exits for the first 5000 (detailed early diagnosis)
             * - Every 10000 exits thereafter (low-overhead long-term monitoring)
             * Uses ring buffer only — safe in VMX root mode.
             */
            if ((Count <= 5000 && (Count % 100) == 0) ||
                (Count > 5000 && (Count % 10000) == 0)) {
                VMXROOT_LOG_INFO("HEARTBEAT CPU%u: count=%lld reason=%u qual=0x%llX RIP=0x%llX",
                           CpuIndex, Count, (ULONG)(ExitReason & 0xFFFF),
                           VmxRead(VMCS_EXIT_QUALIFICATION),
                           VmxRead(VMCS_GUEST_RIP));
            }

            /* Rapid-fire detection at 1K intervals (first 10K only) */
            if (Count - s_LastReportedCount[CpuIndex] >= 1000) {
                s_LastReportedCount[CpuIndex] = Count;
                if (Count <= 10000) {
                    VMXROOT_LOG_INFO("RAPID CPU%u: count=%lld reason=%u RIP=0x%llX",
                               CpuIndex, Count, (ULONG)(ExitReason & 0xFFFF),
                               VmxRead(VMCS_GUEST_RIP));
                }
            }
        }
    }

    /* Check if Guest requested an EPT TLB flush */
    EptCheckPendingInvept();

    /* Check for VM-Entry failure (bit 31) */
    if (ExitReason & 0x80000000) {
        VMXROOT_LOG_ERROR("VM-Entry failure! Reason: %u, Qualification: 0x%llX",
                  ExitReason & 0xFFFF, VmxRead(VMCS_EXIT_QUALIFICATION));
        /*
         * Mark CPU as no longer in VMX operation.
         * VmxShutdown ASM path will execute vmxoff and restore guest state.
         * We must clear both flags so VmxTerminate won't try vmcall or vmxoff.
         */
        if (CpuIndex < g_MaxProcessors) {
            g_VmxState.CpuContexts[CpuIndex].VmcsLaunched = FALSE;
            g_VmxState.CpuContexts[CpuIndex].VmxEnabled = FALSE;
        }
        return FALSE;   /* Shut down VMX */
    }

    /*
     * EARLY DIAGNOSTIC: Log the first N VM-Exits from each CPU.
     * Uses lock-free ring buffer (VMXROOT_LOG_*) — safe in VMX root mode.
     */
    {
        static volatile LONG s_EarlyLogCountPerCpu[64] = { 0 };
        if (CpuIndex < 64) {
            LONG EarlyCount = InterlockedIncrement(&s_EarlyLogCountPerCpu[CpuIndex]);
            if (EarlyCount <= 30) {
                USHORT Reason = (USHORT)(ExitReason & 0xFFFF);
                if (Reason == EXIT_REASON_RDMSR || Reason == EXIT_REASON_WRMSR) {
                    VMXROOT_LOG_INFO("VM-Exit CPU%u #%d: reason=%u (%s) MSR=0x%08X RIP=0x%llX",
                               CpuIndex, (int)EarlyCount, (ULONG)Reason,
                               Reason == EXIT_REASON_RDMSR ? "RDMSR" : "WRMSR",
                               (ULONG)GuestContext->Rcx,
                               VmxRead(VMCS_GUEST_RIP));
                } else {
                    VMXROOT_LOG_INFO("VM-Exit CPU%u #%d: reason=%u qual=0x%llX RIP=0x%llX",
                               CpuIndex, (int)EarlyCount, (ULONG)(ExitReason & 0xFFFF),
                               VmxRead(VMCS_EXIT_QUALIFICATION),
                               VmxRead(VMCS_GUEST_RIP));
                }
            }
        }
    }

    /* Dispatch by exit reason */
    switch (ExitReason & 0xFFFF) {

    case EXIT_REASON_CPUID:
        Result = HandleCpuid(GuestContext);
        break;

    case EXIT_REASON_RDMSR:
        Result = HandleRdmsr(GuestContext);
        break;

    case EXIT_REASON_WRMSR:
        Result = HandleWrmsr(GuestContext);
        break;

    case EXIT_REASON_CR_ACCESS:
        Result = HandleCrAccess(GuestContext);
        break;

    case EXIT_REASON_DR_ACCESS:
        Result = HandleDrAccess(GuestContext);
        break;

    case EXIT_REASON_EXCEPTION_NMI:
        Result = HandleException(GuestContext);
        break;

    case EXIT_REASON_EPT_VIOLATION:
        Result = HandleEptViol(GuestContext);
        break;

    case EXIT_REASON_EPT_MISCONFIG:
        Result = HandleEptMisconfig(GuestContext);
        break;

    case EXIT_REASON_MTF:
        Result = HandleMtf(GuestContext);
        break;

    case EXIT_REASON_VMCALL:
        Result = HandleVmcall(GuestContext);
        break;

    case EXIT_REASON_XSETBV:
        Result = HandleXsetbv(GuestContext);
        break;

    case EXIT_REASON_INVD:
        Result = HandleInvd(GuestContext);
        break;

    case EXIT_REASON_INVLPG:
        Result = HandleInvlpg(GuestContext);
        break;

    case EXIT_REASON_WBINVD:
        Result = HandleWbinvd(GuestContext);
        break;

    case EXIT_REASON_TRIPLE_FAULT:
        Result = HandleTripleFault(GuestContext);
        break;

    /* ===== VMX Instruction Intercepts (nested virtualization) ===== */
    /*
     * When the guest executes VMX/EPT/VPID instructions (VMXON, VMXOFF,
     * VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMREAD, VMRESUME, VMWRITE,
     * INVEPT, INVVPID), these unconditionally cause VM-Exit in VMX
     * non-root operation (Intel SDM Vol. 3C, Section 25.1.2).
     *
     * Since we don't implement full nested virtualization, inject #UD
     * to the guest. The CPUID handler already hides the VMX capability
     * bit (CPUID.1:ECX[5]), so well-behaved software won't attempt these.
     * This handles malicious or VMX-probing code gracefully.
     *
     * Note: VMCALL is handled separately above as our hypercall interface.
     */
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
        /* Inject #UD (vector 6) - no error code */
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                 6);  /* #UD vector */
        break;

    case EXIT_REASON_HLT:
        /*
         * HLT exit — Guest wants to sleep until an interrupt arrives.
         *
         * In nested virtualization (VMware), HLT_EXIT is forced by must-be-1
         * bits, so every Guest HLT causes a VM-Exit.
         *
         * IMPORTANT: We CANNOT execute native HLT in VMX root mode!
         * Doing _enable() + __halt() in VMX root would cause interrupts to
         * be delivered through the Host IDT while on the Host stack (16KB
         * ExAllocatePool buffer). This is catastrophic because:
         *   1. ISRs execute on our tiny Host stack → stack overflow risk
         *   2. ISR runs in the middle of our VM-Exit handler → corrupts
         *      local variables and call chain on the same stack
         *   3. ISR may call KeInsertQueueDpc/scheduler code that assumes
         *      a normal kernel thread stack with proper KPCR/KPRCB linkage
         *   4. IRET from ISR returns to our handler mid-execution with
         *      potentially corrupted state
         *
         * Strategy: Set Guest Activity State to "HLT" (value 1).
         * The CPU will enter Guest mode in HLT state. When an external
         * interrupt arrives, the CPU will VM-Exit with EXIT_REASON_HLT or
         * EXIT_REASON_EXTERNAL_INT (depending on PIN_BASED_EXTERNAL_INT_EXIT).
         * This achieves true CPU yielding without any VMX root mode risk.
         *
         * We do NOT advance Guest RIP — the HLT instruction is "completed"
         * by entering the HLT activity state. When the Guest wakes (via
         * interrupt injection or activity state change back to Active),
         * execution resumes at the instruction AFTER HLT automatically.
         *
         * NOTE: We advance RIP first, then set HLT state. This way, when
         * the CPU wakes from HLT (interrupt arrives → VM-Exit → we set
         * activity state back to Active → VMRESUME), Guest resumes at the
         * instruction after HLT, which is the correct behavior.
         */
        VmxAdvanceGuestRip();
        VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 1);  /* 1 = HLT */
        break;

    case EXIT_REASON_INVPCID:
        /*
         * INVPCID causes VM-Exit when both "INVLPG exiting" (primary bit 9)
         * and "enable INVPCID" (secondary bit 12) are set.
         * VmxAdjustControls may force "INVLPG exiting" on via must-be-1 bits.
         *
         * We just execute the equivalent INVLPG/INVPCID effect (full TLB
         * flush via INVVPID) and advance RIP.
         */
        {
            INVVPID_DESCRIPTOR VpidDesc;
            RtlZeroMemory(&VpidDesc, sizeof(VpidDesc));
            AsmVmxInvvpid(INVVPID_ALL_CONTEXTS, &VpidDesc);
        }
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_PREEMPT_TIMER:
        /* VMX-preemption timer expired. Just resume. */
        break;

    case EXIT_REASON_XSAVES:
    case EXIT_REASON_XRSTORS:
        /*
         * XSAVES/XRSTORS VM-Exit.
         * This should not happen if XSS exiting bitmap is 0, but handle
         * it gracefully: advance RIP and resume (instruction was not executed).
         * Guest will retry.
         * NOTE: Ideally we'd emulate the instruction, but for now just
         * re-inject #UD to let the guest fall back to a different path.
         */
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                 6);  /* #UD vector */
        break;

    case EXIT_REASON_GETSEC:
        /* GETSEC unconditionally causes VM-exit; inject #UD */
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                 6);
        break;

    case EXIT_REASON_RDPMC:
        /* RDPMC - inject #GP(0) if not supported, or pass through */
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                 INTERRUPT_INFO_DELIVER_ERR_CODE |
                 13);  /* #GP vector */
        VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, 0);
        break;

    case EXIT_REASON_MONITOR:
    case EXIT_REASON_MWAIT:
        /* MONITOR/MWAIT - just advance RIP and resume as NOPs */
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_PAUSE:
        /* PAUSE - just advance RIP */
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_GDTR_IDTR_ACCESS:
    case EXIT_REASON_LDTR_TR_ACCESS:
        /* Descriptor table accesses - advance RIP and resume */
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_APIC_ACCESS:
        /*
         * APIC access VM-Exit. This can happen if VMware forces
         * "APIC-register virtualization" or "virtualize APIC accesses"
         * via must-be-1 bits. Just advance RIP.
         */
        VmxAdvanceGuestRip();
        break;

    case EXIT_REASON_TPR_BELOW_THRESHOLD:
        /*
         * TPR below threshold - used for virtual APIC / CR8 monitoring.
         * Just resume, nothing to do.
         */
        break;

    case EXIT_REASON_TASK_SWITCH:
        /*
         * Task switch VM-Exit. Intel SDM: task switches unconditionally
         * cause VM-exit. This should be rare in 64-bit Windows, but can
         * happen (e.g., double-fault via task gate).
         *
         * For now, inject #GP to let the guest handle the error.
         * Full task switch emulation is extremely complex.
         */
        VMXROOT_LOG_WARN("Task switch VM-Exit: qual=0x%llX, RIP=0x%llX",
                 VmxRead(VMCS_EXIT_QUALIFICATION),
                 VmxRead(VMCS_GUEST_RIP));
        VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                 INTERRUPT_INFO_VALID |
                 (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
                 INTERRUPT_INFO_DELIVER_ERR_CODE |
                 13);  /* #GP */
        VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, 0);
        break;

    case EXIT_REASON_IO_INSTRUCTION:
        /*
         * I/O instruction intercept.
         *
         * If VmxAdjustControls forced "unconditional I/O exiting" (bit 24)
         * or "use I/O bitmaps" (bit 25) via must-be-1 bits, every IN/OUT
         * instruction will cause a VM-Exit. Without handling this, the guest
         * re-executes the instruction → VM-Exit → infinite loop → VMware hangs.
         *
         * We emulate by executing the I/O instruction natively in host mode.
         * NOTE: In nested VMware, executing I/O in VMX root is safe because
         * VMware (L0) handles its own I/O virtualization independently.
         *
         * Exit Qualification bits for I/O:
         *   Bits 2:0  = Size (0=1 byte, 1=2 bytes, 3=4 bytes)
         *   Bit 3     = Direction (0=OUT, 1=IN)
         *   Bit 4     = String instruction
         *   Bit 5     = REP prefixed
         *   Bit 6     = Operand encoding (0=DX, 1=immediate)
         *   Bits 31:16 = Port number
         */
        {
            ULONG64 IoQual = VmxRead(VMCS_EXIT_QUALIFICATION);
            USHORT  Port = (USHORT)((IoQual >> 16) & 0xFFFF);
            ULONG   Size = (ULONG)(IoQual & 0x7);
            BOOLEAN IsIn = (IoQual & (1 << 3)) != 0;
            BOOLEAN IsString = (IoQual & (1 << 4)) != 0;

            /*
             * DIAGNOSTIC: Log the first few I/O exits to identify which
             * ports are causing the VM-Exit storm.
             */
            {
                static volatile LONG s_IoExitLogCount = 0;
                LONG IoCount = InterlockedIncrement(&s_IoExitLogCount);
                if (IoCount <= 5) {
                    VMXROOT_LOG_INFO("IO Exit #%d: %s port=0x%04X size=%u string=%u RIP=0x%llX",
                             (int)IoCount,
                             IsIn ? "IN" : "OUT",
                             (ULONG)Port, Size, (ULONG)IsString,
                             VmxRead(VMCS_GUEST_RIP));
                }
            }

            if (!IsString) {
                /*
                 * Simple IN/OUT (not string) — emulate by executing the
                 * I/O in VMX root mode directly, WITHOUT __try/__except.
                 *
                 * CRITICAL: __try/__except (SEH) is UNSAFE in VMX root mode!
                 * The host stack (ExAllocatePoolWithTag'd 16KB buffer) is NOT
                 * a Windows thread kernel stack. SEH relies on walking the
                 * _EXCEPTION_REGISTRATION_RECORD chain on the thread stack,
                 * and NT's exception dispatcher validates stack boundaries.
                 * When SEH triggers on our host stack, the dispatcher follows
                 * invalid/zero-filled records → jumps to a stack address →
                 * executes zeroes (add byte ptr [rax], al) → BSOD 0x0A.
                 *
                 * In VMX root mode (CPL 0, no IOPL restriction), IN/OUT
                 * instructions execute without #GP for any port. The only
                 * risk is accessing non-existent hardware, which on x86
                 * simply returns 0xFF for IN (bus float) and is a NOP for OUT.
                 * VMware virtualizes all I/O ports, so no exception can occur.
                 */
                if (IsIn) {
                    ULONG Value = 0;
                    switch (Size) {
                    case 0: Value = __inbyte(Port); break;
                    case 1: Value = __inword(Port); break;
                    case 3: Value = __indword(Port); break;
                    }
                    /* IN puts result in AL/AX/EAX (lower bits of RAX) */
                    switch (Size) {
                    case 0: GuestContext->Rax = (GuestContext->Rax & ~0xFFULL) | (Value & 0xFF); break;
                    case 1: GuestContext->Rax = (GuestContext->Rax & ~0xFFFFULL) | (Value & 0xFFFF); break;
                    case 3: GuestContext->Rax = (ULONG64)(ULONG)Value; break;
                    }
                } else {
                    /* OUT */
                    ULONG Value = (ULONG)GuestContext->Rax;
                    switch (Size) {
                    case 0: __outbyte(Port, (UCHAR)Value); break;
                    case 1: __outword(Port, (USHORT)Value); break;
                    case 3: __outdword(Port, Value); break;
                    }
                }
            } else {
                /*
                 * String I/O (INS/OUTS) - complex to emulate properly
                 * (needs RSI/RDI/RCX handling with REP prefix).
                 * For now, just advance RIP. The instruction was not executed,
                 * so guest data may be wrong, but this is better than a hang.
                 */
                /* TODO: Full string I/O emulation */
            }
            VmxAdvanceGuestRip();
        }
        break;

    case EXIT_REASON_EXTERNAL_INT:
        /*
         * External interrupt VM-Exit.
         *
         * This occurs when PIN_BASED_EXTERNAL_INT_EXIT is set (forced by
         * must-be-1 bits in nested virtualization — VMware, Hyper-V).
         *
         * With ACK_INT_ON_EXIT enabled:
         *   - The interrupt is automatically acknowledged by the LAPIC
         *   - The vector is stored in EXIT_INTERRUPTION_INFO
         *
         * BUG FIX: The old code DISCARDED the interrupt entirely, which
         * caused critical failures:
         *   - IPIs (inter-processor interrupts) are one-shot — discarding them
         *     means DPC dispatch, TLB shootdowns, and CPU wake-ups are lost
         *   - Timer interrupts lost → scheduler stalls → system freezes
         *   - This was a major contributor to the "VMware hangs" symptom
         *
         * Fix: Re-inject the interrupt into the Guest via VM-Entry interruption
         * info. The vector from EXIT_INTERRUPTION_INFO is re-packed as an
         * external interrupt injection for VM-Entry.
         *
         * If Guest RFLAGS.IF=0 (interrupts disabled), we cannot inject
         * immediately. Set "interrupt-window exiting" and defer.
         *
         * HLT Activity State handling: If Guest was in HLT state (set by our
         * HLT handler), injecting an external interrupt at VM-Entry causes
         * hardware to automatically transition Activity State from HLT to
         * Active (Intel SDM Vol. 3C, 26.6.2). For the deferred path (IF=0),
         * we must explicitly reset Activity State to Active so the Guest can
         * execute and eventually enable interrupts.
         */
        {
            ULONG64 IntInfo = VmxRead(VMCS_EXIT_INTERRUPTION_INFO);
            if (IntInfo & INTERRUPT_INFO_VALID) {
                ULONG Vector = (ULONG)(IntInfo & INTERRUPT_INFO_VECTOR_MASK);
                ULONG64 GuestRflags = VmxRead(VMCS_GUEST_RFLAGS);
                ULONG64 Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);
                ULONG64 ActivityState = VmxRead(VMCS_GUEST_ACTIVITY_STATE);

                /*
                 * Check if Guest can accept the interrupt:
                 *   - RFLAGS.IF must be 1
                 *   - No blocking by STI or MOV SS
                 */
                if ((GuestRflags & (1ULL << 9)) &&
                    !(Interruptibility & 0x3)) {
                    /* Guest is interruptible — inject immediately.
                     * If Guest was in HLT state, hardware auto-transitions
                     * to Active when injecting an external interrupt. */
                    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                             INTERRUPT_INFO_VALID |
                             (INTERRUPT_TYPE_EXTERNAL << INTERRUPT_INFO_TYPE_SHIFT) |
                             Vector);
                } else {
                    /*
                     * Guest has interrupts disabled (CLI / STI shadow / MOV SS).
                     * We cannot inject now. Save the vector and request an
                     * interrupt-window exit to inject when IF becomes 1.
                     *
                     * NOTE: We store only one pending interrupt per CPU.
                     * If another external interrupt arrives before injection,
                     * the older one is lost. In practice this is acceptable
                     * because VMware coalesces rapid external interrupts.
                     */
                    if (CpuIndex < g_MaxProcessors) {
                        g_VmxState.CpuContexts[CpuIndex].PendingInterrupt = TRUE;
                        g_VmxState.CpuContexts[CpuIndex].PendingInterruptVector = Vector;
                    }

                    /* Enable interrupt-window exiting */
                    {
                        ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
                        ProcBased |= PROC_BASED_INT_WINDOW_EXIT;
                        VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
                    }

                    /*
                     * If Guest was in HLT activity state, we MUST reset it to
                     * Active (0). Otherwise the CPU stays halted and can never
                     * execute instructions to enable interrupts (STI), so the
                     * interrupt-window exit would never fire → permanent hang.
                     */
                    if (ActivityState == 1) {
                        VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 0);
                    }
                }
            }
            /* If IntInfo is not valid (shouldn't happen with ACK_INT_ON_EXIT),
             * the interrupt was not acknowledged — it stays pending in the LAPIC
             * and will be delivered to Guest on next VMRESUME when IF=1. */
        }
        break;

    case EXIT_REASON_INT_WINDOW:
        /*
         * Interrupt window exit — Guest is now ready to accept interrupts.
         *
         * This fires because we set PROC_BASED_INT_WINDOW_EXIT when an
         * external interrupt arrived while Guest had IF=0. Now IF=1 and
         * we can inject the deferred interrupt.
         *
         * BUG FIX: Old code just cleared the bit. New code injects the
         * pending interrupt that was saved in CpuContext.
         */
        {
            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased &= ~PROC_BASED_INT_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

            /* Inject pending interrupt if any */
            if (CpuIndex < g_MaxProcessors &&
                g_VmxState.CpuContexts[CpuIndex].PendingInterrupt) {
                ULONG Vector = g_VmxState.CpuContexts[CpuIndex].PendingInterruptVector;
                g_VmxState.CpuContexts[CpuIndex].PendingInterrupt = FALSE;

                VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                         INTERRUPT_INFO_VALID |
                         (INTERRUPT_TYPE_EXTERNAL << INTERRUPT_INFO_TYPE_SHIFT) |
                         Vector);
            }
        }
        break;

    case EXIT_REASON_NMI_WINDOW:
        /*
         * NMI window opened: Guest is now ready to accept NMIs.
         * This exit fires because we deferred NMI injection when "blocking
         * by NMI" was set in HandleException.
         *
         * FIX v2: Record injection fingerprint BEFORE writing ENTRY_INT_INFO
         * so the echo of this delayed injection can be matched by Signal A
         * on a future NMI VM-Exit.
         */
        {
            ULONG   DeferredCpuIdx;
            LONG64  DeferredTsc;
            NMI_FINGERPRINT DeferredFp;

            DeferredCpuIdx = KeGetCurrentProcessorNumber();
            DeferredTsc    = __rdtsc();
            DeferredFp.GuestRip = VmxRead(VMCS_GUEST_RIP);
            DeferredFp.GuestRsp = VmxRead(VMCS_GUEST_RSP);

            /* Record in map BEFORE injection (same as immediate path) */
            NmiRecordInjection(DeferredCpuIdx, &DeferredFp, DeferredTsc);

            /* Clear NMI-window exiting bit */
            {
                ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
                ProcBased &= ~PROC_BASED_NMI_WINDOW_EXIT;
                VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);
            }

            /* Update tracking state */
            if (DeferredCpuIdx < 64) {
                g_DiagNmiTimestamp[DeferredCpuIdx] = DeferredTsc;
                g_DiagNmiLastGuestRipAfterNmi[DeferredCpuIdx] = DeferredFp.GuestRip;
            }

            /* Inject the deferred NMI */
            VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                     INTERRUPT_INFO_VALID |
                     (INTERRUPT_TYPE_NMI << INTERRUPT_INFO_TYPE_SHIFT) |
                     2);  /* NMI vector */

            LOG_INFO("NMI INJECT [deferred/window] CPU%u: rip=0x%llX rsp=0x%llX tsc=%lld",
                     DeferredCpuIdx, DeferredFp.GuestRip, DeferredFp.GuestRsp, DeferredTsc);
        }
        break;

    default:
        /*
         * BUG FIX: Unknown VM-Exit handling with AGGRESSIVE loop protection.
         *
         * If the same exit reason fires repeatedly at the same RIP, we're
         * in an infinite loop (instruction re-executes → same VM-Exit →
         * resume → repeat). This makes VMware appear to "hang".
         *
         * At 3 repetitions we shut down immediately.
         */
        {
            static volatile LONG s_UnhandledCount = 0;
            static volatile ULONG64 s_LastUnhandledRip = 0;
            static volatile ULONG s_LastUnhandledReason = 0;
            ULONG64 GuestRip = VmxRead(VMCS_GUEST_RIP);
            ULONG Reason = ExitReason & 0xFFFF;

            if (Reason == s_LastUnhandledReason && GuestRip == s_LastUnhandledRip) {
                LONG Count = InterlockedIncrement(&s_UnhandledCount);
                if (Count >= 3) {
                    VMXROOT_LOG_ERROR("FATAL: Infinite VM-Exit loop! reason=%u, "
                              "qual=0x%llX, RIP=0x%llX, count=%d - SHUTTING DOWN VMX",
                              Reason, VmxRead(VMCS_EXIT_QUALIFICATION),
                              GuestRip, (int)Count);
                    Result = FALSE;
                    break;
                }
            } else {
                s_LastUnhandledReason = Reason;
                s_LastUnhandledRip = GuestRip;
                s_UnhandledCount = 1;

                /* First occurrence of a new unhandled exit: log details */
                VMXROOT_LOG_WARN("Unhandled VM-Exit: reason=%u, qual=0x%llX, RIP=0x%llX, CPU=%u",
                         Reason, VmxRead(VMCS_EXIT_QUALIFICATION),
                         GuestRip, CpuIndex);
            }

            /*
             * For the first few occurrences, try to advance RIP to avoid
             * infinite loop while we're still diagnosing.
             */
            VmxAdvanceGuestRip();
        }
        break;
    }

    /*
     * DIAGNOSTIC: Confirm handler completion for first 10 exits per CPU.
     */
    {
        static volatile LONG s_DoneLogCount[64] = { 0 };
        if (CpuIndex < 64) {
            LONG DoneCount = InterlockedIncrement(&s_DoneLogCount[CpuIndex]);
            if (DoneCount <= 10) {
                VMXROOT_LOG_INFO("DONE CPU%u #%d: reason=%u result=%d",
                           CpuIndex, (int)DoneCount,
                           (ULONG)(ExitReason & 0xFFFF), (int)Result);
            }
        }
    }

    /*
     * Write back Guest RSP to VMCS before VMRESUME.
     * Any handler that modified GuestContext->Rsp (e.g., DR access with
     * GpReg==4, CR access) will have the change applied to VMCS here.
     */
    VmxWrite(VMCS_GUEST_RSP, GuestContext->Rsp);

    return Result;
}

/* ========================================================================= */
/*  VMRESUME Failure Handler (called from ASM)                               */
/* ========================================================================= */

/*
 * VmxResumeFailedHandler - Called when vmresume fails.
 * This is invoked from AsmVmxExitHandler's VmxResumeFailed path.
 * We're still in VMX root mode, so VMCS reads still work.
 */
VOID VmxResumeFailedHandler(ULONG64 VmInstructionError)
{
    ULONG64 GuestRip = 0, GuestRsp = 0, ExitReason = 0;

    /*
     * Read VMCS fields directly WITHOUT __try/__except.
     *
     * CRITICAL: __try/__except (SEH) is UNSAFE in VMX root mode!
     * The host stack is not a thread kernel stack, so SEH's exception
     * registration chain is invalid here. If vmread fails, it simply
     * sets CF/ZF flags — it does NOT generate an x86 exception.
     * Therefore __try/__except was never needed here in the first place.
     *
     * vmread only fails if:
     *   - Not in VMX operation (impossible — we're called from VM-Exit handler)
     *   - Invalid field encoding (impossible — these are standard encodings)
     * In both cases, the values remain 0 (our initializers above).
     */
    GuestRip = VmxRead(VMCS_GUEST_RIP);
    GuestRsp = VmxRead(VMCS_GUEST_RSP);
    ExitReason = VmxRead(VMCS_EXIT_REASON);

    /*
     * This is a fatal path — we're about to vmxoff + hlt, so
     * we need maximum chance of the message reaching WinDbg.
     */
    VMXROOT_LOG_ERROR("*** VMRESUME FAILED *** VM-instruction error: %llu, "
              "Guest RIP: 0x%llX, RSP: 0x%llX, Last exit reason: %llu, CPU: %u",
              VmInstructionError, GuestRip, GuestRsp,
              ExitReason & 0xFFFF, KeGetCurrentProcessorNumber());
}

/* ========================================================================= */
/*  Individual Exit Handlers                                                 */
/* ========================================================================= */

/* CPUID - delegate to anti-anti-debug engine */
static BOOLEAN HandleCpuid(PGUEST_CONTEXT Ctx)
{
    return AadHandleCpuid(Ctx);
}

/* RDMSR */
static BOOLEAN HandleRdmsr(PGUEST_CONTEXT Ctx)
{
    return HandleRdmsrImpl(Ctx);
}

/* WRMSR */
static BOOLEAN HandleWrmsr(PGUEST_CONTEXT Ctx)
{
    return HandleWrmsrImpl(Ctx);
}

/*
 * CR Access - primarily for CR3 load monitoring (process switch detection)
 */
static BOOLEAN HandleCrAccess(PGUEST_CONTEXT Ctx)
{
    ULONG64     ExitQual;
    ULONG       CrNum;
    ULONG       AccessType;
    ULONG       GpReg;
    ULONG64     NewValue;
    ULONG64     ShadowValue;

    ExitQual = VmxRead(VMCS_EXIT_QUALIFICATION);
    CrNum     = (ULONG)(ExitQual & CR_ACCESS_CR_NUM_MASK);
    AccessType = (ULONG)((ExitQual >> CR_ACCESS_TYPE_SHIFT) & 0x3);
    GpReg     = (ULONG)((ExitQual >> CR_ACCESS_GP_REG_SHIFT) & CR_ACCESS_GP_REG_MASK);

    switch (AccessType) {
    case CR_ACCESS_TYPE_MOV_TO_CR:
        NewValue = GetGpRegValue(Ctx, GpReg);

        if (CrNum == 3) {
            /* CR3 load - process switch */
            VmxWrite(VMCS_GUEST_CR3, NewValue);

            /* Update hardware TSC Offset for the new process context */
            AadUpdateHwTscOffset(NewValue);

            /* DIAGNOSTIC: Log first few CR3 switches to confirm normal operation */
            {
                static volatile LONG s_Cr3SwitchCount = 0;
                LONG Cr3Count = InterlockedIncrement(&s_Cr3SwitchCount);
                if (Cr3Count <= 5) {
                    LOG_INFO("CR3 switch #%d: new CR3=0x%llX CPU=%u",
                             (int)Cr3Count, NewValue, KeGetCurrentProcessorNumber());
                }
            }
        }
        else if (CrNum == 0) {
            /*
             * BUG FIX (Problem B): CR0 ReadShadow must store the Guest's
             * original value, not the VMX-adjusted value. This way, when
             * Guest reads CR0 (MOV from CR0), it sees what it wrote, not
             * the value with VMX fixed bits forced. The actual Guest CR0
             * field stores the adjusted value required by VMX operation.
             *
             * Intel SDM Vol. 3C, Section 25.1.3: "Bits owned by the host
             * are returned from the corresponding read shadow."
             */
            ShadowValue = NewValue;                      /* Guest's original value */
            NewValue |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
            NewValue &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
            VmxWrite(VMCS_GUEST_CR0, NewValue);
            VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, ShadowValue);  /* shadow = original */
        }
        else if (CrNum == 4) {
            /* Keep VMXE bit set in actual CR4, but hide from guest */
            ULONG64 ActualCr4 = NewValue | CR4_VMXE;
            VmxWrite(VMCS_GUEST_CR4, ActualCr4);
            VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, NewValue);
        }
        break;

    case CR_ACCESS_TYPE_MOV_FROM_CR:
        if (CrNum == 3) {
            SetGpRegValue(Ctx, GpReg, VmxRead(VMCS_GUEST_CR3));
        }
        else if (CrNum == 0) {
            SetGpRegValue(Ctx, GpReg, VmxRead(VMCS_CTRL_CR0_READ_SHADOW));
        }
        else if (CrNum == 4) {
            /* Return CR4 without VMXE to hide VMX from guest */
            SetGpRegValue(Ctx, GpReg, VmxRead(VMCS_CTRL_CR4_READ_SHADOW));
        }
        break;

    case CR_ACCESS_TYPE_CLTS:
        /* CLTS - clear Task Switched flag in CR0 */
        {
            ULONG64 Cr0 = VmxRead(VMCS_GUEST_CR0);
            Cr0 &= ~(1ULL << 3);  /* Clear TS bit */
            VmxWrite(VMCS_GUEST_CR0, Cr0);
        }
        break;

    case CR_ACCESS_TYPE_LMSW:
        /* LMSW - load machine status word (low 16 bits of CR0) */
        {
            ULONG64 Cr0 = VmxRead(VMCS_GUEST_CR0);
            USHORT  Msw = (USHORT)(ExitQual >> 16);
            Cr0 = (Cr0 & ~0xFFFFULL) | Msw;
            Cr0 |= CR0_PE;  /* PE cannot be cleared by LMSW */
            /*
             * BUG FIX (Problem G): Apply VMX CR0 fixed bits.
             *
             * VMX requires certain CR0 bits to always be 1 (e.g., NE) and
             * certain bits to always be 0. If LMSW modifies these restricted
             * bits without adjustment, the next VM-Entry will fail because
             * Guest CR0 violates fixed bit constraints.
             *
             * Intel SDM Vol. 3C, Section 26.3.1.1:
             * "If the value of bit X of CR0 is fixed to Y in VMX operation,
             *  then the corresponding bit in the guest CR0 field must be Y."
             */
            Cr0 |= __readmsr(MSR_IA32_VMX_CR0_FIXED0);
            Cr0 &= __readmsr(MSR_IA32_VMX_CR0_FIXED1);
            VmxWrite(VMCS_GUEST_CR0, Cr0);
        }
        break;
    }

    VmxAdvanceGuestRip();
    return TRUE;
}

/* DR Access - delegate to anti-anti-debug.
 * NOTE: With MOV_DR_EXIT disabled in VMCS setup, this handler should
 * NOT fire. If it does fire (due to must-be-1 bits forcing DR exiting),
 * AadHandleDrAccess still handles it correctly by passing through the
 * real DR values (since no target process is set). */
static BOOLEAN HandleDrAccess(PGUEST_CONTEXT Ctx)
{
    return AadHandleDrAccess(Ctx);
}

/* Exception/NMI — Production-grade discrimination + anti-anti-debug delegation */
static BOOLEAN HandleException(PGUEST_CONTEXT Ctx)
{
    ULONG64 IntInfo = VmxRead(VMCS_EXIT_INTERRUPTION_INFO);
    ULONG   IntType = (ULONG)((IntInfo & INTERRUPT_INFO_TYPE_MASK) >> INTERRUPT_INFO_TYPE_SHIFT);

    /*
     * PRODUCTION-GRADE NMI DISCRIMINATION AND HANDLING
     *
     * Goal: Distinguish real hardware NMIs from virtualization-artifact NMIs.
     * Real hardware NMIs MUST be forwarded to Guest OS (KiNmiInterrupt).
     * Virtualization artifacts MUST be silently dropped to prevent loops.
     *
     * Architecture: Per-CPU Hash Map with multi-slot injection tracking.
     *
     * Discrimination signals (all deterministic):
     *   Signal A — Echo match via hash fingerprint correlation
     *              (RIP proximity + TSC window check in map lookup)
     *   Signal B — Exit Qualification bit 11 (IRET unblocking)
     *   Signal C — IDT Vectoring Information field validity
     *   Signal D — Guest RIP stasis detection
     */
    if (IntType == INTERRUPT_TYPE_NMI) {
        ULONG64 Interruptibility;
        ULONG64 ExitQual;
        ULONG64 IdtVectoringInfo;
        ULONG64 GuestRsp;
        ULONG   CpuIdx;
        LONG64  NowTsc;
        LONG    TotalNmi;
        BOOLEAN IsArtifact;      /* TRUE if proven virtualization artifact */
        ULONG   ArtifactReasons; /* Bitfield: which signals triggered */
        NMI_FINGERPRINT CurrentFp;
        LONG EchoMatchSeq;

        /* C89: All variable declarations at block start */
        Interruptibility = VmxRead(VMCS_GUEST_INTERRUPTIBILITY);
        ExitQual         = VmxRead(VMCS_EXIT_QUALIFICATION);
        IdtVectoringInfo = VmxRead(VMCS_IDT_VECTORING_INFO);
        CurrentFp.GuestRip = VmxRead(VMCS_GUEST_RIP);
        CurrentFp.GuestRsp = VmxRead(VMCS_GUEST_RSP);
        CpuIdx           = KeGetCurrentProcessorNumber();
        NowTsc           = __rdtsc();
        if (CpuIdx < 64) {
            TotalNmi = InterlockedIncrement(&g_DiagNmiTotalCount[CpuIdx]);
        } else {
            static volatile LONG s_FallbackCount = 0;
            TotalNmi = InterlockedIncrement(&s_FallbackCount);
        }
        IsArtifact       = FALSE;
        ArtifactReasons  = 0;
        EchoMatchSeq    = -1;

        /* Log first 5 NMIs with full diagnostic detail */
        if (TotalNmi <= 5) {
            LOG_INFO("NMI #%d cpu=%u intinfo=0x%llX qual=0x%llX "
                     "idt_vec=0x%llX intr=0x%llX blocked=%u "
                     "rip=0x%llX rsp=0x%llX tsc=%lld hash=0x%llX",
                     (int)TotalNmi, CpuIdx, IntInfo, ExitQual,
                     IdtVectoringInfo, Interruptibility,
                     (ULONG)((Interruptibility >> 3) & 1),
                     CurrentFp.GuestRip, CurrentFp.GuestRsp,
                     NowTsc, NmiComputeHash(&CurrentFp));
        }

        /* ====================================================================
         * NESTED VIRT NMI SUPPRESSION
         *
         * In nested virtualization (VMware, KVM, etc.), NMI VM-Exits are
         * almost always artifacts of the L0 ↔ L1 interaction:
         *
         *   L1 injects NMI → L0 re-delivers as VM-Exit → L1 injects again
         *   → infinite loop → both vCPUs consumed → VM freeze
         *
         * The discrimination signals (A-D) and rate limiter are insufficient
         * because even allowing a FEW NMI reinjections per second creates
         * thousands of VM-Exits (each injection echoes back), and the
         * cumulative L1→L0→L1 round-trip overhead freezes the VM.
         *
         * Real hardware NMIs (ECC errors, watchdog, etc.) are handled by
         * L0 (VMware/KVM) directly — they never reach L1 as VM-Exits.
         * NMIs that DO reach our L1 handler are exclusively:
         *   - Echo bounces from our own injections
         *   - Virtual NMIs generated by L0 for internal bookkeeping
         *   - IRET-unblocking artifacts
         *
         * Fix: When running under an outer hypervisor, drop ALL NMIs
         * unconditionally.  Zero injections = zero echoes = zero storms.
         * ==================================================================== */
        if (g_OuterHypervisorPresent) {
            if (CpuIdx < 64) {
                InterlockedIncrement(&g_DiagNmiDroppedCount[CpuIdx]);
            }

            if (TotalNmi <= 5 || (TotalNmi % 10000 == 0)) {
                LOG_WARN("NMI NESTED-DROP CPU%u #%d: rip=0x%llX (outer HV present, all NMIs suppressed)",
                         CpuIdx, (int)TotalNmi, CurrentFp.GuestRip);
            }
            return TRUE;  /* Drop — do NOT reinject */
        }

        /* ====================================================================
         * DISCRIMINATION PHASE: Determine if this NMI is real or artifact
         * ==================================================================== */

        /*
         * SIGNAL A — Echo Match via Hash Map Lookup
         *
         * Search all per-CPU slots for a pending injection whose fingerprint
         * correlates with the current NMI (RIP proximity + TSC window).
         * If found: this NMI IS the echo of our own injection → artifact.
         *
         * Key advantage over naive boolean flag:
         *   Independent NMIs from L0 do NOT consume a pending slot — only
         *   true echoes (matching RIP+TSC) are accepted as matches.
         */
        if (NmiLookupEcho(CpuIdx, &CurrentFp, NowTsc, &EchoMatchSeq)) {
            IsArtifact = TRUE;
            ArtifactReasons |= 0x01;  /* bit 0 = Signal A */
            LOG_WARN("NMI ARTIFACT [A-echo-match] CPU%u #%d: seq=%d",
                     CpuIdx, (int)TotalNmi, (int)EchoMatchSeq);
        }

        /*
         * SIGNAL B — Exit Qualification bit 11 (NMI-unblocking due to IRET)
         *
         * Intel SDM Table 27-3, EXIT_QUALIFICATION for Exception/NMI:
         *   bit 11 = NMI-unblocking due to IRET
         * When set: Guest executed IRET which cleared NMI blocking → CPU
         * delivers the deferred/pending NMI. This is NOT a new hardware event.
         * In nested virtualization, L0 may generate these spuriously.
         */
        if (!IsArtifact && (ExitQual & (1ULL << 11))) {
            IsArtifact = TRUE;
            ArtifactReasons |= 0x02;  /* bit 1 = Signal B */
            LOG_WARN("NMI ARTIFACT [B-IRET-unblock] CPU%u #%d: qual=0x%llX",
                     CpuIdx, (int)TotalNmi, ExitQual);
        }

        /*
         * SIGNAL C — IDT Vectoring Info during NMI exit
         *
         * Intel SDM 26.6.1: If VMCS field IDT_VECTORING_INFO has VALID bit
         * set when NMI exits, it means the CPU was already delivering an
         * event (exception/interrupt) through IDT when NMI occurred.
         * Real hardware NMIs don't typically arrive during IDT delivery.
         * In nested virt, indicates L0's virtual NMI injection colliding
         * with another L0-injected event.
         */
        if (!IsArtifact && (IdtVectoringInfo & INTERRUPT_INFO_VALID)) {
            IsArtifact = TRUE;
            ArtifactReasons |= 0x04;  /* bit 2 = Signal C */
            LOG_WARN("NMI ARTIFACT [C-IDT-vectoring] CPU%u #%d: idt_vec=0x%llX",
                     CpuIdx, (int)TotalNmi, IdtVectoringInfo);
        }

        /*
         * SIGNAL D — Guest RIP Stasis Detection (with grace-period guard)
         *
         * After injecting NMI, Guest should enter KiNmiInterrupt and execute
         * thousands of instructions before returning. If Guest RIP hasn't
         * advanced beyond the last known RIP (within ±128 bytes), Guest made
         * no progress since last NMI — likely trapped in injection loop.
         *
         * FIX v2: Grace-period guard to protect real HW NMIs that arrive
         * during active injection windows.
         *
         * Problem: If we inject NMI at RIP=X, then a genuine HW NMI fires
         * before Guest executes much code (Guest still near RIP=X), the old
         * Signal D would kill this real HW NMI as "stasis" artifact.
         *
         * Fix: Require a minimum time gap (NMI_D_GRACE_PERIOD_TSC cycles,
         * ~100us @3GHz) between our last injection timestamp and now. If the
         * NMI arrived too quickly after injection, it's almost certainly a
         * real hardware event (echoes need at least one VM-Entry/VM-Exit
         * round-trip which takes longer), so we skip Signal D entirely
         * to avoid false positive on legitimate HW NMIs.
         */
#define NMI_D_GRACE_PERIOD_TSC    300000  /* ~100us @3GHz: min time before D activates */
        if (!IsArtifact && CpuIdx < 64 &&
            g_DiagNmiLastGuestRipAfterNmi[CpuIdx] != 0) {
            LONG64 TimeSinceLastInject = NowTsc - g_DiagNmiTimestamp[CpuIdx];
            if (TimeSinceLastInject > (LONG64)NMI_D_GRACE_PERIOD_TSC) {
                /* Grace period elapsed: safe to check RIP stasis */
                LONG64 RipDelta = (LONG64)(CurrentFp.GuestRip -
                                  g_DiagNmiLastGuestRipAfterNmi[CpuIdx]);
                if (RipDelta > -NMI_RIP_STASIS_THRESHOLD &&
                    RipDelta <  NMI_RIP_STASIS_THRESHOLD) {
                    IsArtifact = TRUE;
                    ArtifactReasons |= 0x08;  /* bit 3 = Signal D */
                    LOG_WARN("NMI ARTIFACT [D-RIP-stasis] CPU%u #%d: "
                             "rip=0x%llX last=0x%llX delta=%lld tsc_since=%lld",
                             CpuIdx, (int)TotalNmi, CurrentFp.GuestRip,
                             g_DiagNmiLastGuestRipAfterNmi[CpuIdx], RipDelta,
                             TimeSinceLastInject);
                }
            } else if (TotalNmi <= 30 || (TotalNmi % 500 == 0)) {
                /*
                 * DIAGNOSTIC v2: Log when Signal D is skipped by grace period.
                 * This proves Fix #3 is working — a real HW NMI arrived during
                 * the active injection window and was protected from D's
                 * stasis false-positive.
                 */
                LOG_WARN("NMI SIGNAL-D [grace-skip] CPU%u #%d: "
                         "tsc_since=%lld < threshold=%ld rip=0x%llX",
                         CpuIdx, (int)TotalNmi, TimeSinceLastInject,
                         (LONG)NMI_D_GRACE_PERIOD_TSC, CurrentFp.GuestRip);
            }
        }

        /* ====================================================================
         * DECISION PHASE
         * ==================================================================== */

        if (IsArtifact) {
            /* PROVEN ARTIFECT: Drop silently, do NOT reinject */
            if (CpuIdx < 64) {
                InterlockedIncrement(&g_DiagNmiDroppedCount[CpuIdx]);
                g_DiagNmiTimestamp[CpuIdx] = NowTsc;
            }

            if (TotalNmi <= 30 || (TotalNmi % 1000 == 0)) {
                LOG_WARN("NMI DROP CPU%u #%d: reasons=0x%X dropped=%d",
                         CpuIdx, (int)TotalNmi, (unsigned)ArtifactReasons,
                         CpuIdx < 64 ? g_DiagNmiDroppedCount[CpuIdx] : 0);
            }
            return TRUE;  /* Resume without reinjection */
        }

        /*
         * REAL HARDWARE NMI:
         * None of the artifact signals fired → treat as legitimate hardware
         * NMI and forward to Guest OS (KiNmiInterrupt handles ECC errors,
         * watchdog events, etc.)
         *
         * DIAGNOSTIC v2: Log the forward decision with full context.
         * This is the critical path — proves real NMIs are not being
         * silently dropped by our discriminator. Search for this tag
         * in WinDbg output to count how many HW NMIs reach Guest OS.
         */
        LOG_INFO("NMI [REAL-HW-FORWARD] CPU%u #%d: rip=0x%llX rsp=0x%llX tsc=%lld "
                 "(all 4 signals negative → injecting to Guest)",
                 CpuIdx, (int)TotalNmi,
                 CurrentFp.GuestRip, CurrentFp.GuestRsp, NowTsc);

        /* Update tracking state before injection */
        if (CpuIdx < 64) {
            g_DiagNmiTimestamp[CpuIdx] = NowTsc;
            g_DiagNmiLastGuestRipAfterNmi[CpuIdx] = CurrentFp.GuestRip;
        }

        if (!(Interruptibility & (1ULL << 3))) {
            /* Not blocked by NMI: safe to inject immediately.
             * Record fingerprint in map BEFORE writing ENTRY_INT_INFO so
             * the echo can be correlated on next NMI exit. */
            NmiRecordInjection(CpuIdx, &CurrentFp, NowTsc);

            LOG_INFO("NMI INJECT CPU%u #%d: rip=0x%llX rsp=0x%llX tsc=%lld",
                     CpuIdx, (int)TotalNmi,
                     CurrentFp.GuestRip, CurrentFp.GuestRsp, NowTsc);

            VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
                     INTERRUPT_INFO_VALID |
                     (INTERRUPT_TYPE_NMI << INTERRUPT_INFO_TYPE_SHIFT) |
                     2);  /* NMI vector */
        } else {
            /* Blocked by NMI: request NMI-window exiting for deferred injection */
            ULONG64 ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
            ProcBased |= PROC_BASED_NMI_WINDOW_EXIT;
            VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

            /*
             * DIAGNOSTIC v2: Log deferred injection request.
             * The actual injection will happen in EXIT_REASON_NMI_WINDOW handler
             * which now also calls NmiRecordInjection and logs there.
             * This log helps correlate: NMI INJECT[deferred] → NMI-WINDOW exit
             * → NMI INJECT[deferred/window] with matching RIP/RSP.
             */
            LOG_INFO("NMI INJECT [deferred] CPU%u #%d: rip=0x%llX rsp=0x%llX tsc=%lld "
                     "(waiting for NMI window)",
                     CpuIdx, (int)TotalNmi,
                     CurrentFp.GuestRip, CurrentFp.GuestRsp, NowTsc);

            /* If Guest was in HLT state, wake it so NMI-window can fire */
            {
                ULONG64 ActivityState = VmxRead(VMCS_GUEST_ACTIVITY_STATE);
                if (ActivityState == 1) {
                    VmxWrite(VMCS_GUEST_ACTIVITY_STATE, 0);
                }
            }
        }
        return TRUE;
    }

    return AadHandleException(Ctx);
}

/* EPT Violation - delegate to EPT module */
static BOOLEAN HandleEptViol(PGUEST_CONTEXT Ctx)
{
    return HandleEptViolation(Ctx);
}

/* EPT Misconfiguration - critical error */
static BOOLEAN HandleEptMisconfig(PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    LOG_ERROR("EPT misconfiguration at GPA=0x%llX, GuestRIP=0x%llX",
              VmxRead(VMCS_GUEST_PHYSICAL_ADDRESS),
              VmxRead(VMCS_GUEST_RIP));

    /* This is a fatal error - stop VMX */
    return FALSE;
}

/*
 * Monitor Trap Flag - single-step completed.
 * Used by EPT hook engine to restore hook page after a read/write.
 *
 * BUG FIX: The original code restored ALL hooks globally, which caused a
 * multi-core race condition.  For example:
 *   - CPU 0 triggers EPT violation on hook A → switches to permissive → MTF
 *   - CPU 1 triggers EPT violation on hook B → switches to permissive
 *   - CPU 0's MTF fires → restores ALL hooks including B
 *   - CPU 1 hasn't finished executing its instruction → re-faults → infinite loop
 *
 * Fix: Each CPU only restores the specific hook(s) on pages that IT made
 * permissive.  We use a per-CPU tracking array (in ept.c) to record which
 * physical page was relaxed.  The MTF handler queries it and only restores
 * hooks on that specific page.
 */
static BOOLEAN HandleMtf(PGUEST_CONTEXT Ctx)
{
    ULONG64 ProcBased;
    ULONG64 RelaxedPa;
    ULONG   CpuIndex;

    UNREFERENCED_PARAMETER(Ctx);

    CpuIndex = KeGetCurrentProcessorNumber();

    /* Disable MTF */
    ProcBased = VmxRead(VMCS_CTRL_PROC_BASED_VM_EXEC);
    ProcBased &= ~PROC_BASED_MONITOR_TRAP_FLAG;
    VmxWrite(VMCS_CTRL_PROC_BASED_VM_EXEC, ProcBased);

    /* Get which page THIS CPU relaxed (stored by HandleEptViolation) */
    RelaxedPa = EptMtfGetAndClearRelaxedPage();

    /*
     * Restore hook on the page this CPU relaxed.
     *
     * OPTIMIZATION: Use O(1) hash table lookup instead of O(n) linear scan.
     * The previous code iterated over all MAX_EPT_HOOKS (1024) entries on
     * every MTF exit — a hot path in VMX root mode. Since hooks are indexed
     * by physical page address and only ONE hook can exist per 4KB page, a
     * single hash lookup suffices.
     *
     * When RelaxedPa is 0 (shouldn't happen — indicates a logic error),
     * we fall back to the O(n) scan as a safety measure.
     *
     * Per-CPU hook page isolation: use this CPU's private PTE so that
     * restoring permissions only affects THIS CPU's EPT translation.
     * Other CPUs' temporarily relaxed PTEs remain untouched.
     */
    if (RelaxedPa != 0) {
        /* O(1) path: direct hash lookup for the specific hooked page */
        PEPT_HOOK_ENTRY Hook = EptFindHookByPhysicalAddress(RelaxedPa);
        if (Hook && Hook->Active && Hook->TargetPte) {
            PEPT_PTE Pte = EptGetPerCpuPte(CpuIndex, Hook->TargetPhysicalAddr);
            if (!Pte) Pte = Hook->TargetPte;

            if (Pte->Read || Pte->Write) {
                Pte->Read = 0;
                Pte->Write = 0;
                Pte->PhysAddr = Hook->HookPagePa >> 12;

                if (g_EptHookState.ExecuteOnlySupported) {
                    Pte->Execute = 1;
                } else {
                    Pte->Execute = 0;
                }
            }
        }
    } else {
        /* Fallback O(n) path: RelaxedPa unknown, restore ALL hooks (safety) */
        ULONG i;
        for (i = 0; i < MAX_EPT_HOOKS; i++) {
            if (g_EptHookState.Hooks[i].Active && g_EptHookState.Hooks[i].TargetPte) {
                PEPT_PTE Pte = EptGetPerCpuPte(CpuIndex,
                    g_EptHookState.Hooks[i].TargetPhysicalAddr);
                if (!Pte) Pte = g_EptHookState.Hooks[i].TargetPte;

                if (Pte->Read || Pte->Write) {
                    Pte->Read = 0;
                    Pte->Write = 0;
                    Pte->PhysAddr = g_EptHookState.Hooks[i].HookPagePa >> 12;

                    if (g_EptHookState.ExecuteOnlySupported) {
                        Pte->Execute = 1;
                    } else {
                        Pte->Execute = 0;
                    }
                }
            }
        }
    }

    /*
     * BUG FIX (Issue #11): Use INVEPT SINGLE_CONTEXT when per-CPU EPT is active.
     * MTF handler only restores this CPU's private PTEs, so only this CPU's
     * EPT TLB needs flushing.
     */
    {
        ULONG64 CpuEptp = EptGetPerCpuEptp(CpuIndex);
        if (CpuEptp)
            EptInvalidateSingleContext(CpuEptp);
        else
            EptInvalidateAllContexts();
    }

    return TRUE;
}

/*
 * VMCALL - Used for hypervisor control.
 * Magic value in RAX signals shutdown request.
 * VMCALL_MAGIC_SHUTDOWN is defined in vmx.h.
 */

static BOOLEAN HandleVmcall(PGUEST_CONTEXT Ctx)
{
    ULONG64 Rax = Ctx->Rax;
    ULONG   SubCmd;

    /* Legacy shutdown path */
    if (Rax == VMCALL_MAGIC_SHUTDOWN) {
        LOG_INFO("VMCALL shutdown request received");
        VmxAdvanceGuestRip();
        return FALSE;   /* Signal VMX shutdown */
    }

    /* New VMCALL dispatch: RAX high 16 bits = VMCALL_MAGIC */
    if ((Rax & VMCALL_MAGIC_MASK) == VMCALL_MAGIC) {
        SubCmd = (ULONG)(Rax & 0xFFFF);

        switch (SubCmd) {
        case VMCALL_SUBCMD_SHUTDOWN:
            LOG_INFO("VMCALL shutdown request received (new)");
            VmxAdvanceGuestRip();
            return FALSE;

        case VMCALL_SUBCMD_READ_MEMORY:
        case VMCALL_SUBCMD_WRITE_MEMORY:
            return HvHandleMemoryVmcall(Ctx, SubCmd);

        default:
            break;
        }
    }

    /*
     * Unknown VMCALL - not ours.
     *
     * Windows issues VMCALL for Hyper-V enlightenments (TLB flush,
     * VP scheduling hints, etc.) when it detects a hypervisor via
     * CPUID.  VMware/KVM also trigger this.  We must NOT inject #UD
     * or the OS will crash (e.g. SwapContext uses VMCALL for TLB flush).
     *
     * FIX: Instead of blindly returning HV_STATUS_INVALID_HYPERCALL_CODE
     * (0x0002) — which causes SwapContext to crash because TLB is not
     * actually flushed — we now parse the Hyper-V hypercall input value
     * in RCX and emulate the critical TLB flush hypercalls.
     *
     * For emulated calls: RAX = 0 (HV_STATUS_SUCCESS)
     * For unknown calls:  RAX = 2 (HV_STATUS_INVALID_HYPERCALL_CODE)
     */
    {
        static volatile LONG s_VmcallLogCount = 0;
        LONG Count = InterlockedIncrement(&s_VmcallLogCount);
        if (Count <= 20) {
            ULONG64 GuestRip = VmxRead(VMCS_GUEST_RIP);
            VMXROOT_LOG_INFO("VMCALL[%d]: RAX=0x%llX RCX=0x%llX "
                     "callcode=%u RDX=0x%llX R8=0x%llX RIP=0x%llX CPU=%u",
                     (int)Count, Rax, Ctx->Rcx,
                     (ULONG)(Ctx->Rcx & 0xFFFF),
                     Ctx->Rdx, Ctx->R8, GuestRip,
                     KeGetCurrentProcessorNumber());
        }
        Ctx->Rax = HvEmulateHypercall(Ctx->Rcx, Ctx->Rdx, Ctx->R8);
        
        /* Log if hypercall returned error (might indicate problematic call) */
        if (Ctx->Rax != 0 && Count <= 20) {
            LOG_WARN("VMCALL[%d] RETURNED ERROR: status=0x%llX "
                     "callcode=%u",
                     (int)Count, Ctx->Rax,
                     (ULONG)(Ctx->Rcx & 0xFFFF));
        }
    }
    VmxAdvanceGuestRip();
    return TRUE;
}

/* XSETBV - Extended Control Register write */
static BOOLEAN HandleXsetbv(PGUEST_CONTEXT Ctx)
{
    ULONG   Ecx = (ULONG)Ctx->Rcx;
    ULONG64 Value = (Ctx->Rax & 0xFFFFFFFF) | ((Ctx->Rdx & 0xFFFFFFFF) << 32);

    /*
     * BUG FIX (Code Quality #5): Validate XCR0 before executing XSETBV.
     *
     * If the Guest writes an illegal XCR0 combination, the XSETBV instruction
     * would execute in Host context and trigger a #GP, crashing the Hypervisor.
     *
     * Intel SDM Vol. 1, Section 13.3 — XCR0 constraints:
     *   - Bit 0 (x87) must always be 1
     *   - If bit 2 (AVX) is set, bit 1 (SSE) must also be set
     *   - XCR index must be 0 (only XCR0 is currently defined)
     *
     * If validation fails, inject #GP(0) into the Guest instead.
     */
    if (Ecx != 0) {
        /* Only XCR0 (index 0) is valid; all others → #GP(0) */
        goto InjectGp;
    }

    if (!(Value & 1)) {
        /* Bit 0 (x87 FPU) must be 1 */
        goto InjectGp;
    }

    if ((Value & (1ULL << 2)) && !(Value & (1ULL << 1))) {
        /* AVX (bit 2) requires SSE (bit 1) */
        goto InjectGp;
    }

    /* Execute the real XSETBV via ASM wrapper (WDK 7600 has no _xsetbv intrinsic) */
    AsmXsetbv(Ecx, Value);

    VmxAdvanceGuestRip();
    return TRUE;

InjectGp:
    /* Inject #GP(0) into Guest */
    VmxWrite(VMCS_CTRL_VMENTRY_INT_INFO,
             INTERRUPT_INFO_VALID |
             (INTERRUPT_TYPE_HARDWARE_EXCEPTION << INTERRUPT_INFO_TYPE_SHIFT) |
             INTERRUPT_INFO_DELIVER_ERR_CODE |
             13);  /* #GP vector = 13 */
    VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE, 0);
    return TRUE;
}

/* INVD - Invalidate cache without writeback */
static BOOLEAN HandleInvd(PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    /* Convert INVD to WBINVD for safety (write back then invalidate) */
    __wbinvd();

    VmxAdvanceGuestRip();
    return TRUE;
}

/* INVLPG - Invalidate TLB entry */
static BOOLEAN HandleInvlpg(PGUEST_CONTEXT Ctx)
{
    ULONG64 LinearAddr;

    UNREFERENCED_PARAMETER(Ctx);

    LinearAddr = VmxRead(VMCS_EXIT_QUALIFICATION);
    __invlpg((PVOID)LinearAddr);

    VmxAdvanceGuestRip();
    return TRUE;
}

/* WBINVD - Write back and invalidate cache */
static BOOLEAN HandleWbinvd(PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    __wbinvd();

    VmxAdvanceGuestRip();
    return TRUE;
}

/* Triple Fault - fatal */
static BOOLEAN HandleTripleFault(PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    VMXROOT_LOG_ERROR("TRIPLE FAULT! CPU=%u RIP=0x%llX RSP=0x%llX CR3=0x%llX "
              "CS=0x%llX RFLAGS=0x%llX Activity=%llu Interruptibility=0x%llX",
              KeGetCurrentProcessorNumber(),
              VmxRead(VMCS_GUEST_RIP),
              VmxRead(VMCS_GUEST_RSP),
              VmxRead(VMCS_GUEST_CR3),
              VmxRead(VMCS_GUEST_CS_SEL),
              VmxRead(VMCS_GUEST_RFLAGS),
              VmxRead(VMCS_GUEST_ACTIVITY_STATE),
              VmxRead(VMCS_GUEST_INTERRUPTIBILITY));
    VMXROOT_LOG_ERROR("TRIPLE FAULT context: IDT-vectoring=0x%llX, "
              "entry-int=0x%llX, exit-int=0x%llX, exit-reason=%llu",
              VmxRead(VMCS_IDT_VECTORING_INFO),
              VmxRead(VMCS_CTRL_VMENTRY_INT_INFO),
              VmxRead(VMCS_EXIT_INTERRUPTION_INFO),
              VmxRead(VMCS_EXIT_REASON) & 0xFFFF);
    return FALSE;
}

/* ========================================================================= */
/*  GP Register Helpers                                                      */
/* ========================================================================= */

/*
 * Map register index (from exit qualification) to GUEST_CONTEXT offset.
 * Register encoding: 0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI
 *                    8=R8,  9=R9,  10=R10, 11=R11, 12=R12, 13=R13, 14=R14, 15=R15
 *
 * NOTE: RSP (index 4) is now valid in GuestContext because VmxExitHandler()
 * syncs VMCS_GUEST_RSP → GuestContext->Rsp at entry and writes it back at exit.
 * No special-case needed for RegIndex==4 anymore.
 */
static ULONG64 GetGpRegValue(PGUEST_CONTEXT Ctx, ULONG RegIndex)
{
    ULONG64 *Regs = (ULONG64 *)Ctx;

    if (RegIndex <= 15) {
        return Regs[RegIndex];
    }

    return 0;
}

static VOID SetGpRegValue(PGUEST_CONTEXT Ctx, ULONG RegIndex, ULONG64 Value)
{
    ULONG64 *Regs = (ULONG64 *)Ctx;

    if (RegIndex <= 15) {
        Regs[RegIndex] = Value;
    }
}
