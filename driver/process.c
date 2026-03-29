/*
 * process.c - VMX Anti-Anti-Debug Hypervisor
 * Process tracking: manage target processes by PID/CR3
 */

#include "process.h"
#include "log.h"
#include "../common/shared.h"

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);

/* ========================================================================= */
/*  Global State                                                             */
/* ========================================================================= */

PROCESS_TRACKING g_ProcessTracking = { 0 };
EPROCESS_OFFSETS g_EprocessOffsets = { 0 };

/* ========================================================================= */
/*  Dynamic EPROCESS Offset Discovery                                        */
/* ========================================================================= */

/*
 * Resolve the offset of DirectoryTableBase within EPROCESS dynamically.
 *
 * Strategy:
 *   1. Get the current process's EPROCESS pointer (PsGetCurrentProcess)
 *   2. Read the current CR3 via __readcr3()
 *   3. Scan the EPROCESS structure for a ULONG64 matching CR3
 *   4. The match position is the DirectoryTableBase offset
 *
 * This works because:
 *   - We run at PASSIVE_LEVEL during DriverEntry, in System process context
 *   - The System process's CR3 is always loaded when we're in its context
 *   - DirectoryTableBase is always in the first ~0x300 bytes of EPROCESS
 *   - CR3 values are unique (physical page directory address, page-aligned)
 *
 * Fallback: if scan fails, try well-known offsets for common Windows versions.
 */

/* Well-known offsets as fallback (Windows 10/11 x64) */
static const ULONG g_KnownDtbOffsets[] = {
    0x028,  /* Windows 10 1507-22H2, Windows 11 21H2-24H2 */
    0x018,  /* Windows 7/8 x64 */
    0x02C,  /* Some insider builds */
};
#define KNOWN_DTB_OFFSET_COUNT (sizeof(g_KnownDtbOffsets) / sizeof(g_KnownDtbOffsets[0]))

/* Maximum EPROCESS bytes to scan */
#define EPROCESS_SCAN_SIZE      0x700

/*
 * Validate a candidate offset by checking multiple processes
 */
static BOOLEAN ValidateDtbOffset(ULONG Offset)
{
    PEPROCESS   SystemProcess;
    ULONG64     StoredCr3;
    ULONG64     CurrentCr3;

    /*
     * Validate against the System process (PID 4).
     * We're running in System context during DriverEntry,
     * so CR3 should match EPROCESS.DirectoryTableBase.
     */
    SystemProcess = PsGetCurrentProcess();
    CurrentCr3 = __readcr3();

    /* Read the candidate value from EPROCESS */
    StoredCr3 = *(PULONG64)((PUCHAR)SystemProcess + Offset);

    /*
     * CR3 comparison: mask off PCID bits (lower 12 bits).
     * Also handle the case where UserDirectoryTableBase might be adjacent.
     */
    if ((StoredCr3 & ~0xFFFULL) == (CurrentCr3 & ~0xFFFULL)) {
        /*
         * Additional sanity checks:
         * - Value should be page-aligned (bits 0-11 may have PCID, but
         *   the physical address part should be page-aligned)
         * - Value should be non-zero
         * - Value should be a valid physical address (< max physical address)
         *   Typical limit: 48-bit physical addressing = 256TB
         */
        if (StoredCr3 != 0 && (StoredCr3 & ~0xFFFULL) < (1ULL << 48)) {
            return TRUE;
        }
    }

    return FALSE;
}

NTSTATUS ProcessResolveOffsets(VOID)
{
    PEPROCESS   CurrentProcess;
    ULONG64     CurrentCr3;
    ULONG       Offset;
    ULONG       i;

    CurrentProcess = PsGetCurrentProcess();
    CurrentCr3 = __readcr3();

    LOG_INFO("Resolving EPROCESS offsets dynamically...");
    LOG_INFO("  Current EPROCESS: 0x%p", CurrentProcess);
    LOG_INFO("  Current CR3:      0x%llX", CurrentCr3);

    /*
     * Method 1: Scan EPROCESS for matching CR3 value.
     * Search QWORD-aligned offsets in the first EPROCESS_SCAN_SIZE bytes.
     */
    for (Offset = 0; Offset < EPROCESS_SCAN_SIZE; Offset += sizeof(ULONG64)) {
        ULONG64 Value;

        __try {
            Value = *(PULONG64)((PUCHAR)CurrentProcess + Offset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }

        /* Compare with current CR3 (mask PCID bits) */
        if (Value != 0 &&
            (Value & ~0xFFFULL) == (CurrentCr3 & ~0xFFFULL) &&
            (Value & ~0xFFFULL) < (1ULL << 48)) {

            /* Found a candidate - validate it */
            if (ValidateDtbOffset(Offset)) {
                g_EprocessOffsets.DirectoryTableBase = Offset;
                g_EprocessOffsets.Resolved = TRUE;

                LOG_INFO("  DirectoryTableBase offset: 0x%03X (discovered by CR3 scan)",
                         Offset);
                return STATUS_SUCCESS;
            }
        }
    }

    LOG_WARN("CR3 scan did not find DirectoryTableBase, trying known offsets...");

    /*
     * Method 2: Try well-known offsets as fallback.
     * Validate each by checking if the value at that offset matches CR3.
     */
    for (i = 0; i < KNOWN_DTB_OFFSET_COUNT; i++) {
        Offset = g_KnownDtbOffsets[i];

        if (ValidateDtbOffset(Offset)) {
            g_EprocessOffsets.DirectoryTableBase = Offset;
            g_EprocessOffsets.Resolved = TRUE;

            LOG_INFO("  DirectoryTableBase offset: 0x%03X (known offset #%u)",
                     Offset, i);
            return STATUS_SUCCESS;
        }
    }

    /*
     * Method 3: Last resort - use KeAttachProcess + __readcr3 on a
     * different process to cross-validate. Get PID 4 (System).
     */
    LOG_ERROR("Failed to resolve EPROCESS.DirectoryTableBase offset!");
    LOG_ERROR("  Could not find CR3 (0x%llX) in EPROCESS at 0x%p",
              CurrentCr3, CurrentProcess);

    return STATUS_NOT_FOUND;
}

/* ========================================================================= */
/*  Implementation                                                           */
/* ========================================================================= */

VOID ProcessTrackingInit(VOID)
{
    NTSTATUS Status;

    RtlZeroMemory(&g_ProcessTracking, sizeof(g_ProcessTracking));
    KeInitializeSpinLock(&g_ProcessTracking.Lock);

    /* Resolve EPROCESS offsets before anything else */
    Status = ProcessResolveOffsets();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("CRITICAL: Cannot resolve EPROCESS offsets - CR3 lookup will fail!");
        /* We still mark as initialized, but GetProcessCr3 will fail gracefully */
    }

    g_ProcessTracking.Initialized = TRUE;

    LOG_INFO("Process tracking initialized (max targets: %d)", MAX_TARGET_PROCESSES);
}

VOID ProcessTrackingCleanup(VOID)
{
    g_ProcessTracking.Initialized = FALSE;
    g_ProcessTracking.ActiveCount = 0;
}

/*
 * Get the CR3 (DirectoryTableBase) for a given process.
 * Uses the dynamically resolved EPROCESS offset.
 */
static NTSTATUS GetProcessCr3(ULONG Pid, PULONG64 OutCr3)
{
    NTSTATUS    Status;
    PEPROCESS   Process = NULL;
    ULONG64     Cr3;

    if (!g_EprocessOffsets.Resolved) {
        LOG_ERROR("GetProcessCr3: EPROCESS offsets not resolved");
        return STATUS_NOT_SUPPORTED;
    }

    Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /* Read DirectoryTableBase at the dynamically resolved offset */
    Cr3 = *(PULONG64)((PUCHAR)Process + g_EprocessOffsets.DirectoryTableBase);

    ObDereferenceObject(Process);

    if (Cr3 == 0) {
        LOG_ERROR("GetProcessCr3: CR3 is zero for PID %u (offset 0x%X)",
                  Pid, g_EprocessOffsets.DirectoryTableBase);
        return STATUS_UNSUCCESSFUL;
    }

    *OutCr3 = Cr3;
    return STATUS_SUCCESS;
}

NTSTATUS ProcessAddTarget(ULONG Pid, ULONG Flags)
{
    KIRQL   OldIrql;
    ULONG   i;
    ULONG64 Cr3 = 0;
    NTSTATUS Status;

    if (!g_ProcessTracking.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    /* Resolve PID to CR3 */
    Status = GetProcessCr3(Pid, &Cr3);
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("Failed to resolve CR3 for PID %u: 0x%08X", Pid, Status);
        return Status;
    }

    KeAcquireSpinLock(&g_ProcessTracking.Lock, &OldIrql);

    /* Check if already tracked */
    for (i = 0; i < MAX_TARGET_PROCESSES; i++) {
        if (g_ProcessTracking.Targets[i].Active &&
            g_ProcessTracking.Targets[i].Pid == Pid) {
            /* Already tracked - update flags */
            g_ProcessTracking.Targets[i].Flags = Flags;
            g_ProcessTracking.Targets[i].Cr3 = Cr3; /* Refresh CR3 */
            KeReleaseSpinLock(&g_ProcessTracking.Lock, OldIrql);
            LOG_INFO("Updated target PID=%u, CR3=0x%llX, Flags=0x%08X", Pid, Cr3, Flags);
            return STATUS_SUCCESS;
        }
    }

    /* Find a free slot */
    for (i = 0; i < MAX_TARGET_PROCESSES; i++) {
        if (!g_ProcessTracking.Targets[i].Active) {
            g_ProcessTracking.Targets[i].Pid = Pid;
            g_ProcessTracking.Targets[i].Cr3 = Cr3;
            g_ProcessTracking.Targets[i].Flags = Flags;
            g_ProcessTracking.Targets[i].Active = TRUE;
            g_ProcessTracking.ActiveCount++;

            KeReleaseSpinLock(&g_ProcessTracking.Lock, OldIrql);
            LOG_INFO("Added target PID=%u, CR3=0x%llX, Flags=0x%08X", Pid, Cr3, Flags);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_ProcessTracking.Lock, OldIrql);
    LOG_ERROR("No free slots for target process (max=%d)", MAX_TARGET_PROCESSES);
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS ProcessRemoveTarget(ULONG Pid)
{
    KIRQL   OldIrql;
    ULONG   i;

    if (!g_ProcessTracking.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    KeAcquireSpinLock(&g_ProcessTracking.Lock, &OldIrql);

    for (i = 0; i < MAX_TARGET_PROCESSES; i++) {
        if (g_ProcessTracking.Targets[i].Active &&
            g_ProcessTracking.Targets[i].Pid == Pid) {

            g_ProcessTracking.Targets[i].Active = FALSE;
            g_ProcessTracking.Targets[i].Pid = 0;
            g_ProcessTracking.Targets[i].Cr3 = 0;
            g_ProcessTracking.Targets[i].Flags = 0;
            g_ProcessTracking.ActiveCount--;

            KeReleaseSpinLock(&g_ProcessTracking.Lock, OldIrql);
            LOG_INFO("Removed target PID=%u", Pid);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_ProcessTracking.Lock, OldIrql);
    LOG_WARN("Target PID=%u not found", Pid);
    return STATUS_NOT_FOUND;
}

NTSTATUS ProcessUpdateConfig(ULONG Pid, ULONG NewFlags)
{
    KIRQL   OldIrql;
    ULONG   i;

    if (!g_ProcessTracking.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    KeAcquireSpinLock(&g_ProcessTracking.Lock, &OldIrql);

    for (i = 0; i < MAX_TARGET_PROCESSES; i++) {
        if (g_ProcessTracking.Targets[i].Active &&
            g_ProcessTracking.Targets[i].Pid == Pid) {

            g_ProcessTracking.Targets[i].Flags = NewFlags;

            KeReleaseSpinLock(&g_ProcessTracking.Lock, OldIrql);
            LOG_INFO("Updated config for PID=%u, NewFlags=0x%08X", Pid, NewFlags);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_ProcessTracking.Lock, OldIrql);
    return STATUS_NOT_FOUND;
}

ULONG ProcessGetActiveCount(VOID)
{
    return g_ProcessTracking.ActiveCount;
}

/*
 * Fast CR3 lookup - called from VM-Exit handler at high IRQL
 * Lock-free read since we only need approximate consistency
 * and the target array is small enough for a linear scan.
 */
PTARGET_PROCESS ProcessFindByCr3(ULONG64 Cr3)
{
    ULONG i;

    /* Mask off PCID bits - CR3 low 12 bits may contain PCID */
    ULONG64 Cr3Masked = Cr3 & ~0xFFFULL;

    for (i = 0; i < MAX_TARGET_PROCESSES; i++) {
        if (g_ProcessTracking.Targets[i].Active) {
            ULONG64 TargetCr3 = g_ProcessTracking.Targets[i].Cr3 & ~0xFFFULL;
            if (TargetCr3 == Cr3Masked) {
                return &g_ProcessTracking.Targets[i];
            }
        }
    }

    return NULL;
}
