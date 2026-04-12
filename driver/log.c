/*
 * log.c - VMX Anti-Anti-Debug Hypervisor
 * Unified lock-free ring buffer logging + System Thread flush
 *
 * NO SPINLOCKS anywhere in this file.  ALL synchronization uses Interlocked*
 * atomic operations only, making every path safe at ANY IRQL including
 * VMX root mode.
 *
 * UNIFIED ARCHITECTURE:
 *
 * LogWrite (safe at ANY IRQL, including VMX root mode):
 *   - Formats message into stack-local buffer
 *   - Writes to ring buffer ONLY using InterlockedIncrement (lock-free)
 *   - NO DbgPrintEx — no INT 3, no spinlocks, no deadlock risk
 *   - Used by ALL log macros (LOG_*, VMXROOT_LOG_*)
 *
 * Flush Thread (LogFlushThreadRoutine):
 *   - System thread at PASSIVE_LEVEL, polls ring buffer every 50ms
 *   - Outputs ALL new entries via DbgPrintEx (safe on real thread stack)
 *   - Provides real-time WinDbg output for all log entries
 *   - ~50ms max delay from log write to WinDbg display
 *
 * Read path (LogRead):
 *   - Called only from IOCTL context (PASSIVE_LEVEL)
 *   - Reads are serialized by the IOCTL dispatch (single-threaded)
 *   - Uses InterlockedCompareExchange for safe count decrement
 *
 * LOCK-FREE PUBLISH PROTOCOL (prevents reading half-written entries):
 *
 *   Writer (LogWrite):
 *     1. InterlockedIncrement(&WriteIndex) — claim slot
 *     2. Fill Entry fields (Level, Pid, Timestamp, Message)
 *     3. InterlockedExchange(&Ready[Idx], 1) — RELEASE barrier, publish
 *
 *   Reader (FlushThread / LogRead):
 *     1. Check Ready[Idx] != 0 via InterlockedCompareExchange — ACQUIRE
 *     2. Read Entry fields (guaranteed fully written)
 *     3. InterlockedExchange(&Ready[Idx], 0) — RELEASE, make slot reusable
 *
 *   This guarantees readers never see partially-written data, with zero
 *   locks, zero IRQL manipulation — pure atomic operations throughout.
 */

#include "log.h"

/* WDK7 does not define STATUS_NOT_INITIALIZED */
#ifndef STATUS_NOT_INITIALIZED
#define STATUS_NOT_INITIALIZED  ((NTSTATUS)0xC0000535L)
#endif
#include <ntstrsafe.h>

/* ========================================================================= */
/*  Global Log Buffer                                                        */
/* ========================================================================= */

LOG_RING_BUFFER g_LogBuffer = { 0 };

/* ========================================================================= */
/*  Log Level Strings                                                        */
/* ========================================================================= */

static const CHAR *LogLevelStr[] = {
    "ERR",
    "WRN",
    "INF",
    "DBG"
};

/* ========================================================================= */
/*  Implementation                                                           */
/* ========================================================================= */

NTSTATUS LogInitialize(VOID)
{
    RtlZeroMemory(&g_LogBuffer, sizeof(g_LogBuffer));
    g_LogBuffer.WriteIndex = 0;
    g_LogBuffer.ReadIndex = 0;
    g_LogBuffer.Count = 0;
    g_LogBuffer.Initialized = TRUE;

    LOG_INFO("Log system initialized (lock-free ring buffer: %d entries)", LOG_RING_BUFFER_ENTRIES);
    return STATUS_SUCCESS;
}

VOID LogTerminate(VOID)
{
    /* Stop flush thread first (if still running) */
    LogFlushThreadStop();

    g_LogBuffer.Initialized = FALSE;
}

/*
 * LogWrite — Unified logging function (safe at ANY IRQL including VMX root mode).
 *
 * ALL log macros (LOG_*, VMXROOT_LOG_*) now go through this single function.
 * It ONLY writes to the lock-free ring buffer — NO DbgPrintEx here.
 *
 * The flush thread (LogFlushThreadRoutine) is responsible for relaying all
 * ring buffer entries to WinDbg via DbgPrintEx at PASSIVE_LEVEL.
 *
 * This design means:
 * - Safe at ANY IRQL, including VMX root mode, DPC, IPI, etc.
 * - No INT 3, no spinlocks, no deadlock risk
 * - All log output appears in WinDbg via the flush thread (~50ms delay)
 * - Ring buffer entries always available via IOCTL_VMX_GET_LOG
 *
 * LOCK-FREE PROTOCOL (multi-writer safe):
 *
 * 1. InterlockedIncrement(&WriteIndex) — atomically claim a slot
 * 2. Fill Entry data (Level, Pid, Timestamp, Message)
 * 3. InterlockedExchange(&Ready[Idx], 1) — publish: acts as a RELEASE
 *    barrier, guaranteeing all preceding stores (step 2) are visible
 *    to any thread that subsequently reads Ready[Idx] == 1.
 *
 * The flush thread spins on Ready[Idx] before reading the entry, so it
 * never sees partially-written data. After reading, it resets Ready[Idx]
 * to 0 with InterlockedExchange (RELEASE), making the slot reusable.
 *
 * No locks, no IRQL manipulation — pure Interlocked* atomics only.
 */
VOID LogWrite(ULONG Level, ULONG Pid, const CHAR *Format, ...)
{
    va_list         Args;
    LONG            Index;
    PVMX_LOG_ENTRY  Entry;
    CHAR            TempBuffer[VMX_LOG_MAX_MSG];
    NTSTATUS        Status;

    if (!g_LogBuffer.Initialized)
        return;

    /* Format the message into stack-local buffer */
    va_start(Args, Format);
    Status = RtlStringCbVPrintfA(TempBuffer, sizeof(TempBuffer), Format, Args);
    va_end(Args);

    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
        return;

    /* Lock-free ring buffer write — flush thread handles DbgPrintEx output */
    {
        LONG NewIndex;
        LONG OldCount;

        /* Step 1: Atomically claim the next write slot */
        NewIndex = InterlockedIncrement(&g_LogBuffer.WriteIndex);
        /* Convert to 0-based and wrap around */
        Index = (NewIndex - 1) % LOG_RING_BUFFER_ENTRIES;
        /* Handle potential negative modulo (defensive) */
        if (Index < 0)
            Index += LOG_RING_BUFFER_ENTRIES;

        Entry = &g_LogBuffer.Entries[Index];

        /* Step 2: Fill the entry (no lock needed — we own this slot) */
        Entry->Level = Level;
        Entry->Pid = Pid;
        KeQuerySystemTime(&Entry->Timestamp);
        RtlCopyMemory(Entry->Message, TempBuffer, VMX_LOG_MAX_MSG);
        Entry->Message[VMX_LOG_MAX_MSG - 1] = '\0';

        /*
         * Step 3: Publish — mark slot as ready for consumption.
         * InterlockedExchange acts as a full memory barrier (RELEASE semantic),
         * ensuring all stores in Step 2 are globally visible BEFORE Ready becomes 1.
         * The flush thread checks Ready[Idx] BEFORE reading any entry fields.
         */
        InterlockedExchange(&g_LogBuffer.Ready[Index], 1);

        /*
         * Update count: increment but cap at LOG_RING_BUFFER_ENTRIES.
         * Use a CAS loop to saturate.
         */
        do {
            OldCount = g_LogBuffer.Count;
            if (OldCount >= LOG_RING_BUFFER_ENTRIES) {
                /* Buffer is full — count stays at max, old entries are overwritten */
                break;
            }
        } while (InterlockedCompareExchange(&g_LogBuffer.Count, OldCount + 1, OldCount) != OldCount);
    }
}

/* ========================================================================= */
/*  Flush Thread — relays ring buffer entries to DbgPrintEx in PASSIVE_LEVEL */
/* ========================================================================= */

/*
 * LogFlushThreadRoutine — System Thread that periodically reads new entries
 * from the ring buffer and outputs them via DbgPrintEx.
 *
 * This runs at PASSIVE_LEVEL on a normal kernel thread stack, so DbgPrintEx
 * is completely safe here (INT 3 → KdEnterDebugger works fine on a real
 * thread stack, unlike VMX root mode host stack).
 *
 * ALL log entries go through this single output path. LogWrite only writes
 * to the ring buffer; this thread is the sole consumer for WinDbg output.
 *
 * The thread checks for new entries by comparing FlushIndex vs WriteIndex.
 * It uses a 50ms polling interval to balance responsiveness and CPU overhead.
 * When FlushStopEvent is signaled, the thread drains remaining entries and exits.
 */
static VOID LogFlushThreadRoutine(PVOID Context)
{
    LARGE_INTEGER   PollInterval;
    NTSTATUS        WaitStatus;
    LONG            FlushIdx;
    LONG            WriteIdx;
    LONG            Idx;
    PVMX_LOG_ENTRY  Entry;
    ULONG           BatchCount;

    UNREFERENCED_PARAMETER(Context);

    /* 5ms polling interval (reduced from 50ms for faster diagnosis in nested VMware) */
    PollInterval.QuadPart = -50000LL;  /* 5ms in 100ns units, negative = relative */

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
               LOG_PREFIX "[INF] PID=0: Log flush thread started (50ms poll interval)\n");

    while (TRUE) {
        /* Wait for stop event or timeout */
        WaitStatus = KeWaitForSingleObject(
            &g_LogBuffer.FlushStopEvent,
            Executive,
            KernelMode,
            FALSE,
            &PollInterval);

        /* Flush all new entries */
        BatchCount = 0;
        WriteIdx = g_LogBuffer.WriteIndex;
        FlushIdx = g_LogBuffer.FlushIndex;

        while (FlushIdx < WriteIdx && BatchCount < 256) {
            Idx = FlushIdx % LOG_RING_BUFFER_ENTRIES;
            if (Idx < 0)
                Idx += LOG_RING_BUFFER_ENTRIES;

            /*
             * Check Ready flag — writer sets Ready[Idx]=1 AFTER filling all fields.
             * InterlockedCompareExchange acts as an ACQUIRE barrier: if we see 1,
             * all stores by the writer (Level, Pid, Message) are guaranteed visible.
             *
             * If Ready is still 0, the writer is mid-write. Stop here and retry
             * next poll cycle — we must flush in order to preserve log sequence.
             */
            if (!InterlockedCompareExchange(&g_LogBuffer.Ready[Idx], 0, 0)) {
                break;  /* Slot not ready yet — stop, retry next cycle */
            }

            Entry = &g_LogBuffer.Entries[Idx];

            /*
             * Output via DbgPrintEx — safe here at PASSIVE_LEVEL.
             * All entries are ring-buffer-only now, so output everything.
             * Only output INFO level and below (ERROR, WARN, INFO).
             * DEBUG level is ring-buffer only to reduce noise.
             */
            if (Entry->Level <= VMX_LOG_INFO) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           LOG_PREFIX "[%s] PID=%u: %s\n",
                           (Entry->Level < 4) ? LogLevelStr[Entry->Level] : "???",
                           Entry->Pid, Entry->Message);
            }

            /*
             * Reset Ready flag — InterlockedExchange acts as RELEASE barrier.
             * This makes the slot available for reuse when WriteIndex wraps around.
             */
            InterlockedExchange(&g_LogBuffer.Ready[Idx], 0);

            FlushIdx++;
            BatchCount++;
        }

        /* Update FlushIndex (only this thread writes it, so simple store is fine) */
        InterlockedExchange(&g_LogBuffer.FlushIndex, FlushIdx);

        /* If stop event was signaled, drain and exit */
        if (WaitStatus == STATUS_SUCCESS) {
            /* Drain any remaining entries written during our last batch */
            WriteIdx = g_LogBuffer.WriteIndex;
            while (FlushIdx < WriteIdx) {
                Idx = FlushIdx % LOG_RING_BUFFER_ENTRIES;
                if (Idx < 0)
                    Idx += LOG_RING_BUFFER_ENTRIES;

                /* Wait for slot to become ready (writer may be mid-write) */
                if (!InterlockedCompareExchange(&g_LogBuffer.Ready[Idx], 0, 0)) {
                    /* Slot still being written — brief yield then retry */
                    LARGE_INTEGER YieldWait;
                    YieldWait.QuadPart = -1000LL;  /* 0.1ms */
                    KeDelayExecutionThread(KernelMode, FALSE, &YieldWait);
                    continue;
                }

                Entry = &g_LogBuffer.Entries[Idx];
                if (Entry->Level <= VMX_LOG_INFO) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               LOG_PREFIX "[%s] PID=%u: %s\n",
                               (Entry->Level < 4) ? LogLevelStr[Entry->Level] : "???",
                               Entry->Pid, Entry->Message);
                }
                InterlockedExchange(&g_LogBuffer.Ready[Idx], 0);
                FlushIdx++;
            }
            InterlockedExchange(&g_LogBuffer.FlushIndex, FlushIdx);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       LOG_PREFIX "[INF] PID=0: Log flush thread exiting\n");
            PsTerminateSystemThread(STATUS_SUCCESS);
            return;  /* Not reached */
        }
    }
}

NTSTATUS LogFlushThreadStart(VOID)
{
    NTSTATUS        Status;
    HANDLE          ThreadHandle;
    OBJECT_ATTRIBUTES Oa;

    if (!g_LogBuffer.Initialized)
        return STATUS_NOT_INITIALIZED;

    if (g_LogBuffer.FlushThreadRunning)
        return STATUS_ALREADY_REGISTERED;

    /* Initialize stop event (manual reset, initially non-signaled) */
    KeInitializeEvent(&g_LogBuffer.FlushStopEvent, NotificationEvent, FALSE);

    /* Set FlushIndex to current WriteIndex so we don't replay old entries */
    InterlockedExchange(&g_LogBuffer.FlushIndex, g_LogBuffer.WriteIndex);

    /* Create system thread */
    InitializeObjectAttributes(&Oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = PsCreateSystemThread(
        &ThreadHandle,
        THREAD_ALL_ACCESS,
        &Oa,
        NULL,
        NULL,
        LogFlushThreadRoutine,
        NULL);

    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   LOG_PREFIX "[ERR] PID=0: Failed to create log flush thread: 0x%08X\n",
                   Status);
        return Status;
    }

    /* Get thread object reference for waiting on termination */
    Status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID *)&g_LogBuffer.FlushThreadObject,
        NULL);

    g_LogBuffer.FlushThreadHandle = ThreadHandle;
    g_LogBuffer.FlushThreadRunning = TRUE;

    /* Close the handle — we keep the object reference */
    ZwClose(ThreadHandle);

    LOG_INFO("Log flush thread started successfully");
    return STATUS_SUCCESS;
}

VOID LogFlushThreadStop(VOID)
{
    if (!g_LogBuffer.FlushThreadRunning || !g_LogBuffer.FlushThreadObject)
        return;

    /* Signal the thread to stop */
    KeSetEvent(&g_LogBuffer.FlushStopEvent, IO_NO_INCREMENT, FALSE);

    /* Wait for thread to terminate (up to 5 seconds) */
    {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -50000000LL;  /* 5 seconds */

        KeWaitForSingleObject(
            g_LogBuffer.FlushThreadObject,
            Executive,
            KernelMode,
            FALSE,
            &Timeout);
    }

    /* Release object reference */
    ObDereferenceObject(g_LogBuffer.FlushThreadObject);
    g_LogBuffer.FlushThreadObject = NULL;
    g_LogBuffer.FlushThreadRunning = FALSE;
}

/*
 * LogRead — read entries from the ring buffer for IOCTL_VMX_GET_LOG.
 *
 * Called only from IOCTL dispatch at PASSIVE_LEVEL.
 * Uses InterlockedCompareExchange for safe count management.
 * Checks Ready[] flag to avoid reading partially-written entries.
 * No spinlock.
 */
ULONG LogRead(PVMX_LOG_ENTRY OutputBuffer, ULONG MaxEntries)
{
    ULONG   Copied = 0;
    LONG    OldCount;
    LONG    ReadIdx;

    if (!g_LogBuffer.Initialized || !OutputBuffer || MaxEntries == 0)
        return 0;

    while (Copied < MaxEntries) {
        /* Try to decrement count atomically */
        do {
            OldCount = g_LogBuffer.Count;
            if (OldCount <= 0)
                goto done;  /* No more entries */
        } while (InterlockedCompareExchange(&g_LogBuffer.Count, OldCount - 1, OldCount) != OldCount);

        /* Successfully claimed one entry — read it */
        ReadIdx = InterlockedIncrement(&g_LogBuffer.ReadIndex) - 1;
        ReadIdx = ReadIdx % LOG_RING_BUFFER_ENTRIES;
        if (ReadIdx < 0)
            ReadIdx += LOG_RING_BUFFER_ENTRIES;

        /*
         * Check Ready flag — skip entries still being written.
         * This handles the rare case where Count was incremented by LogWrite
         * but the entry data hasn't been fully written yet.
         * At PASSIVE_LEVEL we can safely just skip it rather than busy-wait.
         */
        if (!InterlockedCompareExchange(&g_LogBuffer.Ready[ReadIdx], 0, 0)) {
            /* Entry not ready — put count back and stop */
            InterlockedIncrement(&g_LogBuffer.Count);
            goto done;
        }

        RtlCopyMemory(&OutputBuffer[Copied],
                       &g_LogBuffer.Entries[ReadIdx],
                       sizeof(VMX_LOG_ENTRY));
        Copied++;
    }

done:
    return Copied;
}
