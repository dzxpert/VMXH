/*
 * log.c - VMX Anti-Anti-Debug Hypervisor
 * Kernel-mode logging with ring buffer and DbgPrint output
 */

#include "log.h"
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
    KeInitializeSpinLock(&g_LogBuffer.Lock);
    g_LogBuffer.WriteIndex = 0;
    g_LogBuffer.ReadIndex = 0;
    g_LogBuffer.Count = 0;
    g_LogBuffer.Initialized = TRUE;

    LOG_INFO("Log system initialized (ring buffer: %d entries)", LOG_RING_BUFFER_ENTRIES);
    return STATUS_SUCCESS;
}

VOID LogTerminate(VOID)
{
    g_LogBuffer.Initialized = FALSE;
}

VOID LogWrite(ULONG Level, ULONG Pid, const CHAR *Format, ...)
{
    KIRQL       OldIrql;
    va_list     Args;
    LONG        Index;
    PVMX_LOG_ENTRY Entry;
    CHAR        TempBuffer[VMX_LOG_MAX_MSG];
    NTSTATUS    Status;

    if (!g_LogBuffer.Initialized)
        return;

    /* Format the message */
    va_start(Args, Format);
    Status = RtlStringCbVPrintfA(TempBuffer, sizeof(TempBuffer), Format, Args);
    va_end(Args);

    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
        return;

    /* DbgPrint output (always, for WinDbg/DebugView) */
    if (Level <= VMX_LOG_INFO) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    LOG_PREFIX "[%s] PID=%u: %s\n",
                    (Level < 4) ? LogLevelStr[Level] : "???",
                    Pid, TempBuffer);
    }

    /* Write to ring buffer */
    KeAcquireSpinLock(&g_LogBuffer.Lock, &OldIrql);

    Index = g_LogBuffer.WriteIndex;
    Entry = &g_LogBuffer.Entries[Index];

    Entry->Level = Level;
    Entry->Pid = Pid;
    KeQuerySystemTime(&Entry->Timestamp);
    RtlCopyMemory(Entry->Message, TempBuffer, VMX_LOG_MAX_MSG);
    Entry->Message[VMX_LOG_MAX_MSG - 1] = '\0';

    /* Advance write index (wrap around) */
    g_LogBuffer.WriteIndex = (Index + 1) % LOG_RING_BUFFER_ENTRIES;

    if (g_LogBuffer.Count < LOG_RING_BUFFER_ENTRIES) {
        g_LogBuffer.Count++;
    } else {
        /* Buffer full - advance read index (discard oldest) */
        g_LogBuffer.ReadIndex = (g_LogBuffer.ReadIndex + 1) % LOG_RING_BUFFER_ENTRIES;
    }

    KeReleaseSpinLock(&g_LogBuffer.Lock, OldIrql);
}

ULONG LogRead(PVMX_LOG_ENTRY OutputBuffer, ULONG MaxEntries)
{
    KIRQL   OldIrql;
    ULONG   Copied = 0;

    if (!g_LogBuffer.Initialized || !OutputBuffer || MaxEntries == 0)
        return 0;

    KeAcquireSpinLock(&g_LogBuffer.Lock, &OldIrql);

    while (Copied < MaxEntries && g_LogBuffer.Count > 0) {
        RtlCopyMemory(&OutputBuffer[Copied],
                       &g_LogBuffer.Entries[g_LogBuffer.ReadIndex],
                       sizeof(VMX_LOG_ENTRY));

        g_LogBuffer.ReadIndex = (g_LogBuffer.ReadIndex + 1) % LOG_RING_BUFFER_ENTRIES;
        g_LogBuffer.Count--;
        Copied++;
    }

    KeReleaseSpinLock(&g_LogBuffer.Lock, OldIrql);

    return Copied;
}
