/*
 * log.h - VMX Anti-Anti-Debug Hypervisor
 * Unified lock-free logging system with ring buffer + flush thread
 *
 * DESIGN: ALL logging (both normal context and VMX root mode) writes to
 * a lock-free ring buffer ONLY. A System Thread at PASSIVE_LEVEL polls
 * the ring buffer and relays entries to WinDbg via DbgPrintEx.
 *
 * This unified design eliminates the dual-path complexity and ensures
 * ALL log output is safe at ANY IRQL, including VMX root mode.
 */

#ifndef _VMX_LOG_H_
#define _VMX_LOG_H_

#include <ntddk.h>
#include "../common/shared.h"

/* ========================================================================= */
/*  Configuration                                                            */
/* ========================================================================= */

#define LOG_RING_BUFFER_ENTRIES  8192
#define LOG_PREFIX              "[VMXToolbox] "

/* ========================================================================= */
/*  Log Ring Buffer (lock-free)                                              */
/* ========================================================================= */

typedef struct _LOG_RING_BUFFER {
    VMX_LOG_ENTRY   Entries[LOG_RING_BUFFER_ENTRIES];
    volatile LONG   Ready[LOG_RING_BUFFER_ENTRIES];     /* Per-slot: 1 = data written, 0 = empty/in-progress */
    volatile LONG   WriteIndex;     /* Next write position (atomically incremented) */
    volatile LONG   Count;          /* Current entry count (saturates at ENTRIES) */
    volatile LONG   ReadIndex;      /* Next read position (used only by LogRead) */
    volatile LONG   FlushIndex;     /* Next position for DbgPrintEx flush thread */
    BOOLEAN         Initialized;

    /* Flush thread state */
    HANDLE          FlushThreadHandle;
    PETHREAD        FlushThreadObject;
    KEVENT          FlushStopEvent;     /* Signaled to tell flush thread to exit */
    BOOLEAN         FlushThreadRunning;
} LOG_RING_BUFFER, *PLOG_RING_BUFFER;

/* ========================================================================= */
/*  Functions                                                                */
/* ========================================================================= */

NTSTATUS    LogInitialize(VOID);
VOID        LogTerminate(VOID);

/*
 * Start/Stop the flush thread that relays ring buffer entries to DbgPrintEx.
 *
 * The flush thread runs at PASSIVE_LEVEL in a System Thread context,
 * periodically reading new ring buffer entries and outputting them via
 * DbgPrintEx. This gives real-time WinDbg output for VMXROOT_LOG_* entries
 * without the deadlock risk of calling DbgPrintEx in VMX root mode.
 *
 * Call LogFlushThreadStart() after LogInitialize(), typically in DriverEntry.
 * Call LogFlushThreadStop() before LogTerminate(), typically in DriverUnload.
 */
NTSTATUS    LogFlushThreadStart(VOID);
VOID        LogFlushThreadStop(VOID);

/*
 * Log a message at the specified level.
 * Writes to lock-free ring buffer ONLY — safe at ANY IRQL, including VMX root mode.
 * The flush thread handles all DbgPrintEx output at PASSIVE_LEVEL.
 *
 * This is the ONLY write function — used by both LOG_* and VMXROOT_LOG_* macros.
 */
VOID        LogWrite(ULONG Level, ULONG Pid, const CHAR *Format, ...);

/*
 * LogWriteRingOnly — kept as an inline alias for backward compatibility.
 * All code now goes through LogWrite, which only writes to ring buffer.
 */
#define LogWriteRingOnly LogWrite

/*
 * Read log entries into user-mode buffer via IOCTL.
 * Returns number of entries copied.
 * Must be called at IRQL <= DISPATCH_LEVEL.
 */
ULONG       LogRead(PVMX_LOG_ENTRY OutputBuffer, ULONG MaxEntries);

/* ========================================================================= */
/*  Convenience Macros — ALL safe at any IRQL including VMX root mode        */
/* ========================================================================= */

/* Normal context logging (identical to VMXROOT_LOG_* — unified path) */
#define LOG_ERROR(fmt, ...)     LogWrite(VMX_LOG_ERROR, 0, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)      LogWrite(VMX_LOG_WARN,  0, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)      LogWrite(VMX_LOG_INFO,  0, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)     LogWrite(VMX_LOG_DEBUG, 0, fmt, ##__VA_ARGS__)

/* Process-specific logging */
#define LOG_ERROR_PID(pid, fmt, ...)  LogWrite(VMX_LOG_ERROR, pid, fmt, ##__VA_ARGS__)
#define LOG_INFO_PID(pid, fmt, ...)   LogWrite(VMX_LOG_INFO,  pid, fmt, ##__VA_ARGS__)
#define LOG_DEBUG_PID(pid, fmt, ...)  LogWrite(VMX_LOG_DEBUG, pid, fmt, ##__VA_ARGS__)

/* ========================================================================= */
/*  VMX ROOT MODE Macros — same as LOG_*, kept for code clarity              */
/* ========================================================================= */

#define VMXROOT_LOG_ERROR(fmt, ...)  LogWrite(VMX_LOG_ERROR, 0, fmt, ##__VA_ARGS__)
#define VMXROOT_LOG_WARN(fmt, ...)   LogWrite(VMX_LOG_WARN,  0, fmt, ##__VA_ARGS__)
#define VMXROOT_LOG_INFO(fmt, ...)   LogWrite(VMX_LOG_INFO,  0, fmt, ##__VA_ARGS__)
#define VMXROOT_LOG_DEBUG(fmt, ...)  LogWrite(VMX_LOG_DEBUG, 0, fmt, ##__VA_ARGS__)

/* Global log buffer (defined in log.c) */
extern LOG_RING_BUFFER g_LogBuffer;

#endif /* _VMX_LOG_H_ */
