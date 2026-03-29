/*
 * log.h - VMX Anti-Anti-Debug Hypervisor
 * Kernel-mode logging system with ring buffer
 */

#ifndef _VMX_LOG_H_
#define _VMX_LOG_H_

#include <ntddk.h>
#include "../common/shared.h"

/* ========================================================================= */
/*  Configuration                                                            */
/* ========================================================================= */

#define LOG_RING_BUFFER_ENTRIES  1024
#define LOG_PREFIX              "[VMXToolbox] "

/* ========================================================================= */
/*  Log Ring Buffer                                                          */
/* ========================================================================= */

typedef struct _LOG_RING_BUFFER {
    VMX_LOG_ENTRY   Entries[LOG_RING_BUFFER_ENTRIES];
    volatile LONG   WriteIndex;     /* Next write position */
    volatile LONG   ReadIndex;      /* Next read position */
    volatile LONG   Count;          /* Current entry count */
    KSPIN_LOCK      Lock;
    BOOLEAN         Initialized;
} LOG_RING_BUFFER, *PLOG_RING_BUFFER;

/* ========================================================================= */
/*  Functions                                                                */
/* ========================================================================= */

NTSTATUS    LogInitialize(VOID);
VOID        LogTerminate(VOID);

/*
 * Log a message at the specified level
 */
VOID        LogWrite(ULONG Level, ULONG Pid, const CHAR *Format, ...);

/*
 * Read log entries into user-mode buffer via IOCTL
 * Returns number of entries copied
 */
ULONG       LogRead(PVMX_LOG_ENTRY OutputBuffer, ULONG MaxEntries);

/* ========================================================================= */
/*  Convenience Macros                                                       */
/* ========================================================================= */

#define LOG_ERROR(fmt, ...)     LogWrite(VMX_LOG_ERROR, 0, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)      LogWrite(VMX_LOG_WARN,  0, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)      LogWrite(VMX_LOG_INFO,  0, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)     LogWrite(VMX_LOG_DEBUG, 0, fmt, ##__VA_ARGS__)

/* Process-specific logging */
#define LOG_ERROR_PID(pid, fmt, ...)  LogWrite(VMX_LOG_ERROR, pid, fmt, ##__VA_ARGS__)
#define LOG_INFO_PID(pid, fmt, ...)   LogWrite(VMX_LOG_INFO,  pid, fmt, ##__VA_ARGS__)
#define LOG_DEBUG_PID(pid, fmt, ...)  LogWrite(VMX_LOG_DEBUG, pid, fmt, ##__VA_ARGS__)

/* Global log buffer (defined in log.c) */
extern LOG_RING_BUFFER g_LogBuffer;

#endif /* _VMX_LOG_H_ */
