/*
 * svm_enlightened.h - VMX Anti-Anti-Debug Hypervisor
 * Hyper-V Enlightened VMCB fields for AMD SVM nested virtualization.
 *
 * When running nested under Hyper-V on AMD, the enlightened VMCB fields
 * occupy the reserved area at VMCB offset 0x3E0-0x3FF. These fields
 * enable Hyper-V to optimize nested page table TLB flushes and MSR
 * bitmap handling.
 *
 * Reference: Microsoft Hypervisor Top-Level Functional Specification (TLFS)
 */

#ifndef _SVM_ENLIGHTENED_H_
#define _SVM_ENLIGHTENED_H_

#include <ntddk.h>

/* ========================================================================= */
/*  Enlightened VMCB Fields                                                  */
/*                                                                           */
/*  These overlay VMCB control area at offset 0x3E0 (within Reserved7).      */
/*  The L0 hypervisor reads these to optimize nested operation.              */
/* ========================================================================= */

#define VMCB_ENLIGHTENED_OFFSET     0x3E0

#pragma pack(push, 1)

typedef struct _HV_SVM_ENLIGHTENED_VMCB_FIELDS {
    ULONG       EnlightenedVmcbVersion;         /* Must be 1 */
    ULONG       EnableEnlightenedNptTlb : 1;    /* Use enlightened NPT TLB management */
    ULONG       EnableEnlightenedMsrBitmap : 1; /* Use enlightened MSR bitmap */
    ULONG       Reserved : 30;
    ULONG       VpId;                           /* Virtual Processor ID */
    ULONG       VmId;                           /* Virtual Machine ID */
    ULONG64     PartitionAssistPagePa;          /* PA of partition assist page */
    UCHAR       Reserved2[8];                   /* Pad to 32 bytes total (fits 0x3E0-0x3FF) */
} HV_SVM_ENLIGHTENED_VMCB_FIELDS, *PHV_SVM_ENLIGHTENED_VMCB_FIELDS;

#pragma pack(pop)

C_ASSERT(sizeof(HV_SVM_ENLIGHTENED_VMCB_FIELDS) == 32);

/* The struct fits exactly within the VMCB reserved area at 0x3E0-0x3FF. */

/* ========================================================================= */
/*  VMCB Clean Bit for Enlightened Fields                                    */
/* ========================================================================= */

/*
 * VMCB Clean Bit 31 indicates whether the enlightened fields have changed.
 * When set to 1, L0 Hyper-V can skip re-reading the enlightened fields.
 * When set to 0 (dirty), L0 must process the enlightened fields.
 *
 * Standard VMCB clean bits occupy bits 0-11 (per AMD APM).
 * Bit 31 is a Hyper-V extension for the enlightened area.
 */
#define VMCB_CLEAN_BIT_ENLIGHTENED      (1UL << 31)

/* ========================================================================= */
/*  Partition Assist Page                                                    */
/*                                                                           */
/*  Shared page between L1 and L0 for fast #VMEXIT notification.             */
/*  L0 writes to this page to signal events to L1 without a full exit.       */
/* ========================================================================= */

typedef struct _HV_SVM_PARTITION_ASSIST_PAGE {
    ULONG       TlbLockCount;               /* L0 TLB lock count */
    UCHAR       Reserved[PAGE_SIZE - sizeof(ULONG)];
} HV_SVM_PARTITION_ASSIST_PAGE, *PHV_SVM_PARTITION_ASSIST_PAGE;

C_ASSERT(sizeof(HV_SVM_PARTITION_ASSIST_PAGE) == PAGE_SIZE);

#endif /* _SVM_ENLIGHTENED_H_ */
