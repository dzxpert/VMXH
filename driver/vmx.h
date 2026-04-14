/*
 * vmx.h - VMX Anti-Anti-Debug Hypervisor
 * Core VMX data structures, constants, and VMCS field encodings
 */

#ifndef _VMX_H_
#define _VMX_H_

#include <ntddk.h>
#include <wdm.h>
#include "hv_ops.h"

/* ========================================================================= */
/*  Fundamental Constants                                                    */
/* ========================================================================= */

#define VMX_TAG                     'xmvD'  /* Pool allocation tag */
#define PAGE_SIZE_4KB               0x1000
#define PAGE_MASK_4KB               (~0xFFFULL)
#define ALIGNMENT_PAGE_SIZE         PAGE_SIZE_4KB
/* MAX_PROCESSORS removed — use g_MaxProcessors (from hv_ops.h) */

/* ========================================================================= */
/*  MSR Definitions                                                          */
/* ========================================================================= */

#define MSR_IA32_FEATURE_CONTROL        0x003A
#define MSR_IA32_VMX_BASIC              0x0480
#define MSR_IA32_VMX_PINBASED_CTLS      0x0481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x0482
#define MSR_IA32_VMX_EXIT_CTLS          0x0483
#define MSR_IA32_VMX_ENTRY_CTLS         0x0484
#define MSR_IA32_VMX_MISC               0x0485
#define MSR_IA32_VMX_CR0_FIXED0         0x0486
#define MSR_IA32_VMX_CR0_FIXED1         0x0487
#define MSR_IA32_VMX_CR4_FIXED0         0x0488
#define MSR_IA32_VMX_CR4_FIXED1         0x0489
#define MSR_IA32_VMX_VMCS_ENUM          0x048A
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x048B
#define MSR_IA32_VMX_EPT_VPID_CAP       0x048C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS 0x048D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x048E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS     0x048F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS    0x0490
#define MSR_IA32_VMX_VMFUNC             0x0491

#define MSR_IA32_SYSENTER_CS            0x0174
#define MSR_IA32_SYSENTER_ESP           0x0175
#define MSR_IA32_SYSENTER_EIP           0x0176
#define MSR_IA32_DEBUGCTL               0x01D9
#define MSR_IA32_XSS                    0x0DA0
#define MSR_IA32_PAT                    0x0277
#define MSR_IA32_EFER                   0x0C0000080
#define MSR_IA32_FS_BASE                0x0C0000100
#define MSR_IA32_GS_BASE                0x0C0000101
#define MSR_IA32_KERNEL_GS_BASE         0x0C0000102
#define MSR_IA32_TSC_AUX                0x0C0000103

/* Feature Control bits */
#define FEATURE_CONTROL_LOCKED          (1 << 0)
#define FEATURE_CONTROL_VMXON_ENABLED   (1 << 2)

/* ========================================================================= */
/*  CPUID Definitions                                                        */
/* ========================================================================= */

#define CPUID_VMX_BIT                   5       /* ECX bit 5 of CPUID leaf 1 */
#define CPUID_HYPERVISOR_BIT            31      /* ECX bit 31 of CPUID leaf 1 */

/* ========================================================================= */
/*  CR Bits                                                                  */
/* ========================================================================= */

#define CR4_VMXE                        (1ULL << 13)
#define CR0_PE                          (1ULL << 0)
#define CR0_NE                          (1ULL << 5)
#define CR0_PG                          (1ULL << 31)
#define CR4_PAE                         (1ULL << 5)

/* ========================================================================= */
/*  VMCS Field Encodings                                                     */
/* ========================================================================= */

/* 16-Bit Control Fields */
#define VMCS_CTRL_VPID                          0x00000000
#define VMCS_CTRL_POSTED_INT_NOTIFY_VECTOR      0x00000002
#define VMCS_CTRL_EPTP_INDEX                    0x00000004

/* 16-Bit Guest-State Fields */
#define VMCS_GUEST_ES_SEL                       0x00000800
#define VMCS_GUEST_CS_SEL                       0x00000802
#define VMCS_GUEST_SS_SEL                       0x00000804
#define VMCS_GUEST_DS_SEL                       0x00000806
#define VMCS_GUEST_FS_SEL                       0x00000808
#define VMCS_GUEST_GS_SEL                       0x0000080A
#define VMCS_GUEST_LDTR_SEL                     0x0000080C
#define VMCS_GUEST_TR_SEL                       0x0000080E

/* 16-Bit Host-State Fields */
#define VMCS_HOST_ES_SEL                        0x00000C00
#define VMCS_HOST_CS_SEL                        0x00000C02
#define VMCS_HOST_SS_SEL                        0x00000C04
#define VMCS_HOST_DS_SEL                        0x00000C06
#define VMCS_HOST_FS_SEL                        0x00000C08
#define VMCS_HOST_GS_SEL                        0x00000C0A
#define VMCS_HOST_TR_SEL                        0x00000C0C

/* 64-Bit Control Fields */
#define VMCS_CTRL_IO_BITMAP_A                   0x00002000
#define VMCS_CTRL_IO_BITMAP_B                   0x00002002
#define VMCS_CTRL_MSR_BITMAP                    0x00002004
#define VMCS_CTRL_VMEXIT_MSR_STORE_ADDR         0x00002006
#define VMCS_CTRL_VMEXIT_MSR_LOAD_ADDR          0x00002008
#define VMCS_CTRL_VMENTRY_MSR_LOAD_ADDR         0x0000200A
#define VMCS_CTRL_EXECUTIVE_VMCS_PTR            0x0000200C
#define VMCS_CTRL_TSC_OFFSET                    0x00002010
#define VMCS_CTRL_VIRTUAL_APIC_ADDR             0x00002012
#define VMCS_CTRL_APIC_ACCESS_ADDR              0x00002014
#define VMCS_CTRL_EPT_POINTER                   0x0000201A
#define VMCS_CTRL_EOI_EXIT_BITMAP_0             0x0000201C
#define VMCS_CTRL_XSS_EXITING_BITMAP            0x0000202C

/* 64-Bit Read-Only Data Field */
#define VMCS_GUEST_PHYSICAL_ADDRESS             0x00002400

/* 64-Bit Guest-State Fields */
#define VMCS_GUEST_VMCS_LINK_PTR                0x00002800
#define VMCS_GUEST_IA32_DEBUGCTL                0x00002802
#define VMCS_GUEST_IA32_PAT                     0x00002804
#define VMCS_GUEST_IA32_EFER                    0x00002806
#define VMCS_GUEST_IA32_PERF_GLOBAL_CTRL        0x00002808
#define VMCS_GUEST_PDPTE0                       0x0000280A
#define VMCS_GUEST_PDPTE1                       0x0000280C
#define VMCS_GUEST_PDPTE2                       0x0000280E
#define VMCS_GUEST_PDPTE3                       0x00002810
#define VMCS_GUEST_IA32_XSS                     0x00002812

/* 64-Bit Host-State Fields */
#define VMCS_HOST_IA32_PAT                      0x00002C00
#define VMCS_HOST_IA32_EFER                     0x00002C02
#define VMCS_HOST_IA32_PERF_GLOBAL_CTRL         0x00002C04
#define VMCS_HOST_IA32_XSS                      0x00002C06

/* 32-Bit Control Fields */
#define VMCS_CTRL_PIN_BASED_VM_EXEC             0x00004000
#define VMCS_CTRL_PROC_BASED_VM_EXEC            0x00004002
#define VMCS_CTRL_EXCEPTION_BITMAP              0x00004004
#define VMCS_CTRL_PAGE_FAULT_ERROR_MASK         0x00004006
#define VMCS_CTRL_PAGE_FAULT_ERROR_MATCH        0x00004008
#define VMCS_CTRL_CR3_TARGET_COUNT              0x0000400A
#define VMCS_CTRL_VMEXIT_CONTROLS               0x0000400C
#define VMCS_CTRL_VMEXIT_MSR_STORE_COUNT        0x0000400E
#define VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT         0x00004010
#define VMCS_CTRL_VMENTRY_CONTROLS              0x00004012
#define VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT        0x00004014
#define VMCS_CTRL_VMENTRY_INT_INFO              0x00004016
#define VMCS_CTRL_VMENTRY_EXCEPTION_ERRCODE     0x00004018
#define VMCS_CTRL_VMENTRY_INSTR_LENGTH          0x0000401A
#define VMCS_CTRL_TPR_THRESHOLD                 0x0000401C
#define VMCS_CTRL_SECONDARY_VM_EXEC             0x0000401E
#define VMCS_CTRL_PLE_GAP                       0x00004020
#define VMCS_CTRL_PLE_WINDOW                    0x00004022

/* 32-Bit Read-Only Data Fields */
#define VMCS_VM_INSTRUCTION_ERROR               0x00004400
#define VMCS_EXIT_REASON                        0x00004402
#define VMCS_EXIT_INTERRUPTION_INFO             0x00004404
#define VMCS_EXIT_INTERRUPTION_ERRCODE          0x00004406
#define VMCS_IDT_VECTORING_INFO                 0x00004408
#define VMCS_IDT_VECTORING_ERRCODE              0x0000440A
#define VMCS_EXIT_INSTRUCTION_LENGTH            0x0000440C
#define VMCS_EXIT_INSTRUCTION_INFO              0x0000440E

/* 32-Bit Guest-State Fields */
#define VMCS_GUEST_ES_LIMIT                     0x00004800
#define VMCS_GUEST_CS_LIMIT                     0x00004802
#define VMCS_GUEST_SS_LIMIT                     0x00004804
#define VMCS_GUEST_DS_LIMIT                     0x00004806
#define VMCS_GUEST_FS_LIMIT                     0x00004808
#define VMCS_GUEST_GS_LIMIT                     0x0000480A
#define VMCS_GUEST_LDTR_LIMIT                   0x0000480C
#define VMCS_GUEST_TR_LIMIT                     0x0000480E
#define VMCS_GUEST_GDTR_LIMIT                   0x00004810
#define VMCS_GUEST_IDTR_LIMIT                   0x00004812
#define VMCS_GUEST_ES_ACCESS_RIGHTS             0x00004814
#define VMCS_GUEST_CS_ACCESS_RIGHTS             0x00004816
#define VMCS_GUEST_SS_ACCESS_RIGHTS             0x00004818
#define VMCS_GUEST_DS_ACCESS_RIGHTS             0x0000481A
#define VMCS_GUEST_FS_ACCESS_RIGHTS             0x0000481C
#define VMCS_GUEST_GS_ACCESS_RIGHTS             0x0000481E
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS           0x00004820
#define VMCS_GUEST_TR_ACCESS_RIGHTS             0x00004822
#define VMCS_GUEST_INTERRUPTIBILITY             0x00004824
#define VMCS_GUEST_ACTIVITY_STATE               0x00004826
#define VMCS_GUEST_SMBASE                       0x00004828
#define VMCS_GUEST_IA32_SYSENTER_CS             0x0000482A
#define VMCS_GUEST_PREEMPT_TIMER_VALUE          0x0000482E

/* 32-Bit Host-State Fields */
#define VMCS_HOST_IA32_SYSENTER_CS              0x00004C00

/* Natural-Width Control Fields */
#define VMCS_CTRL_CR0_GUEST_HOST_MASK           0x00006000
#define VMCS_CTRL_CR4_GUEST_HOST_MASK           0x00006002
#define VMCS_CTRL_CR0_READ_SHADOW               0x00006004
#define VMCS_CTRL_CR4_READ_SHADOW               0x00006006
#define VMCS_CTRL_CR3_TARGET_VAL0               0x00006008
#define VMCS_CTRL_CR3_TARGET_VAL1               0x0000600A
#define VMCS_CTRL_CR3_TARGET_VAL2               0x0000600C
#define VMCS_CTRL_CR3_TARGET_VAL3               0x0000600E

/* Natural-Width Read-Only Data Fields */
#define VMCS_EXIT_QUALIFICATION                 0x00006400
#define VMCS_IO_RCX                             0x00006402
#define VMCS_IO_RSI                             0x00006404
#define VMCS_IO_RDI                             0x00006406
#define VMCS_IO_RIP                             0x00006408
#define VMCS_EXIT_GUEST_LINEAR_ADDR             0x0000640A

/* Natural-Width Guest-State Fields */
#define VMCS_GUEST_CR0                          0x00006800
#define VMCS_GUEST_CR3                          0x00006802
#define VMCS_GUEST_CR4                          0x00006804
#define VMCS_GUEST_ES_BASE                      0x00006806
#define VMCS_GUEST_CS_BASE                      0x00006808
#define VMCS_GUEST_SS_BASE                      0x0000680A
#define VMCS_GUEST_DS_BASE                      0x0000680C
#define VMCS_GUEST_FS_BASE                      0x0000680E
#define VMCS_GUEST_GS_BASE                      0x00006810
#define VMCS_GUEST_LDTR_BASE                    0x00006812
#define VMCS_GUEST_TR_BASE                      0x00006814
#define VMCS_GUEST_GDTR_BASE                    0x00006816
#define VMCS_GUEST_IDTR_BASE                    0x00006818
#define VMCS_GUEST_DR7                          0x0000681A
#define VMCS_GUEST_RSP                          0x0000681C
#define VMCS_GUEST_RIP                          0x0000681E
#define VMCS_GUEST_RFLAGS                       0x00006820
#define VMCS_GUEST_PENDING_DBG_EXCEPTIONS       0x00006822
#define VMCS_GUEST_IA32_SYSENTER_ESP            0x00006824
#define VMCS_GUEST_IA32_SYSENTER_EIP            0x00006826

/* Natural-Width Host-State Fields */
#define VMCS_HOST_CR0                           0x00006C00
#define VMCS_HOST_CR3                           0x00006C02
#define VMCS_HOST_CR4                           0x00006C04
#define VMCS_HOST_FS_BASE                       0x00006C06
#define VMCS_HOST_GS_BASE                       0x00006C08
#define VMCS_HOST_TR_BASE                       0x00006C0A
#define VMCS_HOST_GDTR_BASE                     0x00006C0C
#define VMCS_HOST_IDTR_BASE                     0x00006C0E
#define VMCS_HOST_IA32_SYSENTER_ESP             0x00006C10
#define VMCS_HOST_IA32_SYSENTER_EIP             0x00006C12
#define VMCS_HOST_RSP                           0x00006C14
#define VMCS_HOST_RIP                           0x00006C16

/* ========================================================================= */
/*  VM-Exit Reasons                                                          */
/* ========================================================================= */

#define EXIT_REASON_EXCEPTION_NMI               0
#define EXIT_REASON_EXTERNAL_INT                1
#define EXIT_REASON_TRIPLE_FAULT                2
#define EXIT_REASON_INIT_SIGNAL                 3
#define EXIT_REASON_SIPI                        4
#define EXIT_REASON_IO_SMI                      5
#define EXIT_REASON_OTHER_SMI                   6
#define EXIT_REASON_INT_WINDOW                  7
#define EXIT_REASON_NMI_WINDOW                  8
#define EXIT_REASON_TASK_SWITCH                 9
#define EXIT_REASON_CPUID                       10
#define EXIT_REASON_GETSEC                      11
#define EXIT_REASON_HLT                         12
#define EXIT_REASON_INVD                        13
#define EXIT_REASON_INVLPG                      14
#define EXIT_REASON_RDPMC                       15
#define EXIT_REASON_RDTSC                       16
#define EXIT_REASON_RSM                         17
#define EXIT_REASON_VMCALL                      18
#define EXIT_REASON_VMCLEAR                     19
#define EXIT_REASON_VMLAUNCH                    20
#define EXIT_REASON_VMPTRLD                     21
#define EXIT_REASON_VMPTRST                     22
#define EXIT_REASON_VMREAD                      23
#define EXIT_REASON_VMRESUME                    24
#define EXIT_REASON_VMWRITE                     25
#define EXIT_REASON_VMXOFF                      26
#define EXIT_REASON_VMXON                       27
#define EXIT_REASON_CR_ACCESS                   28
#define EXIT_REASON_DR_ACCESS                   29
#define EXIT_REASON_IO_INSTRUCTION              30
#define EXIT_REASON_RDMSR                       31
#define EXIT_REASON_WRMSR                       32
#define EXIT_REASON_VMENTRY_FAIL_GUEST          33
#define EXIT_REASON_VMENTRY_FAIL_MSR            34
#define EXIT_REASON_MWAIT                       36
#define EXIT_REASON_MTF                         37
#define EXIT_REASON_MONITOR                     39
#define EXIT_REASON_PAUSE                       40
#define EXIT_REASON_VMENTRY_FAIL_MCE            41
#define EXIT_REASON_TPR_BELOW_THRESHOLD         43
#define EXIT_REASON_APIC_ACCESS                 44
#define EXIT_REASON_VIRTUALIZED_EOI             45
#define EXIT_REASON_GDTR_IDTR_ACCESS            46
#define EXIT_REASON_LDTR_TR_ACCESS              47
#define EXIT_REASON_EPT_VIOLATION               48
#define EXIT_REASON_EPT_MISCONFIG               49
#define EXIT_REASON_INVEPT                      50
#define EXIT_REASON_RDTSCP                      51
#define EXIT_REASON_PREEMPT_TIMER               52
#define EXIT_REASON_INVVPID                     53
#define EXIT_REASON_WBINVD                      54
#define EXIT_REASON_XSETBV                      55
#define EXIT_REASON_APIC_WRITE                  56
#define EXIT_REASON_RDRAND                      57
#define EXIT_REASON_INVPCID                     58
#define EXIT_REASON_VMFUNC                      59
#define EXIT_REASON_ENCLS                       60
#define EXIT_REASON_RDSEED                      61
#define EXIT_REASON_PML_FULL                    62
#define EXIT_REASON_XSAVES                      63
#define EXIT_REASON_XRSTORS                     64

/* ========================================================================= */
/*  Pin-Based VM-Execution Controls                                          */
/* ========================================================================= */

#define PIN_BASED_EXTERNAL_INT_EXIT         (1 << 0)
#define PIN_BASED_NMI_EXIT                  (1 << 3)
#define PIN_BASED_VIRTUAL_NMIS              (1 << 5)
#define PIN_BASED_PREEMPT_TIMER             (1 << 6)
#define PIN_BASED_POSTED_INTERRUPTS         (1 << 7)

/* ========================================================================= */
/*  Primary Processor-Based VM-Execution Controls                            */
/* ========================================================================= */

#define PROC_BASED_INT_WINDOW_EXIT          (1 << 2)
#define PROC_BASED_USE_TSC_OFFSETTING       (1 << 3)
#define PROC_BASED_HLT_EXIT                 (1 << 7)
#define PROC_BASED_INVLPG_EXIT              (1 << 9)
#define PROC_BASED_MWAIT_EXIT               (1 << 10)
#define PROC_BASED_RDPMC_EXIT               (1 << 11)
#define PROC_BASED_RDTSC_EXIT               (1 << 12)
#define PROC_BASED_CR3_LOAD_EXIT            (1 << 15)
#define PROC_BASED_CR3_STORE_EXIT           (1 << 16)
#define PROC_BASED_CR8_LOAD_EXIT            (1 << 19)
#define PROC_BASED_CR8_STORE_EXIT           (1 << 20)
#define PROC_BASED_TPR_SHADOW               (1 << 21)
#define PROC_BASED_NMI_WINDOW_EXIT          (1 << 22)
#define PROC_BASED_MOV_DR_EXIT              (1 << 23)
#define PROC_BASED_UNCONDITIONAL_IO_EXIT    (1 << 24)
#define PROC_BASED_USE_IO_BITMAPS           (1 << 25)
#define PROC_BASED_MONITOR_TRAP_FLAG        (1 << 27)
#define PROC_BASED_USE_MSR_BITMAPS          (1 << 28)
#define PROC_BASED_MONITOR_EXIT             (1 << 29)
#define PROC_BASED_PAUSE_EXIT               (1 << 30)
#define PROC_BASED_SECONDARY_CONTROLS       (1U << 31)

/* ========================================================================= */
/*  Secondary Processor-Based VM-Execution Controls                          */
/* ========================================================================= */

#define PROC_BASED2_VIRT_APIC_ACCESS        (1 << 0)
#define PROC_BASED2_ENABLE_EPT              (1 << 1)
#define PROC_BASED2_DESC_TABLE_EXIT         (1 << 2)
#define PROC_BASED2_ENABLE_RDTSCP           (1 << 3)
#define PROC_BASED2_VIRT_x2APIC             (1 << 4)
#define PROC_BASED2_ENABLE_VPID             (1 << 5)
#define PROC_BASED2_WBINVD_EXIT             (1 << 6)
#define PROC_BASED2_UNRESTRICTED_GUEST      (1 << 7)
#define PROC_BASED2_APIC_REG_VIRT           (1 << 8)
#define PROC_BASED2_VIRT_INT_DELIVERY       (1 << 9)
#define PROC_BASED2_PAUSE_LOOP_EXIT         (1 << 10)
#define PROC_BASED2_RDRAND_EXIT             (1 << 11)
#define PROC_BASED2_ENABLE_INVPCID          (1 << 12)
#define PROC_BASED2_ENABLE_VMFUNC           (1 << 13)
#define PROC_BASED2_VMCS_SHADOWING          (1 << 14)
#define PROC_BASED2_ENCLS_EXIT              (1 << 15)
#define PROC_BASED2_RDSEED_EXIT             (1 << 16)
#define PROC_BASED2_PML                     (1 << 17)
#define PROC_BASED2_EPT_VIOLATION_VE        (1 << 18)
#define PROC_BASED2_CONCEAL_FROM_PT         (1 << 19)
#define PROC_BASED2_ENABLE_XSAVES          (1 << 20)
#define PROC_BASED2_MODE_BASED_EPT_EXEC    (1 << 22)

/* ========================================================================= */
/*  VM-Exit Controls                                                         */
/* ========================================================================= */

#define VMEXIT_SAVE_DBG_CONTROLS            (1 << 2)
#define VMEXIT_HOST_ADDR_SPACE_SIZE         (1 << 9)
#define VMEXIT_LOAD_IA32_PERF_GLOBAL        (1 << 12)
#define VMEXIT_ACK_INT_ON_EXIT              (1 << 15)
#define VMEXIT_SAVE_IA32_PAT                (1 << 18)
#define VMEXIT_LOAD_IA32_PAT                (1 << 19)
#define VMEXIT_SAVE_IA32_EFER               (1 << 20)
#define VMEXIT_LOAD_IA32_EFER               (1 << 21)
#define VMEXIT_SAVE_PREEMPT_TIMER           (1 << 22)

/* ========================================================================= */
/*  VM-Entry Controls                                                        */
/* ========================================================================= */

#define VMENTRY_LOAD_DBG_CONTROLS           (1 << 2)
#define VMENTRY_IA32E_MODE_GUEST            (1 << 9)
#define VMENTRY_SMM_ENTRY                   (1 << 10)
#define VMENTRY_DEACTIVATE_DUAL_MONITOR     (1 << 11)
#define VMENTRY_LOAD_IA32_PERF_GLOBAL       (1 << 13)
#define VMENTRY_LOAD_IA32_PAT              (1 << 14)
#define VMENTRY_LOAD_IA32_EFER             (1 << 15)

/* ========================================================================= */
/*  Exception Bitmap Bits                                                    */
/* ========================================================================= */

#define EXCEPTION_BITMAP_DE                 (1 << 0)    /* Divide Error */
#define EXCEPTION_BITMAP_DB                 (1 << 1)    /* Debug */
#define EXCEPTION_BITMAP_NMI                (1 << 2)    /* NMI */
#define EXCEPTION_BITMAP_BP                 (1 << 3)    /* Breakpoint */
#define EXCEPTION_BITMAP_OF                 (1 << 4)    /* Overflow */
#define EXCEPTION_BITMAP_BR                 (1 << 5)    /* BOUND Range */
#define EXCEPTION_BITMAP_UD                 (1 << 6)    /* Invalid Opcode */
#define EXCEPTION_BITMAP_NM                 (1 << 7)    /* No Math */
#define EXCEPTION_BITMAP_DF                 (1 << 8)    /* Double Fault */
#define EXCEPTION_BITMAP_TS                 (1 << 10)   /* Invalid TSS */
#define EXCEPTION_BITMAP_NP                 (1 << 11)   /* Segment Not Present */
#define EXCEPTION_BITMAP_SS                 (1 << 12)   /* Stack-Segment Fault */
#define EXCEPTION_BITMAP_GP                 (1 << 13)   /* General Protection */
#define EXCEPTION_BITMAP_PF                 (1 << 14)   /* Page Fault */
#define EXCEPTION_BITMAP_MF                 (1 << 16)   /* FPU Error */
#define EXCEPTION_BITMAP_AC                 (1 << 17)   /* Alignment Check */
#define EXCEPTION_BITMAP_MC                 (1 << 18)   /* Machine Check */
#define EXCEPTION_BITMAP_XM                 (1 << 19)   /* SIMD */

/* ========================================================================= */
/*  Exit Qualification Bits for DR Access                                    */
/* ========================================================================= */

#define DR_ACCESS_REG_MASK                  0x07        /* bits 2:0 - DR number */
#define DR_ACCESS_DIRECTION_BIT             4           /* bit 4: 0=MOV to DR, 1=MOV from DR */
#define DR_ACCESS_DIRECTION_WRITE           0
#define DR_ACCESS_DIRECTION_READ            1
#define DR_ACCESS_GP_REG_SHIFT              8           /* bits 11:8 - GP register */
#define DR_ACCESS_GP_REG_MASK               0x0F

/* ========================================================================= */
/*  Exit Qualification Bits for CR Access                                    */
/* ========================================================================= */

#define CR_ACCESS_CR_NUM_MASK               0x0F        /* bits 3:0 - CR number */
#define CR_ACCESS_TYPE_SHIFT                4           /* bits 5:4 - access type */
#define CR_ACCESS_TYPE_MOV_TO_CR            0
#define CR_ACCESS_TYPE_MOV_FROM_CR          1
#define CR_ACCESS_TYPE_CLTS                 2
#define CR_ACCESS_TYPE_LMSW                 3
#define CR_ACCESS_GP_REG_SHIFT              8           /* bits 11:8 - GP register */
#define CR_ACCESS_GP_REG_MASK               0x0F

/* ========================================================================= */
/*  EPT Violation Exit Qualification                                         */
/* ========================================================================= */

#define EPT_VIOLATION_READ                  (1 << 0)
#define EPT_VIOLATION_WRITE                 (1 << 1)
#define EPT_VIOLATION_EXEC                  (1 << 2)
#define EPT_VIOLATION_READABLE              (1 << 3)
#define EPT_VIOLATION_WRITABLE              (1 << 4)
#define EPT_VIOLATION_EXECUTABLE            (1 << 5)

/* ========================================================================= */
/*  VMCALL Magic Values                                                      */
/* ========================================================================= */

#define VMCALL_MAGIC_SHUTDOWN               0xDEADCAFEULL

/* ========================================================================= */
/*  Interruption Info Field                                                  */
/* ========================================================================= */

#define INTERRUPT_INFO_VECTOR_MASK          0xFF
#define INTERRUPT_INFO_TYPE_SHIFT           8
#define INTERRUPT_INFO_TYPE_MASK            (0x7 << 8)
#define INTERRUPT_INFO_DELIVER_ERR_CODE     (1 << 11)
#define INTERRUPT_INFO_VALID                (1U << 31)

#define INTERRUPT_TYPE_EXTERNAL             0
#define INTERRUPT_TYPE_NMI                  2
#define INTERRUPT_TYPE_HARDWARE_EXCEPTION   3
#define INTERRUPT_TYPE_SOFTWARE_INT         4
#define INTERRUPT_TYPE_PRIV_SOFTWARE_INT    5
#define INTERRUPT_TYPE_SOFTWARE_EXCEPTION   6

/* ========================================================================= */
/*  Data Structures                                                          */
/* ========================================================================= */

/*
 * Segment descriptor for VMCS setup
 */
typedef struct _SEGMENT_DESCRIPTOR {
    USHORT  Selector;
    ULONG   Limit;
    ULONG   AccessRights;
    ULONG64 Base;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

/*
 * Guest register context saved/restored around VM-Exits
 * Must match the layout in vmx_asm.asm
 */
typedef struct _GUEST_CONTEXT {
    ULONG64 Rax;
    ULONG64 Rcx;
    ULONG64 Rdx;
    ULONG64 Rbx;
    ULONG64 Rsp;       /* Placeholder - actual RSP from VMCS */
    ULONG64 Rbp;
    ULONG64 Rsi;
    ULONG64 Rdi;
    ULONG64 R8;
    ULONG64 R9;
    ULONG64 R10;
    ULONG64 R11;
    ULONG64 R12;
    ULONG64 R13;
    ULONG64 R14;
    ULONG64 R15;
} GUEST_CONTEXT, *PGUEST_CONTEXT;

/*
 * VMXON and VMCS region header
 * Must be 4KB aligned, first 4 bytes = VMCS revision ID
 */
typedef struct _VMX_REGION {
    ULONG   RevisionId;
    ULONG   AbortIndicator;
    CHAR    Data[PAGE_SIZE_4KB - 8];
} VMX_REGION, *PVMX_REGION;

/*
 * Per-processor VMX state
 */
typedef struct _VMX_CPU_CONTEXT {
    /* VMXON region */
    PVOID       VmxonRegionVa;
    ULONG64     VmxonRegionPa;

    /* VMCS region */
    PVOID       VmcsRegionVa;
    ULONG64     VmcsRegionPa;

    /* MSR bitmap (4KB) */
    PVOID       MsrBitmapVa;
    ULONG64     MsrBitmapPa;

    /* I/O bitmaps (4KB each): A covers ports 0x0000-0x7FFF, B covers 0x8000-0xFFFF.
     * Initialized to all zeros = no I/O port triggers VM-Exit.
     * When USE_IO_BITMAPS is set, it takes precedence over UNCONDITIONAL_IO_EXIT,
     * effectively neutralizing the must-be-1 UNCONDITIONAL_IO_EXIT bit. */
    PVOID       IoBitmapAVa;
    ULONG64     IoBitmapAPa;
    PVOID       IoBitmapBVa;
    ULONG64     IoBitmapBPa;

    /* Host stack for VM-Exit handler */
    PVOID       HostStackBase;
    SIZE_T      HostStackSize;

    /* State tracking */
    BOOLEAN     VmxEnabled;         /* VMXON executed */
    BOOLEAN     VmcsLaunched;       /* VMLAUNCH executed */
    ULONG       ProcessorNumber;

    /* Original host state (for VMXOFF restoration) */
    ULONG64     OriginalCr4;

    /* TSC compensation for anti-timing */
    LONG64      TscOffset;          /* Accumulated TSC to subtract */
    ULONG64     LastDebugPauseTsc;  /* TSC when debug pause started */
    BOOLEAN     InDebugPause;       /* Currently in debug pause */

    /* Statistics */
    volatile LONG64 ExitCount;

} VMX_CPU_CONTEXT, *PVMX_CPU_CONTEXT;

/*
 * Global VMX state
 */
typedef struct _VMX_STATE {
    PVMX_CPU_CONTEXT CpuContexts;   /* dynamically allocated array [g_MaxProcessors] */
    ULONG           CpuCount;
    BOOLEAN         Initialized;

    /* VMCS revision from IA32_VMX_BASIC */
    ULONG           VmcsRevisionId;

    /* Capability MSR values */
    ULONG64         VmxBasic;
    ULONG64         PinBasedCap;
    ULONG64         ProcBasedCap;
    ULONG64         ProcBased2Cap;
    ULONG64         ExitCap;
    ULONG64         EntryCap;
    ULONG64         EptVpidCap;

    /* True controls if supported */
    BOOLEAN         TrueControlsSupported;
    ULONG64         TruePinBasedCap;
    ULONG64         TrueProcBasedCap;
    ULONG64         TrueExitCap;
    ULONG64         TrueEntryCap;

} VMX_STATE, *PVMX_STATE;

/* ========================================================================= */
/*  Descriptor Table Registers                                               */
/* ========================================================================= */

#pragma pack(push, 1)
typedef struct _DESCRIPTOR_TABLE_REG {
    USHORT  Limit;
    ULONG64 Base;
} DESCRIPTOR_TABLE_REG, *PDESCRIPTOR_TABLE_REG;
#pragma pack(pop)

/* ========================================================================= */
/*  Segment Descriptor (GDT entry) for parsing                               */
/* ========================================================================= */

#pragma pack(push, 1)
typedef struct _GDT_ENTRY {
    USHORT  LimitLow;
    USHORT  BaseLow;
    UCHAR   BaseMid;
    UCHAR   Access;
    UCHAR   LimitHighAndFlags;
    UCHAR   BaseHigh;
} GDT_ENTRY, *PGDT_ENTRY;

/* Extended for system segments (TSS, etc.) in 64-bit mode */
typedef struct _GDT_ENTRY64 {
    USHORT  LimitLow;
    USHORT  BaseLow;
    UCHAR   BaseMid;
    UCHAR   Access;
    UCHAR   LimitHighAndFlags;
    UCHAR   BaseHigh;
    ULONG   BaseUpper;
    ULONG   Reserved;
} GDT_ENTRY64, *PGDT_ENTRY64;
#pragma pack(pop)

/* ========================================================================= */
/*  INVEPT / INVVPID Types                                                   */
/* ========================================================================= */

#define INVEPT_SINGLE_CONTEXT       1
#define INVEPT_ALL_CONTEXTS         2

#define INVVPID_INDIVIDUAL_ADDR     0
#define INVVPID_SINGLE_CONTEXT      1
#define INVVPID_ALL_CONTEXTS        2
#define INVVPID_SINGLE_CONTEXT_RETAIN_GLOBALS  3

typedef struct _INVEPT_DESCRIPTOR {
    ULONG64 EptPointer;
    ULONG64 Reserved;
} INVEPT_DESCRIPTOR, *PINVEPT_DESCRIPTOR;

typedef struct _INVVPID_DESCRIPTOR {
    USHORT  Vpid;
    USHORT  Reserved1;
    ULONG   Reserved2;
    ULONG64 LinearAddress;
} INVVPID_DESCRIPTOR, *PINVVPID_DESCRIPTOR;

/* ========================================================================= */
/*  Function Declarations (implemented across modules)                       */
/* ========================================================================= */

/* vmx_init.c */
NTSTATUS VmxInitialize(PVMX_STATE State);
VOID     VmxTerminate(PVMX_STATE State);
BOOLEAN  VmxIsSupported(VOID);
NTSTATUS VmxSetupVmcs(PVMX_CPU_CONTEXT CpuCtx, PVMX_STATE State);

/* vmx_exit.c */
BOOLEAN  VmxExitHandler(PGUEST_CONTEXT GuestContext);

/* vmx_asm.asm */
extern UCHAR    AsmVmxLaunch(VOID);
extern VOID     AsmVmxResume(VOID);
extern VOID     AsmVmxExitHandler(VOID);
extern UCHAR    AsmVmxInvept(ULONG Type, PINVEPT_DESCRIPTOR Desc);
extern UCHAR    AsmVmxInvvpid(ULONG Type, PINVVPID_DESCRIPTOR Desc);
extern USHORT   AsmGetCs(VOID);
extern USHORT   AsmGetSs(VOID);
extern USHORT   AsmGetDs(VOID);
extern USHORT   AsmGetEs(VOID);
extern USHORT   AsmGetFs(VOID);
extern USHORT   AsmGetGs(VOID);
extern USHORT   AsmGetTr(VOID);
extern USHORT   AsmGetLdtr(VOID);
extern ULONG64  AsmGetGdtBase(VOID);
extern USHORT   AsmGetGdtLimit(VOID);
extern ULONG64  AsmGetIdtBase(VOID);
extern USHORT   AsmGetIdtLimit(VOID);
extern ULONG64  AsmGetRflags(VOID);
extern VOID     AsmSaveHostState(PGUEST_CONTEXT Context);
extern VOID     AsmRestoreGuestState(PGUEST_CONTEXT Context);
extern VOID     AsmXsetbv(ULONG Index, ULONG64 Value);
extern VOID     AsmVmxVmcall(ULONG64 HypercallValue);

#include "hv_detect.h"

/* Global VMX state (defined in vmxdrv.c) — forward-declared here for inlines */
extern VMX_STATE g_VmxState;

FORCEINLINE ULONG64 VmxRead(ULONG Field)
{
    SIZE_T Value = 0;
    __vmx_vmread(Field, &Value);
    return (ULONG64)Value;
}

FORCEINLINE VOID VmxWrite(ULONG Field, ULONG64 Value)
{
    __vmx_vmwrite(Field, Value);
}

/* Helper: Advance guest RIP past the current instruction */
FORCEINLINE VOID VmxAdvanceGuestRip(VOID)
{
    ULONG64 Rip = VmxRead(VMCS_GUEST_RIP);
    ULONG64 Len = VmxRead(VMCS_EXIT_INSTRUCTION_LENGTH);
    VmxWrite(VMCS_GUEST_RIP, Rip + Len);
}

/* VMX HV_OPS backend (registered in vmx_init.c) */
extern HV_OPS g_VmxOps;

#endif /* _VMX_H_ */
