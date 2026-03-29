/*
 * hv_mem.h - VMX Anti-Anti-Debug Hypervisor
 * Hypervisor-level memory read/write via Guest page table traversal.
 *
 * This module provides direct physical memory access to any Guest process's
 * virtual address space by walking the Guest's CR3 page tables.
 * Since the EPT/NPT identity maps all physical memory, Guest physical
 * addresses can be accessed directly as host virtual addresses.
 *
 * This bypasses ALL Guest-level protections:
 *   - ObRegisterCallbacks (no handle needed)
 *   - NtReadVirtualMemory hooks (no API called)
 *   - KeStackAttachProcess (no context switch)
 *   - Any driver-level memory access monitoring
 */

#ifndef _HV_MEM_H_
#define _HV_MEM_H_

#include <ntddk.h>

/* ========================================================================= */
/*  VMCALL Codes for Memory Operations                                       */
/* ========================================================================= */

/*
 * VMCALL dispatch codes (passed in RCX).
 * RAX contains the magic prefix, RCX the subcommand.
 */
#define VMCALL_MAGIC                0xCAFE0000ULL   /* Magic prefix in RAX high bits */
#define VMCALL_MAGIC_MASK           0xFFFF0000ULL

#define VMCALL_SUBCMD_SHUTDOWN      0x0000          /* Existing: shutdown VMX/SVM */
#define VMCALL_SUBCMD_READ_MEMORY   0x0001          /* Read target process memory */
#define VMCALL_SUBCMD_WRITE_MEMORY  0x0002          /* Write target process memory */

/* ========================================================================= */
/*  VMCALL Parameter Block (passed via Guest virtual address in RDX)         */
/* ========================================================================= */

/*
 * Shared parameter block for VMCALL memory operations.
 * The Guest kernel driver fills this, issues VMCALL, and the Hypervisor
 * reads it directly from Guest memory (using the calling process's CR3).
 */
typedef struct _VMCALL_MEM_PARAMS {
    ULONG64     TargetCr3;          /* Target process's CR3 (DirectoryTableBase) */
    ULONG64     TargetVa;           /* Virtual address to read/write in target */
    ULONG64     BufferVa;           /* Buffer VA in the calling process (kernel) */
    ULONG       Size;               /* Number of bytes */
    NTSTATUS    Status;             /* [out] Result status */
} VMCALL_MEM_PARAMS, *PVMCALL_MEM_PARAMS;

/* ========================================================================= */
/*  Guest Page Table Traversal                                               */
/* ========================================================================= */

/*
 * Translate a Guest virtual address to a Guest physical address
 * by walking the Guest's 4-level page table (CR3 -> PML4 -> PDPT -> PD -> PT).
 *
 * Since EPT/NPT identity maps all physical memory:
 *   Guest Physical Address == Host Virtual Address
 * So page table entries can be read by casting the physical address to a pointer.
 *
 * Parameters:
 *   GuestCr3        - The target process's CR3 (DirectoryTableBase)
 *   VirtualAddress   - The virtual address to translate
 *
 * Returns:
 *   Guest physical address, or 0 if translation failed (page not present).
 */
ULONG64 HvGuestVaToPa(ULONG64 GuestCr3, ULONG64 VirtualAddress);

/*
 * Read memory from a Guest process's virtual address space.
 * Uses page table traversal + direct physical memory access.
 *
 * Handles page boundary crossing (reads spanning two pages).
 *
 * Parameters:
 *   GuestCr3    - Target process CR3
 *   SourceVa    - Source virtual address in target process
 *   Destination - Kernel buffer to copy into (must be valid kernel VA)
 *   Size        - Number of bytes to read
 *
 * Returns:
 *   STATUS_SUCCESS or error code.
 */
NTSTATUS HvReadGuestMemory(ULONG64 GuestCr3, ULONG64 SourceVa, PVOID Destination, ULONG Size);

/*
 * Write memory to a Guest process's virtual address space.
 * Uses page table traversal + direct physical memory write.
 *
 * Parameters:
 *   GuestCr3    - Target process CR3
 *   DestVa      - Destination virtual address in target process
 *   Source       - Kernel buffer to copy from (must be valid kernel VA)
 *   Size        - Number of bytes to write
 *
 * Returns:
 *   STATUS_SUCCESS or error code.
 */
NTSTATUS HvWriteGuestMemory(ULONG64 GuestCr3, ULONG64 DestVa, PVOID Source, ULONG Size);

/*
 * Handle a VMCALL/VMMCALL memory read/write request.
 * Called from the VMX/SVM exit handler when a memory VMCALL is received.
 *
 * Parameters:
 *   GuestContext - Saved guest registers
 *   SubCommand   - VMCALL_SUBCMD_READ_MEMORY or VMCALL_SUBCMD_WRITE_MEMORY
 *
 * Register convention:
 *   RAX = VMCALL_MAGIC | SubCommand
 *   RDX = Guest VA of VMCALL_MEM_PARAMS structure
 *
 * Returns TRUE to continue guest, FALSE to shut down.
 */
BOOLEAN HvHandleMemoryVmcall(PVOID GuestContext, ULONG SubCommand);

#endif /* _HV_MEM_H_ */
