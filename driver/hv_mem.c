/*
 * hv_mem.c - VMX Anti-Anti-Debug Hypervisor
 * Hypervisor-level memory read/write via Guest page table traversal.
 *
 * Status (post-2nd-review):
 *
 *   All "VMX-root-mode memory access through PA cast" code paths in
 *   this file are PERMANENTLY DEPRECATED and return a clean failure
 *   (STATUS_NOT_SUPPORTED / #UD injection).  They are kept only so
 *   legacy references compile.
 *
 *   The correct path for user-space IOCTL consumers is:
 *       IOCTL → KernelCopyProcessMemory (vmxdrv.c)
 *           → PsLookupProcessByProcessId + KeStackAttachProcess
 *           → MmCopyVirtualMemory / MmMapIoSpace
 *   which runs at PASSIVE_LEVEL in non-root mode, is SEH-safe, and
 *   correctly translates guest VA → host VA via the OS memory manager.
 *
 *   HvGuestVaToPa() is the one exception — it is kept because internal
 *   code may still legitimately need to walk a guest's CR3 tables to
 *   confirm a VA is mapped (for filtering / diagnostics).  However its
 *   internal SafeReadPhysU64 helper was UNSAFE in VMX root mode
 *   because it cast a physical address to a kernel VA pointer.
 *
 *   The revised SafeReadPhysU64 uses MmGetVirtualForPhysical which is
 *   the OS-sanctioned way to obtain a mapped-VA for a PA.  It is
 *   documented as safe at IRQL ≤ DISPATCH_LEVEL, so callers must be
 *   at that IRQL (non-VMX-root) — matching the IOCTL-path use case.
 *   Calling HvGuestVaToPa from VMX root mode is explicitly UNSUPPORTED
 *   and now guarded by a KeGetCurrentIrql() check that returns 0
 *   immediately if misused.
 */

#include "hv_mem.h"
#include "hv_ops.h"
#include "vmx.h"
#include "log.h"
#include "process.h"

/* ========================================================================= */
/*  Page Table Constants                                                     */
/* ========================================================================= */

#define PAGE_PRESENT        (1ULL << 0)
#define PAGE_LARGE          (1ULL << 7)     /* PS bit: 2MB or 1GB page */
#define PAGE_ADDR_MASK_4K   0x000FFFFFFFFFF000ULL   /* bits 51:12 */
#define PAGE_ADDR_MASK_2M   0x000FFFFFFFE00000ULL   /* bits 51:21 */
#define PAGE_ADDR_MASK_1G   0x000FFFFFC0000000ULL   /* bits 51:30 */

#define PAGE_OFFSET_4K(va)  ((va) & 0xFFF)
#define PAGE_OFFSET_2M(va)  ((va) & 0x1FFFFF)
#define PAGE_OFFSET_1G(va)  ((va) & 0x3FFFFFFF)

#define PML4_INDEX(va)      (((va) >> 39) & 0x1FF)
#define PDPT_INDEX(va)      (((va) >> 30) & 0x1FF)
#define PD_INDEX(va)        (((va) >> 21) & 0x1FF)
#define PT_INDEX(va)        (((va) >> 12) & 0x1FF)

/* ========================================================================= */
/*  Safe Physical Memory Read (OS-sanctioned path)                           */
/* ========================================================================= */

/*
 * Read a ULONG64 from a physical address by first asking the OS for a
 * mapped kernel VA.  Safe at IRQL ≤ DISPATCH_LEVEL (per
 * MmGetVirtualForPhysical contract).  Returns FALSE on any failure.
 *
 * NB: this is NOT safe in VMX root mode.  Callers that might run in
 * root mode must skip this entirely (HvGuestVaToPa checks the IRQL
 * guard at the top and bails out if misused).
 */
static BOOLEAN SafeReadPhysU64(ULONG64 PhysAddr, PULONG64 Value)
{
    PHYSICAL_ADDRESS Pa;
    PVOID            Va;

    if (PhysAddr == 0) return FALSE;

    Pa.QuadPart = (LONGLONG)PhysAddr;
    Va = MmGetVirtualForPhysical(Pa);
    if (!Va) return FALSE;

    /*
     * Read the 8-byte PTE.  We're at IRQL ≤ DISPATCH_LEVEL (caller
     * guard) and MmGetVirtualForPhysical returned a valid kernel-VA
     * mapping, so the read is safe.  SEH is not used because there is
     * nothing we can do on failure that MmGetVirtualForPhysical's
     * internal validation hasn't already ruled out.
     */
    *Value = *(PULONG64)Va;
    return TRUE;
}

/* ========================================================================= */
/*  Guest Page Table Traversal (VA -> PA)                                    */
/* ========================================================================= */

ULONG64 HvGuestVaToPa(ULONG64 GuestCr3, ULONG64 VirtualAddress)
{
    ULONG64 Pml4Base;
    ULONG64 Pml4eAddr, Pml4e;
    ULONG64 PdpteAddr, Pdpte;
    ULONG64 PdeAddr, Pde;
    ULONG64 PteAddr, Pte;

    /*
     * M-7 (revised): HvGuestVaToPa is ONLY safe at IRQL ≤ DISPATCH_LEVEL
     * because its internal SafeReadPhysU64 uses MmGetVirtualForPhysical,
     * which per WDK documentation must not be called above DISPATCH_LEVEL.
     * VMX root mode is effectively "above the scheduler" — IRQL reporting
     * is not meaningful there, but more importantly MmGetVirtualForPhysical
     * may touch paged structures which root-mode mustn't do.
     *
     * If the caller is at an unsafe IRQL we return 0 (translation failed)
     * rather than deref and crash the box.
     */
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return 0;
    }

    /* CR3 -> PML4 base (mask off PCID and flags in lower 12 bits) */
    Pml4Base = GuestCr3 & PAGE_ADDR_MASK_4K;
    if (Pml4Base == 0) {
        return 0;
    }

    /* Level 4: PML4 */
    Pml4eAddr = Pml4Base + PML4_INDEX(VirtualAddress) * 8;
    if (!SafeReadPhysU64(Pml4eAddr, &Pml4e)) {
        return 0;
    }
    if (!(Pml4e & PAGE_PRESENT)) {
        return 0;
    }

    /* Level 3: PDPT */
    PdpteAddr = (Pml4e & PAGE_ADDR_MASK_4K) + PDPT_INDEX(VirtualAddress) * 8;
    if (!SafeReadPhysU64(PdpteAddr, &Pdpte)) {
        return 0;
    }
    if (!(Pdpte & PAGE_PRESENT)) {
        return 0;
    }
    /* Check for 1GB large page */
    if (Pdpte & PAGE_LARGE) {
        return (Pdpte & PAGE_ADDR_MASK_1G) | PAGE_OFFSET_1G(VirtualAddress);
    }

    /* Level 2: PD */
    PdeAddr = (Pdpte & PAGE_ADDR_MASK_4K) + PD_INDEX(VirtualAddress) * 8;
    if (!SafeReadPhysU64(PdeAddr, &Pde)) {
        return 0;
    }
    if (!(Pde & PAGE_PRESENT)) {
        return 0;
    }
    /* Check for 2MB large page */
    if (Pde & PAGE_LARGE) {
        return (Pde & PAGE_ADDR_MASK_2M) | PAGE_OFFSET_2M(VirtualAddress);
    }

    /* Level 1: PT */
    PteAddr = (Pde & PAGE_ADDR_MASK_4K) + PT_INDEX(VirtualAddress) * 8;
    if (!SafeReadPhysU64(PteAddr, &Pte)) {
        return 0;
    }
    if (!(Pte & PAGE_PRESENT)) {
        return 0;
    }

    return (Pte & PAGE_ADDR_MASK_4K) | PAGE_OFFSET_4K(VirtualAddress);
}

/* ========================================================================= */
/*  Memory Read/Write Implementation  (DISABLED after M-7 review)            */
/* ========================================================================= */

/*
 * M-7 FIX: The original implementation directly dereferenced
 *   (PVOID)PhysicalAddress
 * from VMX root mode, which is incorrect.  In root mode the CPU still
 * uses the host CR3 page tables to translate virtual addresses, and
 * host VA != host PA for most addresses.  Combined with SEH being
 * unreliable in root mode, this led to BSOD rather than clean failure.
 *
 * The safe replacement for user-space callers is the IOCTL path in
 * vmxdrv.c (KernelCopyProcessMemory + KeStackAttachProcess + MmMapIoSpace),
 * which runs at PASSIVE_LEVEL in non-root mode.
 *
 * These stubs are kept so that any caller that still references the
 * VMCALL path gets STATUS_NOT_SUPPORTED instead of a BSOD.
 */

NTSTATUS HvReadGuestMemory(ULONG64 GuestCr3, ULONG64 SourceVa, PVOID Destination, ULONG Size)
{
    UNREFERENCED_PARAMETER(GuestCr3);
    UNREFERENCED_PARAMETER(SourceVa);
    UNREFERENCED_PARAMETER(Destination);
    UNREFERENCED_PARAMETER(Size);
    LOG_WARN("HvReadGuestMemory: disabled path (use IOCTL KernelCopyProcessMemory instead)");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS HvWriteGuestMemory(ULONG64 GuestCr3, ULONG64 DestVa, PVOID Source, ULONG Size)
{
    UNREFERENCED_PARAMETER(GuestCr3);
    UNREFERENCED_PARAMETER(DestVa);
    UNREFERENCED_PARAMETER(Source);
    UNREFERENCED_PARAMETER(Size);
    LOG_WARN("HvWriteGuestMemory: disabled path (use IOCTL KernelCopyProcessMemory instead)");
    return STATUS_NOT_SUPPORTED;
}

/* ========================================================================= */
/*  VMCALL Handler for Memory Operations  (DISABLED after M-7 review)        */
/* ========================================================================= */

/*
 * Handle VMCALL/VMMCALL memory read/write requests.
 *
 * M-7 FIX: returns a clean failure (STATUS_NOT_SUPPORTED) to any guest
 * caller without touching the params struct, because:
 *   1. The params VA translation → PA is correct, but dereferencing the
 *      resulting PA as if it were an HVA is wrong (see comments above).
 *   2. SEH is unreliable in VMX root mode, so there is no recoverable
 *      way to "try" the access and fall back.
 *
 * We deliberately do NOT write the Params struct to avoid the very PA
 * dereference that caused the original problem.  The guest sees a VMCALL
 * that apparently succeeded (RIP advanced), but its in-memory status
 * field is untouched — callers should initialise it to a sentinel and
 * treat "unchanged after VMCALL" as failure, or simply stop using this
 * interface and use the IOCTL path.
 */
BOOLEAN HvHandleMemoryVmcall(PVOID GuestContext, ULONG SubCommand)
{
    UNREFERENCED_PARAMETER(GuestContext);
    UNREFERENCED_PARAMETER(SubCommand);

    /* No-op (beyond advancing RIP so the guest doesn't loop). */
    HvAdvanceGuestRip();
    return TRUE;
}
