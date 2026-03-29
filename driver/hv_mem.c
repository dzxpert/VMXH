/*
 * hv_mem.c - VMX Anti-Anti-Debug Hypervisor
 * Hypervisor-level memory read/write via Guest page table traversal.
 *
 * Core idea:
 *   EPT/NPT identity maps all 512GB physical memory, so:
 *     Guest Physical Address == Host Virtual Address
 *   We walk the Guest's CR3 page tables to translate VA -> PA,
 *   then directly memcpy from/to that physical address.
 *   No Windows API is involved, completely invisible to Guest software.
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
/*  Safe Physical Memory Read                                                */
/* ========================================================================= */

/*
 * Read a ULONG64 from a Guest physical address.
 * Since EPT/NPT identity maps physical memory, we cast PA to a pointer.
 *
 * Returns FALSE if the address looks invalid (too high, NULL, etc.)
 */
static BOOLEAN SafeReadPhysU64(ULONG64 PhysAddr, PULONG64 Value)
{
    PULONG64 Ptr;

    /* Basic sanity: reject NULL and addresses beyond reasonable physical range */
    if (PhysAddr == 0 || PhysAddr >= (512ULL * 1024 * 1024 * 1024)) {
        return FALSE;   /* Beyond our 512GB identity map */
    }

    /* Must be 8-byte aligned for page table entries */
    Ptr = (PULONG64)PhysAddr;

    __try {
        *Value = *Ptr;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
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
/*  Memory Read/Write Implementation                                         */
/* ========================================================================= */

/*
 * Copy data between a kernel buffer and Guest physical memory.
 * Handles page boundary crossing: if a read/write spans two 4KB pages,
 * it translates each page separately.
 *
 * Direction: TRUE = read (phys -> buffer), FALSE = write (buffer -> phys)
 */
static NTSTATUS HvCopyGuestMemory(
    ULONG64 GuestCr3,
    ULONG64 GuestVa,
    PVOID   KernelBuffer,
    ULONG   Size,
    BOOLEAN IsRead
)
{
    ULONG   BytesDone = 0;
    PUCHAR  Buffer = (PUCHAR)KernelBuffer;

    while (BytesDone < Size) {
        ULONG64 PhysAddr;
        ULONG   PageOffset;
        ULONG   ChunkSize;
        PVOID   PhysPtr;

        /* Translate current Guest VA -> PA */
        PhysAddr = HvGuestVaToPa(GuestCr3, GuestVa + BytesDone);
        if (PhysAddr == 0) {
            LOG_DEBUG("HvCopyGuestMemory: VA 0x%llX not present (CR3=0x%llX)",
                      GuestVa + BytesDone, GuestCr3);
            return STATUS_INVALID_ADDRESS;
        }

        /* Calculate how much we can do in this page */
        PageOffset = (ULONG)(PhysAddr & 0xFFF);
        ChunkSize = 0x1000 - PageOffset;    /* Bytes remaining in this page */
        if (ChunkSize > (Size - BytesDone)) {
            ChunkSize = Size - BytesDone;
        }

        /* Direct physical memory access (identity map: PA == VA) */
        PhysPtr = (PVOID)PhysAddr;

        __try {
            if (IsRead) {
                RtlCopyMemory(Buffer + BytesDone, PhysPtr, ChunkSize);
            } else {
                RtlCopyMemory(PhysPtr, Buffer + BytesDone, ChunkSize);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LOG_DEBUG("HvCopyGuestMemory: Exception at PA 0x%llX", PhysAddr);
            return STATUS_ACCESS_VIOLATION;
        }

        BytesDone += ChunkSize;
    }

    return STATUS_SUCCESS;
}

NTSTATUS HvReadGuestMemory(ULONG64 GuestCr3, ULONG64 SourceVa, PVOID Destination, ULONG Size)
{
    if (!Destination || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    return HvCopyGuestMemory(GuestCr3, SourceVa, Destination, Size, TRUE);
}

NTSTATUS HvWriteGuestMemory(ULONG64 GuestCr3, ULONG64 DestVa, PVOID Source, ULONG Size)
{
    if (!Source || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    return HvCopyGuestMemory(GuestCr3, DestVa, Source, Size, FALSE);
}

/* ========================================================================= */
/*  VMCALL Handler for Memory Operations                                     */
/* ========================================================================= */

/*
 * Handle VMCALL/VMMCALL memory read/write requests.
 *
 * Called from VMX/SVM exit handler when:
 *   RAX = VMCALL_MAGIC | SubCommand
 *   RDX = Guest VA of VMCALL_MEM_PARAMS
 *
 * The params struct is in the calling process's (kernel driver) address space.
 * We read it using the caller's CR3, perform the operation using the target's
 * CR3, and write the result back.
 */
BOOLEAN HvHandleMemoryVmcall(PVOID GuestContext, ULONG SubCommand)
{
    PGUEST_CONTEXT      Ctx = (PGUEST_CONTEXT)GuestContext;
    ULONG64             CallerCr3;
    ULONG64             ParamsVa;
    ULONG64             ParamsPa;
    PVMCALL_MEM_PARAMS  Params;
    NTSTATUS            Status;

    UNREFERENCED_PARAMETER(Ctx);

    /* RDX = Guest VA of the parameter block */
    ParamsVa = Ctx->Rdx;
    if (ParamsVa == 0) {
        HvAdvanceGuestRip();
        return TRUE;
    }

    /*
     * The caller is our kernel driver (vmxdrv.sys), running in some process context.
     * Read the params from the caller's address space using current Guest CR3.
     */
    CallerCr3 = HvReadGuestCr3();

    /* Translate params VA to PA */
    ParamsPa = HvGuestVaToPa(CallerCr3, ParamsVa);
    if (ParamsPa == 0) {
        LOG_DEBUG("VMCALL mem: cannot translate params VA 0x%llX", ParamsVa);
        HvAdvanceGuestRip();
        return TRUE;
    }

    /* Access the params directly via physical address (identity map) */
    Params = (PVMCALL_MEM_PARAMS)ParamsPa;

    __try {
        /* Validate */
        if (Params->Size == 0 || Params->Size > (64 * 1024) ||
            Params->TargetCr3 == 0 || Params->TargetVa == 0 || Params->BufferVa == 0) {
            Params->Status = STATUS_INVALID_PARAMETER;
            HvAdvanceGuestRip();
            return TRUE;
        }

        /*
         * The buffer is in the caller's kernel address space.
         * Translate it to PA so we can access it directly.
         * For kernel addresses, they're typically in the upper half (0xFFFF8000`00000000+)
         * and mapped in every process's page tables.
         *
         * We need to do the copy page-by-page because the buffer may span
         * multiple physical pages.
         */
        if (SubCommand == VMCALL_SUBCMD_READ_MEMORY) {
            /*
             * Read from target process -> caller's buffer
             * 1. Walk target CR3 to get source PA
             * 2. Walk caller CR3 to get buffer PA
             * 3. Copy PA-to-PA
             */
            ULONG BytesDone = 0;
            ULONG Size = Params->Size;
            ULONG64 TargetCr3 = Params->TargetCr3;
            ULONG64 TargetVa = Params->TargetVa;
            ULONG64 BufferVa = Params->BufferVa;

            while (BytesDone < Size) {
                ULONG64 SrcPa, DstPa;
                ULONG SrcOff, DstOff, Chunk;

                SrcPa = HvGuestVaToPa(TargetCr3, TargetVa + BytesDone);
                DstPa = HvGuestVaToPa(CallerCr3, BufferVa + BytesDone);

                if (SrcPa == 0 || DstPa == 0) {
                    Params->Status = STATUS_INVALID_ADDRESS;
                    HvAdvanceGuestRip();
                    return TRUE;
                }

                /* Chunk = min of remaining bytes in both pages */
                SrcOff = (ULONG)(SrcPa & 0xFFF);
                DstOff = (ULONG)(DstPa & 0xFFF);
                Chunk = 0x1000 - SrcOff;
                if ((0x1000 - DstOff) < Chunk) Chunk = 0x1000 - DstOff;
                if (Chunk > (Size - BytesDone)) Chunk = Size - BytesDone;

                RtlCopyMemory((PVOID)DstPa, (PVOID)SrcPa, Chunk);
                BytesDone += Chunk;
            }

            Params->Status = STATUS_SUCCESS;

        } else if (SubCommand == VMCALL_SUBCMD_WRITE_MEMORY) {
            /*
             * Write from caller's buffer -> target process
             */
            ULONG BytesDone = 0;
            ULONG Size = Params->Size;
            ULONG64 TargetCr3 = Params->TargetCr3;
            ULONG64 TargetVa = Params->TargetVa;
            ULONG64 BufferVa = Params->BufferVa;

            while (BytesDone < Size) {
                ULONG64 SrcPa, DstPa;
                ULONG SrcOff, DstOff, Chunk;

                SrcPa = HvGuestVaToPa(CallerCr3, BufferVa + BytesDone);
                DstPa = HvGuestVaToPa(TargetCr3, TargetVa + BytesDone);

                if (SrcPa == 0 || DstPa == 0) {
                    Params->Status = STATUS_INVALID_ADDRESS;
                    HvAdvanceGuestRip();
                    return TRUE;
                }

                SrcOff = (ULONG)(SrcPa & 0xFFF);
                DstOff = (ULONG)(DstPa & 0xFFF);
                Chunk = 0x1000 - SrcOff;
                if ((0x1000 - DstOff) < Chunk) Chunk = 0x1000 - DstOff;
                if (Chunk > (Size - BytesDone)) Chunk = Size - BytesDone;

                RtlCopyMemory((PVOID)DstPa, (PVOID)SrcPa, Chunk);
                BytesDone += Chunk;
            }

            Params->Status = STATUS_SUCCESS;

        } else {
            Params->Status = STATUS_INVALID_PARAMETER;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_DEBUG("VMCALL mem: exception during operation");
        /* Can't safely write Params->Status here */
    }

    HvAdvanceGuestRip();
    return TRUE;
}
