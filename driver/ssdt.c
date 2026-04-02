/*
 * ssdt.c - VMX Hypervisor Toolbox
 * SSDT (System Service Descriptor Table) Monitoring & Hook Framework
 *
 * SSDT discovery: Resolve several well-known Zw/Nt function pairs via
 * MmGetSystemRoutineAddress, extract the syscall index from each Zw stub's
 * `mov eax, imm32` instruction, then scan ntoskrnl's read-only data section
 * for the LONG array where entry decoding matches all known pairs.
 *
 * This approach is independent of IA32_LSTAR / KiSystemCall64 code layout
 * and works reliably across all x64 Windows versions (Vista through Win11),
 * including systems with KPTI, VBS, and Hyper-V nested virtualization.
 *
 * All hook mechanics delegate to GenericHookInstall() / GenericHookRemove().
 */

#include "ssdt.h"
#include "hv_hook.h"
#include "log.h"
#include <ntstrsafe.h>
#include <ntimage.h>

/* ========================================================================= */
/*  Pool tag                                                                 */
/* ========================================================================= */

#define SSDT_TAG    'TDSS'

/* ========================================================================= */
/*  Globals                                                                  */
/* ========================================================================= */

SSDT_STATE g_SsdtState = { 0 };

/* ========================================================================= */
/*  Forward Declarations                                                     */
/* ========================================================================= */

static NTSTATUS SsdtGetNtoskrnlBase(VOID);
static NTSTATUS SsdtDiscoverByZwStubReverse(VOID);
static PSSDT_HOOK_MAPPING SsdtFindMappingByIndex(ULONG Index);
static PSSDT_HOOK_MAPPING SsdtFindMappingByHookId(ULONG HookId);

/* ========================================================================= */
/*  2a. ntoskrnl Base Discovery                                              */
/* ========================================================================= */

/*
 * ZwQuerySystemInformation declarations for SsdtGetNtoskrnlBase
 */
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG                           NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION  Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

/*
 * SsdtGetNtoskrnlBase - Get ntoskrnl load address and size.
 *
 * Uses ZwQuerySystemInformation(SystemModuleInformation).  The first
 * module returned is always ntoskrnl.exe.
 */
static NTSTATUS SsdtGetNtoskrnlBase(VOID)
{
    NTSTATUS    Status;
    ULONG       Size = 0;
    PRTL_PROCESS_MODULES Modules = NULL;

    Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &Size);
    if (Size == 0) {
        LOG_ERROR("SSDT: ZwQuerySystemInformation(size) failed: 0x%08X", Status);
        return STATUS_UNSUCCESSFUL;
    }

    Modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, Size, SSDT_TAG);
    if (!Modules) return STATUS_INSUFFICIENT_RESOURCES;

    Status = ZwQuerySystemInformation(SystemModuleInformation, Modules, Size, &Size);
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("SSDT: ZwQuerySystemInformation failed: 0x%08X", Status);
        ExFreePoolWithTag(Modules, SSDT_TAG);
        return Status;
    }

    if (Modules->NumberOfModules == 0) {
        ExFreePoolWithTag(Modules, SSDT_TAG);
        return STATUS_NOT_FOUND;
    }

    /* First module is always ntoskrnl.exe */
    g_SsdtState.NtoskrnlBase = (ULONG64)Modules->Modules[0].ImageBase;
    g_SsdtState.NtoskrnlSize = Modules->Modules[0].ImageSize;

    LOG_INFO("SSDT: ntoskrnl base=0x%llX size=0x%X",
             g_SsdtState.NtoskrnlBase, g_SsdtState.NtoskrnlSize);

    ExFreePoolWithTag(Modules, SSDT_TAG);
    return STATUS_SUCCESS;
}


/* ========================================================================= */
/*  2b. Discover by Zw* stub reverse engineering                             */
/* ========================================================================= */

/*
 * Well-known Zw/Nt function pairs for index extraction.
 * These are exported on every x64 Windows version from Vista through Win11.
 * We only need a handful; more pairs = stronger validation.
 */
typedef struct _ZW_NT_PAIR {
    const WCHAR *ZwName;
    const WCHAR *NtName;
} ZW_NT_PAIR;

static const ZW_NT_PAIR g_ZwNtPairs[] = {
    { L"ZwClose",               L"NtClose" },
    { L"ZwOpenProcess",         L"NtOpenProcess" },
    { L"ZwReadFile",            L"NtReadFile" },
    { L"ZwWriteFile",           L"NtWriteFile" },
    { L"ZwCreateFile",          L"NtCreateFile" },
    { L"ZwQueryInformationProcess", L"NtQueryInformationProcess" },
    { L"ZwAllocateVirtualMemory",   L"NtAllocateVirtualMemory" },
    { L"ZwFreeVirtualMemory",       L"NtFreeVirtualMemory" },
};

#define ZW_NT_PAIR_COUNT  (sizeof(g_ZwNtPairs) / sizeof(g_ZwNtPairs[0]))

/*
 * Minimum number of (Index, FuncVa) pairs we need to successfully extract
 * before attempting the brute-force scan. 3 is enough for a unique match;
 * we require at least 3 to proceed.
 */
#define ZW_MIN_PAIRS  3

/*
 * SsdtExtractIndexFromZwStub - Scan the first bytes of a Zw* kernel stub
 * for `mov eax, imm32` (B8 xx xx 00 00) to extract the syscall index.
 *
 * x64 Zw stubs have this instruction within the first ~30 bytes.
 * Returns TRUE on success, with *OutIndex set.
 */
static BOOLEAN SsdtExtractIndexFromZwStub(ULONG64 ZwFuncVa, PULONG OutIndex)
{
    PUCHAR Code;
    ULONG  i;

    if (!MmIsAddressValid((PVOID)ZwFuncVa)) return FALSE;

    Code = (PUCHAR)ZwFuncVa;

    /*
     * Scan up to 30 bytes for B8 xx xx 00 00 (mov eax, imm32 with
     * upper 16 bits zero — syscall indices are < 0x10000).
     * Also accept B8 xx xx xx 00 for future-proofing (up to 16M services).
     */
    for (i = 0; i < 30; i++) {
        if (!MmIsAddressValid((PVOID)(ZwFuncVa + i + 4))) return FALSE;

        if (Code[i] == 0xB8 && Code[i + 3] == 0x00 && Code[i + 4] == 0x00) {
            ULONG Index = *(PUSHORT)(&Code[i + 1]);
            if (Index < SSDT_MAX_SERVICES) {
                *OutIndex = Index;
                return TRUE;
            }
        }
    }

    return FALSE;
}

/*
 * SsdtFindRdataSection - Locate the .rdata (or INITKDBG, PAGE, etc.)
 * section in ntoskrnl that contains read-only data.
 *
 * KiServiceTable lives in a read-only data section. We look for sections
 * with IMAGE_SCN_CNT_INITIALIZED_DATA and !IMAGE_SCN_MEM_WRITE.
 * If no .rdata found, falls back to full ntoskrnl range.
 */
static BOOLEAN SsdtFindRdataSection(
    PUCHAR NtBase, ULONG NtSize,
    PULONG64 OutStart, PULONG64 OutEnd)
{
    PIMAGE_DOS_HEADER       Dos;
    PIMAGE_NT_HEADERS64     Nt;
    PIMAGE_SECTION_HEADER   Sec;
    USHORT                  i, NumSections;
    BOOLEAN                 Found = FALSE;
    ULONG64                 BestStart = 0, BestEnd = 0;

    if (!MmIsAddressValid(NtBase)) return FALSE;

    Dos = (PIMAGE_DOS_HEADER)NtBase;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    Nt = (PIMAGE_NT_HEADERS64)(NtBase + Dos->e_lfanew);
    if (!MmIsAddressValid((PVOID)Nt)) return FALSE;
    if (Nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    NumSections = Nt->FileHeader.NumberOfSections;
    Sec = IMAGE_FIRST_SECTION(Nt);

    for (i = 0; i < NumSections; i++) {
        if (!MmIsAddressValid((PVOID)&Sec[i])) break;

        /*
         * Look for initialized data sections that are not writable.
         * KiServiceTable is typically in a section with these characteristics.
         * We take the largest such section to maximize coverage.
         */
        if ((Sec[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) &&
            !(Sec[i].Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            ULONG64 SecStart = (ULONG64)NtBase + Sec[i].VirtualAddress;
            ULONG64 SecEnd   = SecStart + Sec[i].Misc.VirtualSize;

            if (SecEnd > (ULONG64)NtBase + NtSize) {
                SecEnd = (ULONG64)NtBase + NtSize;
            }

            if (!Found || (SecEnd - SecStart) > (BestEnd - BestStart)) {
                BestStart = SecStart;
                BestEnd   = SecEnd;
                Found = TRUE;
            }
        }
    }

    if (Found) {
        *OutStart = BestStart;
        *OutEnd   = BestEnd;
    }
    return Found;
}

/*
 * SsdtDiscoverByZwStubReverse - Tier 2: Reverse-engineer KiServiceTable
 * location from known Zw/Nt function pairs.
 *
 * Algorithm:
 *   1. For each well-known Zw/Nt pair, resolve both via MmGetSystemRoutineAddress.
 *   2. Extract the syscall index from the Zw stub's `mov eax, imm32`.
 *   3. This gives us (Index, NtFuncVa) tuples.
 *   4. Scan ntoskrnl's read-only data section for a LONG array where
 *      CandidateBase + (Entry[Index] >> 4) == NtFuncVa for all known pairs.
 *   5. Once found, determine ServiceCount by walking entries forward.
 */
static NTSTATUS SsdtDiscoverByZwStubReverse(VOID)
{
    /* Collected (Index, NtFuncVa) pairs */
    ULONG   PairIndex[ZW_NT_PAIR_COUNT];
    ULONG64 PairNtVa[ZW_NT_PAIR_COUNT];
    ULONG   PairCount = 0;
    ULONG   k;

    ULONG64 ScanStart, ScanEnd;
    ULONG64 CandidateBase;
    BOOLEAN Found = FALSE;
    ULONG   ServiceCount = 0;
    ULONG   ValidCount = 0;
    ULONG   i;

    if (g_SsdtState.NtoskrnlBase == 0 || g_SsdtState.NtoskrnlSize == 0) {
        LOG_WARN("SSDT: ZwReverse: ntoskrnl base/size not set");
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Phase 1: Extract (Index, NtFuncVa) pairs from Zw/Nt exports.
     */
    for (k = 0; k < ZW_NT_PAIR_COUNT; k++) {
        UNICODE_STRING ZwName, NtName;
        ULONG64 ZwVa, NtVa;
        ULONG   Index;

        RtlInitUnicodeString(&ZwName, g_ZwNtPairs[k].ZwName);
        RtlInitUnicodeString(&NtName, g_ZwNtPairs[k].NtName);

        ZwVa = (ULONG64)MmGetSystemRoutineAddress(&ZwName);
        NtVa = (ULONG64)MmGetSystemRoutineAddress(&NtName);

        if (!ZwVa || !NtVa) {
            LOG_DEBUG("SSDT: ZwReverse: %wZ or %wZ not found, skipping",
                      &ZwName, &NtName);
            continue;
        }

        if (!SsdtExtractIndexFromZwStub(ZwVa, &Index)) {
            LOG_DEBUG("SSDT: ZwReverse: Failed to extract index from %wZ stub",
                      &ZwName);
            continue;
        }

        /* Sanity: NtFuncVa must be within ntoskrnl */
        if (NtVa < g_SsdtState.NtoskrnlBase ||
            NtVa >= g_SsdtState.NtoskrnlBase + g_SsdtState.NtoskrnlSize)
        {
            continue;
        }

        PairIndex[PairCount] = Index;
        PairNtVa[PairCount]  = NtVa;
        PairCount++;

        LOG_INFO("SSDT: ZwReverse: %wZ -> index=%u, %wZ -> VA=0x%llX",
                 &ZwName, Index, &NtName, NtVa);
    }

    if (PairCount < ZW_MIN_PAIRS) {
        LOG_WARN("SSDT: ZwReverse: Only extracted %u pairs (need %u), aborting",
                 PairCount, (ULONG)ZW_MIN_PAIRS);
        return STATUS_UNSUCCESSFUL;
    }

    LOG_INFO("SSDT: ZwReverse: Extracted %u (Index, NtVa) pairs", PairCount);

    /*
     * Phase 2: Determine scan range.
     * Prefer the read-only data section; fall back to entire ntoskrnl.
     */
    if (!SsdtFindRdataSection((PUCHAR)g_SsdtState.NtoskrnlBase,
                               g_SsdtState.NtoskrnlSize,
                               &ScanStart, &ScanEnd))
    {
        LOG_INFO("SSDT: ZwReverse: Could not locate .rdata, scanning full ntoskrnl");
        ScanStart = g_SsdtState.NtoskrnlBase;
        ScanEnd   = g_SsdtState.NtoskrnlBase + g_SsdtState.NtoskrnlSize;
    } else {
        LOG_INFO("SSDT: ZwReverse: Scanning .rdata [0x%llX, 0x%llX) (%u KB)",
                 ScanStart, ScanEnd,
                 (ULONG)((ScanEnd - ScanStart) / 1024));
    }

    /*
     * Phase 3: Brute-force scan for KiServiceTable.
     *
     * For each 4-byte-aligned candidate address within the scan range,
     * check whether all known (Index, NtVa) pairs decode correctly:
     *   CandidateBase + (*(LONG*)(CandidateBase + Index*4) >> 4) == NtVa
     *
     * The highest Index among our pairs determines the minimum table size
     * the candidate must accommodate.
     */
    {
        ULONG MaxIndex = 0;
        for (k = 0; k < PairCount; k++) {
            if (PairIndex[k] > MaxIndex) MaxIndex = PairIndex[k];
        }

        for (CandidateBase = ScanStart;
             CandidateBase + (ULONG64)(MaxIndex + 1) * sizeof(LONG) <= ScanEnd;
             CandidateBase += sizeof(LONG))
        {
            PLONG   Table;
            ULONG   MatchCount = 0;

            /* Quick check: first candidate entry page must be mapped */
            if (!MmIsAddressValid((PVOID)CandidateBase)) {
                /* Skip ahead to the next page boundary */
                CandidateBase = (CandidateBase + 0x1000) & ~0xFFFULL;
                CandidateBase -= sizeof(LONG);  /* loop will add sizeof(LONG) */
                continue;
            }

            Table = (PLONG)CandidateBase;

            for (k = 0; k < PairCount; k++) {
                ULONG64 EntryAddr = CandidateBase + (ULONG64)PairIndex[k] * sizeof(LONG);
                LONG    Entry;
                ULONG64 DecodedVa;

                if (!MmIsAddressValid((PVOID)EntryAddr)) break;

                Entry = *(PLONG)EntryAddr;
                DecodedVa = CandidateBase + (LONG64)(Entry >> 4);

                if (DecodedVa == PairNtVa[k]) {
                    MatchCount++;
                }
            }

            if (MatchCount >= PairCount) {
                Found = TRUE;
                LOG_INFO("SSDT: ZwReverse: Found KiServiceTable at 0x%llX "
                         "(%u/%u pairs matched)",
                         CandidateBase, MatchCount, PairCount);
                break;
            }
        }
    }

    if (!Found) {
        LOG_WARN("SSDT: ZwReverse: KiServiceTable not found in scan range "
                 "[0x%llX, 0x%llX)", ScanStart, ScanEnd);
        return STATUS_NOT_FOUND;
    }

    /*
     * Phase 4: Determine ServiceCount by walking entries forward until
     * decoded VA falls outside ntoskrnl.
     */
    {
        PLONG Table = (PLONG)CandidateBase;

        for (ServiceCount = 0; ServiceCount < SSDT_MAX_SERVICES; ServiceCount++) {
            ULONG64 EntryAddr = CandidateBase + (ULONG64)ServiceCount * sizeof(LONG);
            LONG    Entry;
            ULONG64 FuncVa;

            if (!MmIsAddressValid((PVOID)EntryAddr)) break;

            Entry  = Table[ServiceCount];
            FuncVa = CandidateBase + (LONG64)(Entry >> 4);

            if (FuncVa < g_SsdtState.NtoskrnlBase ||
                FuncVa >= g_SsdtState.NtoskrnlBase + g_SsdtState.NtoskrnlSize)
            {
                break;
            }
        }

        if (ServiceCount < 100) {
            LOG_WARN("SSDT: ZwReverse: Only found %u entries by walking, "
                     "too few, aborting", ServiceCount);
            return STATUS_UNSUCCESSFUL;
        }

        LOG_INFO("SSDT: ZwReverse: Determined %u services by table walk",
                 ServiceCount);
    }

    /*
     * Phase 5: Decode all SSDT entries into ResolvedAddresses[].
     */
    {
        PLONG Table = (PLONG)CandidateBase;

        for (i = 0; i < ServiceCount; i++) {
            LONG    Entry = Table[i];
            ULONG64 FuncVa = CandidateBase + (LONG64)(Entry >> 4);

            if (FuncVa >= g_SsdtState.NtoskrnlBase &&
                FuncVa <  g_SsdtState.NtoskrnlBase + g_SsdtState.NtoskrnlSize) {
                g_SsdtState.ResolvedAddresses[i] = FuncVa;
                ValidCount++;
            } else {
                g_SsdtState.ResolvedAddresses[i] = 0;
            }
        }
    }

    /* Commit results */
    g_SsdtState.KiServiceTableVa = CandidateBase;
    g_SsdtState.ServiceCount = ServiceCount;

    LOG_INFO("SSDT: ZwReverse: Resolved %u / %u addresses", ValidCount, ServiceCount);
    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  Single On-Demand Resolve                                                 */
/* ========================================================================= */

ULONG64 SsdtResolveAddress(ULONG Index)
{
    if (!g_SsdtState.Initialized || Index >= g_SsdtState.ServiceCount) {
        return 0;
    }

    if (g_SsdtState.ResolvedAddresses[Index] != 0) {
        return g_SsdtState.ResolvedAddresses[Index];
    }

    /* On-demand single resolve from live memory */
    {
        PLONG Table = (PLONG)g_SsdtState.KiServiceTableVa;
        LONG  Entry;

        __try {
            Entry = Table[Index];
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }

        g_SsdtState.ResolvedAddresses[Index] =
            g_SsdtState.KiServiceTableVa + (LONG64)(Entry >> 4);
        return g_SsdtState.ResolvedAddresses[Index];
    }
}

/* ========================================================================= */
/*  2c. Name Resolution                                                      */
/* ========================================================================= */

/*
 * SsdtPopulateNames - Walk ntoskrnl PE export table to match
 * Nt* export addresses to SSDT entry addresses.
 */
NTSTATUS SsdtPopulateNames(VOID)
{
    PUCHAR                  Base;
    PIMAGE_DOS_HEADER       Dos;
    PIMAGE_NT_HEADERS64     Nt;
    PIMAGE_EXPORT_DIRECTORY Export;
    PULONG                  Names;
    PULONG                  Functions;
    PUSHORT                 Ordinals;
    ULONG                   i, j;
    ULONG                   MatchCount = 0;

    if (g_SsdtState.NamesPopulated) return STATUS_SUCCESS;

    if (g_SsdtState.NtoskrnlBase == 0) {
        NTSTATUS Status = SsdtGetNtoskrnlBase();
        if (!NT_SUCCESS(Status)) return Status;
    }

    Base = (PUCHAR)g_SsdtState.NtoskrnlBase;

    __try {
        Dos = (PIMAGE_DOS_HEADER)Base;
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
            LOG_ERROR("SSDT: Invalid ntoskrnl DOS header");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        Nt = (PIMAGE_NT_HEADERS64)(Base + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE) {
            LOG_ERROR("SSDT: Invalid ntoskrnl NT header");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
            LOG_ERROR("SSDT: No export directory in ntoskrnl");
            return STATUS_NOT_FOUND;
        }

        Export = (PIMAGE_EXPORT_DIRECTORY)(Base +
            Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        Names     = (PULONG)(Base + Export->AddressOfNames);
        Functions = (PULONG)(Base + Export->AddressOfFunctions);
        Ordinals  = (PUSHORT)(Base + Export->AddressOfNameOrdinals);

        for (i = 0; i < Export->NumberOfNames; i++) {
            const char *Name = (const char *)(Base + Names[i]);
            ULONG64     FuncRva;
            ULONG64     FuncVa;

            /* Only match Nt* exports (not Zw*) */
            if (Name[0] != 'N' || Name[1] != 't') continue;

            FuncRva = (ULONG64)Functions[Ordinals[i]];
            FuncVa  = (ULONG64)Base + FuncRva;

            /* Search resolved addresses for a match */
            for (j = 0; j < g_SsdtState.ServiceCount; j++) {
                if (g_SsdtState.ResolvedAddresses[j] == FuncVa) {
                    /* Convert ANSI name to wide */
                    ULONG k;
                    for (k = 0; k < SSDT_MAX_NAME_LEN - 1 && Name[k]; k++) {
                        g_SsdtState.NameCache[j][k] = (WCHAR)Name[k];
                    }
                    g_SsdtState.NameCache[j][k] = L'\0';
                    MatchCount++;
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_WARN("SSDT: Exception walking ntoskrnl exports");
        return STATUS_ACCESS_VIOLATION;
    }

    g_SsdtState.NamesPopulated = TRUE;
    LOG_INFO("SSDT: Resolved %u / %u syscall names", MatchCount, g_SsdtState.ServiceCount);
    return STATUS_SUCCESS;
}

/*
 * SsdtFindIndexByName - Lookup syscall index by Nt* function name.
 * Searches name cache first, then falls back to MmGetSystemRoutineAddress.
 */
NTSTATUS SsdtFindIndexByName(const WCHAR *Name, PULONG OutIndex)
{
    ULONG i;

    if (!g_SsdtState.Initialized) return STATUS_UNSUCCESSFUL;

    /* Ensure names are populated */
    if (!g_SsdtState.NamesPopulated) {
        SsdtPopulateNames();
    }

    /* Search name cache */
    for (i = 0; i < g_SsdtState.ServiceCount; i++) {
        if (g_SsdtState.NameCache[i][0] != L'\0') {
            if (_wcsicmp(g_SsdtState.NameCache[i], Name) == 0) {
                *OutIndex = i;
                return STATUS_SUCCESS;
            }
        }
    }

    /* Fallback: resolve via MmGetSystemRoutineAddress and match VA */
    {
        UNICODE_STRING  FuncName;
        PVOID           Addr;

        RtlInitUnicodeString(&FuncName, Name);
        Addr = MmGetSystemRoutineAddress(&FuncName);
        if (!Addr) {
            LOG_WARN("SSDT: Cannot resolve '%wZ'", &FuncName);
            return STATUS_NOT_FOUND;
        }

        for (i = 0; i < g_SsdtState.ServiceCount; i++) {
            if (g_SsdtState.ResolvedAddresses[i] == (ULONG64)Addr) {
                /* Cache the name for future lookups */
                RtlStringCchCopyW(g_SsdtState.NameCache[i], SSDT_MAX_NAME_LEN, Name);
                *OutIndex = i;
                return STATUS_SUCCESS;
            }
        }

        LOG_WARN("SSDT: '%wZ' resolved to 0x%llX but not found in SSDT",
                 &FuncName, (ULONG64)Addr);
        return STATUS_NOT_FOUND;
    }
}

/* ========================================================================= */
/*  Table Query API                                                          */
/* ========================================================================= */

NTSTATUS SsdtGetEntryInfo(ULONG Index, PSSDT_ENTRY_INFO Out)
{
    PLONG Table;

    if (!g_SsdtState.Initialized || Index >= g_SsdtState.ServiceCount) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Out, sizeof(SSDT_ENTRY_INFO));

    Table = (PLONG)g_SsdtState.KiServiceTableVa;

    __try {
        Out->RawOffset = Table[Index];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    Out->SyscallIndex = Index;
    Out->ArgCount = (ULONG)(Out->RawOffset & 0xF);
    Out->FunctionVa = g_SsdtState.ResolvedAddresses[Index];

    if (g_SsdtState.NamesPopulated && g_SsdtState.NameCache[Index][0] != L'\0') {
        RtlStringCchCopyW(Out->FunctionName, SSDT_MAX_NAME_LEN,
                          g_SsdtState.NameCache[Index]);
    }

    return STATUS_SUCCESS;
}

NTSTATUS SsdtDumpTable(ULONG Start, ULONG Count,
                       PSSDT_ENTRY_INFO Out, PULONG OutCount)
{
    ULONG End;
    ULONG i, n = 0;

    if (!g_SsdtState.Initialized) return STATUS_UNSUCCESSFUL;

    if (Start >= g_SsdtState.ServiceCount) {
        *OutCount = 0;
        return STATUS_SUCCESS;
    }

    if (Count == 0) Count = g_SsdtState.ServiceCount;

    End = Start + Count;
    if (End > g_SsdtState.ServiceCount) End = g_SsdtState.ServiceCount;

    for (i = Start; i < End; i++) {
        NTSTATUS Status = SsdtGetEntryInfo(i, &Out[n]);
        if (NT_SUCCESS(Status)) {
            n++;
        }
    }

    *OutCount = n;
    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  Hook Mapping Helpers                                                     */
/* ========================================================================= */

static PSSDT_HOOK_MAPPING SsdtFindMappingByIndex(ULONG Index)
{
    PSSDT_HOOK_MAPPING M = g_SsdtState.HookListHead;
    while (M) {
        if (M->SyscallIndex == Index) return M;
        M = M->Next;
    }
    return NULL;
}

static PSSDT_HOOK_MAPPING SsdtFindMappingByHookId(ULONG HookId)
{
    PSSDT_HOOK_MAPPING M = g_SsdtState.HookListHead;
    while (M) {
        if (M->GenericHookId == HookId) return M;
        M = M->Next;
    }
    return NULL;
}

/* ========================================================================= */
/*  Hook Operations                                                          */
/* ========================================================================= */

NTSTATUS SsdtHookByIndex(ULONG Index, PHOOK_RULE Rule, PULONG OutHookId)
{
    KIRQL           OldIrql;
    ULONG64         FuncVa;
    ULONG           HookId = 0;
    NTSTATUS        Status;
    PSSDT_HOOK_MAPPING Mapping;
    const WCHAR    *Name;

    if (!g_SsdtState.Initialized) return STATUS_UNSUCCESSFUL;
    if (Index >= g_SsdtState.ServiceCount) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_SsdtState.HookLock, &OldIrql);

    /* Check for duplicate */
    if (SsdtFindMappingByIndex(Index)) {
        KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);
        LOG_WARN("SSDT: Syscall %u already hooked", Index);
        return STATUS_ALREADY_REGISTERED;
    }

    KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);

    /* Resolve function address */
    FuncVa = g_SsdtState.ResolvedAddresses[Index];
    if (FuncVa == 0) {
        LOG_ERROR("SSDT: Cannot resolve address for syscall %u", Index);
        return STATUS_NOT_FOUND;
    }

    /* Get name for logging */
    Name = (g_SsdtState.NamesPopulated && g_SsdtState.NameCache[Index][0] != L'\0')
           ? g_SsdtState.NameCache[Index] : NULL;

    /* Delegate to existing GenericHookInstall framework */
    Status = GenericHookInstall(FuncVa, 0 /* kernel */, Name, Rule, &HookId);
    if (!NT_SUCCESS(Status)) {
        LOG_WARN("SSDT: GenericHookInstall failed for syscall %u: 0x%08X", Index, Status);
        return Status;
    }

    /* Create mapping node */
    Mapping = (PSSDT_HOOK_MAPPING)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(SSDT_HOOK_MAPPING), SSDT_TAG);
    if (!Mapping) {
        GenericHookRemove(HookId);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Mapping->SyscallIndex = Index;
    Mapping->GenericHookId = HookId;
    Mapping->IsMonitorHook = FALSE;

    KeAcquireSpinLock(&g_SsdtState.HookLock, &OldIrql);
    Mapping->Next = g_SsdtState.HookListHead;
    g_SsdtState.HookListHead = Mapping;
    g_SsdtState.HookCount++;
    KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);

    if (OutHookId) *OutHookId = HookId;

    LOG_INFO("SSDT: Hooked syscall %u (hookId=%u, VA=0x%llX)", Index, HookId, FuncVa);
    return STATUS_SUCCESS;
}

NTSTATUS SsdtHookByName(const WCHAR *Name, PHOOK_RULE Rule,
                        PULONG OutIndex, PULONG OutHookId)
{
    ULONG       Index = 0;
    NTSTATUS    Status;

    Status = SsdtFindIndexByName(Name, &Index);
    if (!NT_SUCCESS(Status)) return Status;

    Status = SsdtHookByIndex(Index, Rule, OutHookId);
    if (NT_SUCCESS(Status) && OutIndex) {
        *OutIndex = Index;
    }

    return Status;
}

/* ========================================================================= */
/*  Unhook Operations                                                        */
/* ========================================================================= */

NTSTATUS SsdtUnhookByIndex(ULONG Index)
{
    KIRQL               OldIrql;
    PSSDT_HOOK_MAPPING  M, Prev;

    KeAcquireSpinLock(&g_SsdtState.HookLock, &OldIrql);

    Prev = NULL;
    M = g_SsdtState.HookListHead;
    while (M) {
        if (M->SyscallIndex == Index) {
            ULONG HookId = M->GenericHookId;

            /* Unlink */
            if (Prev) Prev->Next = M->Next;
            else g_SsdtState.HookListHead = M->Next;
            g_SsdtState.HookCount--;

            KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);

            GenericHookRemove(HookId);
            ExFreePoolWithTag(M, SSDT_TAG);

            LOG_INFO("SSDT: Unhooked syscall %u (hookId=%u)", Index, HookId);
            return STATUS_SUCCESS;
        }
        Prev = M;
        M = M->Next;
    }

    KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);
    return STATUS_NOT_FOUND;
}

NTSTATUS SsdtUnhookByHookId(ULONG HookId)
{
    KIRQL               OldIrql;
    PSSDT_HOOK_MAPPING  M, Prev;

    KeAcquireSpinLock(&g_SsdtState.HookLock, &OldIrql);

    Prev = NULL;
    M = g_SsdtState.HookListHead;
    while (M) {
        if (M->GenericHookId == HookId) {
            ULONG Index = M->SyscallIndex;

            if (Prev) Prev->Next = M->Next;
            else g_SsdtState.HookListHead = M->Next;
            g_SsdtState.HookCount--;

            KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);

            GenericHookRemove(HookId);
            ExFreePoolWithTag(M, SSDT_TAG);

            LOG_INFO("SSDT: Unhooked hookId=%u (syscall %u)", HookId, Index);
            return STATUS_SUCCESS;
        }
        Prev = M;
        M = M->Next;
    }

    KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);
    return STATUS_NOT_FOUND;
}

VOID SsdtUnhookAll(VOID)
{
    KIRQL               OldIrql;
    PSSDT_HOOK_MAPPING  M, Next;

    KeAcquireSpinLock(&g_SsdtState.HookLock, &OldIrql);

    M = g_SsdtState.HookListHead;
    g_SsdtState.HookListHead = NULL;
    g_SsdtState.HookCount = 0;

    KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);

    /* Remove all hooks outside spinlock */
    while (M) {
        Next = M->Next;
        GenericHookRemove(M->GenericHookId);
        ExFreePoolWithTag(M, SSDT_TAG);
        M = Next;
    }

    LOG_INFO("SSDT: All hooks removed");
}

/* ========================================================================= */
/*  Monitor Mode                                                             */
/* ========================================================================= */

NTSTATUS SsdtSetMonitorMode(PVMX_SSDT_MONITOR_REQUEST Req)
{
    HOOK_RULE   MonitorRule = { 0 };
    ULONG       i;
    ULONG       HookId;
    ULONG       Installed = 0;

    if (!g_SsdtState.Initialized) return STATUS_UNSUCCESSFUL;

    /* Stop existing monitoring first */
    if (g_SsdtState.MonitorMode != SSDT_MONITOR_OFF) {
        SsdtStopMonitoring();
    }

    if (Req->Mode == SSDT_MONITOR_OFF) {
        g_SsdtState.MonitorMode = SSDT_MONITOR_OFF;
        LOG_INFO("SSDT: Monitoring stopped");
        return STATUS_SUCCESS;
    }

    /* Build LOG_ONLY rule */
    MonitorRule.Action = HOOK_ACTION_LOG_ONLY;
    MonitorRule.TargetPid = Req->TargetPid;
    MonitorRule.LogEnabled = TRUE;

    g_SsdtState.MonitorPid = Req->TargetPid;

    if (Req->Mode == SSDT_MONITOR_ALL) {
        LOG_INFO("SSDT: Starting ALL monitoring (PID=%u)...", Req->TargetPid);

        for (i = 0; i < g_SsdtState.ServiceCount; i++) {
            NTSTATUS Status = SsdtHookByIndex(i, &MonitorRule, &HookId);
            if (NT_SUCCESS(Status)) {
                /* Mark as monitor hook */
                KIRQL OldIrql;
                PSSDT_HOOK_MAPPING M;
                KeAcquireSpinLock(&g_SsdtState.HookLock, &OldIrql);
                M = SsdtFindMappingByHookId(HookId);
                if (M) M->IsMonitorHook = TRUE;
                KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);
                Installed++;
            }
            /* Skip already-hooked syscalls silently */
        }

        g_SsdtState.MonitorMode = SSDT_MONITOR_ALL;
        LOG_INFO("SSDT: Monitor ALL installed %u / %u hooks", Installed, g_SsdtState.ServiceCount);

    } else if (Req->Mode == SSDT_MONITOR_FILTERED) {
        ULONG Count = Req->FilterCount;
        if (Count > SSDT_MONITOR_MAX_FILTER) Count = SSDT_MONITOR_MAX_FILTER;

        LOG_INFO("SSDT: Starting FILTERED monitoring (%u indices, PID=%u)...",
                 Count, Req->TargetPid);

        for (i = 0; i < Count; i++) {
            ULONG Idx = Req->FilterIndices[i];
            NTSTATUS Status = SsdtHookByIndex(Idx, &MonitorRule, &HookId);
            if (NT_SUCCESS(Status)) {
                KIRQL OldIrql;
                PSSDT_HOOK_MAPPING M;
                KeAcquireSpinLock(&g_SsdtState.HookLock, &OldIrql);
                M = SsdtFindMappingByHookId(HookId);
                if (M) M->IsMonitorHook = TRUE;
                KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);
                Installed++;
            }
        }

        g_SsdtState.MonitorMode = SSDT_MONITOR_FILTERED;
        LOG_INFO("SSDT: Monitor FILTERED installed %u / %u hooks", Installed, Count);

    } else {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

VOID SsdtStopMonitoring(VOID)
{
    KIRQL               OldIrql;
    PSSDT_HOOK_MAPPING  M, Prev, Next;
    PSSDT_HOOK_MAPPING  RemoveList = NULL;

    if (g_SsdtState.MonitorMode == SSDT_MONITOR_OFF) return;

    /* Extract monitor hooks from list */
    KeAcquireSpinLock(&g_SsdtState.HookLock, &OldIrql);

    Prev = NULL;
    M = g_SsdtState.HookListHead;
    while (M) {
        Next = M->Next;
        if (M->IsMonitorHook) {
            /* Unlink from main list */
            if (Prev) Prev->Next = Next;
            else g_SsdtState.HookListHead = Next;
            g_SsdtState.HookCount--;

            /* Add to remove list */
            M->Next = RemoveList;
            RemoveList = M;
        } else {
            Prev = M;
        }
        M = Next;
    }

    KeReleaseSpinLock(&g_SsdtState.HookLock, OldIrql);

    /* Remove hooks outside spinlock */
    M = RemoveList;
    while (M) {
        Next = M->Next;
        GenericHookRemove(M->GenericHookId);
        ExFreePoolWithTag(M, SSDT_TAG);
        M = Next;
    }

    g_SsdtState.MonitorMode = SSDT_MONITOR_OFF;
    LOG_INFO("SSDT: Monitoring stopped, all monitor hooks removed");
}

/* ========================================================================= */
/*  Lifecycle                                                                */
/* ========================================================================= */

NTSTATUS SsdtInitialize(VOID)
{
    NTSTATUS Status;

    if (g_SsdtState.Initialized) {
        LOG_INFO("SSDT: Already initialized, skipping");
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_SsdtState, sizeof(SSDT_STATE));
    KeInitializeSpinLock(&g_SsdtState.HookLock);

    /* Get ntoskrnl base address */
    Status = SsdtGetNtoskrnlBase();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("SSDT: Failed to get ntoskrnl base: 0x%08X", Status);
        return Status;
    }

    /* Discover KiServiceTable by reverse-engineering Zw/Nt stub pairs */
    Status = SsdtDiscoverByZwStubReverse();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("SSDT: Discovery failed: 0x%08X", Status);
        return Status;
    }

    /* Resolve names (best-effort, don't fail on this) */
    SsdtPopulateNames();

    g_SsdtState.Initialized = TRUE;
    LOG_INFO("SSDT: Initialized with %u services", g_SsdtState.ServiceCount);
    return STATUS_SUCCESS;
}

VOID SsdtCleanup(VOID)
{
    if (!g_SsdtState.Initialized) return;

    LOG_INFO("SSDT: Cleaning up...");

    /* Stop monitoring */
    SsdtStopMonitoring();

    /* Remove all SSDT hooks */
    SsdtUnhookAll();

    g_SsdtState.Initialized = FALSE;
    LOG_INFO("SSDT: Cleanup complete");
}
