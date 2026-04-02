/*
 * ssdt.c - VMX Hypervisor Toolbox
 * SSDT (System Service Descriptor Table) Monitoring & Hook Framework
 *
 * Two-tier discovery + address resolution:
 *
 *   Tier 1 (primary): Map ntoskrnl.exe from disk via ZwCreateSection(SEC_IMAGE),
 *     walk its PE export table to locate KeServiceDescriptorTable, read the
 *     SSDT entries directly from the mapped image. Every byte comes from the
 *     digitally-signed on-disk file — zero in-memory data is trusted.
 *
 *   Tier 2 (fallback): MmGetSystemRoutineAddress("KeServiceDescriptorTable")
 *     to get the live in-memory table pointer, then read entries from the
 *     PatchGuard-protected KiServiceTable. Reliable on x64, but theoretically
 *     touchable in the narrow window before PG activates.
 *
 * All hook mechanics delegate to GenericHookInstall() / GenericHookRemove().
 */

#include "ssdt.h"
#include "hv_hook.h"
#include "log.h"
#include <ntstrsafe.h>
#include <ntimage.h>

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x1000000
#endif

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
static NTSTATUS SsdtMapNtoskrnlFromDisk(VOID);
static VOID     SsdtUnmapFileImage(VOID);
static NTSTATUS SsdtDiscoverAndResolveFromDisk(VOID);
static NTSTATUS SsdtDiscoverAndResolveFromMemory(VOID);
static PSSDT_HOOK_MAPPING SsdtFindMappingByIndex(ULONG Index);
static PSSDT_HOOK_MAPPING SsdtFindMappingByHookId(ULONG HookId);

/* ========================================================================= */
/*  KeServiceDescriptorTable structure (stable across all x64 NT)            */
/* ========================================================================= */

/*
 * Layout (undocumented but binary-stable since x64 Windows XP):
 *
 *   +0x00  PLONG   Base     ->  KiServiceTable (array of relative offsets)
 *   +0x08  PULONG  Count    ->  unused on x64 (always NULL)
 *   +0x10  ULONG64 Limit    ->  number of services (pointer-width storage)
 *   +0x18  PUCHAR  Number   ->  argument byte-count table (KiArgumentTable)
 *
 * KeServiceDescriptorTable[0] = ntoskrnl SSDT
 * KeServiceDescriptorTable[1] = win32k shadow SSDT (not used here)
 *
 * In the SEC_IMAGE mapping, the struct contents are unrelocated:
 *   - Base contains the RVA (relative to ntoskrnl ImageBase), not a live VA
 *   - Limit is an absolute count, position-independent
 */

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PLONG       Base;
    PULONG      Count;
    ULONG64     Limit;
    PUCHAR      Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

/* ========================================================================= */
/*  3a. ntoskrnl Base Discovery + Disk Path                                  */
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
 * SsdtGetNtoskrnlBase - Get ntoskrnl load address, size, and disk path.
 *
 * The disk path (FullPathName) is needed for file-image mapping.
 * The path comes in DOS device form (e.g. "\SystemRoot\system32\ntoskrnl.exe"
 * or "\??\C:\Windows\system32\ntoskrnl.exe") — we normalise it to an
 * NT object path for ZwOpenFile.
 */
static NTSTATUS SsdtGetNtoskrnlBase(VOID)
{
    NTSTATUS    Status;
    ULONG       Size = 0;
    PRTL_PROCESS_MODULES Modules = NULL;
    const char *FullPath;
    ULONG       PathLen, k;

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

    /*
     * Store disk path.  SystemModuleInformation returns paths like:
     *   \SystemRoot\system32\ntoskrnl.exe
     *   \??\C:\WINDOWS\system32\ntoskrnl.exe
     *
     * We convert to an NT path usable by ZwOpenFile:
     *   \SystemRoot\... → already valid NT path, use as-is
     *   \??\...         → already valid NT path, use as-is
     *   Otherwise       → prepend \SystemRoot\system32\ + filename
     */
    FullPath = (const char *)Modules->Modules[0].FullPathName;
    PathLen = (ULONG)strlen(FullPath);

    if (PathLen > 12 && FullPath[0] == '\\' &&
        FullPath[1] == 'D' && FullPath[2] == 'e' && FullPath[3] == 'v' &&
        FullPath[4] == 'i' && FullPath[5] == 'c' && FullPath[6] == 'e' &&
        FullPath[7] == '\\') {
        /*
         * \Device\HarddiskVolumeN\Windows\system32\ntoskrnl.exe
         * ZwOpenFile cannot open \Device\ paths directly.
         * Extract the relative path after the volume (look for \Windows\)
         * and prepend \SystemRoot to form a valid NT path.
         *
         * Search for "\Windows\" (case-insensitive) or "\WINDOWS\".
         */
        const char *WinDir = NULL;
        ULONG j;
        for (j = 8; j + 9 < PathLen; j++) {
            if (FullPath[j] == '\\' &&
                (FullPath[j+1] == 'W' || FullPath[j+1] == 'w') &&
                (FullPath[j+2] == 'i' || FullPath[j+2] == 'I') &&
                (FullPath[j+3] == 'n' || FullPath[j+3] == 'N') &&
                (FullPath[j+4] == 'd' || FullPath[j+4] == 'D') &&
                (FullPath[j+5] == 'o' || FullPath[j+5] == 'O') &&
                (FullPath[j+6] == 'w' || FullPath[j+6] == 'W') &&
                (FullPath[j+7] == 's' || FullPath[j+7] == 'S') &&
                FullPath[j+8] == '\\') {
                WinDir = &FullPath[j];  /* points to "\Windows\..." */
                break;
            }
        }
        if (WinDir) {
            /* Build \SystemRoot\system32\ntoskrnl.exe from \Windows\system32\ntoskrnl.exe */
            WCHAR Prefix[] = L"\\SystemRoot";
            ULONG PrefixLen = (ULONG)wcslen(Prefix);
            const char *Remainder = WinDir + 8; /* skip "\Windows", keep "\system32\..." */
            ULONG RemLen = (ULONG)strlen(Remainder);

            RtlCopyMemory(g_SsdtState.NtoskrnlPath, Prefix, PrefixLen * sizeof(WCHAR));
            for (k = 0; k < RemLen && (PrefixLen + k) < 259; k++) {
                g_SsdtState.NtoskrnlPath[PrefixLen + k] = (WCHAR)(UCHAR)Remainder[k];
            }
            g_SsdtState.NtoskrnlPath[PrefixLen + k] = L'\0';
            LOG_INFO("SSDT: Converted \\Device path to %ws", g_SsdtState.NtoskrnlPath);
        } else {
            /* \Device\ path but no \Windows\ found — use as-is and hope for the best */
            for (k = 0; k < PathLen && k < 259; k++) {
                g_SsdtState.NtoskrnlPath[k] = (WCHAR)(UCHAR)FullPath[k];
            }
            g_SsdtState.NtoskrnlPath[k] = L'\0';
            LOG_WARN("SSDT: \\Device path without \\Windows\\: %ws", g_SsdtState.NtoskrnlPath);
        }
    } else if (PathLen > 0 && FullPath[0] == '\\') {
        /* Already an NT-style path (\SystemRoot\... or \??\...) */
        for (k = 0; k < PathLen && k < 259; k++) {
            g_SsdtState.NtoskrnlPath[k] = (WCHAR)(UCHAR)FullPath[k];
        }
        g_SsdtState.NtoskrnlPath[k] = L'\0';
    } else {
        /* Bare filename or relative — build full path from SystemRoot */
        USHORT FileOffset = Modules->Modules[0].OffsetToFileName;
        const char *FileName = (const char *)Modules->Modules[0].FullPathName + FileOffset;
        WCHAR Prefix[] = L"\\SystemRoot\\system32\\";
        ULONG PrefixLen = (ULONG)wcslen(Prefix);
        ULONG NameLen = (ULONG)strlen(FileName);

        RtlCopyMemory(g_SsdtState.NtoskrnlPath, Prefix, PrefixLen * sizeof(WCHAR));
        for (k = 0; k < NameLen && (PrefixLen + k) < 259; k++) {
            g_SsdtState.NtoskrnlPath[PrefixLen + k] = (WCHAR)(UCHAR)FileName[k];
        }
        g_SsdtState.NtoskrnlPath[PrefixLen + k] = L'\0';
    }

    LOG_INFO("SSDT: ntoskrnl base=0x%llX size=0x%X path=%ws",
             g_SsdtState.NtoskrnlBase, g_SsdtState.NtoskrnlSize,
             g_SsdtState.NtoskrnlPath);

    ExFreePoolWithTag(Modules, SSDT_TAG);
    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  3b. SEC_IMAGE Mapping                                                    */
/* ========================================================================= */

/*
 * SsdtMapNtoskrnlFromDisk - Map ntoskrnl.exe from disk as SEC_IMAGE.
 *
 * Uses ZwCreateSection(SEC_IMAGE) + ZwMapViewOfSection to let the memory
 * manager load the PE with proper section alignment. This means:
 *   - All sections are laid out at their VirtualAddress offsets
 *   - RVAs can be used directly as offsets from the mapping base
 *   - No manual RVA-to-file-offset conversion needed
 *   - Relocations are NOT applied (the image is mapped at an arbitrary VA),
 *     but we only read SSDT relative offsets which are position-independent
 *
 * The mapping is done into System process address space (kernel VA).
 */
static NTSTATUS SsdtMapNtoskrnlFromDisk(VOID)
{
    NTSTATUS            Status;
    UNICODE_STRING      FilePath;
    OBJECT_ATTRIBUTES   ObjAttrs;
    IO_STATUS_BLOCK     IoStatus;
    HANDLE              FileHandle = NULL;
    HANDLE              SectionHandle = NULL;
    PVOID               ViewBase = NULL;
    SIZE_T              ViewSize = 0;

    if (g_SsdtState.NtoskrnlPath[0] == L'\0') {
        return STATUS_NOT_FOUND;
    }

    /* Open the file */
    RtlInitUnicodeString(&FilePath, g_SsdtState.NtoskrnlPath);
    InitializeObjectAttributes(&ObjAttrs, &FilePath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    Status = ZwOpenFile(&FileHandle,
                        FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
                        &ObjAttrs,
                        &IoStatus,
                        FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status)) {
        LOG_WARN("SSDT: ZwOpenFile(%ws) failed: 0x%08X", g_SsdtState.NtoskrnlPath, Status);
        return Status;
    }

    /*
     * Create an image section. SEC_IMAGE tells the memory manager to parse
     * the PE headers and lay out sections at their VirtualAddress offsets,
     * just like a normal image load — but without executing DllMain or
     * applying relocations (we don't need those).
     */
    InitializeObjectAttributes(&ObjAttrs, NULL,
                               OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwCreateSection(&SectionHandle,
                             SECTION_MAP_READ,
                             &ObjAttrs,
                             NULL,              /* MaximumSize = file size */
                             PAGE_READONLY,
                             SEC_IMAGE,         /* Key: image mapping */
                             FileHandle);
    ZwClose(FileHandle);
    FileHandle = NULL;

    if (!NT_SUCCESS(Status)) {
        LOG_WARN("SSDT: ZwCreateSection(SEC_IMAGE) failed: 0x%08X", Status);
        return Status;
    }

    /*
     * Map the section into System process address space.
     * ViewUnmap type = ViewShare so it's automatically cleaned up.
     */
    Status = ZwMapViewOfSection(SectionHandle,
                                ZwCurrentProcess(),
                                &ViewBase,
                                0,              /* ZeroBits */
                                0,              /* CommitSize */
                                NULL,           /* SectionOffset */
                                &ViewSize,
                                ViewShare,
                                0,              /* AllocationType */
                                PAGE_READONLY);
    if (!NT_SUCCESS(Status)) {
        LOG_WARN("SSDT: ZwMapViewOfSection failed: 0x%08X", Status);
        ZwClose(SectionHandle);
        return Status;
    }

    /* Basic PE validation on the mapped image */
    __try {
        PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)ViewBase;
        PIMAGE_NT_HEADERS64 Nt;

        if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
            ZwUnmapViewOfSection(ZwCurrentProcess(), ViewBase);
            ZwClose(SectionHandle);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        Nt = (PIMAGE_NT_HEADERS64)((PUCHAR)ViewBase + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE) {
            ZwUnmapViewOfSection(ZwCurrentProcess(), ViewBase);
            ZwClose(SectionHandle);
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), ViewBase);
        ZwClose(SectionHandle);
        return STATUS_ACCESS_VIOLATION;
    }

    g_SsdtState.FileImageBase = ViewBase;
    g_SsdtState.FileImageViewSize = ViewSize;
    g_SsdtState.FileImageSection = SectionHandle;

    LOG_INFO("SSDT: Mapped ntoskrnl from disk via SEC_IMAGE: base=%p, size=0x%llX",
             ViewBase, (ULONG64)ViewSize);
    return STATUS_SUCCESS;
}

static VOID SsdtUnmapFileImage(VOID)
{
    if (g_SsdtState.FileImageBase) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), g_SsdtState.FileImageBase);
        g_SsdtState.FileImageBase = NULL;
        g_SsdtState.FileImageViewSize = 0;
    }
    if (g_SsdtState.FileImageSection) {
        ZwClose(g_SsdtState.FileImageSection);
        g_SsdtState.FileImageSection = NULL;
    }
}

/* ========================================================================= */
/*  3c. Tier 1: Discover + Resolve from disk                                 */
/* ========================================================================= */

/*
 * SsdtDiscoverAndResolveFromDisk - Walk mapped PE exports to find
 * KeServiceDescriptorTable, read SSDT entries from the clean on-disk image.
 *
 * Because SEC_IMAGE mapping lays out sections at their VirtualAddress offsets,
 * RVAs are direct offsets from the mapping base. The KSERVICE_TABLE_DESCRIPTOR
 * is unrelocated in the mapped image:
 *   - Base contains PreferredBase + RVA (the linker-assigned VA)
 *   - We subtract PreferredBase (from OptionalHeader.ImageBase) to get TableRva
 *   - Limit is position-independent (just a count)
 *
 * x64 SSDT entry format (identical on-disk and in-memory):
 *   LONG entry = KiServiceTable[index]
 *   FunctionVA = KiServiceTableVA + (entry >> 4)
 *   ArgCount   = entry & 0xF
 *
 * We read the LONG entries from the mapped image, then rebase the computed
 * addresses to the live NtoskrnlBase, giving us guaranteed-clean function VAs.
 */
static NTSTATUS SsdtDiscoverAndResolveFromDisk(VOID)
{
    PUCHAR                  MapBase;
    PIMAGE_DOS_HEADER       Dos;
    PIMAGE_NT_HEADERS64     Nt;
    PIMAGE_EXPORT_DIRECTORY Export;
    PULONG                  Names;
    PULONG                  Functions;
    PUSHORT                 Ordinals;
    ULONG64                 PreferredBase;
    ULONG                   i;
    BOOLEAN                 Found = FALSE;
    ULONG                   TableRva = 0;
    ULONG                   ServiceCount = 0;
    ULONG64                 LiveTableVa;
    PLONG                   MappedEntries;
    ULONG                   ValidCount = 0;

    if (!g_SsdtState.FileImageBase || g_SsdtState.NtoskrnlBase == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    MapBase = (PUCHAR)g_SsdtState.FileImageBase;

    __try {
        /* Parse PE headers */
        Dos = (PIMAGE_DOS_HEADER)MapBase;
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        Nt = (PIMAGE_NT_HEADERS64)(MapBase + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PreferredBase = Nt->OptionalHeader.ImageBase;

        /* Locate export directory */
        if (Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
            LOG_WARN("SSDT: No export directory in mapped ntoskrnl");
            return STATUS_NOT_FOUND;
        }

        Export = (PIMAGE_EXPORT_DIRECTORY)(MapBase +
            Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        Names     = (PULONG)(MapBase + Export->AddressOfNames);
        Functions = (PULONG)(MapBase + Export->AddressOfFunctions);
        Ordinals  = (PUSHORT)(MapBase + Export->AddressOfNameOrdinals);

        /* Walk exports to find KeServiceDescriptorTable */
        for (i = 0; i < Export->NumberOfNames; i++) {
            const char *Name = (const char *)(MapBase + Names[i]);
            ULONG FuncRva;
            PKSERVICE_TABLE_DESCRIPTOR Desc;

            /* strcmp inline — looking for "KeServiceDescriptorTable" exactly */
            if (Name[0]  != 'K' || Name[1]  != 'e' || Name[2]  != 'S' ||
                Name[3]  != 'e' || Name[4]  != 'r' || Name[5]  != 'v' ||
                Name[6]  != 'i' || Name[7]  != 'c' || Name[8]  != 'e' ||
                Name[9]  != 'D' || Name[10] != 'e' || Name[11] != 's' ||
                Name[12] != 'c' || Name[13] != 'r' || Name[14] != 'i' ||
                Name[15] != 'p' || Name[16] != 't' || Name[17] != 'o' ||
                Name[18] != 'r' || Name[19] != 'T' || Name[20] != 'a' ||
                Name[21] != 'b' || Name[22] != 'l' || Name[23] != 'e' ||
                Name[24] != '\0') {
                continue;
            }

            FuncRva = Functions[Ordinals[i]];

            /*
             * In the mapped image, KeServiceDescriptorTable is at MapBase+FuncRva.
             * Its .Base field contains an unrelocated pointer:
             *   UnrelocatedBase = PreferredBase + KiServiceTableRva
             * So: TableRva = (ULONG)((ULONG64)Desc->Base - PreferredBase)
             */
            Desc = (PKSERVICE_TABLE_DESCRIPTOR)(MapBase + FuncRva);

            {
                ULONG64 UnrelocatedBase = (ULONG64)Desc->Base;
                ULONG   Limit;

                if (UnrelocatedBase < PreferredBase) {
                    LOG_WARN("SSDT: Disk: UnrelocatedBase 0x%llX < PreferredBase 0x%llX",
                             UnrelocatedBase, PreferredBase);
                    return STATUS_UNSUCCESSFUL;
                }

                TableRva = (ULONG)(UnrelocatedBase - PreferredBase);
                Limit = (ULONG)(Desc->Limit & 0xFFFFFFFF);

                if (Limit == 0 || Limit > SSDT_MAX_SERVICES) {
                    LOG_WARN("SSDT: Disk: Limit=%u out of range", Limit);
                    return STATUS_UNSUCCESSFUL;
                }

                ServiceCount = Limit;
            }

            Found = TRUE;
            LOG_INFO("SSDT: Disk: KeServiceDescriptorTable at RVA 0x%X, "
                     "TableRva=0x%X, Limit=%u", FuncRva, TableRva, ServiceCount);
            break;
        }

        if (!Found) {
            LOG_WARN("SSDT: Disk: KeServiceDescriptorTable export not found");
            return STATUS_NOT_FOUND;
        }

        /* Bounds check: SSDT entries must fit within the mapped view */
        if ((ULONG64)TableRva + (ULONG64)ServiceCount * sizeof(LONG)
            > g_SsdtState.FileImageViewSize)
        {
            LOG_WARN("SSDT: Disk: Table RVA 0x%X + entries exceed mapped view (0x%llX)",
                     TableRva, (ULONG64)g_SsdtState.FileImageViewSize);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        MappedEntries = (PLONG)(MapBase + TableRva);

        /*
         * Compute the live VA of KiServiceTable for entry decoding.
         * KiServiceTableVa = NtoskrnlBase + TableRva
         */
        LiveTableVa = g_SsdtState.NtoskrnlBase + (ULONG64)TableRva;

        /* Resolve each entry: rebase on-disk data to live addresses */
        for (i = 0; i < ServiceCount; i++) {
            LONG    Entry = MappedEntries[i];
            ULONG64 FuncVa = LiveTableVa + (LONG64)(Entry >> 4);

            /* Sanity: function must be within ntoskrnl range */
            if (FuncVa >= g_SsdtState.NtoskrnlBase &&
                FuncVa <  g_SsdtState.NtoskrnlBase + g_SsdtState.NtoskrnlSize) {
                g_SsdtState.ResolvedAddresses[i] = FuncVa;
                ValidCount++;
            } else {
                g_SsdtState.ResolvedAddresses[i] = 0;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_WARN("SSDT: Disk: Exception during discover+resolve");
        return STATUS_ACCESS_VIOLATION;
    }

    /* Commit results to global state */
    g_SsdtState.KiServiceTableVa = g_SsdtState.NtoskrnlBase + (ULONG64)TableRva;
    g_SsdtState.ServiceCount = ServiceCount;

    LOG_INFO("SSDT: Disk: Resolved %u / %u addresses from clean on-disk image",
             ValidCount, ServiceCount);
    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  3d. Tier 2: Discover + Resolve from memory                               */
/* ========================================================================= */

/*
 * SsdtDiscoverAndResolveFromMemory - Fallback: use MmGetSystemRoutineAddress
 * to find KeServiceDescriptorTable in live memory, then read KiServiceTable
 * entries directly.
 *
 * On x64 with PatchGuard active, these addresses are still trustworthy
 * (PG guards KiServiceTable integrity).
 */
static NTSTATUS SsdtDiscoverAndResolveFromMemory(VOID)
{
    UNICODE_STRING                  Name;
    PKSERVICE_TABLE_DESCRIPTOR      KeSDT;
    PLONG                           Table;
    ULONG                           Limit;
    ULONG                           i;

    /* Resolve KeServiceDescriptorTable export */
    RtlInitUnicodeString(&Name, L"KeServiceDescriptorTable");
    KeSDT = (PKSERVICE_TABLE_DESCRIPTOR)MmGetSystemRoutineAddress(&Name);
    if (!KeSDT) {
        LOG_ERROR("SSDT: Memory: KeServiceDescriptorTable not found. "
                  "This should never happen on x64 Windows.");
        return STATUS_NOT_FOUND;
    }

    __try {
        if (!KeSDT->Base) {
            LOG_ERROR("SSDT: Memory: KeServiceDescriptorTable.Base is NULL");
            return STATUS_NOT_FOUND;
        }

        g_SsdtState.KiServiceTableVa = (ULONG64)KeSDT->Base;

        Limit = (ULONG)(KeSDT->Limit & 0xFFFFFFFF);
        if (Limit == 0 || Limit > SSDT_MAX_SERVICES) {
            LOG_ERROR("SSDT: Memory: KeServiceDescriptorTable.Limit=%u out of range", Limit);
            return STATUS_UNSUCCESSFUL;
        }
        g_SsdtState.ServiceCount = Limit;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("SSDT: Memory: Exception reading KeServiceDescriptorTable at %p", KeSDT);
        return STATUS_ACCESS_VIOLATION;
    }

    LOG_INFO("SSDT: Memory: KiServiceTable=0x%llX, ServiceCount=%u",
             g_SsdtState.KiServiceTableVa, g_SsdtState.ServiceCount);

    /* Read live KiServiceTable entries */
    Table = (PLONG)g_SsdtState.KiServiceTableVa;

    __try {
        for (i = 0; i < g_SsdtState.ServiceCount; i++) {
            LONG Entry = Table[i];
            g_SsdtState.ResolvedAddresses[i] =
                g_SsdtState.KiServiceTableVa + (LONG64)(Entry >> 4);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_WARN("SSDT: Memory: Exception resolving entries at index ~%u", i);
        return STATUS_ACCESS_VIOLATION;
    }

    LOG_INFO("SSDT: Memory: Resolved %u addresses from live memory (PG-protected)",
             g_SsdtState.ServiceCount);
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
/*  3e. Name Resolution                                                      */
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
        LOG_WARN("SSDT: Already initialized");
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_SsdtState, sizeof(SSDT_STATE));
    KeInitializeSpinLock(&g_SsdtState.HookLock);

    /* Read LSTAR for informational/diagnostic purposes */
    g_SsdtState.KiSystemCall64Va = __readmsr(0xC0000082);
    if (g_SsdtState.KiSystemCall64Va != 0) {
        LOG_INFO("SSDT: KiSystemCall64 at 0x%llX", g_SsdtState.KiSystemCall64Va);
    }

    /* Get ntoskrnl base address and disk path */
    Status = SsdtGetNtoskrnlBase();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("SSDT: Failed to get ntoskrnl base: 0x%08X", Status);
        return Status;
    }

    /* Tier 1: Map ntoskrnl from disk and resolve SSDT from clean image */
    Status = SsdtMapNtoskrnlFromDisk();
    if (NT_SUCCESS(Status)) {
        Status = SsdtDiscoverAndResolveFromDisk();
        SsdtUnmapFileImage();

        if (NT_SUCCESS(Status)) {
            LOG_INFO("SSDT: Tier 1 (disk) discovery succeeded");
            goto resolved;
        }
        LOG_WARN("SSDT: Tier 1 (disk) resolve failed: 0x%08X, trying Tier 2", Status);
    } else {
        LOG_WARN("SSDT: Tier 1 (disk) map failed: 0x%08X, trying Tier 2", Status);
    }

    /* Tier 2: Discover + resolve from live memory */
    Status = SsdtDiscoverAndResolveFromMemory();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("SSDT: Both Tier 1 and Tier 2 discovery failed. "
                  "Last error: 0x%08X", Status);
        return Status;
    }

    LOG_INFO("SSDT: Tier 2 (memory) discovery succeeded");

resolved:
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

    /* Free file image if still mapped */
    SsdtUnmapFileImage();

    g_SsdtState.Initialized = FALSE;
    LOG_INFO("SSDT: Cleanup complete");
}
