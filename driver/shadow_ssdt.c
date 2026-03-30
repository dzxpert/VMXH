/*
 * shadow_ssdt.c - VMX Hypervisor Toolbox
 * Shadow SSDT (Win32k) Monitoring & Hook Framework
 *
 * Discovers KeServiceDescriptorTableShadow via KTHREAD.ServiceTable,
 * resolves NtUser/NtGdi addresses, and hooks them via the existing
 * GenericHook EPT/NPT framework.
 *
 * Win32k specifics:
 *   - win32k is per-Session mapped, so all reads from W32pServiceTable
 *     must be done inside a GUI process context (KeStackAttachProcess).
 *   - KTHREAD.ServiceTable offset is found by scanning PID=4 threads
 *     (which always point to KeServiceDescriptorTable).
 *   - GUI threads point to KeServiceDescriptorTableShadow instead.
 *   - Win10+ splits win32k into win32kbase.sys + win32kfull.sys + win32k.sys;
 *     name resolution walks all three export tables.
 */

#include "shadow_ssdt.h"
#include "hv_hook.h"
#include "log.h"
#include <ntstrsafe.h>
#include <ntimage.h>

/*
 * KeStackAttachProcess / KeUnstackDetachProcess are in ntifs.h, but
 * we only need the declarations here.  KAPC_STATE is also from ntifs.h.
 */
typedef struct _KAPC_STATE {
    LIST_ENTRY  ApcListHead[2];
    PKPROCESS   Process;
    BOOLEAN     KernelApcInProgress;
    BOOLEAN     KernelApcPending;
    BOOLEAN     UserApcPending;
} KAPC_STATE, *PKAPC_STATE;

NTKERNELAPI VOID KeStackAttachProcess(PEPROCESS Process, PKAPC_STATE ApcState);
NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);

/* ========================================================================= */
/*  Pool tag                                                                 */
/* ========================================================================= */

#define SHADOW_TAG  'SHSS'

/* ========================================================================= */
/*  Globals                                                                  */
/* ========================================================================= */

SHADOW_SSDT_STATE g_ShadowSsdtState = { 0 };

/* ========================================================================= */
/*  Forward Declarations                                                     */
/* ========================================================================= */

static NTSTATUS KthreadResolveServiceTableOffset(VOID);
static NTSTATUS ShadowSsdtDiscover(VOID);
static NTSTATUS ShadowSsdtGetWin32kModules(VOID);
static NTSTATUS ShadowSsdtResolveAllAddresses(VOID);
static NTSTATUS ShadowSsdtPopulateNames(VOID);
static PSSDT_HOOK_MAPPING ShadowFindMappingByIndex(ULONG Index);
static PSSDT_HOOK_MAPPING ShadowFindMappingByHookId(ULONG HookId);

/* ========================================================================= */
/*  Undocumented API declarations                                            */
/* ========================================================================= */

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD *Thread);

#define SystemProcessInformation    5
#define SystemModuleInformation     11

#pragma pack(push, 1)

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER   KernelTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   CreateTime;
    ULONG           WaitTime;
    PVOID           StartAddress;
    CLIENT_ID       ClientId;
    KPRIORITY       Priority;
    LONG            BasePriority;
    ULONG           ContextSwitchCount;
    ULONG           State;
    ULONG           WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   WorkingSetPrivateSize;
    ULONG           HardFaultCount;
    ULONG           NumberOfThreadsHighWatermark;
    ULONGLONG       CycleTime;
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    KPRIORITY       BasePriority;
    HANDLE          UniqueProcessId;
    HANDLE          InheritedFromUniqueProcessId;
    ULONG           HandleCount;
    ULONG           SessionId;
    ULONG_PTR       UniqueProcessKey;
    SIZE_T          PeakVirtualSize;
    SIZE_T          VirtualSize;
    ULONG           PageFaultCount;
    SIZE_T          PeakWorkingSetSize;
    SIZE_T          WorkingSetSize;
    SIZE_T          QuotaPeakPagedPoolUsage;
    SIZE_T          QuotaPagedPoolUsage;
    SIZE_T          QuotaPeakNonPagedPoolUsage;
    SIZE_T          QuotaNonPagedPoolUsage;
    SIZE_T          PagefileUsage;
    SIZE_T          PeakPagefileUsage;
    SIZE_T          PrivatePageCount;
    LARGE_INTEGER   ReadOperationCount;
    LARGE_INTEGER   WriteOperationCount;
    LARGE_INTEGER   OtherOperationCount;
    LARGE_INTEGER   ReadTransferCount;
    LARGE_INTEGER   WriteTransferCount;
    LARGE_INTEGER   OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#pragma pack(pop)

/* Module info structure (also used in ssdt.c, redeclared locally) */
typedef struct _RTL_PROCESS_MODULE_INFORMATION_SHADOW {
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
} RTL_PROCESS_MODULE_INFORMATION_SHADOW;

typedef struct _RTL_PROCESS_MODULES_SHADOW {
    ULONG                                   NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION_SHADOW   Modules[1];
} RTL_PROCESS_MODULES_SHADOW;

/* KeServiceDescriptorTable layout (same as ssdt.c) */
typedef struct _KSERVICE_TABLE_DESCRIPTOR_SHADOW {
    PLONG       Base;
    PULONG      Count;
    ULONG64     Limit;
    PUCHAR      Number;
} KSERVICE_TABLE_DESCRIPTOR_SHADOW;

/* ========================================================================= */
/*  Helper: check if address is in kernel space                              */
/* ========================================================================= */

static __inline BOOLEAN IsKernelAddress(ULONG64 Addr)
{
    return (Addr >= 0xFFFF800000000000ULL);
}

/* ========================================================================= */
/*  3a. KTHREAD.ServiceTable Offset Dynamic Discovery                        */
/* ========================================================================= */

/*
 * KthreadResolveServiceTableOffset
 *
 * Strategy: System process (PID=4) threads never initialise win32k,
 * so their KTHREAD.ServiceTable always points to KeServiceDescriptorTable.
 * We get the known KeServiceDescriptorTable address, then QWORD-scan
 * a System thread's KTHREAD to find the matching offset.
 *
 * A second System thread is used for validation.
 */
static NTSTATUS KthreadResolveServiceTableOffset(VOID)
{
    NTSTATUS    Status;
    ULONG       Size = 0;
    PUCHAR      Buffer = NULL;
    PSYSTEM_PROCESS_INFORMATION Proc;
    ULONG64     KeServiceDescriptorTable = 0;
    UNICODE_STRING Name;
    HANDLE      Tid1 = NULL, Tid2 = NULL;
    PETHREAD    Thread1 = NULL, Thread2 = NULL;
    ULONG       Offset;
    ULONG       Candidate = 0;
    BOOLEAN     Found = FALSE;

    /* Get KeServiceDescriptorTable address */
    RtlInitUnicodeString(&Name, L"KeServiceDescriptorTable");
    KeServiceDescriptorTable = (ULONG64)MmGetSystemRoutineAddress(&Name);
    if (KeServiceDescriptorTable == 0) {
        LOG_ERROR("ShadowSSDT: Cannot resolve KeServiceDescriptorTable");
        return STATUS_NOT_FOUND;
    }

    LOG_INFO("ShadowSSDT: KeServiceDescriptorTable = 0x%llX", KeServiceDescriptorTable);

    /* Enumerate processes to find PID=4 thread IDs */
    Status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &Size);
    if (Size == 0) return STATUS_UNSUCCESSFUL;

    Size += 0x10000;    /* Extra padding for race conditions */
    Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, Size, SHADOW_TAG);
    if (!Buffer) return STATUS_INSUFFICIENT_RESOURCES;

    Status = ZwQuerySystemInformation(SystemProcessInformation, Buffer, Size, &Size);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, SHADOW_TAG);
        return Status;
    }

    /* Find PID=4 (System) and collect two thread IDs */
    Proc = (PSYSTEM_PROCESS_INFORMATION)Buffer;
    for (;;) {
        if ((ULONG)(ULONG_PTR)Proc->UniqueProcessId == 4) {
            if (Proc->NumberOfThreads >= 2) {
                Tid1 = Proc->Threads[0].ClientId.UniqueThread;
                Tid2 = Proc->Threads[1].ClientId.UniqueThread;
            } else if (Proc->NumberOfThreads == 1) {
                Tid1 = Proc->Threads[0].ClientId.UniqueThread;
            }
            break;
        }
        if (Proc->NextEntryOffset == 0) break;
        Proc = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Proc + Proc->NextEntryOffset);
    }

    ExFreePoolWithTag(Buffer, SHADOW_TAG);

    if (Tid1 == NULL) {
        LOG_ERROR("ShadowSSDT: Cannot find System process threads");
        return STATUS_NOT_FOUND;
    }

    /* Get KTHREAD pointer for first thread */
    Status = PsLookupThreadByThreadId(Tid1, &Thread1);
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("ShadowSSDT: PsLookupThreadByThreadId(TID1) failed: 0x%08X", Status);
        return Status;
    }

    /* QWORD scan for KeServiceDescriptorTable address */
    __try {
        for (Offset = 0; Offset < 0x400; Offset += 8) {
            ULONG64 Value = *(PULONG64)((PUCHAR)Thread1 + Offset);
            if (Value == KeServiceDescriptorTable) {
                Candidate = Offset;
                Found = TRUE;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ObDereferenceObject(Thread1);
        return STATUS_ACCESS_VIOLATION;
    }

    ObDereferenceObject(Thread1);

    if (!Found) {
        LOG_ERROR("ShadowSSDT: Could not find ServiceTable in KTHREAD (scanned 0x400 bytes)");
        return STATUS_NOT_FOUND;
    }

    /* Validate with second thread if available */
    if (Tid2 != NULL) {
        Status = PsLookupThreadByThreadId(Tid2, &Thread2);
        if (NT_SUCCESS(Status)) {
            __try {
                ULONG64 Value2 = *(PULONG64)((PUCHAR)Thread2 + Candidate);
                if (Value2 != KeServiceDescriptorTable) {
                    LOG_WARN("ShadowSSDT: Validation failed: Thread2 offset 0x%X = 0x%llX (expected 0x%llX)",
                             Candidate, Value2, KeServiceDescriptorTable);
                    ObDereferenceObject(Thread2);
                    return STATUS_UNSUCCESSFUL;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                ObDereferenceObject(Thread2);
                return STATUS_ACCESS_VIOLATION;
            }
            ObDereferenceObject(Thread2);
        }
    }

    g_ShadowSsdtState.KthreadOffsets.ServiceTableOffset = Candidate;
    g_ShadowSsdtState.KthreadOffsets.Resolved = TRUE;

    LOG_INFO("ShadowSSDT: KTHREAD.ServiceTable offset = 0x%X", Candidate);
    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  3b. KeServiceDescriptorTableShadow Discovery                             */
/* ========================================================================= */

/*
 * ShadowSsdtDiscover
 *
 * Enumerate all threads system-wide. GUI threads have their KTHREAD.ServiceTable
 * pointing to KeServiceDescriptorTableShadow (not KeServiceDescriptorTable).
 * We find the first such thread, validate the Shadow table structure, and
 * record the GUI process for later KeStackAttachProcess calls.
 */
static NTSTATUS ShadowSsdtDiscover(VOID)
{
    NTSTATUS    Status;
    ULONG       Size = 0;
    PUCHAR      Buffer = NULL;
    PSYSTEM_PROCESS_INFORMATION Proc;
    ULONG64     KeServiceDescriptorTable = 0;
    UNICODE_STRING Name;
    ULONG       ServiceTableOffset = g_ShadowSsdtState.KthreadOffsets.ServiceTableOffset;
    ULONG64     ShadowCandidate = 0;
    HANDLE      GuiPid = NULL;
    BOOLEAN     Found = FALSE;

    /* Get KeServiceDescriptorTable for comparison */
    RtlInitUnicodeString(&Name, L"KeServiceDescriptorTable");
    KeServiceDescriptorTable = (ULONG64)MmGetSystemRoutineAddress(&Name);
    if (KeServiceDescriptorTable == 0) return STATUS_NOT_FOUND;

    /* Enumerate all processes and threads */
    Status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &Size);
    if (Size == 0) return STATUS_UNSUCCESSFUL;

    Size += 0x10000;
    Buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, Size, SHADOW_TAG);
    if (!Buffer) return STATUS_INSUFFICIENT_RESOURCES;

    Status = ZwQuerySystemInformation(SystemProcessInformation, Buffer, Size, &Size);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, SHADOW_TAG);
        return Status;
    }

    Proc = (PSYSTEM_PROCESS_INFORMATION)Buffer;
    for (;;) {
        ULONG t;

        /* Skip PID 0 and PID 4 */
        if ((ULONG_PTR)Proc->UniqueProcessId > 4 && Proc->NumberOfThreads > 0) {
            for (t = 0; t < Proc->NumberOfThreads; t++) {
                PETHREAD Thread = NULL;
                HANDLE Tid = Proc->Threads[t].ClientId.UniqueThread;

                Status = PsLookupThreadByThreadId(Tid, &Thread);
                if (NT_SUCCESS(Status)) {
                    __try {
                        ULONG64 Value = *(PULONG64)((PUCHAR)Thread + ServiceTableOffset);

                        if (Value != KeServiceDescriptorTable &&
                            Value != 0 &&
                            IsKernelAddress(Value))
                        {
                            ShadowCandidate = Value;
                            GuiPid = Proc->UniqueProcessId;
                            Found = TRUE;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        /* Skip this thread */
                    }
                    ObDereferenceObject(Thread);

                    if (Found) break;
                }
            }
        }

        if (Found) break;
        if (Proc->NextEntryOffset == 0) break;
        Proc = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Proc + Proc->NextEntryOffset);
    }

    ExFreePoolWithTag(Buffer, SHADOW_TAG);

    if (!Found) {
        LOG_ERROR("ShadowSSDT: No GUI thread found (no KeServiceDescriptorTableShadow candidate)");
        return STATUS_NOT_FOUND;
    }

    LOG_INFO("ShadowSSDT: Shadow candidate = 0x%llX from PID=%u",
             ShadowCandidate, (ULONG)(ULONG_PTR)GuiPid);

    /* Triple validation: Shadow[0] must match SSDT[0] */
    __try {
        KSERVICE_TABLE_DESCRIPTOR_SHADOW *ShadowTable =
            (KSERVICE_TABLE_DESCRIPTOR_SHADOW *)ShadowCandidate;
        KSERVICE_TABLE_DESCRIPTOR_SHADOW *NormalTable =
            (KSERVICE_TABLE_DESCRIPTOR_SHADOW *)KeServiceDescriptorTable;

        /* Shadow[0].Base should equal KeServiceDescriptorTable[0].Base (ntoskrnl SSDT) */
        if (ShadowTable[0].Base != NormalTable[0].Base) {
            LOG_ERROR("ShadowSSDT: Validation failed: Shadow[0].Base=%p != Normal[0].Base=%p",
                      ShadowTable[0].Base, NormalTable[0].Base);
            return STATUS_UNSUCCESSFUL;
        }

        /* Shadow[0].Limit should equal KeServiceDescriptorTable[0].Limit */
        if (ShadowTable[0].Limit != NormalTable[0].Limit) {
            LOG_ERROR("ShadowSSDT: Validation failed: Shadow[0].Limit=%llu != Normal[0].Limit=%llu",
                      ShadowTable[0].Limit, NormalTable[0].Limit);
            return STATUS_UNSUCCESSFUL;
        }

        /* Shadow[1].Limit must be reasonable (win32k service count) */
        {
            ULONG ShadowLimit = (ULONG)(ShadowTable[1].Limit & 0xFFFFFFFF);
            if (ShadowLimit == 0 || ShadowLimit > SHADOW_SSDT_MAX_SERVICES) {
                LOG_ERROR("ShadowSSDT: Validation failed: Shadow[1].Limit=%u out of range", ShadowLimit);
                return STATUS_UNSUCCESSFUL;
            }

            g_ShadowSsdtState.KeServiceDescriptorTableShadowVa = ShadowCandidate;
            g_ShadowSsdtState.W32pServiceTableVa = (ULONG64)ShadowTable[1].Base;
            g_ShadowSsdtState.ServiceCount = ShadowLimit;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("ShadowSSDT: Exception validating Shadow table at 0x%llX", ShadowCandidate);
        return STATUS_ACCESS_VIOLATION;
    }

    /* Acquire reference to GUI process for KeStackAttachProcess */
    {
        PEPROCESS GuiProcess = NULL;
        Status = PsLookupProcessByProcessId(GuiPid, &GuiProcess);
        if (!NT_SUCCESS(Status)) {
            LOG_ERROR("ShadowSSDT: PsLookupProcessByProcessId(PID=%u) failed: 0x%08X",
                      (ULONG)(ULONG_PTR)GuiPid, Status);
            return Status;
        }
        g_ShadowSsdtState.GuiProcess = GuiProcess;     /* Hold reference */
    }

    LOG_INFO("ShadowSSDT: KeServiceDescriptorTableShadow = 0x%llX",
             g_ShadowSsdtState.KeServiceDescriptorTableShadowVa);
    LOG_INFO("ShadowSSDT: W32pServiceTable = 0x%llX, ServiceCount = %u",
             g_ShadowSsdtState.W32pServiceTableVa,
             g_ShadowSsdtState.ServiceCount);
    LOG_INFO("ShadowSSDT: GUI process PID=%u acquired", (ULONG)(ULONG_PTR)GuiPid);

    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  3c. Win32k Module Discovery                                              */
/* ========================================================================= */

/*
 * ShadowSsdtGetWin32kModules - Enumerate loaded modules matching "win32k*".
 * Supports Win10+ split: win32kbase.sys, win32kfull.sys, win32k.sys.
 */
static NTSTATUS ShadowSsdtGetWin32kModules(VOID)
{
    NTSTATUS    Status;
    ULONG       Size = 0;
    RTL_PROCESS_MODULES_SHADOW *Modules = NULL;
    ULONG       i;
    ULONG       Count = 0;

    Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &Size);
    if (Size == 0) return STATUS_UNSUCCESSFUL;

    Modules = (RTL_PROCESS_MODULES_SHADOW *)ExAllocatePoolWithTag(NonPagedPool, Size, SHADOW_TAG);
    if (!Modules) return STATUS_INSUFFICIENT_RESOURCES;

    Status = ZwQuerySystemInformation(SystemModuleInformation, Modules, Size, &Size);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Modules, SHADOW_TAG);
        return Status;
    }

    for (i = 0; i < Modules->NumberOfModules && Count < MAX_WIN32K_MODULES; i++) {
        const char *FileName;
        ULONG k;

        FileName = (const char *)Modules->Modules[i].FullPathName +
                   Modules->Modules[i].OffsetToFileName;

        /* Check if filename starts with "win32k" (case insensitive) */
        if ((FileName[0] == 'w' || FileName[0] == 'W') &&
            (FileName[1] == 'i' || FileName[1] == 'I') &&
            (FileName[2] == 'n' || FileName[2] == 'N') &&
            FileName[3] == '3' && FileName[4] == '2' &&
            (FileName[5] == 'k' || FileName[5] == 'K'))
        {
            WIN32K_MODULE_INFO *M = &g_ShadowSsdtState.Win32kModules[Count];
            const char *FullPath = (const char *)Modules->Modules[i].FullPathName;
            ULONG PathLen = (ULONG)strlen(FullPath);

            M->Base = (ULONG64)Modules->Modules[i].ImageBase;
            M->Size = Modules->Modules[i].ImageSize;

            /* Copy short name */
            for (k = 0; k < 63 && FileName[k]; k++) {
                M->Name[k] = FileName[k];
            }
            M->Name[k] = '\0';

            /* Convert full path to WCHAR for potential file mapping */
            for (k = 0; k < PathLen && k < 259; k++) {
                M->Path[k] = (WCHAR)(UCHAR)FullPath[k];
            }
            M->Path[k] = L'\0';

            LOG_INFO("ShadowSSDT: Found win32k module: %s base=0x%llX size=0x%X",
                     M->Name, M->Base, M->Size);
            Count++;
        }
    }

    ExFreePoolWithTag(Modules, SHADOW_TAG);

    g_ShadowSsdtState.Win32kModuleCount = Count;

    if (Count == 0) {
        LOG_ERROR("ShadowSSDT: No win32k modules found");
        return STATUS_NOT_FOUND;
    }

    LOG_INFO("ShadowSSDT: Found %u win32k module(s)", Count);
    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  Helper: Check if VA falls within any win32k module                       */
/* ========================================================================= */

static BOOLEAN IsInWin32kRange(ULONG64 Va)
{
    ULONG i;
    for (i = 0; i < g_ShadowSsdtState.Win32kModuleCount; i++) {
        ULONG64 Base = g_ShadowSsdtState.Win32kModules[i].Base;
        ULONG   Size = g_ShadowSsdtState.Win32kModules[i].Size;
        if (Va >= Base && Va < Base + Size) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ========================================================================= */
/*  3d. Shadow SSDT Address Resolution (requires Session context)            */
/* ========================================================================= */

/*
 * ShadowSsdtResolveAllAddresses
 *
 * Must be called with KeStackAttachProcess to the GUI process, because
 * win32k VAs are per-Session and only valid in a GUI process context.
 */
static NTSTATUS ShadowSsdtResolveAllAddresses(VOID)
{
    KAPC_STATE  ApcState;
    PLONG       Table;
    ULONG       i;
    ULONG       ValidCount = 0;

    if (!g_ShadowSsdtState.GuiProcess || g_ShadowSsdtState.W32pServiceTableVa == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    KeStackAttachProcess(g_ShadowSsdtState.GuiProcess, &ApcState);

    __try {
        Table = (PLONG)g_ShadowSsdtState.W32pServiceTableVa;

        for (i = 0; i < g_ShadowSsdtState.ServiceCount; i++) {
            LONG    Entry = Table[i];
            ULONG64 FuncVa = g_ShadowSsdtState.W32pServiceTableVa + (LONG64)(Entry >> 4);

            if (IsInWin32kRange(FuncVa)) {
                g_ShadowSsdtState.ResolvedAddresses[i] = FuncVa;
                ValidCount++;
            } else {
                g_ShadowSsdtState.ResolvedAddresses[i] = FuncVa;
                /* Still store it; may be in a module we didn't detect */
                ValidCount++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KeUnstackDetachProcess(&ApcState);
        LOG_WARN("ShadowSSDT: Exception resolving Shadow SSDT addresses");
        return STATUS_ACCESS_VIOLATION;
    }

    KeUnstackDetachProcess(&ApcState);

    LOG_INFO("ShadowSSDT: Resolved %u / %u Shadow SSDT addresses", ValidCount,
             g_ShadowSsdtState.ServiceCount);
    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  3e. Name Resolution (walk win32k PE exports)                             */
/* ========================================================================= */

/*
 * ShadowSsdtPopulateNamesForModule
 *
 * Walk a single win32k module's PE export table (in live memory,
 * inside GUI process context) to match NtUser/NtGdi exports
 * to resolved Shadow SSDT addresses.
 */
static ULONG ShadowSsdtPopulateNamesForModule(
    ULONG64 ModuleBase,
    ULONG   ModuleSize
)
{
    PUCHAR                  Base = (PUCHAR)ModuleBase;
    PIMAGE_DOS_HEADER       Dos;
    PIMAGE_NT_HEADERS64     Nt;
    PIMAGE_EXPORT_DIRECTORY Export;
    PULONG                  Names;
    PULONG                  Functions;
    PUSHORT                 Ordinals;
    ULONG                   i, j;
    ULONG                   MatchCount = 0;

    UNREFERENCED_PARAMETER(ModuleSize);

    __try {
        Dos = (PIMAGE_DOS_HEADER)Base;
        if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        Nt = (PIMAGE_NT_HEADERS64)(Base + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        if (Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
            return 0;
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

            /* Only match NtUser* and NtGdi* exports */
            if (!((Name[0] == 'N' && Name[1] == 't' && Name[2] == 'U') ||
                  (Name[0] == 'N' && Name[1] == 't' && Name[2] == 'G'))) {
                continue;
            }

            FuncRva = (ULONG64)Functions[Ordinals[i]];
            FuncVa  = (ULONG64)Base + FuncRva;

            /* Search resolved addresses for a match */
            for (j = 0; j < g_ShadowSsdtState.ServiceCount; j++) {
                if (g_ShadowSsdtState.ResolvedAddresses[j] == FuncVa) {
                    /* Convert ANSI name to wide */
                    ULONG k;
                    for (k = 0; k < SSDT_MAX_NAME_LEN - 1 && Name[k]; k++) {
                        g_ShadowSsdtState.NameCache[j][k] = (WCHAR)Name[k];
                    }
                    g_ShadowSsdtState.NameCache[j][k] = L'\0';
                    MatchCount++;
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_WARN("ShadowSSDT: Exception walking module exports at 0x%llX", ModuleBase);
    }

    return MatchCount;
}

/*
 * ShadowSsdtPopulateNames
 *
 * Walk all win32k modules in GUI process context to resolve names.
 */
static NTSTATUS ShadowSsdtPopulateNames(VOID)
{
    KAPC_STATE  ApcState;
    ULONG       i;
    ULONG       TotalMatches = 0;

    if (g_ShadowSsdtState.NamesPopulated) return STATUS_SUCCESS;
    if (!g_ShadowSsdtState.GuiProcess) return STATUS_UNSUCCESSFUL;

    KeStackAttachProcess(g_ShadowSsdtState.GuiProcess, &ApcState);

    for (i = 0; i < g_ShadowSsdtState.Win32kModuleCount; i++) {
        ULONG Matches = ShadowSsdtPopulateNamesForModule(
            g_ShadowSsdtState.Win32kModules[i].Base,
            g_ShadowSsdtState.Win32kModules[i].Size
        );
        TotalMatches += Matches;
        LOG_INFO("ShadowSSDT: Module '%s' matched %u names",
                 g_ShadowSsdtState.Win32kModules[i].Name, Matches);
    }

    KeUnstackDetachProcess(&ApcState);

    g_ShadowSsdtState.NamesPopulated = TRUE;
    LOG_INFO("ShadowSSDT: Total name matches: %u / %u", TotalMatches,
             g_ShadowSsdtState.ServiceCount);
    return STATUS_SUCCESS;
}

/* ========================================================================= */
/*  Table Query API                                                          */
/* ========================================================================= */

NTSTATUS ShadowSsdtGetEntryInfo(ULONG Index, PSSDT_ENTRY_INFO Out)
{
    KAPC_STATE ApcState;

    if (!g_ShadowSsdtState.Initialized || Index >= g_ShadowSsdtState.ServiceCount) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Out, sizeof(SSDT_ENTRY_INFO));

    /* Read raw SSDT entry from Session context */
    KeStackAttachProcess(g_ShadowSsdtState.GuiProcess, &ApcState);

    __try {
        PLONG Table = (PLONG)g_ShadowSsdtState.W32pServiceTableVa;
        Out->RawOffset = Table[Index];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KeUnstackDetachProcess(&ApcState);
        return STATUS_ACCESS_VIOLATION;
    }

    KeUnstackDetachProcess(&ApcState);

    Out->SyscallIndex = Index;
    Out->ArgCount = (ULONG)(Out->RawOffset & 0xF);
    Out->FunctionVa = g_ShadowSsdtState.ResolvedAddresses[Index];

    if (g_ShadowSsdtState.NamesPopulated &&
        g_ShadowSsdtState.NameCache[Index][0] != L'\0') {
        RtlStringCchCopyW(Out->FunctionName, SSDT_MAX_NAME_LEN,
                          g_ShadowSsdtState.NameCache[Index]);
    }

    return STATUS_SUCCESS;
}

NTSTATUS ShadowSsdtDumpTable(ULONG Start, ULONG Count,
                              PSSDT_ENTRY_INFO Out, PULONG OutCount)
{
    ULONG End;
    ULONG i, n = 0;

    if (!g_ShadowSsdtState.Initialized) return STATUS_UNSUCCESSFUL;

    if (Start >= g_ShadowSsdtState.ServiceCount) {
        *OutCount = 0;
        return STATUS_SUCCESS;
    }

    if (Count == 0) Count = g_ShadowSsdtState.ServiceCount;

    End = Start + Count;
    if (End > g_ShadowSsdtState.ServiceCount) End = g_ShadowSsdtState.ServiceCount;

    for (i = Start; i < End; i++) {
        NTSTATUS Status = ShadowSsdtGetEntryInfo(i, &Out[n]);
        if (NT_SUCCESS(Status)) {
            n++;
        }
    }

    *OutCount = n;
    return STATUS_SUCCESS;
}

NTSTATUS ShadowSsdtFindIndexByName(const WCHAR *Name, PULONG OutIndex)
{
    ULONG i;

    if (!g_ShadowSsdtState.Initialized) return STATUS_UNSUCCESSFUL;

    /* Ensure names are populated */
    if (!g_ShadowSsdtState.NamesPopulated) {
        ShadowSsdtPopulateNames();
    }

    /* Search name cache */
    for (i = 0; i < g_ShadowSsdtState.ServiceCount; i++) {
        if (g_ShadowSsdtState.NameCache[i][0] != L'\0') {
            if (_wcsicmp(g_ShadowSsdtState.NameCache[i], Name) == 0) {
                *OutIndex = i;
                return STATUS_SUCCESS;
            }
        }
    }

    LOG_WARN("ShadowSSDT: Name '%ws' not found in Shadow SSDT", Name);
    return STATUS_NOT_FOUND;
}

/* ========================================================================= */
/*  Hook Mapping Helpers                                                     */
/* ========================================================================= */

static PSSDT_HOOK_MAPPING ShadowFindMappingByIndex(ULONG Index)
{
    PSSDT_HOOK_MAPPING M = g_ShadowSsdtState.HookListHead;
    while (M) {
        if (M->SyscallIndex == Index) return M;
        M = M->Next;
    }
    return NULL;
}

static PSSDT_HOOK_MAPPING ShadowFindMappingByHookId(ULONG HookId)
{
    PSSDT_HOOK_MAPPING M = g_ShadowSsdtState.HookListHead;
    while (M) {
        if (M->GenericHookId == HookId) return M;
        M = M->Next;
    }
    return NULL;
}

/* ========================================================================= */
/*  Hook Operations                                                          */
/* ========================================================================= */

NTSTATUS ShadowSsdtHookByIndex(ULONG Index, PHOOK_RULE Rule, PULONG OutHookId)
{
    KIRQL           OldIrql;
    ULONG64         FuncVa;
    ULONG           HookId = 0;
    NTSTATUS        Status;
    PSSDT_HOOK_MAPPING Mapping;
    const WCHAR    *Name;
    KAPC_STATE      ApcState;

    if (!g_ShadowSsdtState.Initialized) return STATUS_UNSUCCESSFUL;
    if (Index >= g_ShadowSsdtState.ServiceCount) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_ShadowSsdtState.HookLock, &OldIrql);

    /* Check for duplicate */
    if (ShadowFindMappingByIndex(Index)) {
        KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);
        LOG_WARN("ShadowSSDT: Shadow syscall %u already hooked", Index);
        return STATUS_ALREADY_REGISTERED;
    }

    KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);

    /* Resolve function address */
    FuncVa = g_ShadowSsdtState.ResolvedAddresses[Index];
    if (FuncVa == 0) {
        LOG_ERROR("ShadowSSDT: Cannot resolve address for Shadow syscall %u", Index);
        return STATUS_NOT_FOUND;
    }

    /* Get name for logging */
    Name = (g_ShadowSsdtState.NamesPopulated &&
            g_ShadowSsdtState.NameCache[Index][0] != L'\0')
           ? g_ShadowSsdtState.NameCache[Index] : NULL;

    /*
     * Attach to GUI process context to ensure win32k VAs are valid
     * for the EPT hook installation (which reads the target page).
     */
    KeStackAttachProcess(g_ShadowSsdtState.GuiProcess, &ApcState);

    Status = GenericHookInstall(FuncVa, 0 /* kernel */, Name, Rule, &HookId);

    KeUnstackDetachProcess(&ApcState);

    if (!NT_SUCCESS(Status)) {
        LOG_WARN("ShadowSSDT: GenericHookInstall failed for Shadow syscall %u: 0x%08X",
                 Index, Status);
        return Status;
    }

    /* Create mapping node */
    Mapping = (PSSDT_HOOK_MAPPING)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(SSDT_HOOK_MAPPING), SHADOW_TAG);
    if (!Mapping) {
        GenericHookRemove(HookId);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Mapping->SyscallIndex = Index;
    Mapping->GenericHookId = HookId;
    Mapping->IsMonitorHook = FALSE;

    KeAcquireSpinLock(&g_ShadowSsdtState.HookLock, &OldIrql);
    Mapping->Next = g_ShadowSsdtState.HookListHead;
    g_ShadowSsdtState.HookListHead = Mapping;
    g_ShadowSsdtState.HookCount++;
    KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);

    if (OutHookId) *OutHookId = HookId;

    LOG_INFO("ShadowSSDT: Hooked Shadow syscall %u (hookId=%u, VA=0x%llX)",
             Index, HookId, FuncVa);
    return STATUS_SUCCESS;
}

NTSTATUS ShadowSsdtHookByName(const WCHAR *Name, PHOOK_RULE Rule,
                               PULONG OutIndex, PULONG OutHookId)
{
    ULONG       Index = 0;
    NTSTATUS    Status;

    Status = ShadowSsdtFindIndexByName(Name, &Index);
    if (!NT_SUCCESS(Status)) return Status;

    Status = ShadowSsdtHookByIndex(Index, Rule, OutHookId);
    if (NT_SUCCESS(Status) && OutIndex) {
        *OutIndex = Index;
    }

    return Status;
}

/* ========================================================================= */
/*  Unhook Operations                                                        */
/* ========================================================================= */

NTSTATUS ShadowSsdtUnhookByIndex(ULONG Index)
{
    KIRQL               OldIrql;
    PSSDT_HOOK_MAPPING  M, Prev;

    KeAcquireSpinLock(&g_ShadowSsdtState.HookLock, &OldIrql);

    Prev = NULL;
    M = g_ShadowSsdtState.HookListHead;
    while (M) {
        if (M->SyscallIndex == Index) {
            ULONG HookId = M->GenericHookId;

            if (Prev) Prev->Next = M->Next;
            else g_ShadowSsdtState.HookListHead = M->Next;
            g_ShadowSsdtState.HookCount--;

            KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);

            GenericHookRemove(HookId);
            ExFreePoolWithTag(M, SHADOW_TAG);

            LOG_INFO("ShadowSSDT: Unhooked Shadow syscall %u (hookId=%u)", Index, HookId);
            return STATUS_SUCCESS;
        }
        Prev = M;
        M = M->Next;
    }

    KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);
    return STATUS_NOT_FOUND;
}

NTSTATUS ShadowSsdtUnhookByHookId(ULONG HookId)
{
    KIRQL               OldIrql;
    PSSDT_HOOK_MAPPING  M, Prev;

    KeAcquireSpinLock(&g_ShadowSsdtState.HookLock, &OldIrql);

    Prev = NULL;
    M = g_ShadowSsdtState.HookListHead;
    while (M) {
        if (M->GenericHookId == HookId) {
            ULONG Index = M->SyscallIndex;

            if (Prev) Prev->Next = M->Next;
            else g_ShadowSsdtState.HookListHead = M->Next;
            g_ShadowSsdtState.HookCount--;

            KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);

            GenericHookRemove(HookId);
            ExFreePoolWithTag(M, SHADOW_TAG);

            LOG_INFO("ShadowSSDT: Unhooked hookId=%u (Shadow syscall %u)", HookId, Index);
            return STATUS_SUCCESS;
        }
        Prev = M;
        M = M->Next;
    }

    KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);
    return STATUS_NOT_FOUND;
}

VOID ShadowSsdtUnhookAll(VOID)
{
    KIRQL               OldIrql;
    PSSDT_HOOK_MAPPING  M, Next;

    KeAcquireSpinLock(&g_ShadowSsdtState.HookLock, &OldIrql);

    M = g_ShadowSsdtState.HookListHead;
    g_ShadowSsdtState.HookListHead = NULL;
    g_ShadowSsdtState.HookCount = 0;

    KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);

    /* Remove all hooks outside spinlock */
    while (M) {
        Next = M->Next;
        GenericHookRemove(M->GenericHookId);
        ExFreePoolWithTag(M, SHADOW_TAG);
        M = Next;
    }

    LOG_INFO("ShadowSSDT: All Shadow SSDT hooks removed");
}

/* ========================================================================= */
/*  Monitor Mode                                                             */
/* ========================================================================= */

NTSTATUS ShadowSsdtSetMonitorMode(PVMX_SHADOW_SSDT_MONITOR_REQUEST Req)
{
    HOOK_RULE   MonitorRule = { 0 };
    ULONG       i;
    ULONG       HookId;
    ULONG       Installed = 0;

    if (!g_ShadowSsdtState.Initialized) return STATUS_UNSUCCESSFUL;

    /* Stop existing monitoring first */
    if (g_ShadowSsdtState.MonitorMode != SSDT_MONITOR_OFF) {
        ShadowSsdtStopMonitoring();
    }

    if (Req->Mode == SSDT_MONITOR_OFF) {
        g_ShadowSsdtState.MonitorMode = SSDT_MONITOR_OFF;
        LOG_INFO("ShadowSSDT: Monitoring stopped");
        return STATUS_SUCCESS;
    }

    /* Build LOG_ONLY rule */
    MonitorRule.Action = HOOK_ACTION_LOG_ONLY;
    MonitorRule.TargetPid = Req->TargetPid;
    MonitorRule.LogEnabled = TRUE;

    g_ShadowSsdtState.MonitorPid = Req->TargetPid;

    if (Req->Mode == SSDT_MONITOR_ALL) {
        LOG_INFO("ShadowSSDT: Starting ALL monitoring (PID=%u)...", Req->TargetPid);

        for (i = 0; i < g_ShadowSsdtState.ServiceCount; i++) {
            NTSTATUS Status = ShadowSsdtHookByIndex(i, &MonitorRule, &HookId);
            if (NT_SUCCESS(Status)) {
                KIRQL OldIrql;
                PSSDT_HOOK_MAPPING M;
                KeAcquireSpinLock(&g_ShadowSsdtState.HookLock, &OldIrql);
                M = ShadowFindMappingByHookId(HookId);
                if (M) M->IsMonitorHook = TRUE;
                KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);
                Installed++;
            }
        }

        g_ShadowSsdtState.MonitorMode = SSDT_MONITOR_ALL;
        LOG_INFO("ShadowSSDT: Monitor ALL installed %u / %u hooks",
                 Installed, g_ShadowSsdtState.ServiceCount);

    } else if (Req->Mode == SSDT_MONITOR_FILTERED) {
        ULONG Count = Req->FilterCount;
        if (Count > SHADOW_SSDT_MONITOR_MAX_FILTER) Count = SHADOW_SSDT_MONITOR_MAX_FILTER;

        LOG_INFO("ShadowSSDT: Starting FILTERED monitoring (%u indices, PID=%u)...",
                 Count, Req->TargetPid);

        for (i = 0; i < Count; i++) {
            ULONG Idx = Req->FilterIndices[i];
            NTSTATUS Status = ShadowSsdtHookByIndex(Idx, &MonitorRule, &HookId);
            if (NT_SUCCESS(Status)) {
                KIRQL OldIrql;
                PSSDT_HOOK_MAPPING M;
                KeAcquireSpinLock(&g_ShadowSsdtState.HookLock, &OldIrql);
                M = ShadowFindMappingByHookId(HookId);
                if (M) M->IsMonitorHook = TRUE;
                KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);
                Installed++;
            }
        }

        g_ShadowSsdtState.MonitorMode = SSDT_MONITOR_FILTERED;
        LOG_INFO("ShadowSSDT: Monitor FILTERED installed %u / %u hooks", Installed, Count);

    } else {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

VOID ShadowSsdtStopMonitoring(VOID)
{
    KIRQL               OldIrql;
    PSSDT_HOOK_MAPPING  M, Prev, Next;
    PSSDT_HOOK_MAPPING  RemoveList = NULL;

    if (g_ShadowSsdtState.MonitorMode == SSDT_MONITOR_OFF) return;

    /* Extract monitor hooks from list */
    KeAcquireSpinLock(&g_ShadowSsdtState.HookLock, &OldIrql);

    Prev = NULL;
    M = g_ShadowSsdtState.HookListHead;
    while (M) {
        Next = M->Next;
        if (M->IsMonitorHook) {
            if (Prev) Prev->Next = Next;
            else g_ShadowSsdtState.HookListHead = Next;
            g_ShadowSsdtState.HookCount--;

            M->Next = RemoveList;
            RemoveList = M;
        } else {
            Prev = M;
        }
        M = Next;
    }

    KeReleaseSpinLock(&g_ShadowSsdtState.HookLock, OldIrql);

    /* Remove hooks outside spinlock */
    M = RemoveList;
    while (M) {
        Next = M->Next;
        GenericHookRemove(M->GenericHookId);
        ExFreePoolWithTag(M, SHADOW_TAG);
        M = Next;
    }

    g_ShadowSsdtState.MonitorMode = SSDT_MONITOR_OFF;
    LOG_INFO("ShadowSSDT: Monitoring stopped, all monitor hooks removed");
}

/* ========================================================================= */
/*  Lifecycle                                                                */
/* ========================================================================= */

NTSTATUS ShadowSsdtInitialize(VOID)
{
    NTSTATUS Status;

    if (g_ShadowSsdtState.Initialized) {
        LOG_WARN("ShadowSSDT: Already initialized");
        return STATUS_ALREADY_REGISTERED;
    }

    /* SSDT module must be initialized first (we need KeServiceDescriptorTable) */
    if (!g_SsdtState.Initialized) {
        LOG_ERROR("ShadowSSDT: Regular SSDT must be initialized first (--ssdt-init)");
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(&g_ShadowSsdtState, sizeof(SHADOW_SSDT_STATE));
    KeInitializeSpinLock(&g_ShadowSsdtState.HookLock);

    /* Step 1: Discover KTHREAD.ServiceTable offset */
    Status = KthreadResolveServiceTableOffset();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("ShadowSSDT: KTHREAD offset discovery failed: 0x%08X", Status);
        return Status;
    }

    /* Step 2: Find KeServiceDescriptorTableShadow */
    Status = ShadowSsdtDiscover();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("ShadowSSDT: Shadow SSDT discovery failed: 0x%08X", Status);
        return Status;
    }

    /* Step 3: Enumerate win32k modules */
    Status = ShadowSsdtGetWin32kModules();
    if (!NT_SUCCESS(Status)) {
        LOG_WARN("ShadowSSDT: Win32k module enumeration failed: 0x%08X (continuing)", Status);
        /* Non-fatal: we can still resolve addresses, just not names */
    }

    /* Step 4: Resolve all Shadow SSDT addresses */
    Status = ShadowSsdtResolveAllAddresses();
    if (!NT_SUCCESS(Status)) {
        LOG_ERROR("ShadowSSDT: Address resolution failed: 0x%08X", Status);
        if (g_ShadowSsdtState.GuiProcess) {
            ObDereferenceObject(g_ShadowSsdtState.GuiProcess);
            g_ShadowSsdtState.GuiProcess = NULL;
        }
        return Status;
    }

    /* Step 5: Populate names (best-effort) */
    Status = ShadowSsdtPopulateNames();
    if (!NT_SUCCESS(Status)) {
        LOG_WARN("ShadowSSDT: Name population failed: 0x%08X (non-fatal)", Status);
    }

    g_ShadowSsdtState.Initialized = TRUE;

    LOG_INFO("ShadowSSDT: Initialized successfully! %u services, %u win32k modules",
             g_ShadowSsdtState.ServiceCount,
             g_ShadowSsdtState.Win32kModuleCount);

    return STATUS_SUCCESS;
}

VOID ShadowSsdtCleanup(VOID)
{
    if (!g_ShadowSsdtState.Initialized) return;

    LOG_INFO("ShadowSSDT: Cleaning up...");

    /* Stop monitoring first */
    ShadowSsdtStopMonitoring();

    /* Remove all hooks */
    ShadowSsdtUnhookAll();

    /* Release GUI process reference */
    if (g_ShadowSsdtState.GuiProcess) {
        ObDereferenceObject(g_ShadowSsdtState.GuiProcess);
        g_ShadowSsdtState.GuiProcess = NULL;
    }

    g_ShadowSsdtState.Initialized = FALSE;

    LOG_INFO("ShadowSSDT: Cleanup complete");
}
