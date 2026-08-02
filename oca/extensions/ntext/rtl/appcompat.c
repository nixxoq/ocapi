/*++

Copyright (c) 2026 Shorthorn Project

Module Name:

    appcompat.c

Abstract:

    Implement Aplication compatibility for One-Core-API functions

Author:

    Skulltrail 29-January-2026

Revision History:

    NixxO 02-August-2026 - Add DisableOsSpoofing feature

--*/

#include "main.h"
#include <ntstrsafe.h>

#define MAX_PATH 260

#define NEW_STYLE_BIT_MASK 0x8000000000000000

#define OLD_CONDITION(_m_, _t_) (ULONG)((_m_ & (0xff << (1 << _t_))) >> (1 << _t_))

#define OLD_STYLE_CONDITION_MASK(_m_) (((_m_) & NEW_STYLE_BIT_MASK) == 0)

#define RTL_GET_CONDITION(_m_, _t_)                                                                                    \
    (OLD_STYLE_CONDITION_MASK(_m_) ? (OLD_CONDITION(_m_, _t_)) : RtlpVerGetConditionMask((_m_), (_t_)))

#define LEXICAL_COMPARISON 1
#define MAX_STRING_LENGTH 20

static WCHAR SECTION_COMMON_NAME[] = L"\\BaseNamedObjects\\SharedAppCompat";
static WCHAR SECTION_MSI_NAME[] = L"\\BaseNamedObjects\\SharedAppCompatMsi";
static WCHAR SECTION_EXE_TO_MSI_NAME[] = L"\\BaseNamedObjects\\SharedAppCompatExeMsi";
static WCHAR SECTION_MSI_TYPE_NAME[] = L"\\BaseNamedObjects\\SharedAppCompatMsiType";

typedef enum _MSI_INSTALLATION_TYPE
{
    MsiServerCalledFromMsi,
    MsiServerCalledFromExe,
    MsiServerCalledFromMsiFromExe
} MSI_INSTALLATION_TYPE;

typedef struct _OCA_COMPATIBILITY_INFO
{
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;
    UCHAR CSDVersion;
    ULONG OSPlatformId;
    WCHAR emuPath[MAX_PATH];
    ULONG MsiInstallationType;
} OCA_COMPATIBILITY_INFO, *POCA_COMPATIBILITY_INFO;

void
SanitizeFilenameForRegistry(const WCHAR *src, WCHAR *dst, size_t dstSize)
{
    size_t i;
    for (i = 0; src[i] != 0 && i < dstSize - 1; i++)
    {
        if (src[i] == L'\\')
            dst[i] = L'/'; // replace backslash with forward slash
        else
            dst[i] = src[i];
    }
    dst[i] = 0;
}

ULONG
GetNextPointValue(IN OUT WCHAR **p, IN OUT ULONG *len)
{
    ULONG Number;

    Number = 0;

    while (*len && (UNICODE_NULL != **p) && **p != L'.')
    {
        if (L' ' != **p)
        {
            Number = (Number * 10) + ((ULONG) * *p - L'0');
        }

        (*p)++;
        (*len)--;
    }

    if ((*len) && (L'.' == **p))
    {
        (*p)++;
        (*len)--;
    }

    return Number;
}

BOOLEAN
GetMsiPathFromCommandLine(LPCWSTR CmdLine, LPWSTR OutPath, ULONG OutSize)
{
    const WCHAR *p = CmdLine;
    const WCHAR *start, *end;
    ULONG len;

    if (!CmdLine || !OutPath || OutSize == 0)
        return FALSE;

    OutPath[0] = 0;

    /* Search for the /i or /package parameter */
    while (*p)
    {
        /* Skip spaces */
        while (*p == L' ')
            p++;

        /* Check for /i */
        if ((p[0] == L'/' || p[0] == L'-') && (p[1] == L'i' || p[1] == L'I'))
        {
            p += 2;

            /* Skip ':' if present */
            if (*p == L':')
                p++;

            /* Skip spaces */
            while (*p == L' ')
                p++;

            goto extract;
        }

        /* Check for /package */
        if ((p[0] == L'/' || p[0] == L'-') && (_wcsnicmp(&p[1], L"package", 7) == 0))
        {
            p += 8;

            if (*p == L':')
                p++;
            while (*p == L' ')
                p++;

            goto extract;
        }

        p++;
    }

    return FALSE;

extract:

    /* Case: quoted path */
    if (*p == L'"')
    {
        p++;
        start = p;

        while (*p && *p != L'"')
            p++;

        end = p;

        len = (ULONG)(end - start);

        if (len >= OutSize)
            return FALSE;

        wcsncpy(OutPath, start, len);
        OutPath[len] = 0;

        return TRUE;
    }

    /* Case: unquoted path */
    start = p;
    while (*p && *p != L' ')
        p++;

    end = p;

    len = (ULONG)(end - start);

    if (len >= OutSize)
        return FALSE;

    wcsncpy(OutPath, start, len);
    OutPath[len] = 0;

    return TRUE;
}

static PSECURITY_DESCRIPTOR g_Sd = NULL;

static BOOLEAN
GetWorldSecurityDescriptor(PSECURITY_DESCRIPTOR *OutSd)
{
    if (g_Sd)
    {
        *OutSd = g_Sd;
        return TRUE;
    }

    g_Sd = (PSECURITY_DESCRIPTOR)RtlAllocateHeap(RtlProcessHeap(), 0, SECURITY_DESCRIPTOR_MIN_LENGTH);

    if (!g_Sd)
        return FALSE;

    if (!NT_SUCCESS(RtlCreateSecurityDescriptor(g_Sd, SECURITY_DESCRIPTOR_REVISION)))
        return FALSE;

    /* NULL DACL = full access */
    if (!NT_SUCCESS(RtlSetDaclSecurityDescriptor(g_Sd, TRUE, NULL, FALSE)))
        return FALSE;

    *OutSd = g_Sd;
    return TRUE;
}

BOOLEAN
StoreInSharedSection(POCA_COMPATIBILITY_INFO OcaCompatInfo, const PWCHAR StorageType)
{
    UNICODE_STRING sectionName;
    PVOID baseAddress;
    SIZE_T viewSize;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize;
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;

    GetWorldSecurityDescriptor(&sd);

    RtlInitUnicodeString(&sectionName, StorageType);
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, sd);

    maxSize.QuadPart = sizeof(OCA_COMPATIBILITY_INFO);

    status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttr, &maxSize, PAGE_READWRITE, SEC_COMMIT, NULL);

    if (status == STATUS_OBJECT_NAME_COLLISION)
    {
        status = NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, &objAttr);
    }

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[StoreInSharedSection] NtCreateSection failed: 0x%08X\n", status);
        return FALSE;
    }

    baseAddress = NULL;
    viewSize = (SIZE_T)maxSize.QuadPart;

    status = NtMapViewOfSection(
        hSection,
        (HANDLE)-1, // Current process
        &baseAddress, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READWRITE);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[StoreInSharedSection] NtMapViewOfSection failed: 0x%08X\n", status);
        NtUnmapViewOfSection((HANDLE)-1, baseAddress);
        NtClose(hSection);
        return FALSE;
    }

    memcpy(baseAddress, OcaCompatInfo, sizeof(OCA_COMPATIBILITY_INFO));

    return TRUE;
}

BOOLEAN
LoadFromSharedSection(POCA_COMPATIBILITY_INFO OcaCompatInfo, const PWCHAR StorageType)
{
    UNICODE_STRING sectionName;
    PVOID baseAddress;
    SIZE_T viewSize;
    HANDLE hSection = NULL;
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    PSECURITY_DESCRIPTOR sd = NULL;

    GetWorldSecurityDescriptor(&sd);

    RtlInitUnicodeString(&sectionName, StorageType);
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, sd);

    status = NtOpenSection(&hSection, SECTION_MAP_READ, &objAttr);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[LoadFromSharedSection] Error NtOpenSection: 0x%08X\n", status);
        return FALSE;
    }

    baseAddress = NULL;
    viewSize = 0;

    status = NtMapViewOfSection(hSection, (HANDLE)-1, &baseAddress, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[LoadFromSharedSection] Error NtMapViewOfSection: 0x%08X\n", status);
        NtClose(hSection);
        return FALSE;
    }

    memcpy(OcaCompatInfo, baseAddress, sizeof(OCA_COMPATIBILITY_INFO));

    NtUnmapViewOfSection((HANDLE)-1, baseAddress);

    NtClose(hSection);

    return TRUE;
}

BOOLEAN
StoreMsiInstallationTypeInSharedSection(ULONG MsiInstallationType, const PWCHAR StorageType)
{
    UNICODE_STRING sectionName;
    PVOID baseAddress;
    SIZE_T viewSize;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize;
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    ULONG msiType = MsiInstallationType;

    GetWorldSecurityDescriptor(&sd);

    RtlInitUnicodeString(&sectionName, StorageType);
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, sd);

    maxSize.QuadPart = sizeof(ULONG);

    status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttr, &maxSize, PAGE_READWRITE, SEC_COMMIT, NULL);

    if (status == STATUS_OBJECT_NAME_COLLISION)
    {
        status = NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, &objAttr);
    }

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[StoreInSharedSection] NtCreateSection failed: 0x%08X\n", status);
        return FALSE;
    }

    baseAddress = NULL;
    viewSize = (SIZE_T)maxSize.QuadPart;

    status = NtMapViewOfSection(
        hSection,
        (HANDLE)-1, // Current process
        &baseAddress, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READWRITE);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[StoreInSharedSection] NtMapViewOfSection failed: 0x%08X\n", status);
        NtUnmapViewOfSection((HANDLE)-1, baseAddress);
        NtClose(hSection);
        return FALSE;
    }

    memcpy(baseAddress, &msiType, sizeof(ULONG));

    return TRUE;
}

BOOLEAN
LoadMsiInstallationTypeFromSharedSection(PULONG MsiInstallationType, const PWCHAR StorageType)
{
    UNICODE_STRING sectionName;
    PVOID baseAddress;
    SIZE_T viewSize;
    HANDLE hSection = NULL;
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    PSECURITY_DESCRIPTOR sd = NULL;

    GetWorldSecurityDescriptor(&sd);

    RtlInitUnicodeString(&sectionName, StorageType);
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, sd);

    status = NtOpenSection(&hSection, SECTION_MAP_READ, &objAttr);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[LoadFromSharedSection] Error NtOpenSection: 0x%08X\n", status);
        return FALSE;
    }

    baseAddress = NULL;
    viewSize = 0;

    status = NtMapViewOfSection(hSection, (HANDLE)-1, &baseAddress, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[LoadFromSharedSection] Error NtMapViewOfSection: 0x%08X\n", status);
        NtClose(hSection);
        return FALSE;
    }

    memcpy(MsiInstallationType, baseAddress, sizeof(ULONG));

    NtUnmapViewOfSection((HANDLE)-1, baseAddress);

    NtClose(hSection);

    return TRUE;
}

BOOLEAN
GetProcessFullPathByPid(HANDLE ProcessId, PWSTR Buffer, ULONG BufferCch)
{
    NTSTATUS status;
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    ULONG len;
    PUNICODE_STRING img;

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    cid.UniqueProcess = ProcessId;
    cid.UniqueThread = NULL;

    status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, &oa, &cid);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[OCA][PATH] NtOpenProcess failed: 0x%08X\n", status);
        return FALSE;
    }

    /* Primeiro consulta tamanho */
    status = NtQueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &len);

    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        NtClose(hProcess);
        return FALSE;
    }

    img = (PUNICODE_STRING)RtlAllocateHeap(RtlProcessHeap(), 0, len);
    if (!img)
    {
        NtClose(hProcess);
        return FALSE;
    }

    status = NtQueryInformationProcess(hProcess, ProcessImageFileName, img, len, &len);

    if (!NT_SUCCESS(status))
    {
        RtlFreeHeap(RtlProcessHeap(), 0, img);
        NtClose(hProcess);
        return FALSE;
    }

    if ((img->Length / sizeof(WCHAR)) >= BufferCch)
    {
        RtlFreeHeap(RtlProcessHeap(), 0, img);
        NtClose(hProcess);
        return FALSE;
    }

    RtlCopyMemory(Buffer, img->Buffer, img->Length);
    Buffer[img->Length / sizeof(WCHAR)] = L'\0';

    // DbgPrint("[OCA][PATH] Parent ImagePath (NT): %ws\n", Buffer);

    RtlFreeHeap(RtlProcessHeap(), 0, img);
    NtClose(hProcess);

    return TRUE;
}

BOOLEAN
ReadDisableOsSpoofing(PWSTR FilePath)
{
    WCHAR SanitizedPath[MAX_PATH];
    WCHAR SubKeyPath[MAX_PATH];
    WCHAR buffer[256];

    UNICODE_STRING KeyName;
    UNICODE_STRING ValueName;
    OBJECT_ATTRIBUTES Obj;
    HANDLE Handle;

    NTSTATUS status;
    PKEY_VALUE_PARTIAL_INFORMATION KeyInfo;
    ULONG informationLength;

    if (!FilePath)
        return FALSE;

    RtlZeroMemory(buffer, sizeof(buffer));
    KeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    SanitizeFilenameForRegistry(FilePath, SanitizedPath, MAX_PATH);

    swprintf(SubKeyPath, L"SOFTWARE\\OCA\\Settings\\%s", SanitizedPath);

    RtlInitUnicodeString(&ValueName, L"DisableOsSpoofing");
    RtlInitUnicodeString(&KeyName, SubKeyPath);

    InitializeObjectAttributes(&Obj, &KeyName, OBJ_CASE_INSENSITIVE, HKEY_CURRENT_USER, NULL);

    status = NtOpenKey(&Handle, KEY_READ, &Obj);
    if (!NT_SUCCESS(status))
        return FALSE;

    status =
        NtQueryValueKey(Handle, &ValueName, KeyValuePartialInformation, KeyInfo, sizeof(buffer), &informationLength);
    NtClose(Handle);

    if (NT_SUCCESS(status) && KeyInfo->Type == REG_DWORD)
    {
        return *((PDWORD)KeyInfo->Data) != 0;
    }
    return FALSE;
}

BOOLEAN
ReadEmulatedVersion(PUNICODE_STRING EmulatedVersion, PWSTR FilePath)
{
    WCHAR SanitizedPath[MAX_PATH];
    WCHAR SubKeyPath[MAX_PATH];
    WCHAR buffer[256];

    UNICODE_STRING KeyName;
    UNICODE_STRING ValueName;
    OBJECT_ATTRIBUTES Obj;
    HANDLE Handle;

    NTSTATUS status;
    PKEY_VALUE_PARTIAL_INFORMATION KeyInfo;
    ULONG informationLength;

    PWSTR heapBuf;
    SIZE_T lenChars, lenBytes;

    RtlZeroMemory(EmulatedVersion, sizeof(*EmulatedVersion));
    RtlZeroMemory(buffer, sizeof(buffer));

    KeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    /* Monta o caminho RELATIVO ao HKCU */
    if (FilePath)
    {
        SanitizeFilenameForRegistry(FilePath, SanitizedPath, MAX_PATH);

        swprintf(SubKeyPath, L"SOFTWARE\\OCA\\Settings\\%s", SanitizedPath);

        RtlInitUnicodeString(&ValueName, L"CompatWindowsVersion");
    }
    else
    {
        RtlInitUnicodeString(&KeyName, L"SOFTWARE\\OCA\\Settings");

        RtlInitUnicodeString(&ValueName, L"GlobalVersion");
    }

    if (FilePath)
        RtlInitUnicodeString(&KeyName, SubKeyPath);

    InitializeObjectAttributes(
        &Obj, &KeyName, OBJ_CASE_INSENSITIVE, HKEY_CURRENT_USER, /* <<< AQUI está a correção */
        NULL);

    status = NtOpenKey(&Handle, KEY_READ, &Obj);
    if (!NT_SUCCESS(status))
        return FALSE;

    status =
        NtQueryValueKey(Handle, &ValueName, KeyValuePartialInformation, KeyInfo, sizeof(buffer), &informationLength);

    if (NT_SUCCESS(status) && (KeyInfo->Type == REG_SZ || KeyInfo->Type == REG_MULTI_SZ))
    {
        PWSTR regStr = (PWSTR)KeyInfo->Data;

        lenChars = wcslen(regStr) + 1;
        lenBytes = lenChars * sizeof(WCHAR);

        heapBuf = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), 0, lenBytes);

        if (!heapBuf)
        {
            NtClose(Handle);
            return FALSE;
        }

        RtlCopyMemory(heapBuf, regStr, lenBytes);

        EmulatedVersion->Buffer = heapBuf;
        EmulatedVersion->Length = (USHORT)((lenChars - 1) * sizeof(WCHAR));
        EmulatedVersion->MaximumLength = (USHORT)lenBytes;

        NtClose(Handle);
        return TRUE;
    }

    NtClose(Handle);
    return FALSE;
}

BOOLEAN
CheckIsUnsafeExe(LPWSTR ExePath)
{
    if (wcsstr(ExePath, L"svchost") != NULL || wcsstr(ExePath, L"explorer") != NULL ||
        wcsstr(ExePath, L"smss") != NULL || wcsstr(ExePath, L"csrsrv") != NULL ||
        wcsstr(ExePath, L"winlogon") != NULL || wcsstr(ExePath, L"wininit") != NULL ||
        wcsstr(ExePath, L"searchindexer") != NULL || wcsstr(ExePath, L"wmiprvse") != NULL ||
        wcsstr(ExePath, L"lsass") != NULL || wcsstr(ExePath, L"WindowsSearch") != NULL ||
        wcsstr(ExePath, L"userinit") != NULL)
    {
        return TRUE;
    }
    return FALSE;
}

BOOLEAN
CheckIsMsiOrServicesExec(LPWSTR path, BOOLEAN isMsi)
{
    LPCWSTR name = wcsrchr(path, L'\\');
    if (!name)
        name = path;
    else
        name++;

    return isMsi ? (_wcsicmp(name, L"msiexec.exe") == 0) : (_wcsicmp(name, L"services.exe") == 0);
}

void
ParseEmulationVersionAndApplyOnPeb(UNICODE_STRING EmulatedVersion, PPEB Peb)
{
    PWCHAR p;
    ULONG maj;
    ULONG min;
    ULONG bld;
    ULONG len;

    p = EmulatedVersion.Buffer;
    len = EmulatedVersion.Length / sizeof(WCHAR);

    maj = GetNextPointValue(&p, &len);
    min = GetNextPointValue(&p, &len);
    bld = GetNextPointValue(&p, &len);

    DbgPrint("[EMU] Parsed version: Major=%lu Minor=%lu Build=%lu\n", maj, min, bld);

    Peb->OSMajorVersion = maj;
    Peb->OSMinorVersion = min;
    Peb->OSBuildNumber = (USHORT)bld;
    Peb->OSCSDVersion = (USHORT)(GetNextPointValue(&p, &len)) << 8;
    Peb->OSCSDVersion |= (USHORT)GetNextPointValue(&p, &len);
    Peb->OSPlatformId = GetNextPointValue(&p, &len);
}

void
CreateCompatVersionAndStore(PPEB Peb, PWCHAR emuPath, const PWCHAR storageType)
{
    OCA_COMPATIBILITY_INFO OcaCompatInfo = {0};

    OcaCompatInfo.MajorVersion = Peb->OSMajorVersion;
    OcaCompatInfo.MinorVersion = Peb->OSMinorVersion;
    OcaCompatInfo.BuildNumber = Peb->OSBuildNumber;

    wcscpy(OcaCompatInfo.emuPath, emuPath);

    StoreInSharedSection(&OcaCompatInfo, storageType);
}

VOID
SaveMsiInstallationType(MSI_INSTALLATION_TYPE MsiInstallationType)
{
    OCA_COMPATIBILITY_INFO MsiInstallTypeInfo = {0};

    MsiInstallTypeInfo.MsiInstallationType = MsiInstallationType;
    StoreInSharedSection(&MsiInstallTypeInfo, SECTION_MSI_TYPE_NAME);
}

ULONG_PTR
GetParentProcessId(void)
{
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen;
    NTSTATUS status;

    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

    if (!NT_SUCCESS(status))
        return (ULONG_PTR)-1;

    if (retLen < sizeof(pbi))
        return (ULONG_PTR)-1;

    return pbi.InheritedFromUniqueProcessId;
}

BOOLEAN
GetParentProcessPeb(PHANDLE ParentProcessHandle, PVOID ParentPeb, BOOLEAN *IsWow64Parent)
{
    ULONG_PTR parentPid;
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    HANDLE hParent;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen;
    PVOID peb32Addr;

    if (!ParentProcessHandle || !ParentPeb)
        return FALSE;

    *ParentProcessHandle = NULL;
    if (IsWow64Parent)
        *IsWow64Parent = FALSE;

    parentPid = GetParentProcessId();
    if (!parentPid)
        return FALSE;

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)parentPid;
    cid.UniqueThread = NULL;

    status = NtOpenProcess(&hParent, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &oa, &cid);
    if (!NT_SUCCESS(status))
        return FALSE;

    /* 1) Tentar descobrir se é WOW64 */
    peb32Addr = NULL;
    status = NtQueryInformationProcess(hParent, ProcessWow64Information, &peb32Addr, sizeof(peb32Addr), &retLen);

    if (NT_SUCCESS(status) && peb32Addr)
    {
        /* Processo pai é WOW64 → ler PEB32 */
        if (IsWow64Parent)
            *IsWow64Parent = TRUE;

        status = NtReadVirtualMemory(hParent, peb32Addr, ParentPeb, sizeof(PEB32), NULL);

        if (!NT_SUCCESS(status))
        {
            NtClose(hParent);
            return FALSE;
        }
    }
    else
    {
        /* Processo pai é nativo */
        status = NtQueryInformationProcess(hParent, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

        if (!NT_SUCCESS(status))
        {
            NtClose(hParent);
            return FALSE;
        }

        status = NtReadVirtualMemory(hParent, pbi.PebBaseAddress, ParentPeb, sizeof(PEB), NULL);

        if (!NT_SUCCESS(status))
        {
            NtClose(hParent);
            return FALSE;
        }
    }

    *ParentProcessHandle = hParent;
    return TRUE;
}

NTSTATUS
RtlGetVersionInternal(OUT PRTL_OSVERSIONINFOW lpVersionInformation)
{
    PPEB Peb;
    NT_PRODUCT_TYPE NtProductType;

    Peb = NtCurrentPeb();
    lpVersionInformation->dwMajorVersion = Peb->OSMajorVersion;
    lpVersionInformation->dwMinorVersion = Peb->OSMinorVersion;
    lpVersionInformation->dwBuildNumber = Peb->OSBuildNumber;
    lpVersionInformation->dwPlatformId = Peb->OSPlatformId;
    if (Peb->CSDVersion.Buffer)
    {
        wcscpy(lpVersionInformation->szCSDVersion, Peb->CSDVersion.Buffer);
    }
    else
    {
        lpVersionInformation->szCSDVersion[0] = 0;
    }

    if (lpVersionInformation->dwOSVersionInfoSize == sizeof(OSVERSIONINFOEXW))
    {
        ((POSVERSIONINFOEXW)lpVersionInformation)->wServicePackMajor = (Peb->OSCSDVersion >> 8) & 0xFF;
        ((POSVERSIONINFOEXW)lpVersionInformation)->wServicePackMinor = Peb->OSCSDVersion & 0xFF;
        ((POSVERSIONINFOEXW)lpVersionInformation)->wSuiteMask = (USHORT)(SharedUserData->SuiteMask & 0xffff);
        ((POSVERSIONINFOEXW)lpVersionInformation)->wProductType = 0;
        if (RtlGetNtProductType(&NtProductType))
        {
            ((POSVERSIONINFOEXW)lpVersionInformation)->wProductType = (UCHAR)NtProductType;
            if (NtProductType == VER_NT_WORKSTATION)
            {
                //
                // For workstation product never return VER_SUITE_TERMINAL
                //
                ((POSVERSIONINFOEXW)lpVersionInformation)->wSuiteMask =
                    ((POSVERSIONINFOEXW)lpVersionInformation)->wSuiteMask & 0xffef;
            }
        }
    }

    return STATUS_SUCCESS;
}

VOID
SetPebVersionValuesByOcaCompatibilitySettings(PPEB Peb, OCA_COMPATIBILITY_INFO OcaCompatInfo)
{
    Peb->OSMajorVersion = OcaCompatInfo.MajorVersion;
    Peb->OSMinorVersion = OcaCompatInfo.MinorVersion;
    Peb->OSBuildNumber = (USHORT)OcaCompatInfo.BuildNumber;
    Peb->OSCSDVersion = (USHORT)OcaCompatInfo.CSDVersion;
    Peb->OSPlatformId = OcaCompatInfo.OSPlatformId;
}

UNICODE_STRING msiDll = RTL_CONSTANT_STRING(L"msi.dll");

typedef struct _OCA_MSI_INFO
{
    ULONG timestamp;
    ULONG majorVersion;
    ULONG minorVersion;
    ULONG buildNumber;
    ULONG servicePack;
} OCA_MSI_INFO, *POCA_MSI_INFO;

#ifdef _WIN64
// 64-bit MSI
OCA_MSI_INFO msiInfo[] = {
    {0} // has to be at end
};
#else
// 32-bit MSI
OCA_MSI_INFO msiInfo[] = {
    {0x5CE31D9B, 0x20709C, 0x20BC00, 0x2073BC, 0x20BC04},
    {0} // has to be at end
};
#endif

NTSTATUS
MsiChangeCachedVersion(ULONG MajorVersion, ULONG MinorVersion, ULONG BuildNumber, ULONG ServicePack)
{
    /* global variables from msi.dll */
    int *g_iMajorVersion = NULL;
    int *g_iMinorVersion = NULL;
    int *g_iWindowsBuild = NULL;
    int *g_iServicePackLevel = NULL;

    ULONG_PTR MsiModuleBase = 0;
    NTSTATUS Status;
    ULONG Timestamp;
    POCA_MSI_INFO MsiInfo;
    int i = 0;

    DbgPrint("[MsiChangeCachedVersion] Entered\n");
    DbgPrint(
        "[MsiChangeCachedVersion] Requested version: %lu.%lu build %lu SP %lu\n", MajorVersion, MinorVersion,
        BuildNumber, ServicePack);

    /* Check if msi.dll is loaded */
    Status = LdrGetDllHandleEx(LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT, NULL, NULL, &msiDll, &(PVOID)MsiModuleBase);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[MsiChangeCachedVersion] LdrGetDllHandle failed: 0x%08X\n", Status);
        return Status;
    }

    if (MsiModuleBase == 0)
    {
        DbgPrint("[MsiChangeCachedVersion] msi.dll handle is NULL\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrint("[MsiChangeCachedVersion] msi.dll base address: %p\n", MsiModuleBase);

    __try
    {
        Timestamp = *(ULONG *)(MsiModuleBase + *(ULONG *)(MsiModuleBase + 0x3C) // lfa_new to PE header
                               + 8);                                            // timestamp offset
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[MsiChangeCachedVersion] Exception while resolving MSI timestamp\n");
        return STATUS_ACCESS_VIOLATION;
    }

    DbgPrint("[MsiChangeCachedVersion] Timestamp queried: %lu\n", Timestamp);

    while (1)
    {
        MsiInfo = &msiInfo[i];
        if (!MsiInfo->timestamp)
        {
            DbgPrint("[MsiChangeCachedVersion] Unsupported MSI build signature %lu\n", Timestamp);
            return STATUS_NOT_IMPLEMENTED;
        }
        else if (MsiInfo->timestamp == Timestamp)
        {
            DbgPrint("[MsiChangeCachedVersion] Detected timestamp index %lu as valid\n", Timestamp);

            g_iMajorVersion = (int *)(MsiModuleBase + MsiInfo->majorVersion);
            g_iMinorVersion = (int *)(MsiModuleBase + MsiInfo->minorVersion);
            g_iWindowsBuild = (int *)(MsiModuleBase + MsiInfo->buildNumber);
            g_iServicePackLevel = (int *)(MsiModuleBase + MsiInfo->servicePack);

            DbgPrint("[MsiChangeCachedVersion] Version pointers resolved:\n");
            DbgPrint("  MajorVersion     @ %p = %i\n", g_iMajorVersion, *g_iMajorVersion);
            DbgPrint("  MinorVersion     @ %p = %i\n", g_iMinorVersion, *g_iMinorVersion);
            DbgPrint("  WindowsBuild     @ %p = %i\n", g_iWindowsBuild, *g_iWindowsBuild);
            DbgPrint("  ServicePackLevel @ %p = %i\n", g_iServicePackLevel, *g_iServicePackLevel);
            break;
        }
        i++;
    }

    __try
    {
        DbgPrint("[MsiChangeCachedVersion] Writing new cached version values...\n");
        if (g_iMajorVersion)
            *g_iMajorVersion = MajorVersion;
        if (g_iMinorVersion)
            *g_iMinorVersion = MinorVersion;
        if (g_iWindowsBuild)
            *g_iWindowsBuild = BuildNumber;
        if (g_iServicePackLevel)
            *g_iServicePackLevel = ServicePack;

        DbgPrint("[MsiChangeCachedVersion] Cached MSI version successfully updated\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[MsiChangeCachedVersion] Exception while writing MSI globals\n");
        return STATUS_ACCESS_VIOLATION;
    }

    DbgPrint("[MsiChangeCachedVersion] Completed successfully\n");
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
RtlGetVersionAppCompat(OUT PRTL_OSVERSIONINFOW lpVersionInformation)
{
    PPEB Peb;
    HANDLE parentHandle;
    PEB ParentPeb;
    WCHAR emuPath[MAX_PATH];
    WCHAR msiPath[MAX_PATH];
    OCA_COMPATIBILITY_INFO OcaCompatInfo;
    WCHAR parentPath[MAX_PATH];
    ULONG_PTR parentPid;
    BOOLEAN IsWow64Parent = FALSE;
    static volatile LONG g_RtlGetVersionInitialized = 0;

    Peb = NtCurrentPeb();

    if (g_RtlGetVersionInitialized > 0)
    {
        return RtlGetVersionInternal(lpVersionInformation);
    }

    memset(&OcaCompatInfo, 0, sizeof(OCA_COMPATIBILITY_INFO));

    // Copy the current image path to emulation path on start
    memcpy(emuPath, Peb->ProcessParameters->ImagePathName.Buffer, MAX_PATH * sizeof(WCHAR));

    // Check if is the executable name is in whitlist
    if (!CheckIsUnsafeExe(emuPath))
    {
        UNICODE_STRING EmulatedVersionGlobal;

        RtlZeroMemory(&EmulatedVersionGlobal, sizeof(EmulatedVersionGlobal));
        RtlZeroMemory(&ParentPeb, sizeof(PEB));

        if (GetParentProcessPeb(&parentHandle, &ParentPeb, &IsWow64Parent))
        {
            if (IsWow64Parent)
            {
                /* Interpretar ParentPeb como PEB32 */
                PEB32 *Peb32 = (PEB32 *)(void *)&ParentPeb;

                Peb->OSMajorVersion = Peb32->OSMajorVersion;
                Peb->OSMinorVersion = Peb32->OSMinorVersion;
                Peb->OSBuildNumber = Peb32->OSBuildNumber;
                Peb->OSCSDVersion = Peb32->OSCSDVersion;
                Peb->OSPlatformId = Peb32->OSPlatformId;
            }
            else
            {
                /* ParentPeb é PEB nativo */
                Peb->OSMajorVersion = ParentPeb.OSMajorVersion;
                Peb->OSMinorVersion = ParentPeb.OSMinorVersion;
                Peb->OSBuildNumber = ParentPeb.OSBuildNumber;
                Peb->OSCSDVersion = ParentPeb.OSCSDVersion;
                Peb->OSPlatformId = ParentPeb.OSPlatformId;
            }
        }

        if (ReadDisableOsSpoofing(emuPath))
        {
            // Spoof as Server 2003
            Peb->OSMajorVersion = 5;
            Peb->OSMinorVersion = 2;
            Peb->OSBuildNumber = 3790;
        }
        else
        {
            // Check if the global emulation version key is filled
            if (ReadEmulatedVersion(&EmulatedVersionGlobal, NULL))
            {
                ParseEmulationVersionAndApplyOnPeb(EmulatedVersionGlobal, Peb);
                RtlFreeUnicodeString(&EmulatedVersionGlobal);
                return RtlGetVersionInternal(lpVersionInformation);
            }
        }

        if (!CheckIsMsiOrServicesExec(emuPath, TRUE))
        {
            UNICODE_STRING EmulatedVersion;

            RtlZeroMemory(&EmulatedVersion, sizeof(EmulatedVersion));

            if (ReadEmulatedVersion(&EmulatedVersion, emuPath))
            {
                ParseEmulationVersionAndApplyOnPeb(EmulatedVersion, Peb);
                RtlFreeUnicodeString(&EmulatedVersion);
                CreateCompatVersionAndStore(Peb, emuPath, SECTION_COMMON_NAME);
                StoreMsiInstallationTypeInSharedSection(MsiServerCalledFromExe, SECTION_MSI_TYPE_NAME);
                goto Exit;
            }
            else
            {
                parentPid = GetParentProcessId();

                if (GetProcessFullPathByPid((HANDLE)(ULONG_PTR)parentPid, parentPath, MAX_PATH))
                {
                    if (ReadEmulatedVersion(&EmulatedVersion, parentPath))
                    {
                        ParseEmulationVersionAndApplyOnPeb(EmulatedVersion, Peb);
                        CreateCompatVersionAndStore(Peb, emuPath, SECTION_MSI_NAME);
                        StoreMsiInstallationTypeInSharedSection(MsiServerCalledFromExe, SECTION_MSI_TYPE_NAME);
                        RtlFreeUnicodeString(&EmulatedVersion);
                        return RtlGetVersionInternal(lpVersionInformation);
                    }
                    else if (CheckIsMsiOrServicesExec(parentPath, TRUE))
                    {
                        if (LoadFromSharedSection(&OcaCompatInfo, SECTION_MSI_NAME))
                        {
                            Peb->OSMajorVersion = OcaCompatInfo.MajorVersion;
                            Peb->OSMinorVersion = OcaCompatInfo.MinorVersion;
                            Peb->OSBuildNumber = (USHORT)OcaCompatInfo.BuildNumber;
                            StoreMsiInstallationTypeInSharedSection(MsiServerCalledFromExe, SECTION_MSI_TYPE_NAME);
                            CreateCompatVersionAndStore(Peb, emuPath, SECTION_COMMON_NAME);
                            return RtlGetVersionInternal(lpVersionInformation);
                        }
                    }
                    else if (CheckIsMsiOrServicesExec(parentPath, FALSE))
                    {
                        if (LoadFromSharedSection(&OcaCompatInfo, SECTION_MSI_NAME))
                        {
                            Peb->OSMajorVersion = OcaCompatInfo.MajorVersion;
                            Peb->OSMinorVersion = OcaCompatInfo.MinorVersion;
                            Peb->OSBuildNumber = (USHORT)OcaCompatInfo.BuildNumber;
                            StoreMsiInstallationTypeInSharedSection(MsiServerCalledFromExe, SECTION_MSI_TYPE_NAME);
                            CreateCompatVersionAndStore(Peb, emuPath, SECTION_COMMON_NAME);
                            return RtlGetVersionInternal(lpVersionInformation);
                        }
                        // Workaround to get chrome for Windows 7 working and not affecting anothers executables child
                        // of services.exe
                        if (wcsstr(Peb->ProcessParameters->CommandLine.Buffer, L"/svc") != NULL)
                        {
                            if (LoadFromSharedSection(&OcaCompatInfo, SECTION_COMMON_NAME))
                            {
                                Peb->OSMajorVersion = OcaCompatInfo.MajorVersion;
                                Peb->OSMinorVersion = OcaCompatInfo.MinorVersion;
                                Peb->OSBuildNumber = (USHORT)OcaCompatInfo.BuildNumber;
                                StoreMsiInstallationTypeInSharedSection(MsiServerCalledFromExe, SECTION_MSI_TYPE_NAME);
                                return RtlGetVersionInternal(lpVersionInformation);
                            }
                        }
                    }
                }
            }

            CreateCompatVersionAndStore(Peb, emuPath, SECTION_COMMON_NAME);
            StoreMsiInstallationTypeInSharedSection(MsiServerCalledFromExe, SECTION_MSI_TYPE_NAME);
            g_RtlGetVersionInitialized++;
            return RtlGetVersionInternal(lpVersionInformation);
        }
        else
        {

            if (wcsstr(Peb->ProcessParameters->CommandLine.Buffer, L"/V") != NULL)
            {
                // MsiChangeCachedVersion(6,1,7601,1);
                if (LoadFromSharedSection(&OcaCompatInfo, SECTION_MSI_NAME))
                {
                    Peb->OSMajorVersion = OcaCompatInfo.MajorVersion;
                    Peb->OSMinorVersion = OcaCompatInfo.MinorVersion;
                    Peb->OSBuildNumber = (USHORT)OcaCompatInfo.BuildNumber;
                    StoreMsiInstallationTypeInSharedSection(MsiServerCalledFromExe, SECTION_MSI_TYPE_NAME);
                    return RtlGetVersionInternal(lpVersionInformation);
                }
            }

            if (GetMsiPathFromCommandLine(Peb->ProcessParameters->CommandLine.Buffer, msiPath, 260))
            {
                UNICODE_STRING EmulatedVersionMsi;

                memset(&EmulatedVersionMsi, 0, sizeof(UNICODE_STRING));

                wcscpy(emuPath, msiPath);
                if (ReadEmulatedVersion(&EmulatedVersionMsi, emuPath))
                {
                    ParseEmulationVersionAndApplyOnPeb(EmulatedVersionMsi, Peb);
                    CreateCompatVersionAndStore(Peb, emuPath, SECTION_MSI_NAME);
                    StoreMsiInstallationTypeInSharedSection(MsiServerCalledFromMsi, SECTION_MSI_TYPE_NAME);
                    RtlFreeUnicodeString(&EmulatedVersionMsi);
                    return RtlGetVersionInternal(lpVersionInformation);
                }
            }
            else
            {
                ULONG MsiType;
                if (LoadMsiInstallationTypeFromSharedSection(&MsiType, SECTION_MSI_TYPE_NAME))
                {
                    DbgPrint("MsiInstallationType salvo: %d\n", MsiType);

                    switch (MsiType)
                    {
                        case MsiServerCalledFromMsi:
                            if (LoadFromSharedSection(&OcaCompatInfo, SECTION_MSI_NAME))
                            {
                                Peb->OSMajorVersion = OcaCompatInfo.MajorVersion;
                                Peb->OSMinorVersion = OcaCompatInfo.MinorVersion;
                                Peb->OSBuildNumber = (USHORT)OcaCompatInfo.BuildNumber;
                                return RtlGetVersionInternal(lpVersionInformation);
                            }
                            break;
                        case MsiServerCalledFromMsiFromExe:
                            if (LoadFromSharedSection(&OcaCompatInfo, SECTION_EXE_TO_MSI_NAME))
                            {
                                Peb->OSMajorVersion = OcaCompatInfo.MajorVersion;
                                Peb->OSMinorVersion = OcaCompatInfo.MinorVersion;
                                Peb->OSBuildNumber = (USHORT)OcaCompatInfo.BuildNumber;
                                return RtlGetVersionInternal(lpVersionInformation);
                            }
                            break;
                        case MsiServerCalledFromExe:
                            if (LoadFromSharedSection(&OcaCompatInfo, SECTION_COMMON_NAME))
                            {
                                Peb->OSMajorVersion = OcaCompatInfo.MajorVersion;
                                Peb->OSMinorVersion = OcaCompatInfo.MinorVersion;
                                Peb->OSBuildNumber = (USHORT)OcaCompatInfo.BuildNumber;
                                return RtlGetVersionInternal(lpVersionInformation);
                            }
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }

Exit:
    g_RtlGetVersionInitialized++;
    return RtlGetVersionInternal(lpVersionInformation);
}

BOOLEAN
RtlpVerCompare(LONG Condition, LONG Value1, LONG Value2, BOOLEAN *Equal, int Flags)
{
    char String1[MAX_STRING_LENGTH];
    char String2[MAX_STRING_LENGTH];
    LONG Comparison;

    if (Flags & LEXICAL_COMPARISON)
    {
        sprintf(String1, "%d", Value1);
        sprintf(String2, "%d", Value2);
        Comparison = strcmp(String2, String1);
        Value1 = 0;
        Value2 = Comparison;
    }
    *Equal = (Value1 == Value2);
    switch (Condition)
    {
        case VER_EQUAL:
            return (Value2 == Value1);

        case VER_GREATER:
            return (Value2 > Value1);

        case VER_LESS:
            return (Value2 < Value1);

        case VER_GREATER_EQUAL:
            return (Value2 >= Value1);

        case VER_LESS_EQUAL:
            return (Value2 <= Value1);

        default:
            break;
    }

    return FALSE;
}

ULONG
RtlpVerGetConditionMask(ULONGLONG ConditionMask, ULONG TypeMask)
{
    ULONG NumBitsToShift;
    ULONG Condition = 0;

    if (!TypeMask)
    {
        return 0;
    }

    for (NumBitsToShift = 0; TypeMask; NumBitsToShift++)
    {
        TypeMask >>= 1;
    }

    Condition |= (ConditionMask) >> ((NumBitsToShift - 1) * VER_NUM_BITS_PER_CONDITION_MASK);
    Condition &= VER_CONDITION_MASK;
    return Condition;
}

NTSTATUS
NTAPI
RtlVerifyVersionInfoAppCompat(IN PRTL_OSVERSIONINFOEXW VersionInfo, IN ULONG TypeMask, IN ULONGLONG ConditionMask)
{
    ULONG i;
    OSVERSIONINFOEXW CurrVersion;
    BOOLEAN SuiteFound = FALSE;
    BOOLEAN Equal;
    NTSTATUS Status;
    ULONG Condition;

    if (TypeMask == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&CurrVersion, sizeof(OSVERSIONINFOEXW));
    CurrVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    Status = RtlGetVersionAppCompat((PRTL_OSVERSIONINFOW)&CurrVersion);
    if (Status != STATUS_SUCCESS)
        return Status;

    if ((TypeMask & VER_SUITENAME) && (VersionInfo->wSuiteMask != 0))
    {
        for (i = 0; i < 16; i++)
        {
            if (VersionInfo->wSuiteMask & (1 << i))
            {
                switch (RTL_GET_CONDITION(ConditionMask, VER_SUITENAME))
                {
                    case VER_AND:
                        if (!(CurrVersion.wSuiteMask & (1 << i)))
                        {
                            return STATUS_REVISION_MISMATCH;
                        }
                        break;

                    case VER_OR:
                        if (CurrVersion.wSuiteMask & (1 << i))
                        {
                            SuiteFound = TRUE;
                        }
                        break;

                    default:
                        return STATUS_INVALID_PARAMETER;
                }
            }
        }
        if ((RtlpVerGetConditionMask(ConditionMask, VER_SUITENAME) == VER_OR) && (SuiteFound == FALSE))
        {
            return STATUS_REVISION_MISMATCH;
        }
    }

    Equal = TRUE;
    Condition = VER_EQUAL;
    if (TypeMask & VER_MAJORVERSION)
    {
        Condition = RTL_GET_CONDITION(ConditionMask, VER_MAJORVERSION);
        if (RtlpVerCompare(Condition, VersionInfo->dwMajorVersion, CurrVersion.dwMajorVersion, &Equal, 0) == FALSE)
        {
            if (!Equal)
            {
                return STATUS_REVISION_MISMATCH;
            }
        }
    }

    if (Equal)
    {
        ASSERT(Condition);
        if (TypeMask & VER_MINORVERSION)
        {
            if (Condition == VER_EQUAL)
            {
                Condition = RTL_GET_CONDITION(ConditionMask, VER_MINORVERSION);
            }
            if (RtlpVerCompare(
                    Condition, VersionInfo->dwMinorVersion, CurrVersion.dwMinorVersion, &Equal, LEXICAL_COMPARISON) ==
                FALSE)
            {
                if (!Equal)
                {
                    return STATUS_REVISION_MISMATCH;
                }
            }
        }

        if (Equal)
        {
            if (TypeMask & VER_SERVICEPACKMAJOR)
            {
                if (Condition == VER_EQUAL)
                {
                    Condition = RTL_GET_CONDITION(ConditionMask, VER_SERVICEPACKMAJOR);
                }
                if (RtlpVerCompare(
                        Condition, VersionInfo->wServicePackMajor, CurrVersion.wServicePackMajor, &Equal, 0) == FALSE)
                {
                    if (!Equal)
                    {
                        return STATUS_REVISION_MISMATCH;
                    }
                }
            }
            if (Equal)
            {
                if (TypeMask & VER_SERVICEPACKMINOR)
                {
                    if (Condition == VER_EQUAL)
                    {
                        Condition = RTL_GET_CONDITION(ConditionMask, VER_SERVICEPACKMINOR);
                    }
                    if (RtlpVerCompare(
                            Condition, (ULONG)VersionInfo->wServicePackMinor, (ULONG)CurrVersion.wServicePackMinor,
                            &Equal, LEXICAL_COMPARISON) == FALSE)
                    {
                        return STATUS_REVISION_MISMATCH;
                    }
                }
            }
        }
    }

    if ((TypeMask & VER_BUILDNUMBER) && RtlpVerCompare(
                                            RTL_GET_CONDITION(ConditionMask, VER_BUILDNUMBER),
                                            VersionInfo->dwBuildNumber, CurrVersion.dwBuildNumber, &Equal, 0) == FALSE)
    {
        return STATUS_REVISION_MISMATCH;
    }

    if ((TypeMask & VER_PLATFORMID) && RtlpVerCompare(
                                           RTL_GET_CONDITION(ConditionMask, VER_PLATFORMID), VersionInfo->dwPlatformId,
                                           CurrVersion.dwPlatformId, &Equal, 0) == FALSE)
    {
        return STATUS_REVISION_MISMATCH;
    }

    if ((TypeMask & VER_PRODUCT_TYPE) && RtlpVerCompare(
                                             RTL_GET_CONDITION(ConditionMask, VER_PRODUCT_TYPE),
                                             VersionInfo->wProductType, CurrVersion.wProductType, &Equal, 0) == FALSE)
    {
        return STATUS_REVISION_MISMATCH;
    }

    return STATUS_SUCCESS;
}