#pragma once

#include <winsock2.h>
#include <windows.h>
#include <winternl.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

#ifndef QWORD_DEFINED
#define QWORD_DEFINED
typedef unsigned __int64 QWORD;
#endif

// Macro for initializing UNICODE_STRING without RtlInitUnicodeString
#define SET_UNICODE_STRING(us, wstr) \
    us.Buffer = wstr; \
    us.Length = (USHORT)(wcslen(wstr) * sizeof(wchar_t)); \
    us.MaximumLength = us.Length + sizeof(wchar_t);

// PEB structures for module enumeration
typedef struct _MY_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

// NT function typedefs
typedef NTSTATUS (NTAPI *_LdrLoadDll)(
    PWSTR SearchPath,
    PULONG DllFlags,
    PUNICODE_STRING DllName,
    PVOID *BaseAddress
);

typedef NTSTATUS (NTAPI *_NtOpenProcessToken)(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle
);

typedef VOID (NTAPI *pfnRtlFreeUnicodeString)(PUNICODE_STRING);
