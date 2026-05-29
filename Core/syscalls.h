#pragma once

#include "Core/ntdefs.h"

//Indirect Syscalls 

struct SYSCALL_GATE {
    PVOID pAddress;     //Address of NT function in ntdll 
    WORD wServiceId;    //SSN
    PVOID pSyscallAddr; //Address of syscall instruction in ntdll
};

extern "C" {
    extern DWORD wSystemCall;   //SSN for current syscall
    extern PVOID pSyscallAddress;   //Address of ntdll syscall gadget 
    
    //assembly stub
    NTSTATUS IndirectSyscall(
        ULONG_PTR n1, ULONG_PTR n2, ULONG_PTR n3, ULONG_PTR n4,
        ULONG_PTR n5, ULONG_PTR n6, ULONG_PTR n7, ULONG_PTR n8,
        ULONG_PTR n9, ULONG_PTR n10, ULONG_PTR n11
    );
}

SYSCALL_GATE GetSSNByHash(QWORD qFunctionHash);
inline PVOID FindSyscallInstruction(unsigned char* pBytes, int searchLimit);

//prepare syscall gate by setting the SSN and syscall address
#define PREPARE_SYSCALL(gate) \
    wSystemCall = (gate).wServiceId; \
    pSyscallAddress = (gate).pSyscallAddr;

