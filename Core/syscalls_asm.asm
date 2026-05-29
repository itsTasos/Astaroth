section .data
    extern wSystemCall  
    extern pSyscallAddress

section .text
    global IndirectSyscall    

IndirectSyscall:
    mov r10, rcx            ;NT calling convention
    mov eax, dword [rel wSystemCall]    ;Load SSN    
    jmp qword [rel pSyscallAddress]     ;Jump to ntdll syscall             
