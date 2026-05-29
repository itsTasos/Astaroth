#pragma once

#include "Core/ntdefs.h"

//file defs for self deletion 
#define FileRenameInformation 10
#define FileDispositionInformationEx 64

#define FILE_DISPOSITION_FLAG_DELETE 0x00000001
#define FILE_DISPOSITION_FLAG_POSIX_SEMANTICS 0x00000002

typedef struct _FILE_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, *PFILE_DISPOSITION_INFORMATION_EX;



void Internal_Suicide(const wchar_t* botPath);
