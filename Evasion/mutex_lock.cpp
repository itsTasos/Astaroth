#include "Evasion/mutex_lock.h"
#include "Core/api_resolve.h"
#include "Crypto/obfuscation.h"

//single instance mutex
static HANDLE xmutex = NULL;

//single instance mutex function
bool check_mutex(){
    API_TABLE& API = GetAPI();
    xmutex = API.CreateMutexW(NULL, TRUE, L"Global\\{B9E2D1A0-5F3C-4D2E-8A1B-7C9F0D6E4A2B}");

    if(GetLastError() == ERROR_ALREADY_EXISTS){
        if(xmutex) API.CloseHandle(xmutex);

        return false;
    }

    return true;
}
