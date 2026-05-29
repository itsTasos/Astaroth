#pragma once

#include <winsock2.h>
#include <windows.h>
#include <winternl.h>

//Reconnaissance
void user_id(wchar_t* outUsername);
bool IsAdmin();
void GetProcessList();
DWORD GetPidByName(const wchar_t* processName);
bool GetNativeUserSID(PUNICODE_STRING pSidString);
