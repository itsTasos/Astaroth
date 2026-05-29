#pragma once

#include <winsock2.h>
#include <windows.h>

bool Internal_Inject(DWORD targetPid, PBYTE payload, SIZE_T payloadSize);
