#pragma once

#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <string>

void smart_sleep(int base_ms, int jitter_percent);
void escape_json(const char *input, char *output, int out_size);
std::string WStringToString(const std::wstring& wstr);
void CleanAndParse(char* cmd);
void mRtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);
bool custom_wcsicmp(const wchar_t* str1, const wchar_t* str2);
void custom_memcpy(PVOID dest, const PVOID src, SIZE_T n);

// Custom FD_ISSET — avoids __WSAFDIsSet IAT import from WS2_32.dll
inline bool custom_fd_isset(SOCKET fd, fd_set* set) {
    if (!set) return false;
    for (u_int i = 0; i < set->fd_count; i++) {
        if (set->fd_array[i] == fd) return true;
    }
    return false;
}
