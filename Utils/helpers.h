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
