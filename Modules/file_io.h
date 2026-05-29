#pragma once

#include <winsock2.h>
#include <windows.h>

void Internal_Dir(const wchar_t* directoryPath);
void Internal_Read(const wchar_t* filePath);
void Internal_Write(const wchar_t* filePath, const char* data);
