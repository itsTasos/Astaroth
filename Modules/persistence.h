#pragma once

#include <winsock2.h>
#include <windows.h>

bool safe_migrate();
bool establishPersistence();
void Internal_Persist(const wchar_t* botPath);
