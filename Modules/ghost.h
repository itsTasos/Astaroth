#pragma once

#include "Core/ntdefs.h"

// Returns STATUS_SUCCESS (0) on success, NTSTATUS error code on failure.
NTSTATUS GhostExecute(PVOID payloadBuffer, SIZE_T payloadSize, const wchar_t* spoofImagePath = NULL);
