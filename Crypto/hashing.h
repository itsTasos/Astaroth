#pragma once

#ifndef QWORD_DEFINED
#define QWORD_DEFINED
typedef unsigned __int64 QWORD;
#endif

// Custom hash function — unique seed + rotation mixing
// Avoids known YARA signatures for DJB2/FNV-1a variants
constexpr QWORD HashString(const char* str) {
    QWORD hash = 0xA3B1C2D4E5F60718ULL;
    int c = 0;
    while ((c = *str++)) {
        hash ^= (QWORD)c;
        hash = (hash << 13) | (hash >> 51); // rotate left 13
        hash *= 0x9E3779B97F4A7C15ULL;       // Fibonacci hashing multiplier
    }
    return hash;
}
