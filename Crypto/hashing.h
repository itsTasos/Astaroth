#pragma once

#ifndef QWORD_DEFINED
#define QWORD_DEFINED
typedef unsigned __int64 QWORD;
#endif

// DJB2-variant hash function (constexpr for compile-time use)
constexpr QWORD HashString(const char* str) {
    QWORD hash = 0xCBF29CE484222325;
    int c = 0;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}
