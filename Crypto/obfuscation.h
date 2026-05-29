#pragma once
#include <windows.h> 

// Compile-time XOR seed derived from build timestamp
#define SEED ((((__TIME__[7] - '0') * 1 + (__TIME__[6] - '0') * 10 \
                   + (__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 \
                   + (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000) & 0xFF))

// Compile-time string obfuscator template
template <unsigned int N, unsigned char K>
struct obfuscator {
    unsigned char m_data[N] = {0};
    

    __forceinline constexpr obfuscator(const char* data) {
        for (unsigned int i = 0; i < N; i++) {
            m_data[i] = data[i] ^ K;
        }
    }
};

// RAII deobfuscator that wipes memory on destruction
template <unsigned int N, unsigned char K>
class deobfuscator {
    char m_data[N];
public:
    __forceinline deobfuscator(const obfuscator<N, K>& obf) {
        for (unsigned int i = 0; i < N; i++) {
            m_data[i] = obf.m_data[i] ^ K;
        }
    }
    
    __forceinline ~deobfuscator() {
        SecureZeroMemory(m_data, N);
    }

    //Operator Overloading - automated type casting
     __forceinline operator const char*() const {
        return m_data;
    }

    __forceinline const char* get() const { return m_data; }
};


#define STR(str) \
    ([]() { \
        constexpr unsigned char K = (SEED + __COUNTER__) & 0xFF; \
        constexpr auto size = sizeof(str)/sizeof(str[0]); \
        constexpr obfuscator<size, K> obfuscated_str(str); \
        return deobfuscator<size, K>(obfuscated_str); \
    }())
