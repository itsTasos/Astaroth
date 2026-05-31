#include "Utils/helpers.h"
#include <cstdlib>
#include <cstring>

//random sleep time function
void smart_sleep(int base_ms, int jitter_percent) {
    
    int range = (base_ms * jitter_percent) / 100;
    int random_offset = (range > 0) ? (rand() % (2 * range)) - range : 0;
    int final_sleep = base_ms + random_offset;

    Sleep(final_sleep);
}

void escape_json(const char *input, char *output, int out_size) {
    int j = 0;
    for (int i = 0; input[i] != '\0' && j < out_size - 5; i++) {
        switch (input[i]) {
            case '\"': output[j++] = '\\'; output[j++] = '\"'; break;
            case '\\': output[j++] = '\\'; output[j++] = '\\'; break;
            case '\n': output[j++] = '\\'; output[j++] = 'n';  break;
            case '\r': output[j++] = '\\'; output[j++] = 'r';  break;
            case '\t': output[j++] = '\\'; output[j++] = 't';  break;
            default:   output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

//Wide string to string
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

void CleanAndParse(char* cmd) {
    size_t len = strlen(cmd);
        while (len > 0 && (cmd[len - 1] == '\n' || cmd[len - 1] == '\r' || cmd[len - 1] == ' ')) {
        cmd[len - 1] = '\0';
        len--;
    }
}

//manual RtlInitUnicodeString
void mRtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source) {
    if (source) {
        USHORT length = (USHORT)(wcslen(source) * sizeof(WCHAR));
        target->Length = length;
        target->MaximumLength = length + sizeof(WCHAR);
        target->Buffer = (PWSTR)source;
    }
}

// Custom case-insensitive string comparison [avoid CRT hooks]
bool custom_wcsicmp(const wchar_t* str1, const wchar_t* str2) {
    if (!str1 || !str2) return false;
    while (*str1 && *str2) {
        wchar_t c1 = (*str1 >= L'A' && *str1 <= L'Z') ? (*str1 + 32) : *str1;
        wchar_t c2 = (*str2 >= L'A' && *str2 <= L'Z') ? (*str2 + 32) : *str2;
        if (c1 != c2) return false;
        str1++;
        str2++;
    }
    return (*str1 == *str2);
}

//custom memory copy [avoid CRT hooks]
void custom_memcpy(PVOID dest, const PVOID src, SIZE_T n) {
    char* d = (char*)dest;
    const char* s = (const char*)src;
    for (SIZE_T i = 0; i < n; i++) {
        d[i] = s[i];
    }
}
