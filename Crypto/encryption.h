#pragma once

#include <windows.h>

// Macro to check if BCrypt APIs return true
#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

//macros for RSA 
#define BCRYPT_RSA_ALGORITHM    L"RSA"
#define BCRYPT_RSAPUBLIC_BLOB   L"RSAPUBLICBLOB"
#define BCRYPT_PAD_PKCS1        0x00000002

//macros for AES
#define BCRYPT_AES_ALGORITHM    L"AES"
#define BCRYPT_CHAINING_MODE    L"ChainingMode"
#define BCRYPT_CHAIN_MODE_CBC   L"ChainingModeCBC"
#define BCRYPT_OBJECT_LENGTH    L"ObjectLength"
#define BCRYPT_BLOCK_LENGTH     L"BlockLength"
#define BCRYPT_BLOCK_PADDING    0x00000001


void xor_encryption(char *data, int data_len);
bool GenerateSessionKey(BYTE* aesKey, ULONG keySize);
bool EncryptSessionKeyRSA(BYTE* aesKey, ULONG aesKeySize, BYTE* encryptedKeyOut, ULONG* encryptedKeySize);
bool AESEncrypt(BYTE* key, ULONG keySize, BYTE* plainText, ULONG plainTextSize, BYTE* cipherText, ULONG* cipherTextSize, BYTE* iv);
bool AESDecrypt(BYTE* key, ULONG keySize, BYTE* cipherText, ULONG cipherTextSize, BYTE* plainText, ULONG* plainTextSize, BYTE* iv);

