//=========================================================================
//                      Target Brief
//=========================================================================
// by      : INSANE
// created : 17/02/2026
//
// purpose : Brief information about target process.
//-------------------------------------------------------------------------
#include "TargetBrief_t.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <dirent.h>
#include <string.h>

#include "../Alias.h"



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int TargetBrief_InitializePID(TargetBrief_t* pThis, pid_t iTargetPID)
{
    pThis->m_iTargetPID = iTargetPID;


    char szTargetFilePath[256] = {0};
    if(snprintf(szTargetFilePath, sizeof(szTargetFilePath), "/proc/%d/comm", iTargetPID) <= 0)
        return 0;


    // open "/proc/<PID>/comm" file.
    FILE* pFile = fopen(szTargetFilePath, "r");
    if(pFile == NULL)
        return 0; 


    // Read at max 64 characters into the buffer.
    if(fgets(pThis->m_szTargetName, MAX_TARGET_NAME, pFile) == NULL)
        return 0;


    fclose(pFile);


    // Terminate string at newline character.
    for(int i = 0; i < MAX_TARGET_NAME; i++)
    {
        if(pThis->m_szTargetName[i] == '\n')
        {
            pThis->m_szTargetName[i] = 0;
            return 1;
        }
    }

    // in case we failed to find the string's end, that means
    // the buffer size was too small, and was unable to fit the 
    // target process's name from the "/proc/<PID>/comm" file.
    return 0;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int TargetBrief_InitializeName(TargetBrief_t* pThis, const char* szTargetName)
{
    DIR* pDirectory = opendir("/proc");
    if(pDirectory == nullptr)
        return 0;


    struct dirent* pDirEntity = NULL;
    while((pDirEntity = readdir(pDirectory)) != nullptr)
    {
        int iProcID = atoi(pDirEntity->d_name);
        if(iProcID <= 0)
            continue;

        // contruct file path.
        char szBuffer[256];
        snprintf(szBuffer, sizeof(szBuffer), "/proc/%d/comm", iProcID);


        // open & read file @ file path.
        FILE* pFile = fopen(szBuffer, "r");
        if(pFile == nullptr)
            continue;

        char* fgetsOut = fgets(szBuffer, sizeof(szBuffer), pFile);
        fclose(pFile);

        if(fgetsOut == nullptr)
            continue;


        szBuffer[strcspn(szBuffer, "\n")] = 0;

        // Found target process.
        if(strcmp(szBuffer, szTargetName) == 0)
        {
            pThis->m_iTargetPID = iProcID;
            strncpy(pThis->m_szTargetName, szBuffer, MAX_TARGET_NAME);

            return 1;
        }
    }


    closedir(pDirectory);
    return 0;
}
