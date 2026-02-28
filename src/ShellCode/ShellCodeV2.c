//=========================================================================
//                      Shell Code
//=========================================================================
// by      : INSANE
// created : 27/02/2026
//
// purpose : Handle shellcode injection and execution into target process 
//           using pTrace
//-------------------------------------------------------------------------
#include "ShellCodeV2.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/wait.h>

#include "../TargetBrief/TargetBrief_t.h"

// Util...
#include "../Util/AAManager/AAManager.h"
#include "../Util/Terminal/Terminal.h"

// ILIB...
#include "../../lib/ILIB/ILIB_Vector.h"
#include "../../lib/ILIB/ILIB_ArenaAllocator.h"



static ArenaAllocator_t* g_pArenaAlloc = nullptr;
REGISTER_ARENA_ALLOCATOR(g_pArenaAlloc);


static bool GetAllThreads(pid_t iTargetPID, pid_t* pVecThreads);


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool ShellCode_StopTargetAllThreads(struct TargetBrief_t* pTarget)
{
    // Get all threads.
    pid_t* vecThreads = nullptr; Vector_Reserve(vecThreads, 0);
    if(GetAllThreads(pTarget->m_iTargetPID, vecThreads) == false)
    {
        FAIL_LOG("Failed to get all threads");
        return false;
    }
    

    // PTRACE_SEIZE + PTRACE_INTERRUPT all threads.
    bool bThreadSeizeFailed = false;
    for(int iThreadIndex = 0; iThreadIndex < Vector_Len(vecThreads); iThreadIndex++)
    {
        pid_t iThreadID = vecThreads[iThreadIndex];


        // Seize this tracee.
        errno = 0;
        long iSeizeErrCode = ptrace(PTRACE_SEIZE, iThreadID, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE);
        if(iSeizeErrCode == -1 && errno != 0)
        {
            FAIL_LOG("Failed to PTRACE_SEIZE target process [ %s , pid : %d ]", pTarget->m_szTargetName, pTarget->m_iTargetPID);
            perror("PTRACE_SEIZE");

            bThreadSeizeFailed = true;
            break;
        }


        // Ask this tracee to stop.
        errno = 0;
        long iInterErrCode = ptrace(PTRACE_INTERRUPT, iThreadID, NULL, NULL);
        if(iInterErrCode == -1 && errno != 0)
        {
            FAIL_LOG("Failed to PTRACE_INTERRUPT target process [ %s , pid : %d ]", pTarget->m_szTargetName, pTarget->m_iTargetPID);
            perror("PTRACE_INTERRUPT");

            bThreadSeizeFailed = true;
            break;
        }
    }


    // if we failed to seize all threads, cleanup and leave.
    if(bThreadSeizeFailed == true)
    {
        Vector_Free(vecThreads);
        return false;
    }


    // waitpid() till all threads stop.
    int iThreadStopped = 0;
    while(iThreadStopped < Vector_Len(vecThreads))
    {
        int   iStatus   = 0;
        pid_t iThreadID = waitpid(-1, &iStatus, __WALL);

        if(iThreadID > 0)
        {
            iThreadStopped++;
            LOG("Thread ID : %d, Index : %d stopped", iThreadID, iThreadStopped);
        }
    }


    Vector_Free(vecThreads);
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool ShellCode_StartTargetAllThreads(struct TargetBrief_t* pTarget)
{
    // Get all threads.
    pid_t* vecThreads = nullptr; Vector_Reserve(vecThreads, 0);
    if(GetAllThreads(pTarget->m_iTargetPID, vecThreads) == false)
    {
        FAIL_LOG("Failed to get all threads");
        return false;
    }


    // Unfreezing all threads.
    for(int iThreadIndex = 0; iThreadIndex < Vector_Len(vecThreads); iThreadIndex++)
    {
        long iDetachErrCode = ptrace(PTRACE_DETACH, vecThreads[iThreadIndex], NULL, NULL);

        if(iDetachErrCode == -1)
        {
            perror("PTRACE_DETACH");
        }
    }
    LOG("Detach from %d thread(s)", Vector_Len(vecThreads));


    Vector_Free(vecThreads);
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void* ShellCode_MMap(struct TargetBrief_t* pTarget, void* pVAddr, size_t iSize)
{
    return NULL;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int ShellCode_MUnMap(struct TargetBrief_t* pTarget, void* pVAddr, size_t iSize)
{
    return 0;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool GetAllThreads(pid_t iTargetPID, pid_t* pVecThreads)
{
    // Iterate "/proc/<PID>/task/" directory and ptrace(ptrace_cont) each thread.
    char szPath[256];
    snprintf(szPath, sizeof(szPath), "/proc/%d/task/", iTargetPID);


    // open "/proc/<PID>/task/" directory.
    DIR* pDirectory = opendir(szPath);
    if(pDirectory == NULL)
    {
        FAIL_LOG("Failed to open directory %s", szPath);
        return false;
    }
    

    // Iterate this directory & collect all thread IDs.
    Vector_Clear(pVecThreads);
    struct dirent* pDirEntity = NULL;
    while((pDirEntity = readdir(pDirectory)) != NULL)
    {
        pid_t iThreadID = (pid_t)atoi(pDirEntity->d_name);
        if(iThreadID <= 0)
            continue;

        Vector_PushBack(pVecThreads, iThreadID);
    }


    closedir(pDirectory);
    return true;
}
