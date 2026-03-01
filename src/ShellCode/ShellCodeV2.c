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
#include <sys/mman.h>
#include <sys/user.h>

#include "../TargetBrief/TargetBrief_t.h"

// Util...
#include "../Util/AAManager/AAManager.h"
#include "../Util/Terminal/Terminal.h"

// ILIB...
#include "../../lib/ILIB/ILIB_Vector.h"
#include "../../lib/ILIB/ILIB_ArenaAllocator.h"


// This is just to prevent bullshit, nothing else.
#define MAX_SHELLCODE_SIZE (1024)


REGISTER_ARENA_ALLOCATOR(g_pArenaAlloc);


/* Iterates /proc/ITARGETPID/task/ directory and collects all threads ( folder in that directory ) 
   and pushes them in PVECTHREADS which is expected to be ILIB_VECTOR. */
static bool ShellCode_GetAllThreads(pid_t iTargetPID, pid_t* pVecThreads);

/* Read NBYTES from virtual address PADDRESS of target process ITHREADID into buffer PBYTES 
   using ptrace(PTRACE_PEEKDATA) */
static bool ShellCode_ReadBytesPTrace(unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID);

/* Write NBYTES at virtual address PADDRESS of target process ITHREADID from buffer PBYTES 
   using ptrace(PTRACE_POKEDATA) */
static bool ShellCode_WriteBytesPTrace(unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID);

/* Inject, Execute and Restore shellcode into target process ITHREADID. 
   Returns -1 on fail, and rAX register's value at shellcode exec end on success. */
static uint64_t ShellCode_RemoteExec(unsigned char* shellCode, size_t iShellCodeSize, pid_t iThreadID);



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool ShellCode_StopTargetAllThreads(struct TargetBrief_t* pTarget)
{
    // Get all threads.
    pid_t* vecThreads = nullptr; Vector_Reserve(vecThreads, 0);
    if(ShellCode_GetAllThreads(pTarget->m_iTargetPID, vecThreads) == false)
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
    if(ShellCode_GetAllThreads(pTarget->m_iTargetPID, vecThreads) == false)
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
    void* pOutput = MAP_FAILED;

    static const size_t iAdrsByteOffset = 2;
    static const size_t iSizeByteOffset = 12;
    static unsigned char shellCodeTemplate[] = 
    {
        // mov rdi, [ map adrs here ] 
        0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // mov rsi, [ map size here ]
        0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        // mov rdx, 3  
        0x48, 0xC7, 0xC2, 0x03, 0x00, 0x00, 0x00, 
        // mov r10, 0x100022 ( MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE ) 
        0x49, 0xC7, 0xC2, 0x22, 0x00, 0x10, 0x00,
        // mov r8,  -1
        0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF,
        // mov r9,  0
        0x49, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 
        // mov rax, 9
        0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00, 
        // syscall     
        0x0F, 0x05, 
        // int3
        0xcc,
    };
    size_t iShellCodeSize = sizeof(shellCodeTemplate);

    // Shell code is very small ( less than 64 bytes ) so its fine on the stack.
    unsigned char shellCode[sizeof(shellCodeTemplate)];

    // Modify template according to our needs.
    memcpy(shellCode, shellCodeTemplate, iShellCodeSize);
    *(uint64_t*)(shellCode + iAdrsByteOffset) = (uint64_t)pVAddr; // Should handle endian.
    *(uint64_t*)(shellCode + iSizeByteOffset) = (uint64_t)iSize;  // Should handle endian.

    LOG("Map address %p, Map size : %zu", *(uint64_t*)(shellCode + iAdrsByteOffset), *(uint64_t*)(shellCode + iSizeByteOffset));


    return (void*)ShellCode_RemoteExec(shellCode, iShellCodeSize, pTarget->m_iTargetPID);
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int ShellCode_MUnMap(struct TargetBrief_t* pTarget, void* pVAddr, size_t iSize)
{
    static const size_t iAdrsByteOffset = 2;
    static const size_t iSizeByteOffset = 12;
    static unsigned char shellCodeTemplate[] = 
    {
        // mov rdi, [ map adrs here ] 
        0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // mov rsi, [ map size here ]
        0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        // mov rax, 11
        0x48, 0xC7, 0xC0, 0x0b, 0x00, 0x00, 0x00, 
        // syscall     
        0x0F, 0x05, 
        // int3
        0xcc,
    };
    size_t iShellCodeSize = sizeof(shellCodeTemplate);

    // Shell code is very small ( less than 64 bytes ) so its fine on the stack.
    unsigned char shellCode[sizeof(shellCodeTemplate)];

    // Modify template according to our needs.
    memcpy(shellCode, shellCodeTemplate, iShellCodeSize);
    *(uint64_t*)(shellCode + iAdrsByteOffset) = (uint64_t)pVAddr; // Should handle endian.
    *(uint64_t*)(shellCode + iSizeByteOffset) = (uint64_t)iSize;  // Should handle endian.

    LOG("Map address %p, Map size : %zu", *(uint64_t*)(shellCode + iAdrsByteOffset), *(uint64_t*)(shellCode + iSizeByteOffset));


    return (int)ShellCode_RemoteExec(shellCode, iShellCodeSize, pTarget->m_iTargetPID);
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool ShellCode_GetAllThreads(pid_t iTargetPID, pid_t* pVecThreads)
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


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool ShellCode_ReadBytesPTrace(unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID)
{
    if(nBytes == 0)
        return false;


    size_t nIterations = ((nBytes - 1) / sizeof(long)) + 1;
    for(size_t i = 0; i < nIterations; i++)
    {
        errno = 0;

        const uintptr_t iAddress = (uintptr_t)pAddress + (i * sizeof(long));
        const long      iData    = ptrace(PTRACE_PEEKDATA, iThreadID, iAddress, NULL);

        // did ptrace(PEEKDATA) failed?
        if(iData == -1 && errno != 0)
            return false;

        for(int j = 0; j < sizeof(long); j++)
        {
            const unsigned char* szBytes   = (const unsigned char*)&iData;
            const int            iAbsIndex = (i * sizeof(long)) + j;

            if(iAbsIndex >= nBytes)
                break;

            pBytes[iAbsIndex] = szBytes[j];
        }
    }


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool ShellCode_WriteBytesPTrace(unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID)
{
    if(nBytes == 0)
        return false;


    size_t nIterations = ((nBytes - 1) / sizeof(long)) + 1;
    for(size_t i = 0; i < nIterations; i++)
    {
        long            iData    = 0;
        unsigned char*  szBytes  = (unsigned char*)&iData;
        const uintptr_t iAddress = (uintptr_t)pAddress + (i * sizeof(long));

        // NOTE : Since ptarce(pokedata) writes 8 bytes at a time ( sizeof(long) )
        //      we can write in all iterations ( 8 bytes ) correctly except for the last 
        //      iterations ( where we have nBytes % sizeof(long) bytes ). In that case we have
        //      to first read the original bytes at that location and modifying some bytes
        //      and keep the remaning intact, and write it back.
        if(i < nIterations - 1)
        {
            for(int j = 0; j < sizeof(long); j++)
            {
                int iAbsIndex = (i * sizeof(long)) + j;
                szBytes[j]    = pBytes[iAbsIndex];
            }
        }
        else
        {
            errno = 0;
            iData = ptrace(PTRACE_PEEKDATA, iThreadID, iAddress, NULL);

            if(iData == -1 && errno != 0) // peekdata failed?
                return false;

            for(int j = 0; j < sizeof(long); j++)
            {
                const int iAbsIndex = (i * sizeof(long)) + j;

                if(iAbsIndex >= nBytes)
                    break;

                szBytes[j] = pBytes[iAbsIndex];
            }
        }

        errno         = 0;
        long iErrCode = ptrace(PTRACE_POKEDATA, iThreadID, iAddress, iData);
        if(iErrCode == -1 && errno != 0) // pokedata failed ?
            return false;
    }


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static uint64_t ShellCode_RemoteExec(unsigned char* shellCode, size_t iShellCodeSize, pid_t iThreadID)
{
    uint64_t pOutput = ((uint64_t)-1);

    assertion(iShellCodeSize <= MAX_SHELLCODE_SIZE && "ShellCode size too big");

    
    // Setup our local arena.
    static bool    s_bArenaInit = false;
    static Arena_t s_localArena;
    if(s_bArenaInit == false)
    {
        s_bArenaInit = Arena_Initialize(&s_localArena, MAX_SHELLCODE_SIZE * 2);
        if(s_bArenaInit == false)
        {
            FAIL_LOG("Failed to initailize local arena");
            return pOutput;
        }
    }
    

    Arena_Clear(&s_localArena);
    unsigned char* pOrignalCode = (unsigned char*)Arena_Allocate(&s_localArena, iShellCodeSize);
    unsigned char* pTempBuffer  = (unsigned char*)Arena_Allocate(&s_localArena, iShellCodeSize);
    assertion(pOrignalCode != nullptr && pTempBuffer != nullptr && "Arena allocation failed.");
    

    // Target's main thread will be used to execute our shell code.
    pid_t iTargetThread = iThreadID;

    struct user_regs_struct regs;
    int iGetRegErrCode = ptrace(PTRACE_GETREGS, iTargetThread, NULL, &regs);
    if(iGetRegErrCode == -1)
    {
        perror("Failed to get registers");
        return pOutput;
    }


    // Stack frame must be aligned!
    unsigned long long iRspOriginal = regs.rsp;
    if((regs.rsp % 16) != 0)
    {
        regs.rsp -= regs.rsp % 16;

        // Check.
        if((regs.rsp % 16) != 0)
        {
            FAIL_LOG("Failed to align rsp %p", (void*)regs.rsp);
            return pOutput;
        }
    }


    // Back up original bytes @ RIP.
    ShellCode_ReadBytesPTrace(pOrignalCode, iShellCodeSize, (void*)regs.rip, iTargetThread);


    // Write shellcode @ RIP.
    ShellCode_WriteBytesPTrace(shellCode,   iShellCodeSize, (void*)regs.rip, iTargetThread);
    ShellCode_ReadBytesPTrace (pTempBuffer, iShellCodeSize, (void*)regs.rip, iTargetThread);
    if(memcmp(shellCode, pTempBuffer, iShellCodeSize) != 0)
    {
        FAIL_LOG("Failed to write shellcode @ rip %p", (void*)regs.rip);
        return pOutput;
    }


    // Let it run till it hits our breakpoint.
    ptrace(PTRACE_CONT, iTargetThread, NULL, NULL);

    
    // Wait till hit int3 inst.
    waitpid(iTargetThread, NULL, 0);


    // Now our shellcode is done executing. Retrieve mmap()'s output.
    struct user_regs_struct regsNew;
    iGetRegErrCode = ptrace(PTRACE_GETREGS, iTargetThread, NULL, &regsNew);
    if(iGetRegErrCode == -1)
    {
        perror("Failed to get new registers.");
        return pOutput;
    }
    pOutput = regsNew.rax;


    // Restore opbytes.
    ShellCode_WriteBytesPTrace(pOrignalCode, iShellCodeSize, (void*)regs.rip, iTargetThread);
    ShellCode_ReadBytesPTrace (pTempBuffer,  iShellCodeSize, (void*)regs.rip, iTargetThread);
    if(memcmp(pOrignalCode, pTempBuffer, iShellCodeSize) != 0)
    {
        FAIL_LOG("Failed to restore bytes after shellcode @ rip %p", (void*)regs.rip);
        return pOutput;
    }


    // Restore registers...
    regs.rsp       = iRspOriginal;
    iGetRegErrCode = ptrace(PTRACE_SETREGS, iTargetThread, NULL, &regs);
    if(iGetRegErrCode == -1)
    {
        perror("Failed to get new registers");
        return pOutput;
    }


    WIN_LOG("Done Shellcode Exec");
    return pOutput;
}
