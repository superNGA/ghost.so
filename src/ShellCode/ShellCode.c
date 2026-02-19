//=========================================================================
//                      Shell Code
//=========================================================================
// by      : INSANE
// created : 18/02/2026
//
// purpose : Handle Shell Code generation & execution.
//-------------------------------------------------------------------------
#include "ShellCode.h"
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <assert.h>

// ptrace stuff
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

// Util
#include "../Util/Assertions/Assertions.h"
#include "../Util/Terminal/Terminal.h"

#include "../TargetBrief/TargetBrief_t.h"


/*

TODO: Make cs2 run shell code.
TODO: Generate custom shell code for shared object.
TODO: Inject custom shell code.
TODO: Run custom shell code.
TODO: Load all PT_LOAD segments into mmap-ed regions.
TODO: Restore target from shellcode, and make it resume properly.

 */



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
struct Thread_t
{
    pid_t m_iThreadID;
};
typedef struct Thread_t Thread_t;



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static Elf64_Ehdr* g_pElfHeader  = NULL;
static Elf64_Phdr* g_pSegHeaders = NULL;



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static int   ShellCode_ExecuteShellCode (TargetBrief_t* pTarget);
static int   ShellCode_WriteBytes       (unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID);
static int   ShellCode_ReadBytes        (unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID);
static pid_t ShellCode_StopAllThreads   (TargetBrief_t* pTarget);
static int   ShellCode_StartAllThreads  (TargetBrief_t* pTarget);
static int   ShellCode_GetAllThreads    (pid_t iTargetPID, Thread_t** pThreadsOut, int* nThreads);



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int ShellCode_MapSharedObject(const char* szFile, TargetBrief_t* pTarget)
{
    ShellCode_ExecuteShellCode(pTarget);
    return 1;

    // assert(g_pElfHeader == NULL && g_pSegHeaders == NULL && "Global objects are already initialized.");
    //
    //
    // FILE* pFile = fopen(szFile, "r");
    // fseek(pFile, 0, SEEK_SET); // just to make sure.
    //
    // // Read header.
    // g_pElfHeader      = malloc(sizeof(Elf64_Ehdr));
    // size_t nBytesRead = fread(&g_pElfHeader, 1, sizeof(Elf64_Ehdr), pFile);
    // if(nBytesRead == 0)
    //     return 0;
    //
    //
    // // Our Given shared object must be valid.
    // assert(g_pElfHeader->e_phentsize == sizeof(Elf64_Phdr) && "Invalid program header entry size in given shared object.");
    //
    //
    // // Go to program ( segment ) headers.
    // fseek(pFile, g_pElfHeader->e_phoff, SEEK_SET);
    //
    // size_t iSegHeaderSize = g_pElfHeader->e_phentsize * g_pElfHeader->e_phnum;
    // g_pSegHeaders         = (Elf64_Phdr*)malloc(iSegHeaderSize);
    // fread(g_pSegHeaders, 1, iSegHeaderSize, pFile); // reading headers into our buffer.
    //
    //
    // fclose(pFile);
    // return 1;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static int ShellCode_ExecuteShellCode(TargetBrief_t* pTarget)
{
    static unsigned char shellCode[] = 
    {
        // mov rdi, 0
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00, 
        // mov rsi, 0x0807060504030201
        0x48, 0xBE, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        // mov rdx, 3  
        0x48, 0xC7, 0xC2, 0x03, 0x00, 0x00, 0x00, 
        // mov r10, 0x22 
        0x49, 0xC7, 0xC2, 0x22, 0x00, 0x00, 0x00,
        // mov r8,  0
        0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF,
        // mov r9,  0
        0x49, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00, 
        // mov rax, 9
        0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00, 
        // syscall     
        0x0F, 0x05, 
        // mov r10, rax
        0x49, 0x89, 0xC2, 
        // int3
        0xcc,
    };
    size_t iShellCodeSize = sizeof(shellCode);


    // Wait till atleast one of the target threads stop completly.
    pid_t iTargetThread = pTarget->m_iTargetPID;
    if(ShellCode_StopAllThreads(pTarget) == 0)
    {
        FAIL_LOG("Failed to stop target process [ %s ]", pTarget->m_szTargetName);
        return 0;
    }


    LOG("Target Thread : %d, ProcID : %d", iTargetThread, pTarget->m_iTargetPID);

    struct user_regs_struct regs; memset(&regs, 0, sizeof(struct user_regs_struct));
    int iGetRegErrCode = ptrace(PTRACE_GETREGS, iTargetThread, NULL, &regs); // it will ignore either addr or data & use the other.
    if(iGetRegErrCode == -1)
    {
        perror("Failed to get registers");
        ptrace(PTRACE_DETACH, pTarget->m_iTargetPID);
        return 1;
    }


    printf("RIP : %p\n", (void*)regs.rip);
    printf("RSP : %p\n", (void*)regs.rsp);
    printf("RBP : %p\n", (void*)regs.rbp);

    // Stack frame must be aligned!
    if((regs.rsp % 16) != 0)
    {
        regs.rsp -= regs.rsp % 16;
        printf("Stack frame not aligned!. Modifyied it to : %p\n", (void*)regs.rsp);
    }

    // Is stack frame aligned now?
    if((regs.rsp % 16) == 0)
    {
        printf("Stack frame is aligned!\n");
    }
    else
    {
        printf("Failed to align stack frame!\n");
    }


    unsigned char* pOrignalCode = malloc(iShellCodeSize);
    unsigned char* pTempBuffer  = malloc(iShellCodeSize);
    printf("Malloced successfully\n");


    // Back up original bytes @ RIP.
    printf("Storing %zu original bytes\n", iShellCodeSize);
    ShellCode_ReadBytes(pOrignalCode, iShellCodeSize, (void*)regs.rip, iTargetThread);
    for(int i = 0; i < iShellCodeSize; i++) printf("%02X ", pOrignalCode[i]); printf("\n");


    // Write shellcode @ RIP.
    printf("Writting shellcode\n");
    ShellCode_WriteBytes(shellCode,   iShellCodeSize, (void*)regs.rip, iTargetThread);
    ShellCode_ReadBytes (pTempBuffer, iShellCodeSize, (void*)regs.rip, iTargetThread);
    for(int i = 0; i < iShellCodeSize; i++) printf("%02X ", pTempBuffer[i]); printf("\n");


    // Let it run till it hits our breakpoint.
    ptrace(PTRACE_CONT, iTargetThread, NULL, NULL);

    
    // Wait till hit int3 inst.
    waitpid(iTargetThread, NULL, 0);


    // Now our shellcode is done executing, retrieve mmap()'s output.
    struct user_regs_struct regsNew; memset(&regsNew, 0, sizeof(struct user_regs_struct));
    iGetRegErrCode = ptrace(PTRACE_GETREGS, iTargetThread, NULL, &regsNew);
    if(iGetRegErrCode == -1)
    {
        printf("ptrace -> GETREGS failed with error code : %d\n", iGetRegErrCode);
        ptrace(PTRACE_DETACH, pTarget->m_iTargetPID);
        return 1;
    }
    printf("mmap allcoated memory @ adrs : %p\n", (void*)regsNew.rax);


    // Restore .text
    printf("Restoring original bytes.\n");
    ShellCode_WriteBytes(pOrignalCode, iShellCodeSize, (void*)regs.rip, iTargetThread);
    ShellCode_ReadBytes (pTempBuffer,  iShellCodeSize, (void*)regs.rip, iTargetThread);
    for(int i = 0; i < iShellCodeSize; i++) printf("%02X ", pTempBuffer[i]); printf("\n");
    printf("\nRestored original bytes.\n");


    // Restore registers...
    ptrace(PTRACE_SETREGS, iTargetThread, NULL, &regs);
    printf("Restored registers\n");


    // Run the process and detach...
    ShellCode_StartAllThreads(pTarget);
    free(pOrignalCode);
    printf("Done Shellcode Exec\n");
    return 1;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static int ShellCode_WriteBytes(unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID)
{
    if(nBytes == 0)
        return 0;


    int iIterations = ((nBytes - 1) / sizeof(long)) + 1;
    for(int i = 0; i < iIterations; i++)
    {
        long            iData    = 0;
        unsigned char*  szBytes  = (unsigned char*)&iData;
        const uintptr_t iAddress = (uintptr_t)pAddress + (i * sizeof(long));

        // NOTE : Since ptarce(pokedata) writes 8 bytes at a time ( sizeof(long) )
        //      we can write in all iterations ( 8 bytes ) correctly except for the last 
        //      iterations ( where we have nBytes % sizeof(long) bytes ). In that case we have
        //      to first read the original bytes at that location and modifying some bytes
        //      and keep the remaning intact, and write it back.
        if(i < iIterations - 1)
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
                return 0;

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
            return 0;
    }


    return 1;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static int ShellCode_ReadBytes(unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID)
{
    if(nBytes == 0)
        return 0;


    int iIterations = ((nBytes - 1) / sizeof(long)) + 1;
    for(int i = 0; i < iIterations; i++)
    {
        errno = 0;

        const uintptr_t iAddress = (uintptr_t)pAddress + (i * sizeof(long));
        const long      iData    = ptrace(PTRACE_PEEKDATA, iThreadID, iAddress, NULL);

        // did ptrace(PEEKDATA) failed?
        if(iData == -1 && errno != 0)
            return 0;

        for(int j = 0; j < sizeof(long); j++)
        {
            const unsigned char* szBytes   = (const unsigned char*)&iData;
            const int            iAbsIndex = (i * sizeof(long)) + j;

            if(iAbsIndex >= nBytes)
                break;

            pBytes[iAbsIndex] = szBytes[j];
        }
    }


    return 1;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static pid_t ShellCode_StopAllThreads(TargetBrief_t* pTarget)
{
    // Get all threads.
    Thread_t* pThreads = NULL;
    int       nThreads = 0;
    if(ShellCode_GetAllThreads(pTarget->m_iTargetPID, &pThreads, &nThreads) == 0)
    {
        FAIL_LOG("Failed to get all threads");
        return 0;
    }
    

    // PTRACE_SEIZE + PTRACE_INTERRUPT all threads.
    bool bThreadSeizeFailed = false;
    for(int iThreadIndex = 0; iThreadIndex < nThreads; iThreadIndex++)
    {
        pid_t iThreadID = pThreads[iThreadIndex].m_iThreadID;


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
        free(pThreads);
        return 0;
    }


    // waitpid() till all threads stop.
    int iThreadStopped = 0;
    while(iThreadStopped < nThreads)
    {
        int   iStatus   = 0;
        pid_t iThreadID = waitpid(-1, &iStatus, __WALL);

        if(iThreadID > 0)
        {
            iThreadStopped++;
            LOG("Thread %d stopped", iThreadStopped);
        }
    }


    free(pThreads);
    return 1;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static int ShellCode_StartAllThreads(TargetBrief_t* pTarget)
{
    // Get all threads.
    Thread_t* pThreads = NULL;
    int       nThreads = 0;
    if(ShellCode_GetAllThreads(pTarget->m_iTargetPID, &pThreads, &nThreads) == 0)
    {
        FAIL_LOG("Failed to get all threads");
        return 0;
    }


    // Unfreezing all threads.
    for(int iThreadIndex = 0; iThreadIndex < nThreads; iThreadIndex++)
    {
        ptrace(PTRACE_DETACH, pThreads[iThreadIndex].m_iThreadID, NULL, NULL);
    }
    LOG("Unfreezed %d threads", nThreads);


    free(pThreads);
    return 1;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static int ShellCode_GetAllThreads(pid_t iTargetPID, Thread_t** pThreadsOut, int* nThreads)
{
    // Iterate "/proc/<PID>/task/" directory and ptrace(ptrace_cont) each thread.
    char szPath[256];
    snprintf(szPath, sizeof(szPath), "/proc/%d/task/", iTargetPID);


    // open "/proc/<PID>/task/" directory.
    DIR* pDirectory = opendir(szPath);
    if(pDirectory == NULL)
    {
        FAIL_LOG("Failed to open directory %s", szPath);
        return 0;
    }
    

    // Iterate this directory
    struct dirent* pDirEntity = NULL;
    *nThreads                 = 0;
    while((pDirEntity = readdir(pDirectory)) != NULL)
    {
        int iThreadID = atoi(pDirEntity->d_name);
        if(iThreadID <= 0)
            continue;

        (*nThreads)++;
    }


    // Go to directory's start again.
    rewinddir(pDirectory);

    assertion(*pThreadsOut == NULL && "pThreadsOut is already containing some addres");
    *pThreadsOut = (Thread_t*)malloc(sizeof(Thread_t) * (*nThreads));

    
    // Collect all thread IDs.
    int iThreadIndex = 0;
    while((pDirEntity = readdir(pDirectory)) != NULL)
    {
        int iThreadID = atoi(pDirEntity->d_name);
        if(iThreadID <= 0)
            continue;

        (*pThreadsOut)[iThreadIndex].m_iThreadID = iThreadID;
        iThreadIndex++;
    }
    

    closedir(pDirectory);
    return 1;
}
