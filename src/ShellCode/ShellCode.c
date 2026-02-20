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
#include "../Alias.h"
#include "../Util/Assertions/Assertions.h"
#include "../Util/Terminal/Terminal.h"

#include "../TargetBrief/TargetBrief_t.h"


/*

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
static void* ShellCode_MmapViaCodeInjection(void* pAddress, size_t iSize, TargetBrief_t* pTarget);
static bool  ShellCode_WriteBytes          (unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID);
static bool  ShellCode_WriteBytesFromFile  (const char* szFilePath, Elf64_Phdr* pSegment, void* pAddress, TargetBrief_t* pTarget);
static bool  ShellCode_ReadBytes           (unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID);
static bool  ShellCode_StopAllThreads      (TargetBrief_t* pTarget);
static bool  ShellCode_StartAllThreads     (TargetBrief_t* pTarget);
static bool  ShellCode_GetAllThreads       (pid_t iTargetPID, Thread_t** pThreadsOut, int* nThreads);



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool ShellCode_MapSharedObject(const char* szFile, TargetBrief_t* pTarget)
{
    assertion(g_pElfHeader == NULL && g_pSegHeaders == NULL && "Global objects are already initialized.");


    FILE* pFile = fopen(szFile, "r");
    if(pFile == nullptr)
    {
        FAIL_LOG("Failed to open file : %s", szFile);
        return false;
    }

    fseek(pFile, 0, SEEK_SET); // just to make sure.

    // Read header.
    g_pElfHeader      = malloc(sizeof(Elf64_Ehdr));
    size_t nBytesRead = fread(g_pElfHeader, 1, sizeof(Elf64_Ehdr), pFile);
    if(nBytesRead == 0)
    {
        fclose(pFile);
        return false;
    }


    // Our Given shared object must be valid.
    assertion(g_pElfHeader->e_ehsize    == sizeof(Elf64_Ehdr) && "Invalid ELF header entry size in given shared object.");
    assertion(g_pElfHeader->e_phentsize == sizeof(Elf64_Phdr) && "Invalid program header entry size in given shared object.");


    // Go to program ( segment ) headers.
    fseek(pFile, g_pElfHeader->e_phoff, SEEK_SET);

    size_t iSegHeaderSize = g_pElfHeader->e_phentsize * g_pElfHeader->e_phnum;
    g_pSegHeaders         = (Elf64_Phdr*)malloc(iSegHeaderSize);
    fread(g_pSegHeaders, 1, iSegHeaderSize, pFile); // reading headers into our buffer.

    fclose(pFile);


    // Stop this shit.
    if(ShellCode_StopAllThreads(pTarget) == false)
        return false; 


    for(int iSegIndex = 0; iSegIndex < g_pElfHeader->e_phnum; iSegIndex++)
    {
        Elf64_Phdr* pSegHeader = &g_pSegHeaders[iSegIndex];

        if(pSegHeader->p_type != PT_LOAD)
            continue;


        // mmap() memory for this segment into target process.
        void* pAdrs = ShellCode_MmapViaCodeInjection((void*)pSegHeader->p_vaddr, pSegHeader->p_memsz, pTarget);
        if(pAdrs == MAP_FAILED)
        {
            FAIL_LOG("Failed to mmap() into target process for segment index %d", iSegIndex);
            break;
        }
        WIN_LOG("mmap'ed %zu bytes @ %p ( requested adrs : %p )", pSegHeader->p_memsz, pAdrs, (void*)pSegHeader->p_vaddr);


        // Write segment to mmap()'ed memory.
        if(ShellCode_WriteBytesFromFile(szFile, pSegHeader, pAdrs, pTarget) == false)
        {
            FAIL_LOG("Failed to write segment ( index : %d ) to memory", iSegIndex);
            return false;
        }
        WIN_LOG("Wrote %zu bytes to memory : %p", pSegHeader->p_filesz, pAdrs);
    }


    // Unfreeze target.
    if(ShellCode_StartAllThreads(pTarget) == false)
        return false;


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void* ShellCode_MmapViaCodeInjection(void* pAddress, size_t iSize, TargetBrief_t* pTarget)
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
    size_t iShellCodeSize = sizeof(shellCodeTemplate);

    // Shell code is very small ( less than 64 bytes ) so its fine on the stack.
    unsigned char shellCode   [sizeof(shellCodeTemplate)];
    unsigned char pOrignalCode[sizeof(shellCodeTemplate)];
    unsigned char pTempBuffer [sizeof(shellCodeTemplate)];


    // Modify template according to our needs.
    memcpy(shellCode, shellCodeTemplate, iShellCodeSize);
    *(shellCode + iAdrsByteOffset) = (uint64_t)pAddress; // Should handle endian.
    *(shellCode + iSizeByteOffset) = (uint64_t)iSize;    // Should handle endian.


    // Target's main thread will be used to execute our shell code.
    pid_t iTargetThread = pTarget->m_iTargetPID;

    struct user_regs_struct regs;
    int iGetRegErrCode = ptrace(PTRACE_GETREGS, iTargetThread, NULL, &regs);
    if(iGetRegErrCode == -1)
    {
        perror("Failed to get registers");
        ptrace(PTRACE_DETACH, pTarget->m_iTargetPID);
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
    ShellCode_ReadBytes(pOrignalCode, iShellCodeSize, (void*)regs.rip, iTargetThread);
    LOG("Stored %zu original bytes", iShellCodeSize);


    // Write shellcode @ RIP.
    ShellCode_WriteBytes(shellCode,   iShellCodeSize, (void*)regs.rip, iTargetThread);
    ShellCode_ReadBytes (pTempBuffer, iShellCodeSize, (void*)regs.rip, iTargetThread);
    if(memcmp(shellCode, pTempBuffer, iShellCodeSize) != 0)
    {
        FAIL_LOG("Failed to write shellcode @ rip %p", (void*)regs.rip);
    }
    LOG("Wrote shellcode");


    // Let it run till it hits our breakpoint.
    ptrace(PTRACE_CONT, iTargetThread, NULL, NULL);

    
    // Wait till hit int3 inst.
    waitpid(iTargetThread, NULL, 0);


    // Now our shellcode is done executing. Retrieve mmap()'s output.
    struct user_regs_struct regsNew;
    iGetRegErrCode = ptrace(PTRACE_GETREGS, iTargetThread, NULL, &regsNew);
    if(iGetRegErrCode == -1)
    {
        perror("Failed to get registers");
        ptrace(PTRACE_DETACH, pTarget->m_iTargetPID);
        return pOutput;
    }
    LOG("mmap allcoated memory @ adrs : %p", (void*)regsNew.rax);
    pOutput = (void*)regsNew.rax;


    // Restore .text
    ShellCode_WriteBytes(pOrignalCode, iShellCodeSize, (void*)regs.rip, iTargetThread);
    ShellCode_ReadBytes (pTempBuffer,  iShellCodeSize, (void*)regs.rip, iTargetThread);
    if(memcmp(pOrignalCode, pTempBuffer, iShellCodeSize) != 0)
    {
        FAIL_LOG("Failed to restore bytes after shellcode @ rip %p", (void*)regs.rip);
        return pOutput;
    }
    LOG("Restored original bytes.");


    // Restore registers...
    regs.rsp = iRspOriginal;
    ptrace(PTRACE_SETREGS, iTargetThread, NULL, &regs);
    LOG("Restored registers");

    WIN_LOG("Done Shellcode Exec");
    return pOutput;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool ShellCode_WriteBytes(unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID)
{
    if(nBytes == 0)
        return false;


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
            return false;
    }


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool ShellCode_WriteBytesFromFile(const char* szFilePath, Elf64_Phdr* pSegment, void* pAddress, TargetBrief_t* pTarget)
{
    FILE* pFile = fopen(szFilePath, "r");
    if(pFile == nullptr)
        return false;


    // allcoate size for temp buffer.
    unsigned char* pSegContents = malloc(pSegment->p_filesz);
    assertion(pSegContents != nullptr && "Failed malloc. wtf u doing?");


    // Read file to temp buffer.
    fseek(pFile, pSegment->p_offset, SEEK_SET);
    uint64_t nBytesWritten = fread(pSegContents, 1, pSegment->p_filesz, pFile);
    if(nBytesWritten != pSegment->p_filesz)
    {
        FAIL_LOG("Wrote %lu bytes, but needed to write %lu bytes", nBytesWritten, pSegment->p_filesz);

        free(pSegContents);
        fclose(pFile);
        return false;
    }


    // Write from temp buffer to memory using ptrace(PTRACE_POKEDATA)
    if(ShellCode_WriteBytes(pSegContents, pSegment->p_filesz, pAddress, pTarget->m_iTargetPID) == false)
    {
        FAIL_LOG("Failed to write bytes to memory address : %p", pAddress);

        free(pSegContents);
        fclose(pFile);
        return false;
    }


    free(pSegContents);
    fclose(pFile);
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool ShellCode_ReadBytes(unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID)
{
    if(nBytes == 0)
        return false;


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


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool ShellCode_StopAllThreads(TargetBrief_t* pTarget)
{
    // Get all threads.
    Thread_t* pThreads = NULL;
    int       nThreads = 0;
    if(ShellCode_GetAllThreads(pTarget->m_iTargetPID, &pThreads, &nThreads) == false)
    {
        FAIL_LOG("Failed to get all threads");
        return false;
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
        return false;
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
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool ShellCode_StartAllThreads(TargetBrief_t* pTarget)
{
    // Get all threads.
    Thread_t*    pThreads = NULL;
    int          nThreads = 0;
    if(ShellCode_GetAllThreads(pTarget->m_iTargetPID, &pThreads, &nThreads) == false)
    {
        FAIL_LOG("Failed to get all threads");
        return false;
    }


    // Unfreezing all threads.
    for(int iThreadIndex = 0; iThreadIndex < nThreads; iThreadIndex++)
    {
        long iDetachErrCode = ptrace(PTRACE_DETACH, pThreads[iThreadIndex].m_iThreadID, NULL, NULL);

        if(iDetachErrCode == -1)
        {
            perror("PTRACE_DETACH");
        }
    }
    LOG("Detach %d threads", nThreads);


    free(pThreads);
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool ShellCode_GetAllThreads(pid_t iTargetPID, Thread_t** pThreadsOut, int* nThreads)
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
    return true;
}
