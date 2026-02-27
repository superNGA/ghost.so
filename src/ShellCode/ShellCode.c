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
#include "../../lib/ILIB/ILIB_Assertion.h"
#include "../Util/Terminal/Terminal.h"

#include "../TargetBrief/TargetBrief_t.h"




///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
struct Thread_t
{
    pid_t m_iThreadID;
};
typedef struct Thread_t Thread_t;



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static Elf64_Ehdr* g_pElfHeader   = nullptr; // Elf header...
static Elf64_Phdr* g_pProHeaders  = nullptr; // Segment or Program headers...
static Elf64_Shdr* g_pSecHeaders  = nullptr; // Sections headers...
static const char* g_pSecStrTable = nullptr; // Section header string table...



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void* ShellCode_MmapViaCodeInjection(void* pAddress, size_t iSize, TargetBrief_t* pTarget);
static bool  ShellCode_WriteBytes          (unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID);
static bool  ShellCode_WriteBytesFromFile  (const char* szFilePath, Elf64_Phdr* pSegment, void* pAddress, TargetBrief_t* pTarget);
static bool  ShellCode_ReadBytesFromFile   (const char* szFilePath, uint64_t iOffset, void* pBuffer, size_t nBytes);
static bool  ShellCode_ReadBytes           (unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID);
static bool  ShellCode_StopAllThreads      (TargetBrief_t* pTarget);
static bool  ShellCode_StartAllThreads     (TargetBrief_t* pTarget);
static bool  ShellCode_GetAllThreads       (pid_t iTargetPID, Thread_t** pThreadsOut, int* nThreads);


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static const char* ShellCode_StrTableIndex(int iIndex, const char* szStrTbl, size_t iTableSizeInBytes)
{
    int iCurIndex = 0;
    for(size_t iChar = 0; iChar < iTableSizeInBytes; iChar++)
    {
        if(iCurIndex == iIndex)
            return szStrTbl + iChar;

        if(szStrTbl[iChar] == '\0')
            iCurIndex++;
    }

    return nullptr;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void Relocations(const char* szFilePath)
{

    for(int iSegmentIndex = 0; iSegmentIndex < g_pElfHeader->e_phnum; iSegmentIndex++)
    {
        Elf64_Phdr* pSegment = &g_pProHeaders[iSegmentIndex];

        // Copy dynamic entries ( shits ) into our memory.
        if(pSegment->p_type != PT_DYNAMIC)
            continue;

        Elf64_Dyn* pDynamicShits = malloc(pSegment->p_filesz);
        if(ShellCode_ReadBytesFromFile(szFilePath, pSegment->p_offset, pDynamicShits, pSegment->p_filesz) == false)
        {
            FAIL_LOG("Failed to read dynamic shits from file");
            free(pDynamicShits);
            continue;
        }

        // How many dynamic shits do we have.
        size_t nDynamicShits = pSegment->p_filesz / sizeof(Elf64_Dyn);
        WIN_LOG("We have %zu Dynamic shits", nDynamicShits);


        // Allocating string table.
        const char* szDynamicStrTbl  = nullptr;
        size_t      iStringTableSize = 0;
        for(size_t iDynEntryIndex = 0; iDynEntryIndex < nDynamicShits; iDynEntryIndex++)
        {
            Elf64_Dyn* pDynEntry = &pDynamicShits[iDynEntryIndex];
            if(pDynEntry->d_tag == DT_STRSZ)
            {
                iStringTableSize = pDynEntry->d_un.d_val;
                szDynamicStrTbl  = (const char*)malloc(pDynEntry->d_un.d_val);
                break;
            }
        }
        WIN_LOG("String table size : %zu", iStringTableSize);


        // Acquiring string table.
        for(size_t iDynEntryIndex = 0; iDynEntryIndex < nDynamicShits; iDynEntryIndex++)
        {
            Elf64_Dyn* pDynEntry = &pDynamicShits[iDynEntryIndex];
            if(pDynEntry->d_tag == DT_STRTAB)
            {
                uint64_t iOffset = 0;
                for(size_t i = 0; i < g_pElfHeader->e_phnum; i++)
                {
                    Elf64_Phdr* pSeg = &g_pProHeaders[i];
                    if(pDynEntry->d_un.d_ptr >= pSeg->p_vaddr && pDynEntry->d_un.d_ptr < pSeg->p_vaddr + pSeg->p_memsz)
                    {
                        iOffset = pSeg->p_offset + pDynEntry->d_un.d_ptr - pSeg->p_vaddr;
                        break;
                    }
                }
                LOG("Reading string table from offset : %zu", iOffset);
                if(ShellCode_ReadBytesFromFile(szFilePath, iOffset, (void*)szDynamicStrTbl, iStringTableSize) == false)
                {
                    FAIL_LOG("Failed to get dynamic string table");
                    abort();
                }
                break;
            }
        }


        // All string in the string table.
        int i = 0;
        while(true)
        {
            printf("%c", szDynamicStrTbl[i]);

            if(szDynamicStrTbl[i] == 0)
                printf("\n%d : ", i + 1);

            i++;

            if(i >= iStringTableSize)
                break;
        }


        // Allocating string table.
        Elf64_Sym* pSymbolTbl     = nullptr;
        size_t     iSymbolTblSize = 0;
        for(size_t iDynEntryIndex = 0; iDynEntryIndex < nDynamicShits; iDynEntryIndex++)
        {
            Elf64_Dyn* pDynEntry = &pDynamicShits[iDynEntryIndex];

            if(pDynEntry->d_tag == DT_HASH)
            {
                WIN_LOG("Captured symbol talbe size");
                iSymbolTblSize = pDynEntry->d_un.d_val;
                pSymbolTbl     = malloc(iSymbolTblSize);
                break;
            }
        }
        WIN_LOG("Symbol table size : %zu", iSymbolTblSize);



        free(pDynamicShits);
    }
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void DynamicShits(const char* szFilePath)
{
    for(int iSegmentIndex = 0; iSegmentIndex < g_pElfHeader->e_phnum; iSegmentIndex++)
    {
        Elf64_Phdr* pSegment = &g_pProHeaders[iSegmentIndex];

        if(true)
        {
            switch(pSegment->p_type)
            {
                case PT_NULL:         printf("PT_NULL");             break;
                case PT_LOAD:         printf("PT_LOAD");             break;
                case PT_DYNAMIC:      printf("PT_DYNAMIC");          break;
                case PT_INTERP:       printf("PT_INTERP");           break;
                case PT_NOTE:         printf("PT_NOTE");             break;
                case PT_SHLIB:        printf("PT_SHLIB");            break;
                case PT_PHDR:         printf("PT_PHDR");             break;
                case PT_TLS:          printf("PT_TLS");              break;
                case PT_NUM:          printf("PT_NUM");              break;
                case PT_LOOS:         printf("PT_LOOS");             break;
                case PT_GNU_EH_FRAME: printf("PT_GNU_EH_FRAME");     break;
                case PT_GNU_STACK:    printf("PT_GNU_STACK");        break;
                case PT_GNU_RELRO:    printf("PT_GNU_RELRO");        break;
                case PT_GNU_PROPERTY: printf("PT_GNU_PROPERTY");     break;
                case PT_GNU_SFRAME:   printf("PT_GNU_SFRAME");       break;
                case PT_LOSUNW:       printf("PT_LOSUNW");           break;
                case PT_SUNWSTACK:    printf("PT_SUNWSTACK");        break;
                case PT_HISUNW:       printf("PT_HISUNW");           break;
                case PT_LOPROC:       printf("PT_LOPROC");           break;
                case PT_HIPROC:       printf("PT_HIPROC");           break;
                default:              printf("Invalid ass segment"); break;
            }
            printf("\n");
        }


        // Copy dynamic entries ( shits ) into our memory.
        if(pSegment->p_type != PT_DYNAMIC)
            continue;

        Elf64_Dyn* pDynamicShits = malloc(pSegment->p_filesz);
        if(ShellCode_ReadBytesFromFile(szFilePath, pSegment->p_offset, pDynamicShits, pSegment->p_filesz) == false)
        {
            FAIL_LOG("Failed to read dynamic shits from file");
            free(pDynamicShits);
            continue;
        }

        // How many dynamic shits do we have.
        size_t nDynamicShits = pSegment->p_filesz / sizeof(Elf64_Dyn);
        WIN_LOG("We have %zu Dynamic shits", nDynamicShits);


        // Allocating string table.
        const char* szDynamicStrTbl  = nullptr;
        size_t      iStringTableSize = 0;
        for(size_t iDynEntryIndex = 0; iDynEntryIndex < nDynamicShits; iDynEntryIndex++)
        {
            Elf64_Dyn* pDynEntry = &pDynamicShits[iDynEntryIndex];
            if(pDynEntry->d_tag == DT_STRSZ)
            {
                iStringTableSize = pDynEntry->d_un.d_val;
                szDynamicStrTbl  = (const char*)malloc(pDynEntry->d_un.d_val);
                break;
            }
        }
        WIN_LOG("String table size : %zu", iStringTableSize);


        // Acquiring string table.
        for(size_t iDynEntryIndex = 0; iDynEntryIndex < nDynamicShits; iDynEntryIndex++)
        {
            Elf64_Dyn* pDynEntry = &pDynamicShits[iDynEntryIndex];
            if(pDynEntry->d_tag == DT_STRTAB)
            {
                uint64_t iOffset = 0;
                for(size_t i = 0; i < g_pElfHeader->e_phnum; i++)
                {
                    Elf64_Phdr* pSeg = &g_pProHeaders[i];
                    if(pDynEntry->d_un.d_ptr >= pSeg->p_vaddr && pDynEntry->d_un.d_ptr < pSeg->p_vaddr + pSeg->p_memsz)
                    {
                        // iOffset = g_pElfHeader->e_phoff + (pSeg - g_pProHeaders) + pDynEntry->d_un.d_ptr - pSeg->p_vaddr;
                        iOffset = pSeg->p_offset + pDynEntry->d_un.d_ptr - pSeg->p_vaddr;
                        break;
                    }
                }
                LOG("Reading string table from offset : %zu", iOffset);
                if(ShellCode_ReadBytesFromFile(szFilePath, iOffset, (void*)szDynamicStrTbl, iStringTableSize) == false)
                {
                    FAIL_LOG("Failed to get dynamic string table");
                    abort();
                }
                break;
            }
        }


        // All string in the string table.
        int i = 0;
        while(true)
        {
            printf("%c", szDynamicStrTbl[i]);

            if(szDynamicStrTbl[i] == 0)
                printf("\n%d : ", i + 1);

            i++;

            if(i >= iStringTableSize)
                break;
        }


        for(size_t iDynEntryIndex = 0; iDynEntryIndex < nDynamicShits; iDynEntryIndex++)
        {
            Elf64_Dyn* pDynEntry = &pDynamicShits[iDynEntryIndex];

            if(pDynEntry->d_tag != DT_NEEDED)
                continue;

            LOG("%lu, %s", pDynEntry->d_un.d_val, szDynamicStrTbl + pDynEntry->d_un.d_val);
        }

        for(size_t iDynEntryIndex = 0; iDynEntryIndex < nDynamicShits; iDynEntryIndex++)
        {
            Elf64_Dyn* pDynEntry = &pDynamicShits[iDynEntryIndex];

            switch(pDynEntry->d_tag)
            {
                case DT_NULL:            printf("DT_NULL");            break;
                case DT_NEEDED:          printf("DT_NEEDED");          break;
                case DT_PLTRELSZ:        printf("DT_PLTRELSZ");        break;
                case DT_PLTGOT:          printf("DT_PLTGOT");          break;
                case DT_HASH:            printf("DT_HASH");            break;
                case DT_STRTAB:          printf("DT_STRTAB");          break;
                case DT_SYMTAB:          printf("DT_SYMTAB");          break;
                case DT_RELA:            printf("DT_RELA");            break;
                case DT_RELASZ:          printf("DT_RELASZ");          break;
                case DT_RELAENT:         printf("DT_RELAENT");         break;
                case DT_STRSZ:           printf("DT_STRSZ");           break;
                case DT_SYMENT:          printf("DT_SYMENT");          break;
                case DT_INIT:            printf("DT_INIT");            break;
                case DT_FINI:            printf("DT_FINI");            break;
                case DT_SONAME:          printf("DT_SONAME");          break;
                case DT_RPATH:           printf("DT_RPATH");           break;
                case DT_SYMBOLIC:        printf("DT_SYMBOLIC");        break;
                case DT_REL:             printf("DT_REL");             break;
                case DT_RELSZ:           printf("DT_RELSZ");           break;
                case DT_RELENT:          printf("DT_RELENT");          break;
                case DT_PLTREL:          printf("DT_PLTREL");          break;
                case DT_DEBUG:           printf("DT_DEBUG");           break;
                case DT_TEXTREL:         printf("DT_TEXTREL");         break;
                case DT_JMPREL:          printf("DT_JMPREL");          break;
                case DT_BIND_NOW:        printf("DT_BIND_NOW");        break;
                case DT_INIT_ARRAY:      printf("DT_INIT_ARRAY");      break;
                case DT_FINI_ARRAY:      printf("DT_FINI_ARRAY");      break;
                case DT_INIT_ARRAYSZ:    printf("DT_INIT_ARRAYSZ");    break;
                case DT_FINI_ARRAYSZ:    printf("DT_FINI_ARRAYSZ");    break;
                case DT_RUNPATH:         printf("DT_RUNPATH");         break;
                case DT_FLAGS:           printf("DT_FLAGS");           break;
                case DT_ENCODING:        printf("DT_ENCODING");        break;
                case DT_PREINIT_ARRAYSZ: printf("DT_PREINIT_ARRAYSZ"); break;
                case DT_SYMTAB_SHNDX:    printf("DT_SYMTAB_SHNDX");    break;
                case DT_RELRSZ:          printf("DT_RELRSZ");          break;
                case DT_RELR:            printf("DT_RELR");            break;
                case DT_RELRENT:         printf("DT_RELRENT");         break;

                default: break;
            }
            printf("\n");


            if(pDynEntry->d_tag != DT_SYMTAB)
                continue;
        }

        free(pDynamicShits);
    }
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool ShellCode_MapSharedObject(const char* szFile, TargetBrief_t* pTarget)
{
    assertion(g_pElfHeader == NULL && g_pProHeaders == NULL && "Global objects are already initialized.");


    // Elf header...
    g_pElfHeader = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
    ShellCode_ReadBytesFromFile(szFile, 0, g_pElfHeader, sizeof(Elf64_Ehdr));

    // Program ( segment ) headers...
    size_t iProHdrSize = g_pElfHeader->e_phentsize * g_pElfHeader->e_phnum;
    g_pProHeaders      = (Elf64_Phdr*)malloc(iProHdrSize);
    ShellCode_ReadBytesFromFile(szFile, g_pElfHeader->e_phoff, g_pProHeaders, iProHdrSize);

    // Section headers...
    size_t iSecHdrSize  = g_pElfHeader->e_shentsize * g_pElfHeader->e_shnum;
    g_pSecHeaders       = (Elf64_Shdr*)malloc(iSecHdrSize);
    ShellCode_ReadBytesFromFile(szFile, g_pElfHeader->e_shoff, g_pSecHeaders, iSecHdrSize);

    // Our Given shared object must be valid.
    assertion(g_pElfHeader->e_ehsize    == sizeof(Elf64_Ehdr) && "Invalid ELF header entry size in given shared object.");
    assertion(g_pElfHeader->e_phentsize == sizeof(Elf64_Phdr) && "Invalid program header entry size in given shared object.");
    assertion(g_pElfHeader->e_shentsize == sizeof(Elf64_Shdr) && "Invalid section header entry size in given shared object.");


    // Storing section header string table.
    Elf64_Shdr* pSecHdr = &g_pSecHeaders[g_pElfHeader->e_shstrndx];
    g_pSecStrTable      = malloc(pSecHdr->sh_size);
    ShellCode_ReadBytesFromFile(szFile, pSecHdr->sh_offset, (void*)g_pSecStrTable, pSecHdr->sh_size);


    // Delete this. 
    // This is so that we can fuck around with section headers.
    // DynamicShits(szFile);
    Relocations(szFile);
    return true;


    // Stop this shit.
    if(ShellCode_StopAllThreads(pTarget) == false)
        return false; 


    for(int iSegIndex = 0; iSegIndex < g_pElfHeader->e_phnum; iSegIndex++)
    {
        Elf64_Phdr* pSegHeader = &g_pProHeaders[iSegIndex];

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
static bool ShellCode_ReadBytesFromFile(const char* szFilePath, uint64_t iOffset, void* pBuffer, size_t nBytes)
{
    FILE* pFile = fopen(szFilePath, "r");
    if(pFile == nullptr)
        return false;


    fseek(pFile, iOffset, SEEK_SET);

    uint64_t nBytesRead = fread(pBuffer, 1, nBytes, pFile);

    fclose(pFile);

    // We read all bytes or not?
    return nBytes == nBytesRead;
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
