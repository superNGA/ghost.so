//=========================================================================
//                      Shell Code
//=========================================================================
// by      : INSANE
// created : 18/02/2026
//
// purpose : Handle Shell Code generation & execution.
//-------------------------------------------------------------------------
#include "ShellCode.h"
#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <assert.h>



static Elf64_Ehdr* g_pElfHeader  = NULL;
static Elf64_Phdr* g_pSegHeaders = NULL;


static int ShellCode_GenerateShellCode();
static int ShellCode_ExecuteShellCode();



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int ShellCode_MapSharedObject(const char* szFile)
{
    assert(g_pElfHeader == NULL && g_pSegHeaders == NULL && "Global objects are already initialized.");


    FILE* pFile = fopen(szFile, "r");
    fseek(pFile, 0, SEEK_SET); // just to make sure.

    // Read header.
    g_pElfHeader      = malloc(sizeof(Elf64_Ehdr));
    size_t nBytesRead = fread(&g_pElfHeader, 1, sizeof(Elf64_Ehdr), pFile);
    if(nBytesRead == 0)
        return 0;


    // Our Given shared object must be valid.
    assert(g_pElfHeader->e_phentsize == sizeof(Elf64_Phdr) && "Invalid program header entry size in given shared object.");


    // Go to program ( segment ) headers.
    fseek(pFile, g_pElfHeader->e_phoff, SEEK_SET);

    size_t iSegHeaderSize = g_pElfHeader->e_phentsize * g_pElfHeader->e_phnum;
    g_pSegHeaders         = (Elf64_Phdr*)malloc(iSegHeaderSize);
    fread(g_pSegHeaders, 1, iSegHeaderSize, pFile); // reading headers into our buffer.


    fclose(pFile);
    return 1;
}
