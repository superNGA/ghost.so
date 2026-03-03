#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "TargetBrief/TargetBrief_t.h"
#include "MappedObject/MappedObject.h"
#include "ShellCode/ShellCodeV2.h"
#include "MapParser/MapParser.h"

// Util...
#include "Util/Terminal/Terminal.h"
#include "Util/AAManager/AAManager.h"

// ILIB...
#include "../lib/ILIB/ILIB_Vector.h"


/* 

Final goal. Map target shared object into memory and all its dependencies.

TODO: Ignore finding dependency in the target's maps. Just do it manually.
TODO: Construct a clean and absolute mmap allocation solution.
TODO: Construct a clean and absolute mmap free solution.

*/

static void PrintDependencyTree(MappedObject_t* pObj, int iIndentation);
static void PrintMapEntries(MapEntry_t* pEntries, size_t nEntries);


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(int nArgs, char** szArgs)
{
    if(nArgs <= 1)
    {
        printf("Target name not specified\n");
        return 1;
    }


    // Construct target brief.
    TargetBrief_t target; 
    const char* szTargetName = szArgs[1];
    if(TargetBrief_InitializeName(&target, szTargetName) == false)
    {
        FAIL_LOG("No such process as %s exists\n", szTargetName);
        return 1;
    }

    WIN_LOG("Target process found [ %s ] with pid %d", target.m_szTargetName, target.m_iTargetPID);


    MapEntry_t* vecTargetMaps = nullptr; Vector_Reserve(vecTargetMaps, 1); 
    MapParser_Parse(&target, vecTargetMaps);


    // .so file to mapped object.
    MappedObject_t obj;
    bool bMOInit = MappedObject_Initialize(&obj, "TestELF/testlib.so");
    LOG("MappedObject Init : %s", bMOInit == true ? "Succeeded" : "Failed");


    LOG(".so               : %s", obj.m_szName);
    LOG("ElfHeaders      @ : %p", *(void**)&obj.m_elfHeader);
    LOG("Program Headers @ : %p", obj.m_pProHeader);
    LOG("Dynamic Segment @ : %p", obj.m_pDynamicEntries);
    LOG("Dependencies    @ : %p", obj.m_pDependencies);
    LOG("Load base         : %p", obj.m_iLoadBase);


    MappedObject_LoadAll(&obj, &target);
    return 0;

    
    if(ShellCode_StopTargetAllThreads(&target) == false)
        return 1;

    void* pMap = ShellCode_MMap(&target, (void*)0x558c9a002000, 0x1000, 
            (uint32_t)(PROT_READ | PROT_EXEC), 
            (uint32_t)(MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE));
    int some = ShellCode_MUnMap(&target, (void*)0x558c9a000000, 0x3000);
    
    if(ShellCode_StartTargetAllThreads(&target) == false)
        return 1;


    LOG("%d", some);
    LOG("MMaped @ %p", pMap);


    AAManager_UninitializeAll();
    return 0;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void PrintDependencyTree(MappedObject_t* pObj, int iIndentation)
{
    for(int i = 0; i < iIndentation; i++)
        printf("    ");

    printf("%s\n", pObj->m_szName);

    for(int i = 0; i < pObj->m_nDependencies; i++)
    {
        if(pObj->m_pDependencies[i] != 0)
            PrintDependencyTree(pObj->m_pDependencies[i], iIndentation + 1);
    }
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void PrintMapEntries(MapEntry_t* vecEntries, size_t nEntries)
{
    for(size_t i = 0; i < nEntries; i++)
    {
        MapEntry_t* pEntry = &vecEntries[i];

        printf("%lx-%lx ", pEntry->m_iStartAdrs, pEntry->m_iStartAdrs + pEntry->m_iSize);

        printf("%c", pEntry->m_bPermRead    == true ? 'r' : '-');
        printf("%c", pEntry->m_bPermWrite   == true ? 'w' : '-');
        printf("%c", pEntry->m_bPermExec    == true ? 'x' : '-');
        printf("%c", pEntry->m_bPermPrivate == true ? 'p' : '-');
        printf(" ");

        printf("%08lx ",    pEntry->m_iFileOffset);

        printf("%02x:%02x ", pEntry->m_iDevMajor, pEntry->m_iDevMinor);

        printf("%d ",      pEntry->m_iInode);

        printf("%s",       pEntry->m_szPathName);
        
        printf("\n");
    }
}
