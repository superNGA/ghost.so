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

TODO: Verify loaded segments.
TOOD: Fail safely.

*/

static void PrintDependencyTree(MappedObject_t* pObj, int iIndentation);
void PrintMapEntries(const MapEntry_t* pEntries, size_t nEntries);


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


    // .so file to mapped object.
    MappedObject_t obj; static const char* s_szTestLib = "TestELF/testlib.so";
    if(MappedObject_Initialize(&obj, s_szTestLib) == false)
    {
        FAIL_LOG("Failed to initialize mapped object for %s");
        return 1;
    }

    
    // pages allocated to this process. ( before modifying, so we can retore to this in case
    // we fail. )
    MapEntry_t* vecOriginalMaps = nullptr; MapParser_Parse(&target, &vecOriginalMaps);


    // Freeze! This is FBI!
    ShellCode_StopTargetAllThreads(&target);

    bool bObjLoadWin = MappedObject_LoadAll(&obj, &target);
    if(bObjLoadWin == false)
    {
        FAIL_LOG("Failed to load file '%s' ( + depencencies ) into target process '%s'", s_szTestLib, target.m_szTargetName);

        // Unallocate all allocated memory if we failed.
        MappedObject_RestoreTo(vecOriginalMaps, &target);

        // Check if we successfully cleaned-up.
        MapEntry_t* vecNewMaps = nullptr; MapParser_Parse(&target, &vecNewMaps);
        if(MapParser_Compare(vecOriginalMaps, vecNewMaps) == false)
        {
            FAIL_LOG("Failed to cleanup.");
        }
        else
        {
            WIN_LOG("Cleaned up successfully");
        }
        Vector_Free(vecNewMaps);

        goto EXIT;
    }


    MappedObject_VerifyLoadedObj(&obj, &target);
    

EXIT:
    // Sorry for the inconvenience sir, you are free to go. :)
    ShellCode_StartTargetAllThreads(&target);
    Vector_Free(vecOriginalMaps);
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
void PrintMapEntries(const MapEntry_t* vecEntries, size_t nEntries)
{
    for(size_t i = 0; i < nEntries; i++)
    {
        const MapEntry_t* pEntry = &vecEntries[i];

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
