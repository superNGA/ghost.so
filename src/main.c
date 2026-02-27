#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "TargetBrief/TargetBrief_t.h"
#include "MappedObject/MappedObject.h"
#include "Util/Terminal/Terminal.h"


/* Final goal. Map target shared object into memory and all its dependencies. */
static void PrintDependencyTree(MappedObject_t* pObj, int iIndentation);


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
    MappedObject_t obj;
    bool bMOInit = MappedObject_Initialize(&obj, "TestELF/testlib.so");
    LOG("MappedObject Init : %s", bMOInit == true ? "Succeeded" : "Failed");


    LOG(".so               : %s", obj.m_szName);
    LOG("ElfHeaders      @ : %p", *(void**)&obj.m_elfHeader);
    LOG("Program Headers @ : %p", obj.m_pProHeader);
    LOG("Dynamic Segment @ : %p", obj.m_pDynamicEntries);
    LOG("Dependencies    @ : %p", obj.m_pDependencies);
    LOG("Load base         : %p", obj.m_iLoadBase);

    
    // Dependency tree.
    PrintDependencyTree(&obj, 0);



    MappedObject_Uninitialize(&obj);
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
