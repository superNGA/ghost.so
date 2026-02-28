//=========================================================================
//                      Mapped Object
//=========================================================================
// by      : INSANE
// created : 22/02/2026
//
// purpose : Mapping information and dependency info for a .so file.
//-------------------------------------------------------------------------
#include "MappedObject.h"
#include <stdbool.h>

#define _GNU_SOURCE
#define __USE_GNU
#include <dlfcn.h>
#include <link.h>

#include "../Util/Util.h"
#include "../Util/Terminal/Terminal.h"

// ILIB...
#include "../../lib/ILIB/ILIB_Vector.h"
#include "../../lib/ILIB/ILIB_ArenaAllocator.h"
#include "../Util/AAManager/AAManager.h"


// Globals...
static ArenaAllocator_t* g_pArenaAlloc;
REGISTER_ARENA_ALLOCATOR(g_pArenaAlloc);


static bool InitMappedObject(MappedObject_t* pObj, const char* szFile);
static bool StoreStringTable(MappedObject_t* pObj);
static bool ResolveDependencies(MappedObject_t* pHead, MappedObject_t* pObj);
static MappedObject_t* FindDependency(MappedObject_t* pHead, const char* szDependency);



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool MappedObject_Initialize(MappedObject_t* pObj, const char* szFile)
{
    bool bParentInit = InitMappedObject(pObj, szFile);
    if(bParentInit == false)
        return false;


    // Store all dependencies as mapped objects recusively.
    bool bDependencyInit = ResolveDependencies(pObj, pObj);
    if(bDependencyInit == false)
    {
        FAIL_LOG("Failed to initialize dependencies");
        return false;
    }

    // Allocation size. Just for debugging purposes.
    LOG("Size : %zu, Arena Count : %zu, Capacity : %zu", 
            ArenaAllocator_SizeAll   (g_pArenaAlloc), 
            ArenaAllocator_ArenaCount(g_pArenaAlloc),
            ArenaAllocator_Capacity  (g_pArenaAlloc));

    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool InitMappedObject(MappedObject_t* pObj, const char* szFile)
{
    assertion(sizeof(pObj->m_elfHeader) == sizeof(Elf64_Ehdr) && "Object struct is invalid");

    memset(pObj, 0, sizeof(MappedObject_t));


    // Read elf header.
    if(Util_ReadFromFile(szFile, &pObj->m_elfHeader, 0, sizeof(pObj->m_elfHeader)) != sizeof(Elf64_Ehdr))
        return false;

    
    // Read program headers.
    size_t iProHeaderSize = pObj->m_elfHeader.e_phentsize * pObj->m_elfHeader.e_phnum;
    pObj->m_pProHeader    = ArenaAllocator_Allocate(g_pArenaAlloc, iProHeaderSize);
    assertion(pObj->m_pProHeader != nullptr && "Failed to allocate memory to program headers");

    if(Util_ReadFromFile(szFile, pObj->m_pProHeader, pObj->m_elfHeader.e_phoff, iProHeaderSize) != iProHeaderSize)
        return false;


    // Get dynamic segment header from segment headers.
    Elf64_Phdr* pDynSegment = nullptr;
    for(int iSegIndex = 0; iSegIndex < pObj->m_elfHeader.e_phnum; iSegIndex++)
    {
        if(pObj->m_pProHeader[iSegIndex].p_type == PT_DYNAMIC)
        {
            pObj->m_iDynSegmentIndex = iSegIndex;
            pDynSegment              = &pObj->m_pProHeader[iSegIndex];
            break;
        }
    }

    if(pDynSegment == nullptr)
        return false;


    // Read dynamic segments.
    pObj->m_pDynamicEntries = ArenaAllocator_Allocate(g_pArenaAlloc, pDynSegment->p_filesz);
    assertion(pObj->m_pDynamicEntries != nullptr && "Failed to allocate memory to Dynamic segment.");
    if(Util_ReadFromFile(szFile, pObj->m_pDynamicEntries, pDynSegment->p_offset, pDynSegment->p_filesz) != pDynSegment->p_filesz)
        return false;


    // Store file's name as well.
    strncpy(pObj->m_szName, szFile, sizeof(pObj->m_szName));


    // Store string table.
    if(StoreStringTable(pObj) == false)
        return false;


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool StoreStringTable(MappedObject_t* pObj)
{
    Elf64_Phdr* pDymSegHdr = &pObj->m_pProHeader[pObj->m_iDynSegmentIndex];

    assertion(pDymSegHdr->p_type == PT_DYNAMIC && "Invalid Mapped Object instance.");

    
    // String table size.
    Elf64_Dyn* pStrTabDynEnt = nullptr;
    pObj->m_iStringTableSize = 0;
    size_t nDynEntries       = pDymSegHdr->p_filesz / sizeof(Elf64_Dyn);
    for(size_t iDynEntIndex = 0; iDynEntIndex < nDynEntries; iDynEntIndex++)
    {
        Elf64_Dyn* pDynEntry = &pObj->m_pDynamicEntries[iDynEntIndex];

        // string table dynamic entry index.
        if(pDynEntry->d_tag == DT_STRSZ && pObj->m_iStringTableSize == 0)
        {
            pObj->m_iStringTableSize = pDynEntry->d_un.d_val;
        }
        
        if(pDynEntry->d_tag == DT_STRTAB && pStrTabDynEnt == nullptr)
        {
            pStrTabDynEnt = pDynEntry;
        }
    }


    // Failed to find string table.
    if(pStrTabDynEnt == nullptr || pObj->m_iStringTableSize == 0)
    {
        FAIL_LOG("Invalid string table for file %s. String table handle : %p, size : %zu", 
                pObj->m_szName, pStrTabDynEnt, pObj->m_iStringTableSize);

        return false;
    }


    pObj->m_szStringTable = ArenaAllocator_Allocate(g_pArenaAlloc, pObj->m_iStringTableSize);

    // string table address to offset in file.
    size_t nStrTblBytes = 0;
    for(size_t i = 0; i < pObj->m_elfHeader.e_phnum; i++)
    {
        Elf64_Phdr* pPhdr = &pObj->m_pProHeader[i];

        uintptr_t iStrTblVAdrs = pStrTabDynEnt->d_un.d_ptr;
        if(iStrTblVAdrs >= pPhdr->p_vaddr && iStrTblVAdrs < pPhdr->p_vaddr + pPhdr->p_memsz)
        {
            uintptr_t iOffset = iStrTblVAdrs - pPhdr->p_vaddr + pPhdr->p_offset;
            nStrTblBytes = Util_ReadFromFile(pObj->m_szName, (void*)pObj->m_szStringTable, iOffset, pObj->m_iStringTableSize);

            break;
        }
    }

    return nStrTblBytes == pObj->m_iStringTableSize;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool ResolveDependencies(MappedObject_t* pHead, MappedObject_t* pObj)
{
    Elf64_Phdr* pDymSegHdr  = &pObj->m_pProHeader[pObj->m_iDynSegmentIndex];
    size_t      nDynEntries = pDymSegHdr->p_filesz / sizeof(Elf64_Dyn);


    // Verifying Mapped Object's validity.
    assertion(pDymSegHdr->p_type == PT_DYNAMIC && "Invalid Mapped Object instance.");
    assertion(pObj->m_iDynSegmentIndex < pObj->m_elfHeader.e_phnum && "Invalid dynamic segment index.");


    // Find DT_NEEDED entries in PT_DYNAMIC segment.
    int* vecNeededEntIndex = nullptr; Vector_Reserve(vecNeededEntIndex, 10);

    for(size_t iDynEntIndex = 0; iDynEntIndex < nDynEntries; iDynEntIndex++)
    {
        Elf64_Dyn* pDynEntry = &pObj->m_pDynamicEntries[iDynEntIndex];

        if(pDynEntry->d_tag == DT_NEEDED)
        {
            Vector_PushBack(vecNeededEntIndex, iDynEntIndex);
        }
    }


    // Allocate memory for dependencies.
    pObj->m_nDependencies     = Vector_Len(vecNeededEntIndex);
    size_t iDependencyArrSize = sizeof(MappedObject_t*) * pObj->m_nDependencies; // array of pointers to MappedObject_t(s).
    pObj->m_pDependencies     = ArenaAllocator_Allocate(g_pArenaAlloc, iDependencyArrSize);
    memset(pObj->m_pDependencies, 0, iDependencyArrSize);



    // Recursively load all dependencies.
    bool bFailed = false;
    for(int i = 0; i < Vector_Len(vecNeededEntIndex); i++)
    {
        // NOTE : We save the dependency's name as the full path to that file and 
        //      not just the file name. Hence we can't compare the "Dependency name" we get from
        //      DT_NEEDED entries against szName of already initialized entries.
        int         iIndex           = vecNeededEntIndex[i];
        Elf64_Dyn*  pDynEntry        = &pObj->m_pDynamicEntries[iIndex];
        const char* szDependencyName = &pObj->m_szStringTable[pDynEntry->d_un.d_val];
        void*       hDepencency      = dlopen(szDependencyName, RTLD_NOW);

        if(hDepencency == nullptr)
        {
            FAIL_LOG("Failed to find dependency : %s", szDependencyName);
            bFailed = true; break;
        }


        struct link_map* pInfo = nullptr;
        if(dlinfo(hDepencency, RTLD_DI_LINKMAP, &pInfo) != 0)
        {
            FAIL_LOG("dlinfo() failed on dependency %s which dlopen successfully loaded.", szDependencyName);
            dlclose(hDepencency);
            bFailed = true; break;
        }


        // NOTE : s_szFileNameBuffer is a static array of characters. And this is a recursive function.
        // By the time we call this function recursively, all use of this array must be done.
        static char s_szFileNameBuffer[MAX_MAPPED_OBJECT_NAME_SIZE];
        strncpy(s_szFileNameBuffer, pInfo->l_name, sizeof(s_szFileNameBuffer));
        dlclose(hDepencency);


        // Check if we have already initialized this file as MappedObject_t(s).
        MappedObject_t* pExistingObj = FindDependency(pHead, s_szFileNameBuffer);
        if(pExistingObj != nullptr)
        {
            pObj->m_pDependencies[i] = pExistingObj;
            LOG("Found repeating dependency %s", pObj->m_pDependencies[i]->m_szName);
        }
        else
        {
            MappedObject_t* pUniqueDependency = ArenaAllocator_Allocate(g_pArenaAlloc, sizeof(MappedObject_t));

            if(InitMappedObject(pUniqueDependency, s_szFileNameBuffer) == false)
            {
                bFailed = true; break;
            }

            pObj->m_pDependencies[i] = pUniqueDependency;
            LOG("Initialized unique dependency %s", s_szFileNameBuffer);

            if(ResolveDependencies(pHead, pUniqueDependency) == false)
            {
                bFailed = true; break;
            }
        }
    }


    Vector_Free(vecNeededEntIndex);
    return bFailed == false;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static MappedObject_t* FindDependency(MappedObject_t* pHead, const char* szDependency)
{
    if(strncmp(szDependency, pHead->m_szName, MAX_MAPPED_OBJECT_NAME_SIZE) == 0)
        return pHead;

    for(int i = 0; i < pHead->m_nDependencies; i++)
    {
        MappedObject_t* pDepencency = pHead->m_pDependencies[i];

        if(pDepencency == nullptr)
            continue;

        if(strncmp(szDependency, pDepencency->m_szName, MAX_MAPPED_OBJECT_NAME_SIZE) == 0)
            return pDepencency;

        MappedObject_t* pObj = FindDependency(pDepencency, szDependency);

        if(pObj != nullptr)
            return pObj;
    }

    return nullptr;
}
