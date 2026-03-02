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
#include <sys/mman.h>

#define _GNU_SOURCE
#define __USE_GNU
#include <dlfcn.h>
#include <link.h>

#include "../Util/Util.h"
#include "../Util/Terminal/Terminal.h"

#include "../ShellCode/ShellCodeV2.h"
#include "../TargetBrief/TargetBrief_t.h"
#include "../MapParser/MapParser.h"

// ILIB...
#include "../../lib/ILIB/ILIB_Vector.h"
#include "../../lib/ILIB/ILIB_ArenaAllocator.h"
#include "../Util/AAManager/AAManager.h"
#include "../../lib/ILIB/ILIB_Maths.h"


#define MAX_LOAD_BIAS_FIND_ATTEMPT (1000)
#define DEFAULT_LOAD_BIAS          (0x500000000000)


// Globals...
REGISTER_ARENA_ALLOCATOR(g_pArenaAlloc);



/* Store SZFILE's elf header, all program headers, entire dynamic (PT_DYNAMIC) segment and the string table (DT_STRTAB)
   thats present in the dynamic segment in POBJ along with some other metadata about SZFILE. 
   Returns false on failure and true on success. */
static bool _InitMappedObject(MappedObject_t* pObj, const char* szFile);


/* Store the string table ( DT_STRTAB ) whose address is present in the PT_DYNAMIC segment of file 
   pObj->m_szName, into pObj->m_szStringTable along with string table size ( DT_STRSZ ).
   Returns false on failure and true on success. */
static bool _StoreStringTable(MappedObject_t* pObj);


/* Find all the DT_NEEDED entries in phead and find them on disk, then run em through _InitMappedObject(), 
   and them do it recursively on all the dependencies skipping repeating dependencies. This is a recursive function. */
static bool _ResolveDependencies(MappedObject_t* pHead, MappedObject_t* pObj);


/* Find MappedObject_t of file SZDEPENDENCY in PHEAD's dependency array. 
   Return nullptr on failure. Valid MappedObject_t* on success. */
static MappedObject_t* _FindDependency(MappedObject_t* pHead, const char* szDependency);


/* Push back PHEAD and all of its dependencies to PVECOUT, skipping repeating dependencies. */
static void _CollectUniqueObjects(MappedObject_t* pThisObj, MappedObject_t** pVecOut);



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool MappedObject_Initialize(MappedObject_t* pObj, const char* szFile)
{
    bool bParentInit = _InitMappedObject(pObj, szFile);
    if(bParentInit == false)
        return false;


    // Store all dependencies as mapped objects recursively.
    bool bDependencyInit = _ResolveDependencies(pObj, pObj);
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
bool MappedObject_LoadAll(MappedObject_t* pHead, TargetBrief_t* pTarget)
{
    /*
    
       X. What pages are allocated.
       What pages we need to allcoate.
       A load biase for which all pages can be allocated.
       Allcoate all pages.
       Write segments to pages.

    */
    MappedObject_t** vecUnqiueObj = nullptr;
    Vector_Reserve(vecUnqiueObj, 1);
    _CollectUniqueObjects(pHead, vecUnqiueObj);


    // Page size on this machine.
    long iPageSize = sysconf(_SC_PAGESIZE);

    // Vector of pages that are this process already has.
    MapEntry_t* vecMaps = nullptr; Vector_Reserve(vecMaps, 1);

    // Temp array of page ranges.
    typedef struct PageRange_t { uintptr_t m_iPageMin, m_iPageMax; } PageRange_t;
    PageRange_t* vecTempPageRanges = nullptr; Vector_Reserve(vecTempPageRanges, 1);


    for(size_t iObjIndex = 0; iObjIndex < Vector_Len(vecUnqiueObj); iObjIndex++)
    {
        MappedObject_t* pObj = vecUnqiueObj[iObjIndex];


        // Create an array of PageRange_t containing 
        // min ( p_vaddr ) Rounded to PageSize toward zero and 
        // max ( p_vaddr + p_memsz ) rounded to PageSize away from zero for
        // all PT_LOAD segments. 
        //
        // Now ( vecTempPageRanger entries ) + ( load bias ) can act as "page where this segment
        // can be loaded."
        Vector_Clear(vecTempPageRanges);
        for(size_t iHdrIndex = 0; iHdrIndex < pObj->m_elfHeader.e_phnum; iHdrIndex++)
        {
            Elf64_Phdr* pProHeader = &pObj->m_pProHeader[iHdrIndex];

            if(pProHeader->p_type != PT_LOAD)
                continue;

            PageRange_t iSegmentRange = {0};
            iSegmentRange.m_iPageMin = Maths_RoundTowardZero(pProHeader->p_vaddr,                       iPageSize);
            iSegmentRange.m_iPageMax = Maths_Round          (pProHeader->p_vaddr + pProHeader->p_memsz, iPageSize);
            Vector_PushBack(vecTempPageRanges, iSegmentRange);

            LOG("Estimated page %lx - %lx", iSegmentRange.m_iPageMin, iSegmentRange.m_iPageMax);
        }


        // Already allcoated pages.
        Vector_Clear(vecMaps);
        MapParser_Parse(pTarget, vecMaps);


        // Now starting from a default load bias we can work our way upward ( load bias += PageSize each iteration ) 
        // until we find a load bias where all segments can be loaded with no conflicts.
        uintptr_t iLoadBias = DEFAULT_LOAD_BIAS;
        bool bLoadBiasFound = false;

        for(int iAttempt = 0; iAttempt < MAX_LOAD_BIAS_FIND_ATTEMPT; iAttempt++)
        {
            iLoadBias += ( iAttempt * iPageSize );

            bool bMapCollided = false;

            for(size_t iMapIndex = 0; iMapIndex < Vector_Len(vecMaps); iMapIndex++)
            {
                MapEntry_t* pMapEntry = &vecMaps[iMapIndex];

                // Iterate over all maps this process is also allocated and check if it overlaps with 
                // any of our ( page range + load bias ).
                for(size_t iSegPageIndex = 0; iSegPageIndex < Vector_Len(vecTempPageRanges); iSegPageIndex++)
                {
                    PageRange_t* pSegPageRange = &vecTempPageRanges[iSegPageIndex];

                    bool bMinOverlapping = 
                        pSegPageRange->m_iPageMin + iLoadBias >= pMapEntry->m_iStartAdrs && 
                        pSegPageRange->m_iPageMin + iLoadBias <  pMapEntry->m_iStartAdrs + pMapEntry->m_iSize;
                    bool bMaxOverlapping = 
                        pSegPageRange->m_iPageMax + iLoadBias >= pMapEntry->m_iStartAdrs && 
                        pSegPageRange->m_iPageMax + iLoadBias <  pMapEntry->m_iStartAdrs + pMapEntry->m_iSize;

                    if(bMaxOverlapping == true || bMinOverlapping == true)
                    {
                        bMapCollided = true;
                        break;
                    }
                }

                if(bMapCollided == true)
                    break;
            }


            // if we found no collisions with this load bias. we can break out.
            if(bMapCollided == false)
            {
                bLoadBiasFound = true;
                break;
            }
        }


        if(bLoadBiasFound == false)
        {
            FAIL_LOG("Failed to find a load bias. Final load bias attempted : %p", iLoadBias);
            exit(1);
        }


        // Now we have a LoadBias which we can safely use to allocate our pages / and map our segments.
    }


    Vector_Free(vecUnqiueObj);
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool _InitMappedObject(MappedObject_t* pObj, const char* szFile)
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
    if(_StoreStringTable(pObj) == false)
        return false;


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool _StoreStringTable(MappedObject_t* pObj)
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
static bool _ResolveDependencies(MappedObject_t* pHead, MappedObject_t* pObj)
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
        MappedObject_t* pExistingObj = _FindDependency(pHead, s_szFileNameBuffer);
        if(pExistingObj != nullptr)
        {
            pObj->m_pDependencies[i] = pExistingObj;
            LOG("Found repeating dependency %s", pObj->m_pDependencies[i]->m_szName);
        }
        else
        {
            MappedObject_t* pUniqueDependency = ArenaAllocator_Allocate(g_pArenaAlloc, sizeof(MappedObject_t));

            if(_InitMappedObject(pUniqueDependency, s_szFileNameBuffer) == false)
            {
                bFailed = true; break;
            }

            pObj->m_pDependencies[i] = pUniqueDependency;
            LOG("Initialized unique dependency %s", s_szFileNameBuffer);

            if(_ResolveDependencies(pHead, pUniqueDependency) == false)
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
static MappedObject_t* _FindDependency(MappedObject_t* pHead, const char* szDependency)
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

        MappedObject_t* pObj = _FindDependency(pDepencency, szDependency);

        if(pObj != nullptr)
            return pObj;
    }

    return nullptr;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void _CollectUniqueObjects(MappedObject_t* pThisObj, MappedObject_t** pVecOut)
{
    // Is this object already pushed? 
    bool bRepeating = false;
    for(int i = 0; i < Vector_Len(pVecOut); i++)
    {
        if(pVecOut[i] == pThisObj)
        {
            bRepeating = true;
            break;
        }
    }
    

    // If not pushed already push it back.
    if(bRepeating == false)
        Vector_PushBack(pVecOut, pThisObj);


    // Recurse on dependencies.
    for(int i = 0; i < pThisObj->m_nDependencies; i++)
    {
        _CollectUniqueObjects(pThisObj->m_pDependencies[i], pVecOut);
    }
}
