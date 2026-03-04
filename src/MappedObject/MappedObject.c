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
#include "../ShellCode/PTraceHelper.h"
#include "../TargetBrief/TargetBrief_t.h"
#include "../MapParser/MapParser.h"

// ILIB...
#include "../../lib/ILIB/ILIB_Vector.h"
#include "../../lib/ILIB/ILIB_ArenaAllocator.h"
#include "../Util/AAManager/AAManager.h"
#include "../../lib/ILIB/ILIB_Maths.h"

// SHA-256 hashing for verifying loaded segments.
#include "../Util/SHA-256/sha256.h"


#define MAX_LOAD_BIAS_FIND_ATTEMPT (100000) // 100K attempts.
#define DEFAULT_LOAD_BIAS          (0x500000000000)


// Globals...
REGISTER_ARENA_ALLOCATOR(g_pArenaAlloc);
REGISTER_ARENA(g_pArena, 1024);



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
typedef struct MapRange_t
{
    uintptr_t m_iMapMin; // Min ( start ) address of map.
    uintptr_t m_iMapMax; // Max ( end )   address of map.

    Elf64_Phdr* m_pOwnerSegmentHdr; // Pointer to program header of the segment which is mapped @ this map.

} MapRange_t;



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


/* Push back PHEAD and all of its dependencies to PVECOUT ( address of MappedObject_t** ( array of MappedObject_t*)),
   skipping repeating dependencies. */
static void _CollectUniqueObjects(MappedObject_t* pThisObj, MappedObject_t*** pVecOut);


/* Generate page aligned map ranges for all PT_LOAD segments of MappedObject_t POBJ. */
static void _GenerateObjMaps(MapRange_t** vecObjMaps, MappedObject_t* pObj);


/* Find a memory address in virtual memory space of target, such that all maps in VECOBJMAPS 
   can be allocated without collision. Returns 0 on failure. */
static uintptr_t _FindLoadBias(uintptr_t iDefaultLoadBias, size_t iMaxAttempt, const MapRange_t* vecObjMaps, const MapEntry_t* vecTargetMaps);


/* Allocate all maps in VECOBJMAPS using shellcode and write "owner" segments
   to allocated space. */
static bool _WriteObjToMemory(MappedObject_t* pObj, const MapRange_t* vecObjMaps, TargetBrief_t* pTarget);


/* Generate SHA-256 hash for NBYTES from file SZFILE at IOFFSET. */
static bool _GenerateSHA256File(const char* szFile, size_t nBytes, size_t iOffset, BYTE* pHashOut);


/* Generate SHA-256 hash for NBYTES from virtual address PVADRS of process PTARGET. */
static bool _GenerateSHA256PTrace(TargetBrief_t* pTarget, size_t nBytes, void* pVAdrs, BYTE* pHashOut);



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
    bool bOk = true;

    // Page size.
    long iPageSize = sysconf(_SC_PAGESIZE);


    // pHead + dependencies ( skip repetition. )
    MappedObject_t** vecUniqueObj = nullptr; Vector_Reserve(vecUniqueObj, 1);
    _CollectUniqueObjects(pHead, &vecUniqueObj);

    MapRange_t* vecObjMaps    = nullptr; // Obj Maps. ( to load )
    MapEntry_t* vecTargetMaps = nullptr; // Target Maps. ( already loaded. )


    // for all obj, Generate map -> Find Load Bias -> Load -> Write.
    for(size_t iObjIndex = 0; iObjIndex < Vector_Len(vecUniqueObj); iObjIndex++)
    {
        MappedObject_t* pObj = vecUniqueObj[iObjIndex];


        // Step 1. Page align segment start & end.
        Vector_Clear(vecObjMaps); _GenerateObjMaps(&vecObjMaps, pObj);


        // Step 2. Know what maps already exist.
        Vector_Clear(vecTargetMaps); MapParser_Parse(pTarget, &vecTargetMaps);


        // Step 3. Find load bias.
        pObj->m_iLoadBase = _FindLoadBias(DEFAULT_LOAD_BIAS, MAX_LOAD_BIAS_FIND_ATTEMPT, vecObjMaps, vecTargetMaps);
        if(pObj->m_iLoadBase == 0)
        {
            FAIL_LOG("Failed to find load bias");
            bOk = false;
            break;
        }


        // Step 4. mmap() + write segment to target.
        if(_WriteObjToMemory(pObj, vecObjMaps, pTarget) == false)
        {
            FAIL_LOG("Failed to write object for object : %s", pObj->m_szName);
            bOk = false;
            break;
        }


        WIN_LOG("Mapped %s", pObj->m_szName);
    }


    Vector_Free(vecUniqueObj );
    Vector_Free(vecTargetMaps);
    Vector_Free(vecObjMaps   );
    return bOk;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool MappedObject_RestoreTo(const struct MapEntry_t* pRestoreTo, struct TargetBrief_t* pTarget)
{
    /* This functions is not "VeRy FaSt AnD oPtImAl", but it is simple. And we are in no hurry.
       This function needs to be correct before it needs to be fast. */

    // New maps ( to compare pRestoreTo against. )
    MapEntry_t* vecNewMaps  = nullptr; MapParser_Parse(pTarget, &vecNewMaps);

    long        iPageSize   = sysconf(_SC_PAGESIZE);
    size_t      nPagesFreed = 0;
    
    for(size_t iMapIndex = 0; iMapIndex < Vector_Len(vecNewMaps); iMapIndex++)
    {
        MapEntry_t* pNewMap = &vecNewMaps[iMapIndex];

        assertion((pNewMap->m_iSize % iPageSize) == 0 && "Map size in a MapEntry is not page alinged.");
        size_t nPages         = pNewMap->m_iSize / iPageSize;
        size_t iFirstFreePage = 0;
        size_t iPageIndex     = 0;
        for(; iPageIndex < nPages; iPageIndex++)
        {
            uintptr_t pPageAdrs        = pNewMap->m_iStartAdrs + (iPageIndex * iPageSize);
            bool      bPageOverlapping = false;

            for(size_t i = 0; i < Vector_Len(pRestoreTo); i++)
            {
                const MapEntry_t* pOriginalMap = &pRestoreTo[i];

                bool bPageOnLeft  = pPageAdrs                  + iPageSize             <= pOriginalMap->m_iStartAdrs;
                bool bPageOnRight = pOriginalMap->m_iStartAdrs + pOriginalMap->m_iSize <= pPageAdrs;

                assertion((bPageOnRight == true && bPageOnLeft == true) == false && "Something's fucked up bro");

                // This page is overlapping with this MapEntry_t entry.
                if(bPageOnLeft == false && bPageOnRight == false)
                {
                    bPageOverlapping = true;
                    break;
                }
            }

            if(bPageOverlapping == false)
                continue;

            if(iFirstFreePage < iPageIndex)
            {
                ShellCode_MUnMap(pTarget, (void*)(pNewMap->m_iStartAdrs + (iFirstFreePage * iPageSize)), (iPageIndex - iFirstFreePage) * iPageSize);
                nPagesFreed   += iPageIndex - iFirstFreePage;
                iFirstFreePage = iPageIndex;
            }

            iFirstFreePage++;
        }

        // Flushing.
        if(iFirstFreePage < iPageIndex)
        {
            ShellCode_MUnMap(pTarget, (void*)(pNewMap->m_iStartAdrs + (iFirstFreePage * iPageSize)), (iPageIndex - iFirstFreePage) * iPageSize);
            nPagesFreed   += iPageIndex - iFirstFreePage;
            iFirstFreePage = iPageIndex;
        }
    }

    WIN_LOG("Freed %zu pages", nPagesFreed);


    Vector_Free(vecNewMaps);
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool MappedObject_VerifyLoadedObj(MappedObject_t* pHead, struct TargetBrief_t* pTarget)
{
    // pHead + Dependencies ( skip repeating dependencies )
    MappedObject_t** vecUniqueObj = nullptr; _CollectUniqueObjects(pHead, &vecUniqueObj);

    BYTE hashFile  [SHA256_BLOCK_SIZE] = {0};
    BYTE hashTarget[SHA256_BLOCK_SIZE] = {0};

    bool bOk = true;

    for(size_t iObjIndex = 0; iObjIndex < Vector_Len(vecUniqueObj); iObjIndex++)
    {
        const MappedObject_t* pObj = vecUniqueObj[iObjIndex];
        // invalid load base -> not initialized.
        assertion(pObj->m_iLoadBase != 0 && "Load base is 0. This MappedObject_t is invalid.");

        LOG("Verifying '%s'", pObj->m_szName);

        int nVerifiedSegments = 0;
        for(size_t iHdrIndex = 0; iHdrIndex < pObj->m_elfHeader.e_phnum; iHdrIndex++)
        {
            const Elf64_Phdr* pProHeader = &pObj->m_pProHeader[iHdrIndex];
            // only PT_LOAD segments are loaded.
            if(pProHeader->p_type != PT_LOAD)
                continue;


            // Generate SHA-256 hash for this segment using file.
            if(_GenerateSHA256File(pObj->m_szName, pProHeader->p_filesz, pProHeader->p_offset, hashFile) == false)
            {
                FAIL_LOG("Failed to generate SHA-256 for file '%s' segment index '%d'", 
                        pObj->m_szName, nVerifiedSegments);

                bOk = false; break;
            }

            // Generate SHA-256 hash for this segment from bytes at address "where it is supposed to be".
            if(_GenerateSHA256PTrace(pTarget, pProHeader->p_filesz, (void*)(pObj->m_iLoadBase + pProHeader->p_vaddr), hashTarget) == false)
            {
                FAIL_LOG("Failed to generate SHA-256 for '%s' for %zu bytes @ %p", 
                        pObj->m_szName, pProHeader->p_filesz, (void*)(pObj->m_iLoadBase + pProHeader->p_vaddr));

                bOk = false; break;
            }


            if(memcmp(hashFile, hashTarget, SHA256_BLOCK_SIZE) != 0)
            {
                FAIL_LOG("SHA-256 Hash didn't match");

                printf("SHA-256 file   : ");
                for(int i = 0; i < SHA256_BLOCK_SIZE; i++) printf("%02x", hashFile[i]); printf("\n");
                printf("SHA-256 memory : ");
                for(int i = 0; i < SHA256_BLOCK_SIZE; i++) printf("%02x", hashTarget[i]); printf("\n");

                bOk = false;
                break;
            }

            static char s_szTempBuffer[65] = {0};
            for(int i = 0; i < SHA256_BLOCK_SIZE; i++)
                snprintf(s_szTempBuffer + (i * 2), 3, "%02x", hashTarget[i]);

            WIN_LOG("SHA-256 hash matched %s", s_szTempBuffer);
            
            nVerifiedSegments++;
        }

        WIN_LOG("'%s' verified %d segments", pObj->m_szName, nVerifiedSegments);
    }


    Vector_Free(vecUniqueObj);
    return bOk;
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
static void _CollectUniqueObjects(MappedObject_t* pThisObj, MappedObject_t*** pVecOut)
{
    // Is this object already pushed? 
    bool bRepeating = false;
    for(int i = 0; i < Vector_Len(*pVecOut); i++)
    {
        if((*pVecOut)[i] == pThisObj)
        {
            bRepeating = true;
            break;
        }
    }
    

    // If not pushed already push it back.
    if(bRepeating == false)
        Vector_PushBack(*pVecOut, pThisObj);


    // Recurse on dependencies.
    for(int i = 0; i < pThisObj->m_nDependencies; i++)
    {
        _CollectUniqueObjects(pThisObj->m_pDependencies[i], pVecOut);
    }
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void _GenerateObjMaps(MapRange_t** vecObjMaps, MappedObject_t* pObj)
{
    Vector_Clear(*vecObjMaps);

    long iPageSize = sysconf(_SC_PAGESIZE);

    for(size_t i = 0; i < pObj->m_elfHeader.e_phnum; i++)
    {
        Elf64_Phdr* pProHeader = &pObj->m_pProHeader[i];

        if(pProHeader->p_type != PT_LOAD)
            continue;

        MapRange_t mapRange = {0};
        mapRange.m_iMapMin          = Maths_RoundTowardZero(pProHeader->p_vaddr,                       iPageSize);
        mapRange.m_iMapMax          = Maths_Round          (pProHeader->p_vaddr + pProHeader->p_memsz, iPageSize);
        mapRange.m_pOwnerSegmentHdr = pProHeader;

        assertion(mapRange.m_iMapMin >= 0 && mapRange.m_iMapMax > mapRange.m_iMapMin && "Invalid min & max");
        assertion(mapRange.m_pOwnerSegmentHdr != nullptr && "Invalid owner segment");

        Vector_PushBack(*vecObjMaps, mapRange);
    }
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static uintptr_t _FindLoadBias(uintptr_t iDefaultLoadBias, size_t iMaxAttempt, const MapRange_t* vecObjMaps, const MapEntry_t* vecTargetMaps)
{
    uintptr_t iLoadBias = iDefaultLoadBias;
    uintptr_t iPageSize = (uintptr_t)sysconf(_SC_PAGESIZE);

    for(size_t iAttempt = 0; iAttempt < iMaxAttempt; iAttempt++)
    {
        iLoadBias += iPageSize;

        bool bMapCollided = false;

        for(size_t iTargetMapIndex = 0; iTargetMapIndex < Vector_Len(vecTargetMaps); iTargetMapIndex++)
        {
            const MapEntry_t* pTargetMap = &vecTargetMaps[iTargetMapIndex];

            // Iterate over all maps this process is also allocated and check if it overlaps with 
            // any of our ( page range + load bias ).
            for(size_t iObjMapIndex = 0; iObjMapIndex < Vector_Len(vecObjMaps); iObjMapIndex++)
            {
                const MapRange_t* pObjMap = &vecObjMaps[iObjMapIndex];

                assertion(pTargetMap->m_iStartAdrs < pTargetMap->m_iStartAdrs + pTargetMap->m_iSize && "Invalid target map");
                assertion(pObjMap->m_iMapMax       > pObjMap->m_iMapMin                             && "Invalid obj map");

                // Is object map entirely on left.
                bool bObjMapOnLeft = pObjMap->m_iMapMax + iLoadBias < pTargetMap->m_iStartAdrs;
                // Is object map entirely on right.
                bool bObjMapOnRight = pObjMap->m_iMapMin + iLoadBias >= pTargetMap->m_iStartAdrs + pTargetMap->m_iSize;

                assertion((bObjMapOnRight == true && bObjMapOnLeft == true) == false && "Object map can't be entirely on left and right at the same time");

                if(bObjMapOnLeft == false && bObjMapOnRight == false)
                {
                    bMapCollided = true;
                    break;
                }
            }

            if(bMapCollided == true)
                break;
        }


        // No collisions? good.
        if(bMapCollided == false)
            return iLoadBias;
    }

    return 0;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool _WriteObjToMemory(MappedObject_t* pObj, const MapRange_t* vecObjMaps, TargetBrief_t* pTarget)
{
    for(size_t i = 0; i < Vector_Len(vecObjMaps); i++)
    {
        const MapRange_t* pObjMap = &vecObjMaps[i];

        void* pAllocatedMap = ShellCode_MMap(pTarget, 
                (void*)(pObj->m_iLoadBase + pObjMap->m_iMapMin),    // Map address. 
                pObjMap->m_iMapMax - pObjMap->m_iMapMin,            // Map size.
                pObjMap->m_pOwnerSegmentHdr->p_flags,               // Map protection.
                MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE); // Map Flags.

        if(pAllocatedMap == MAP_FAILED)
            return false;

        
        // Write from file to newly allocated memory.
        bool bSegWriteWin = PTraceHelper_WriteBytesFromFile(
                pObj->m_szName,                        // File's path.
                pObjMap->m_pOwnerSegmentHdr->p_filesz, // Bytes to write. 
                pObjMap->m_pOwnerSegmentHdr->p_offset, // Segment start offset into file.
                (void*)(pObj->m_iLoadBase + pObjMap->m_pOwnerSegmentHdr->p_vaddr), // Allocated map.
                pTarget->m_iTargetPID);                // Main thread id of target process.
    
        if(bSegWriteWin == false)
            return false;

        LOG("Mapped Segment %zu / %zu", i + 1, Vector_Len(vecObjMaps));
    }


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool _GenerateSHA256File(const char* szFile, size_t nBytes, size_t iOffset, BYTE* pHashOut)
{
    SHA256_CTX ctx; sha256_init(&ctx);

    size_t iArenaCapacity = Arena_Capacity(g_pArena);
    size_t nBytesHashed  = 0;

    while(true)
    {
        if(nBytesHashed >= nBytes)
            break;

        Arena_Memset(g_pArena, 0);
        void* pBuffer = Arena_AllocateAll(g_pArena);

        // Read n bytes from file.
        size_t nBytesLeft   = nBytes - nBytesHashed;
        size_t nBytesToRead = nBytesLeft >= iArenaCapacity ? iArenaCapacity : nBytesLeft;
        size_t nBytesRead   = Util_ReadFromFile(szFile, pBuffer, iOffset + nBytesHashed, nBytesToRead);

        // Did we failed to read ?
        if(nBytesRead != nBytesToRead)
        {
            FAIL_LOG("An error occured while reading %zu bytes from file %s. Only read %zu bytes.", 
                    nBytesToRead, szFile, nBytesRead);
            return false;
        }

        sha256_update(&ctx, pBuffer, nBytesRead);

        nBytesHashed += nBytesRead;
    }

    sha256_final(&ctx, pHashOut);
    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static bool _GenerateSHA256PTrace(TargetBrief_t* pTarget, size_t nBytes, void* pVAdrs, BYTE* pHashOut)
{
    SHA256_CTX ctx; sha256_init(&ctx);


    size_t iArenaCapacity = Arena_Capacity(g_pArena);
    size_t nBytesHashed  = 0;

    while(true)
    {
        if(nBytesHashed >= nBytes)
            break;

        Arena_Memset(g_pArena, 0);
        void* pBuffer = Arena_AllocateAll(g_pArena);

        // Read n bytes from target.
        size_t nBytesLeft   = nBytes - nBytesHashed;
        size_t nBytesToRead = nBytesLeft >= iArenaCapacity ? iArenaCapacity : nBytesLeft;
        bool bPTraceReadWin = PTraceHelper_ReadBytes(pBuffer, nBytesToRead, (void*)((uintptr_t)pVAdrs + nBytesHashed), pTarget->m_iTargetPID);
        if(bPTraceReadWin == false)
            return false;

        sha256_update(&ctx, pBuffer, nBytesToRead);

        nBytesHashed += nBytesToRead;
    }

    sha256_final(&ctx, pHashOut);
    return true;
}
