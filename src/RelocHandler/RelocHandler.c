//=========================================================================
//                      Relocation Handler
//=========================================================================
// by      : INSANE
// created : 04/03/2026
//
// purpose : Handle relocations for MappedObject_t ( thats loaded ) and its 
//           dependencies.
//-------------------------------------------------------------------------
#include "RelocHandler.h"

#include <elf.h>
#include "../MappedObject/MappedObject.h"
#include "../TargetBrief/TargetBrief_t.h"
#include "../ShellCode/PTraceHelper.h"

// UTIL...
#include "../Util/Terminal/Terminal.h"

// ILIB...
#include "../../lib/ILIB/ILIB_Vector.h"


// Delete this...
static uint64_t g_iUnhandledRelocs = 0;



/* Iterate relocation talbe at 'pRel' containing Elf64_Rel entries, and process relocations. */
bool _HandleRel (const MappedObject_t* pObj, uintptr_t pRel,  size_t iRelSz,  size_t iRelEntSz,  TargetBrief_t* pTraget);

/* Iterate relocation talbe at 'pRelA' containing Elf64_Rela entries, and process relocations. */
bool _HandleRelA(const MappedObject_t* pObj, uintptr_t pRelA, size_t iRelASz, size_t iRelAEntSz, TargetBrief_t* pTraget);

/* Iterate relocation talbe at 'pRelR' containing Elf64_Relr entries, and process relocations. */
bool _HandleRelR(const MappedObject_t* pObj, uintptr_t pRelR, size_t iRelRSz, size_t iRelREntSz, TargetBrief_t* pTraget);

/* Dispatch correct relcoation handler based on relocation type. */
void _DispatchRelHandler(uint64_t iRelType, uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);

/* All relocation handlers. */
void _Handle_R_X86_64_64             (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_PC32           (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOT32          (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_PLT32          (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_COPY           (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GLOB_DAT       (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_JUMP_SLOT      (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_RELATIVE       (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOTPCREL       (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_32             (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_32S            (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_16             (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_PC16           (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_8              (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_PC8            (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_DTPMOD64       (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_DTPOFF64       (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_TPOFF64        (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_TLSGD          (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_TLSLD          (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_DTPOFF32       (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOTTPOFF       (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_TPOFF32        (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_PC64           (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOTOFF64       (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOTPC32        (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOT64          (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOTPCREL64     (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOTPC64        (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOTPLT64       (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_PLTOFF64       (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_SIZE32         (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_SIZE64         (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOTPC32_TLSDESC(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_TLSDESC_CALL   (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_TLSDESC        (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_IRELATIVE      (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_RELATIVE64     (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_GOTPCRELX      (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);
void _Handle_R_X86_64_REX_GOTPCRELX  (uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID);



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool RelocHandler_Reloc(struct MappedObject_t* pHead, TargetBrief_t* pTarget)
{
    bool bOk = true;

    MappedObject_t** vecUniqueObj = nullptr; MappedObject_CollectUniqueObjects(pHead, &vecUniqueObj);


    for(size_t iObjIndex = 0; iObjIndex < Vector_Len(vecUniqueObj); iObjIndex++)
    {
        MappedObject_t* pObj = vecUniqueObj[iObjIndex];
        LOG("%s", pObj->m_szName);


        Elf64_Phdr* pDynSegHdr  = &pObj->m_pProHeader[pObj->m_iDynSegmentIndex];
        size_t      nDynEntries = pDynSegHdr->p_filesz / sizeof(Elf64_Dyn);
        assertion(pDynSegHdr->p_type == PT_DYNAMIC && "Invalid dynamic segment index");


        uintptr_t pRel      = 0, pRelA      = 0, pRelR      = 0, pPlt   = 0; // Reloc table pointers.
        size_t    iRelSz    = 0, iRelASz    = 0, iRelRSz    = 0, iPltSz = 0; // Reloc table sizes.
        size_t    iRelEntSz = 0, iRelAEntSz = 0, iRelREntSz = 0;             // Reloc table entry sizes.


        for(Elf64_Dyn* pDyn = pObj->m_pDynamicEntries; pDyn->d_tag != DT_NULL; pDyn++)
        {
            switch (pDyn->d_tag) 
            {
                case DT_JMPREL:   if(pPlt       == 0 ) pPlt       = pDyn->d_un.d_ptr; break;
                case DT_PLTRELSZ: if(iPltSz     == 0 ) iPltSz     = pDyn->d_un.d_val; break;

                case DT_RELA:     if(pRelA      == 0 ) pRelA      = pDyn->d_un.d_ptr; break;
                case DT_RELASZ:   if(iRelASz    == 0 ) iRelASz    = pDyn->d_un.d_val; break;
                case DT_RELAENT:  if(iRelAEntSz == 0 ) iRelAEntSz = pDyn->d_un.d_val; break;

                case DT_REL:      if(pRel       == 0 ) pRel       = pDyn->d_un.d_ptr; break;
                case DT_RELSZ:    if(iRelSz     == 0 ) iRelSz     = pDyn->d_un.d_val; break;
                case DT_RELENT:   if(iRelEntSz  == 0 ) iRelEntSz  = pDyn->d_un.d_val; break;

                // case DT_TEXTREL: printf("DT_TEXTREL\n"); break;

                case DT_RELR:     if(pRelR      == 0 ) pRelR      = pDyn->d_un.d_ptr; break;
                case DT_RELRSZ:   if(iRelRSz    == 0 ) iRelRSz    = pDyn->d_un.d_val; break;
                case DT_RELRENT:  if(iRelREntSz == 0 ) iRelREntSz = pDyn->d_un.d_val; break;

                default: break;
            }
        }

        if(pRel != 0)
        {
            if(_HandleRel(pObj, pRel, iRelSz, iRelEntSz, pTarget) == false)
            {
                FAIL_LOG("Failed 'rel' relocations");
                bOk = false; break;
            }
        }
        if(pRelA != 0) 
        {
            if(_HandleRelA(pObj, pRelA, iRelASz, iRelAEntSz, pTarget) == false)
            {
                FAIL_LOG("Failed 'relA' relocations");
                bOk = false; break;
            }
        }
        if(pRelR != 0) 
        {
            if(_HandleRelR(pObj, pRelR, iRelRSz, iRelREntSz, pTarget) == false)
            {
                FAIL_LOG("Failed 'relR' relocations");
                bOk = false; break;
            }
        }

        FAIL_LOG("%zu unhandled relocations for '%s'", g_iUnhandledRelocs, pObj->m_szName);
        g_iUnhandledRelocs = 0;
    }
    
    Vector_Free(vecUniqueObj);
    return bOk;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool _HandleRel(const MappedObject_t* pObj, uintptr_t pRel, size_t iRelSz, size_t iRelEntSz, TargetBrief_t* pTarget)
{
    assertion(iRelEntSz == sizeof(Elf64_Rel) && "Mismatching relocation entry size.");
    if(iRelEntSz != sizeof(Elf64_Rel))
        return false;
    
    static size_t s_iEntrySz  = sizeof(Elf64_Rel);
    size_t        nRelEntries = iRelSz / iRelEntSz;
    uintptr_t     pTableAbs   = pObj->m_iLoadBase + pRel;

    for(size_t i = 0; i < nRelEntries; i++)
    {
        Elf64_Rel rel;

        // Read one entry.
        bool bReadWin = PTraceHelper_ReadBytes((unsigned char*)(&rel), s_iEntrySz,
                (void*)(pTableAbs + (i * s_iEntrySz)), 
                pTarget->m_iTargetPID);

        // Did we failed to read entry ?
        if(bReadWin == false)
        {
            FAIL_LOG("Failed to read relocation entry index %zu", i);
            return false;
        }

        uint64_t iRelType  = ELF64_R_TYPE(rel.r_info);
        uint64_t iSymIndex = ELF64_R_SYM (rel.r_info);

        // Get Add-End for this relocation entry.
        uint64_t iAddEnd        = 0; 
        bool     bAddEndReadWin = PTraceHelper_ReadBytes(
                (unsigned char*)(&iAddEnd),                 // buffer
                sizeof(iAddEnd),                            // buffer size
                (void*)(pObj->m_iLoadBase + rel.r_offset),  // address to read from
                pTarget->m_iTargetPID);                     // Target

        if(bAddEndReadWin == false) // Failed to read Add-End?
            return false;

        _DispatchRelHandler(iRelType, pObj->m_iLoadBase, rel.r_offset, iAddEnd, pTarget->m_iTargetPID);
    }

    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool _HandleRelA(const MappedObject_t* pObj, uintptr_t pRelA, size_t iRelASz, size_t iRelAEntSz, TargetBrief_t* pTarget)
{
    static size_t s_iEntrySz  = sizeof(Elf64_Rela);
    size_t        nRelEntries = iRelASz / s_iEntrySz;
    uintptr_t     pTableAbs   = pObj->m_iLoadBase + pRelA;


    assertion(iRelAEntSz == s_iEntrySz && "Mismatching relocation entry size.");
    if(iRelAEntSz != s_iEntrySz)
        return false;


    for(size_t i = 0; i < nRelEntries; i++)
    {
        Elf64_Rela relA = {0};

        bool bReadWin = PTraceHelper_ReadBytes((unsigned char*)(&relA), s_iEntrySz,
                (void*)(pTableAbs + (i * s_iEntrySz)), 
                pTarget->m_iTargetPID);

        if(bReadWin == false)
        {
            FAIL_LOG("Failed to read relocation entry index %zu", i);
            return false;
        }

        uint64_t iRelType  = ELF64_R_TYPE(relA.r_info);
        uint64_t iSymIndex = ELF64_R_SYM(relA.r_info);

        _DispatchRelHandler(iRelAEntSz, pObj->m_iLoadBase, relA.r_offset, relA.r_addend, pTarget->m_iTargetPID);
    }

    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool _HandleRelR(const MappedObject_t* pObj, uintptr_t pRelR, size_t iRelRSz, size_t iRelREntSz, TargetBrief_t* pTarget)
{
    static size_t s_iEntrySz  = sizeof(Elf64_Relr);
    size_t        nRelEntries = iRelRSz / s_iEntrySz;
    uintptr_t     pTableAbs   = pObj->m_iLoadBase + pRelR;


    assertion(iRelREntSz == s_iEntrySz && "Mismatching relocation entry size.");
    if(iRelREntSz != s_iEntrySz)
        return false;


    // Number of relocations done. ( dubugging use only. )
    size_t nRelsDone = 0;

    // Last relocation site that was fixed.
    uintptr_t iLastFixedLoc = UINTPTR_MAX;

    for(size_t iRelIndex = 0; iRelIndex < nRelEntries; iRelIndex++)
    {
        Elf64_Relr relR       = {0};
        uintptr_t  pEntryAdrs = pTableAbs + (iRelIndex * s_iEntrySz);

        // Read relR entry.
        bool bReadWin = PTraceHelper_ReadBytes((unsigned char*)(&relR), s_iEntrySz, (void*)(pEntryAdrs), pTarget->m_iTargetPID);

        // Failed to read.
        if(bReadWin == false) return false;


        // Even entry.
        if((relR & 1) == 0)
        {
            uint64_t  iAddEnd  = 0;
            uintptr_t iRelSite = pObj->m_iLoadBase + relR;
            bool      bReadWin = PTraceHelper_ReadBytes((unsigned char*)(&iAddEnd), s_iEntrySz, (void*)iRelSite, pTarget->m_iTargetPID);

            if(bReadWin == false) { LOG("Failed read. Even entry. Site %p", iRelSite); return false; }

            uint64_t iResolvedAdrs = pObj->m_iLoadBase + iAddEnd; // + load bias to whatever is already there ( addend. ).
            PTraceHelper_WriteBytes((unsigned char*)(&iResolvedAdrs), sizeof(iResolvedAdrs), (void*)iRelSite, pTarget->m_iTargetPID);

            iLastFixedLoc = iRelSite;
            nRelsDone++;
        }
        else
        {
            // Start at bit 1 ( 0 is for checking if its odd or not ). got to 63rd bit ( last one )
            // and relocate only the ones whose bit is toggled.
            for(uint64_t iMaskedRelIndex = 1; iMaskedRelIndex < 64; iMaskedRelIndex++)
            {
                assertion(iLastFixedLoc != UINTPTR_MAX && "this elf file has an odd relr entry as its first entry");

                iLastFixedLoc += s_iEntrySz;

                if((relR & (1llu << iMaskedRelIndex)) != 0)
                {
                    uintptr_t  iRelSite   = iLastFixedLoc;
                    Elf64_Relr relSiteVal = {0};
                    bool       bReadWin   = PTraceHelper_ReadBytes((unsigned char*)(&relSiteVal), s_iEntrySz, (void*)iRelSite, pTarget->m_iTargetPID);

                    // Failed to read.
                    if(bReadWin == false) return false;

                    uintptr_t iResolvedAdrs = pObj->m_iLoadBase + relSiteVal;
                    bool bWriteWin = PTraceHelper_WriteBytes((unsigned char*)(&iResolvedAdrs), s_iEntrySz, (void*)iRelSite, pTarget->m_iTargetPID);
                    
                    // Failed to write.
                    if(bWriteWin == false) return false;

                    nRelsDone++;
                }
            } // for(uint64_t iMaskedRelIndex = 1; iMaskedRelIndex < 64; iMaskedRelIndex++)

        }
    }

    WIN_LOG("%zu relocations done", nRelsDone);

    return nRelsDone >= nRelEntries;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void _DispatchRelHandler(uint64_t iRelType, uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)
{
    switch (iRelType) 
    {
        case R_X86_64_64:              _Handle_R_X86_64_64             (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_PC32:            _Handle_R_X86_64_PC32           (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOT32:           _Handle_R_X86_64_GOT32          (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_PLT32:           _Handle_R_X86_64_PLT32          (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_COPY:            _Handle_R_X86_64_COPY           (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GLOB_DAT:        _Handle_R_X86_64_GLOB_DAT       (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_JUMP_SLOT:       _Handle_R_X86_64_JUMP_SLOT      (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_RELATIVE:        _Handle_R_X86_64_RELATIVE       (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOTPCREL:        _Handle_R_X86_64_GOTPCREL       (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_32:              _Handle_R_X86_64_32             (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_32S:             _Handle_R_X86_64_32S            (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_16:              _Handle_R_X86_64_16             (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_PC16:            _Handle_R_X86_64_PC16           (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_8:               _Handle_R_X86_64_8              (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_PC8:             _Handle_R_X86_64_PC8            (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_DTPMOD64:        _Handle_R_X86_64_DTPMOD64       (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_DTPOFF64:        _Handle_R_X86_64_DTPOFF64       (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_TPOFF64:         _Handle_R_X86_64_TPOFF64        (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_TLSGD:           _Handle_R_X86_64_TLSGD          (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_TLSLD:           _Handle_R_X86_64_TLSLD          (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_DTPOFF32:        _Handle_R_X86_64_DTPOFF32       (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOTTPOFF:        _Handle_R_X86_64_GOTTPOFF       (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_TPOFF32:         _Handle_R_X86_64_TPOFF32        (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_PC64:            _Handle_R_X86_64_PC64           (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOTOFF64:        _Handle_R_X86_64_GOTOFF64       (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOTPC32:         _Handle_R_X86_64_GOTPC32        (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOT64:           _Handle_R_X86_64_GOT64          (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOTPCREL64:      _Handle_R_X86_64_GOTPCREL64     (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOTPC64:         _Handle_R_X86_64_GOTPC64        (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOTPLT64:        _Handle_R_X86_64_GOTPLT64       (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_PLTOFF64:        _Handle_R_X86_64_PLTOFF64       (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_SIZE32:          _Handle_R_X86_64_SIZE32         (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_SIZE64:          _Handle_R_X86_64_SIZE64         (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOTPC32_TLSDESC: _Handle_R_X86_64_GOTPC32_TLSDESC(iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_TLSDESC_CALL:    _Handle_R_X86_64_TLSDESC_CALL   (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_TLSDESC:         _Handle_R_X86_64_TLSDESC        (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_IRELATIVE:       _Handle_R_X86_64_IRELATIVE      (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_RELATIVE64:      _Handle_R_X86_64_RELATIVE64     (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_GOTPCRELX:       _Handle_R_X86_64_GOTPCRELX      (iLoadBias, iOffset, iAddEnd, iTargetID); break;
        case R_X86_64_REX_GOTPCRELX:   _Handle_R_X86_64_REX_GOTPCRELX  (iLoadBias, iOffset, iAddEnd, iTargetID); break;
    }
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void _Handle_R_X86_64_64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)              { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_PC32(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)            { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GOT32(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)           { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_PLT32(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)           { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_COPY(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)            { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GLOB_DAT(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)        { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_JUMP_SLOT(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)       { g_iUnhandledRelocs++; }


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void _Handle_R_X86_64_RELATIVE(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)
{
    // NOTE: Endian is handled according to this machine.
    uintptr_t iResolvedAdrs = iLoadBias + iAddEnd;
    PTraceHelper_WriteBytes((unsigned char*)&iResolvedAdrs, sizeof(iResolvedAdrs), (void*)(iLoadBias + iOffset), iTargetID);
}


void _Handle_R_X86_64_GOTPCREL(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)        { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_32(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)              { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_32S(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)             { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_16(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)              { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_PC16(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)            { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_8(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)               { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_PC8(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)             { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_DTPMOD64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)        { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_DTPOFF64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)        { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_TPOFF64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)         { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_TLSGD(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)           { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_TLSLD(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)           { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_DTPOFF32(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)        { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GOTTPOFF(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)        { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_TPOFF32(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)         { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_PC64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)            { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GOTOFF64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)        { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GOTPC32(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)         { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GOT64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)           { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GOTPCREL64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)      { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GOTPC64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)         { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GOTPLT64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)        { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_PLTOFF64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)        { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_SIZE32(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)          { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_SIZE64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)          { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GOTPC32_TLSDESC(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID) { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_TLSDESC_CALL(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)    { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_TLSDESC(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)         { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_IRELATIVE(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)       { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_RELATIVE64(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)      { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_GOTPCRELX(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)       { g_iUnhandledRelocs++; }
void _Handle_R_X86_64_REX_GOTPCRELX(uintptr_t iLoadBias, uintptr_t iOffset, uintptr_t iAddEnd, pid_t iTargetID)   { g_iUnhandledRelocs++; }
