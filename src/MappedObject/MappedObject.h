//=========================================================================
//                      Mapped Object
//=========================================================================
// by      : INSANE
// created : 22/02/2026
//
// purpose : Mapping information and dependency info for a .so file.
//-------------------------------------------------------------------------
#ifndef MAPPEDOBJECT_H
#define MAPPEDOBJECT_H


#include <elf.h>
#include <stdbool.h>
#include <stddef.h>


#define MAX_MAPPED_OBJECT_NAME_SIZE (128)


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
typedef struct MappedObject_t
{
    Elf64_Ehdr  m_elfHeader;         // Elf header of this elf object.
    Elf64_Phdr* m_pProHeader;        // Program ( segment ) headers of this object.
    Elf64_Dyn*  m_pDynamicEntries;   // PT_DYNAMIC segment. 
    size_t      m_iDynSegmentIndex;  // Index of the first PT_DYNAMIC segment.
    uintptr_t   m_iLoadBase;         // Offest at which first segment is loaded at.

    const char* m_szStringTable;     // Holds the (.dynstr) string table.
    size_t      m_iStringTableSize;  // size of the string table in bytes.

    char        m_szName[MAX_MAPPED_OBJECT_NAME_SIZE]; // File's name.
    struct MappedObject_t** m_pDependencies;                       // DT_NEEDED entries for this shared object.
    size_t      m_nDependencies;     // Number of dependencies.

} MappedObject_t;


/* Load this shared object file as "struct MappedObject_t" and all of its dependencies 
   forming a tree structure. */
bool MappedObject_Initialize(MappedObject_t* pObj, const char* szFile);


#endif
