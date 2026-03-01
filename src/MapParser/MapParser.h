//=========================================================================
//                      Map Parser
//=========================================================================
// by      : INSANE
// created : 01/03/2026
//
// purpose : parse /proc/<ProcID>/maps file and store in a minimal struct.
//-------------------------------------------------------------------------
#ifndef MAPPARSER_H
#define MAPPARSER_H


#include <stdbool.h>
#include <stdint.h>


struct TargetBrief_t;

#define MAX_MAP_PATH_NAME_SIZE (256)


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
typedef struct MapEntry_t
{
    uint64_t m_iStartAdrs;   // map address start.
    uint64_t m_iSize;        // map address size ( end - start )

    bool     m_bPermRead;    // Read premission for this map.
    bool     m_bPermWrite;   // Write premission for this map.
    bool     m_bPermExec;    // Execution premission for this map.
    bool     m_bPermPrivate; // Private ( copy on write ) map.

    uint64_t m_iFileOffset;  // Offset into the file/whatever.
    uint16_t m_iDevMajor;    // device ( major ) 
    uint16_t m_iDevMinor;    // device ( minor )
    uint32_t m_iInode;       // inode of device.

    // file path thats backcing this mapping.
    char     m_szPathName[MAX_MAP_PATH_NAME_SIZE]; 

    
} MapEntry_t;


/* Synchronous. Parse /proc/<procID>/maps file for target process PTARGET and 
   an return an array of MapEntry_t instances. */
struct MapEntry_t* MapParser_Parse(struct TargetBrief_t* pTarget);


#endif
