//=========================================================================
//                      Target Brief
//=========================================================================
// by      : INSANE
// created : 17/02/2026
//
// purpose : Brief information about target process.
//-------------------------------------------------------------------------
#ifndef TARGETBRIEF_T_H
#define TARGETBRIEF_T_H

#include <sys/types.h>


#define MAX_TARGET_NAME 128 // In Bytes


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
struct TargetBrief_t
{
    char  m_szTargetName[MAX_TARGET_NAME];
    pid_t m_iTargetPID;
};
typedef struct TargetBrief_t TargetBrief_t;


/* To initialize TargetBrief_t from target process's ID. */
int TargetBrief_InitializePID(TargetBrief_t* pThis, pid_t iTargetPID);

/* To initialize TargetBrief_t from target process's name.
   Target process name will only be effective after the last backslash (/) 
   so absolute or relative addresses are also fine.*/
int TargetBrief_InitializeName(TargetBrief_t* pThis, const char* szTargetName);


#endif // TARGETBRIEF_T_H
