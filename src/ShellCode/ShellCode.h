//=========================================================================
//                      Shell Code
//=========================================================================
// by      : INSANE
// created : 18/02/2026
//
// purpose : Handle Shell Code generation & execution.
//-------------------------------------------------------------------------
#ifndef SHELLCODE_H
#define SHELLCODE_H

#include "../Alias.h"


struct TargetBrief_t;


/* Generate shell code to load all PT_LOAD segments of given file. */
bool ShellCode_MapSharedObject(const char* szFile, struct TargetBrief_t* pTarget);



#endif
