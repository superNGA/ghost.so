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



/* Generate shell code to load all PT_LOAD segments of given file. */
int ShellCode_MapSharedObject(const char* szFile);



#endif
