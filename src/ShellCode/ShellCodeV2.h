//=========================================================================
//                      Shell Code
//=========================================================================
// by      : INSANE
// created : 27/02/2026
//
// purpose : Handle shellcode injection and execution into target process 
//           using pTrace
//-------------------------------------------------------------------------
#ifndef SHELLCODE_V2_H
#define SHELLCODE_V2_H

#include <stddef.h>
#include <stdbool.h>

struct TargetBrief_t;



/* Stop all threads of the target process PTARGET using ( PTRACE_SEIZE + PTRACE_INTERRUPT ).
   This is a synchronous ( pretty big word init ) function. Returns false on failure. */
bool ShellCode_StopTargetAllThreads(struct TargetBrief_t* pTarget);


/* Start / unfreeze all threads of the target process PTARGET using pTrace(PTRACE_DETACH). 
   This is a synchronous function. Returns false on failure. */
bool ShellCode_StartTargetAllThreads(struct TargetBrief_t* pTarget);


/* Injects shellcode in process PTARGET, executes and restores, resulting in a call to 
   mmap() with first argument as PVADDR ( preferred address for mapping )
   and second argument as ISIZE ( size of allocation ).
   Returns mmap()'s return value. */
void* ShellCode_MMap(struct TargetBrief_t* pTarget, void* pVAddr, size_t iSize);


/* Injects shellcode in process PTARGET, executes and restores, resulting in a call to 
   munmap() with first argument as PVADDR ( starting address of the memory mapping to 
   be removed. ) and second argument as ISIZE ( size of memory area to be unmapped 
   in bytes ). Returns munmap()'s return value. */
int ShellCode_MUnMap(struct TargetBrief_t* pTarget, void* pVAddr, size_t iSize);


#endif
