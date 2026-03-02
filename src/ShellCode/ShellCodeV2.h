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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct TargetBrief_t;



/* Synchronous. Stop all threads of the target process PTARGET using
   ( PTRACE_SEIZE + PTRACE_INTERRUPT ). Returns false on failure. */
bool ShellCode_StopTargetAllThreads(struct TargetBrief_t* pTarget);


/* Synchronous. Start / unfreeze all threads of the target process PTARGET
   using pTrace(PTRACE_DETACH). Returns false on failure. */
bool ShellCode_StartTargetAllThreads(struct TargetBrief_t* pTarget);


/* Injects shellcode in process PTARGEt, execute and restores, resulting in a call to 
   mmap(PVADDR, ISIZE, PPROTECTION, IMAPFLAGS, -1, 0). 
   Returns mmap() output. */
void* ShellCode_MMap(struct TargetBrief_t* pTarget, void* pVAddr, size_t iSize, uint32_t iMapProtection, uint32_t iMapFlags);


/* Injects shellcode in process PTARGET, executes and restores, resulting in a call to 
   munmap() with first argument as PVADDR ( starting address of the memory mapping to 
   be removed. ) and second argument as ISIZE ( size of memory area to be unmapped 
   in bytes ). Returns munmap()'s return value. */
int ShellCode_MUnMap(struct TargetBrief_t* pTarget, void* pVAddr, size_t iSize);


#endif
