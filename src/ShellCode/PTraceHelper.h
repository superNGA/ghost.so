//=========================================================================
//                      PTrace Helper
//=========================================================================
// by      : INSANE
// created : 03/03/2026
//
// purpose : Useful wrappers for ptrace().
//-------------------------------------------------------------------------
#ifndef PTRACE_HELPER_H
#define PTRACE_HELPER_H


#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>


/* Read NBYTES from virtual address PADDRESS of target process ITHREADID into buffer PBYTES 
   using ptrace(PTRACE_PEEKDATA) */
bool PTraceHelper_ReadBytes(
        unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID);

/* Write NBYTES at virtual address PADDRESS of target process ITHREADID from buffer PBYTES 
   using ptrace(PTRACE_POKEDATA) */
bool PTraceHelper_WriteBytes(
        unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID);


/* Write NBYTEs at virtual address VADRS of target process ITHREADID from file 
   SZFILE starting from offset IOFFSEt into the file. */
bool PTraceHelper_WriteBytesFromFile(
        const char* szFile, size_t nBytes, size_t iOffset, void* pVAdrs, pid_t iThreadID);


#endif
