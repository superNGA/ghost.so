//=========================================================================
//                      Utility
//=========================================================================
// by      : INSANE
// created : 25/02/2026
//
// purpose : Utility stuff. 
//-------------------------------------------------------------------------
#ifndef UTILITY_H
#define UTILITY_H


#include <stddef.h>
#include <unistd.h>


/* Read NBYTES bytes from SZFILE into PBUFFER. Returns number of bytes read. */
size_t Util_ReadFromFile(const char* szFile, void* pBuffer, size_t iSeekOffset, size_t nBytes);


#endif
