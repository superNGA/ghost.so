//=========================================================================
//                      Utility
//=========================================================================
// by      : INSANE
// created : 25/02/2026
//
// purpose : Utility stuff. 
//-------------------------------------------------------------------------
#include "Util.h"
#include <stdio.h>



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
size_t Util_ReadFromFile(const char* szFile, void* pBuffer, size_t iSeekOffset, size_t nBytes)
{
    // open file handle.
    FILE* pFile = fopen(szFile, "r");
    if(pFile == NULL)
        return 0;

    // seek.
    fseek(pFile, iSeekOffset, SEEK_SET);

    // Read.
    size_t nBytesRead = fread(pBuffer, 1, nBytes, pFile);

    // close file handle.
    fclose(pFile);

    // return bytes read.
    return nBytesRead;
}
