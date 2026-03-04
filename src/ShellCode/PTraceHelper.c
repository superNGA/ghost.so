//=========================================================================
//                      PTrace Helper
//=========================================================================
// by      : INSANE
// created : 03/03/2026
//
// purpose : Useful wrappers for ptrace().
//-------------------------------------------------------------------------
#include "PTraceHelper.h"

#include <errno.h>
#include <stdint.h>
#include <sys/ptrace.h>

#include "../Util/Util.h"
#include "../Util/AAManager/AAManager.h"
#include "../Util/Terminal/Terminal.h"
#include "../../lib/ILIB/ILIB_ArenaAllocator.h"


REGISTER_ARENA(g_pArena, 1024);



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool PTraceHelper_WriteBytes(unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID)
{
    if(nBytes == 0)
        return false;


    size_t nIterations = ((nBytes - 1) / sizeof(long)) + 1;
    for(size_t i = 0; i < nIterations; i++)
    {
        long            iData    = 0;
        unsigned char*  szBytes  = (unsigned char*)&iData;
        const uintptr_t iAddress = (uintptr_t)pAddress + (i * sizeof(long));

        // NOTE : Since ptarce(pokedata) writes 8 bytes at a time ( sizeof(long) )
        //      we can write in all iterations ( 8 bytes ) correctly except for the last 
        //      iterations ( where we have nBytes % sizeof(long) bytes ). In that case we have
        //      to first read the original bytes at that location and modifying some bytes
        //      and keep the remaning intact, and write it back.
        if(i < nIterations - 1)
        {
            for(int j = 0; j < sizeof(long); j++)
            {
                int iAbsIndex = (i * sizeof(long)) + j;
                szBytes[j]    = pBytes[iAbsIndex];
            }
        }
        else
        {
            errno = 0;
            iData = ptrace(PTRACE_PEEKDATA, iThreadID, iAddress, NULL);

            if(iData == -1 && errno != 0) // peekdata failed?
                return false;

            for(int j = 0; j < sizeof(long); j++)
            {
                const int iAbsIndex = (i * sizeof(long)) + j;

                if(iAbsIndex >= nBytes)
                    break;

                szBytes[j] = pBytes[iAbsIndex];
            }
        }

        errno         = 0;
        long iErrCode = ptrace(PTRACE_POKEDATA, iThreadID, iAddress, iData);
        if(iErrCode == -1 && errno != 0) // pokedata failed ?
            return false;
    }


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool PTraceHelper_ReadBytes(unsigned char* pBytes, size_t nBytes, void* pAddress, pid_t iThreadID)
{
    if(nBytes == 0)
        return false;


    size_t nIterations = ((nBytes - 1) / sizeof(long)) + 1;
    for(size_t i = 0; i < nIterations; i++)
    {
        errno = 0;

        const uintptr_t iAddress = (uintptr_t)pAddress + (i * sizeof(long));
        const long      iData    = ptrace(PTRACE_PEEKDATA, iThreadID, iAddress, NULL);

        // did ptrace(PEEKDATA) failed?
        if(iData == -1 && errno != 0)
            return false;

        for(int j = 0; j < sizeof(long); j++)
        {
            const unsigned char* szBytes   = (const unsigned char*)&iData;
            const int            iAbsIndex = (i * sizeof(long)) + j;

            if(iAbsIndex >= nBytes)
                break;

            pBytes[iAbsIndex] = szBytes[j];
        }
    }


    return true;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
bool PTraceHelper_WriteBytesFromFile(const char* szFile, size_t nBytes, size_t iOffset, void* pVAdrs, pid_t iThreadID)
{
    size_t iArenaCapacity = Arena_Capacity(g_pArena);
    size_t nBytesWritten  = 0;

    while(true)
    {
        if(nBytesWritten >= nBytes)
            break;

        Arena_Memset(g_pArena, 0);
        void* pBuffer = Arena_AllocateAll(g_pArena);

        // Read n bytes from file.
        size_t nBytesLeft   = nBytes - nBytesWritten;
        size_t nBytesToRead = nBytesLeft >= iArenaCapacity ? iArenaCapacity : nBytesLeft;
        size_t nBytesRead   = Util_ReadFromFile(szFile, pBuffer, iOffset + nBytesWritten, nBytesToRead);

        // Did we failed to read ?
        if(nBytesRead != nBytesToRead)
        {
            FAIL_LOG("An error occured while reading %zu bytes from file %s. Only read %zu bytes.", 
                    nBytesToRead, szFile, nBytesRead);
            return false;
        }

        // Write to target process.
        bool bWriteOpWin = PTraceHelper_WriteBytes(pBuffer, nBytesRead, (void*)((uintptr_t)pVAdrs + nBytesWritten), iThreadID);
        if(bWriteOpWin == false)
        {
            FAIL_LOG("Failed to write %zu bytes @ %zu using ptrace()", nBytesRead, (size_t)pVAdrs); 
            return false;
        }

        nBytesWritten += nBytesRead;
    }


    return true;
}
