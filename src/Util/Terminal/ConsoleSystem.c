//=========================================================================
//                      Printf Wrapper
//=========================================================================
// by      : INSANE
// created : 26/01/2026
//
// purpose : Printf wrapper for convinence.
//-------------------------------------------------------------------------
#include "ConsoleSystem.h"
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>



static pthread_mutex_t s_mtx = PTHREAD_MUTEX_INITIALIZER;


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void PrintToConsole(const char* szCaller, const char* szFGColor, const char* szModifier, const char* szFormat, ...)
{
    pthread_mutex_lock(&s_mtx);
    
    // 2 calls so that caller name is always in white.
    if(szCaller[0] != '\0')
    {
        printf("%s%s[ %s ] %s", FG_BRIGHT_WHITE, BOLD, szCaller, RESET);
    }

    // Format text.
    printf("%s%s", szFGColor, szModifier);

    // Print using varadic args.
    va_list args; va_start(args, szFormat);
    vprintf(szFormat, args);
    va_end(args);

    // Reset
    printf("%s\n", RESET);

    pthread_mutex_unlock(&s_mtx);
}
