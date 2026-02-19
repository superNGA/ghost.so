//=========================================================================
//                      WRITE TO TERMINAL
//=========================================================================
// by      : INSANE
// created : 26/01/2026
// 
// purpose : Writes to terminal, in colors. Quick toggles.
//-------------------------------------------------------------------------
#pragma once
#include "ConsoleSystem.h"


#define EXPAND(X) X

#define CONCAT_HELPER(x,y)      x##y
#define CONCAT(x,y)             CONCAT_HELPER(x,y)


// To manually set color when we are writting something to the console.
#define CONSOLE_RED     "\033[31m"
#define CONSOLE_GREEN   "\033[32m"
#define CONSOLE_YELLOW  "\033[93m"
#define CONSOLE_RESET   "\033[0m"
#define CONSOLE_CYAN    "\033[96m"


// Formatted console output helper macors. So we disable then quickly.
#define ENABLE_CONSOLE_LOGS true


#if (ENABLE_CONSOLE_LOGS == true)

#define WIN_LOG(...)       PrintToConsole(__FUNCTION__, FG_BRIGHT_GREEN, "", __VA_ARGS__)
#define FAIL_LOG(...)      PrintToConsole(__FUNCTION__, FG_BRIGHT_RED,   "", __VA_ARGS__)
#define LOG(...)           PrintToConsole(__FUNCTION__, FG_BRIGHT_CYAN,  "", __VA_ARGS__)

#else 

#define WIN_LOG(msg, ...)       (void)0
#define FAIL_LOG(msg, ...)      (void)0
#define LOG(msg, ...)           (void)0

#endif // _DEBUG
