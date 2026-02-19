//=========================================================================
//                      Printf Wrapper
//=========================================================================
// by      : INSANE
// created : 26/01/2026
//
// purpose : Printf wrapper for convinence.
//-------------------------------------------------------------------------
#pragma once


static const char* RESET               = "\033[0m";
static const char* FG_BLACK            = "\033[30m";
static const char* FG_RED              = "\033[31m";
static const char* FG_GREEN            = "\033[32m";
static const char* FG_YELLOW           = "\033[33m";
static const char* FG_BLUE             = "\033[34m";
static const char* FG_MAGENTA          = "\033[35m";
static const char* FG_CYAN             = "\033[36m";
static const char* FG_WHITE            = "\033[37m";
static const char* FG_BRIGHT_BLACK     = "\033[90m";
static const char* FG_BRIGHT_RED       = "\033[91m";
static const char* FG_BRIGHT_GREEN     = "\033[92m";
static const char* FG_BRIGHT_YELLOW    = "\033[93m";
static const char* FG_BRIGHT_BLUE      = "\033[94m";
static const char* FG_BRIGHT_MAGENTA   = "\033[95m";
static const char* FG_BRIGHT_CYAN      = "\033[96m";
static const char* FG_BRIGHT_WHITE     = "\033[97m";
static const char* BOLD                = "\033[1m";
static const char* ITALIC              = "\033[3m";
static const char* UNDERLINE           = "\033[4m";
static const char* BLINKING            = "\033[5m";
static const char* STRIKE              = "\033[9m";



void PrintToConsole(const char* szCaller, const char* szFGColor, const char* szModifier, const char* szFormat, ...);

