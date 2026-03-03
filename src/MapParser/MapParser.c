//=========================================================================
//                      Map Parser
//=========================================================================
// by      : INSANE
// created : 01/03/2026
//
// purpose : parse /proc/<ProcID>/maps file and store in a minimal struct.
//-------------------------------------------------------------------------
#include "MapParser.h"
#include <stdbool.h>

#include "../TargetBrief/TargetBrief_t.h"

// Util...
#include "../Util/AAManager/AAManager.h"
#include "../Util/Terminal/Terminal.h"

// ILIB.
#include "../../lib/ILIB/ILIB_ArenaAllocator.h"
#include "../../lib/ILIB/ILIB_Vector.h"
#include "../../lib/ILIB/ILIB_Assertion.h"


REGISTER_ARENA_ALLOCATOR(g_pArenaAlloc);


/* Excepts a null terminated strings representing a hexa-decimal number 
   and returns it as a 64 bit unsinged int. Returns if encountered a null-terminator
   a non-hexa-decimal character. */
static uint64_t _HexStringToInt(const char* szString);


/* These collection of functions go through given token ( SZTOKEN ) and extract information
   and store then in the provided MapEntry_t instance ( PMAPENTRY ). */
static void _HandleAddress    (const char* szToken, MapEntry_t* pMapEntry);
static void _HandlePermissions(const char* szToken, MapEntry_t* pMapEntry);
static void _HandleFileOffset (const char* szToken, MapEntry_t* pMapEntry);
static void _HandleDevice     (const char* szToken, MapEntry_t* pMapEntry);
static void _HandleInode      (const char* szToken, MapEntry_t* pMapEntry);
static void _HandleFilePath   (const char* szToken, MapEntry_t* pMapEntry);



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
typedef enum ParserStates_t
{
    ParserState_Invalid = -1,

    // Order of these ParserStates_t enum entries is very important.
    ParserState_Address     = 0,
    ParserState_Permissions = 1,
    ParserState_FileOffset  = 2,
    ParserState_Device      = 3,
    ParserState_Inode       = 4,
    ParserState_FilePath    = 5,

    ParserState_COUNT,

} ParserStates_t;



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void MapParser_Parse(struct TargetBrief_t* pTarget, MapEntry_t** vecMaps)
{
    // construct path.
    char szPath[256];
    snprintf(szPath, sizeof(szPath), "/proc/%d/maps", pTarget->m_iTargetPID);

    // open /proc/<pid>/maps file.
    FILE* pFile = fopen(szPath, "r");
    if(pFile == nullptr)
        return;


    // A ILIB vector of type char can work a little bit like std::string.
    char* tempString = nullptr; Vector_Reserve(tempString, 10); Vector_Clear(tempString);
    fseek(pFile, 0, SEEK_SET);
    char c = EOF;

    // parser's state ( dictates what to treat this token as. )
    ParserStates_t iParserState = ParserState_Address;
    MapEntry_t     tempMapEntry = {0};

    Vector_Clear(*vecMaps);
    while((c = fgetc(pFile)) != EOF)
    {
        // This makes sure that no token will be captured which starts with ' ' ( space ).
        if(c == ' ' && Vector_Len(tempString) == 0)
            continue;


        // no emtpy string.
        if(c == ' ' && iParserState < ParserState_FilePath)
        {
            // Null-terminate this string.
            Vector_PushBack(tempString, 0);
            
            switch (iParserState) 
            {
                case ParserState_Address:     _HandleAddress    (tempString, &tempMapEntry); break;
                case ParserState_Permissions: _HandlePermissions(tempString, &tempMapEntry); break;
                case ParserState_FileOffset:  _HandleFileOffset (tempString, &tempMapEntry); break;
                case ParserState_Device:      _HandleDevice     (tempString, &tempMapEntry); break;
                case ParserState_Inode:       _HandleInode      (tempString, &tempMapEntry); break;

                default: assertion(false && "Invalid Parser State."); break;
            }

            iParserState++;
            Vector_Clear(tempString);

            continue;
        }


        // for new line char, restore parser state and store whatever string
        // we have in tempstring as "file path".
        if(c == '\n')
        {
            Vector_PushBack(tempString, 0);
            _HandleFilePath(tempString, &tempMapEntry);
            Vector_PushBack(*vecMaps, tempMapEntry);

            iParserState = ParserState_Address;
            Vector_Clear(tempString);
            memset(&tempMapEntry, 0, sizeof(tempMapEntry));
            continue;
        }

        Vector_PushBack(tempString, c);
    }


    // close file and leave.
    Vector_Free(tempString);
    fclose(pFile);
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static uint64_t _HexStringToInt(const char* szString)
{
    uint64_t iOutput = 0;

    while(*szString != 0)
    {
        char     c     = *szString;
        uint64_t iTemp = 0;

        if     (c >= '0' && c <= '9') iTemp = c - '0';
        else if(c >= 'A' && c <= 'F') iTemp = c - 'A' + 10;
        else if(c >= 'a' && c <= 'f') iTemp = c - 'a' + 10;
        else return iOutput;

        iOutput *= 0x10;
        iOutput += iTemp;

        szString++;
    }

    return iOutput;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void _HandleAddress(const char* szToken, MapEntry_t* pMapEntry)
{
    pMapEntry->m_iStartAdrs = _HexStringToInt(szToken);


    for(int i = 0; i < 100; i++)
    {
        char c = *szToken; szToken++;

        // String ended before map end address ?
        assertion(c != 0 && "No map end address found in token");

        if(c == '-') // NOTE : Now szToken is pointing at char next to '-' and not at '-'
            break;
    }

    uint64_t iEndAdrs = _HexStringToInt(szToken);

    assertion(iEndAdrs > pMapEntry->m_iStartAdrs && pMapEntry->m_iStartAdrs != 0 && iEndAdrs != 0 && "Invalid token.");

    pMapEntry->m_iSize = iEndAdrs - pMapEntry->m_iStartAdrs;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void _HandlePermissions(const char* szToken, MapEntry_t* pMapEntry)
{
    pMapEntry->m_bPermRead    = szToken[0] == 'r';
    pMapEntry->m_bPermWrite   = szToken[1] == 'w';
    pMapEntry->m_bPermExec    = szToken[2] == 'x';
    pMapEntry->m_bPermPrivate = szToken[3] == 'p';
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void _HandleFileOffset(const char* szToken, MapEntry_t* pMapEntry)
{
    pMapEntry->m_iFileOffset = _HexStringToInt(szToken);
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void _HandleDevice(const char* szToken, MapEntry_t* pMapEntry)
{
    pMapEntry->m_iDevMajor = _HexStringToInt(szToken);

    for(int i = 0; i < 100; i++)
    {
        char c = *szToken; szToken++;
        assertion(c != 0 && "No map end address found in this token");
        if(c == ':') // NOTE : Now szToken is pointing at char next to ':' and not at ':'
            break;
    }

    pMapEntry->m_iDevMinor = _HexStringToInt(szToken);
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static void _HandleInode(const char* szToken, MapEntry_t* pMapEntry)
{
    pMapEntry->m_iInode = atoi(szToken);
}


///////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////// 
static void _HandleFilePath(const char* szToken, MapEntry_t* pMapEntry)
{
    strncpy(pMapEntry->m_szPathName, szToken, sizeof(pMapEntry->m_szPathName));
}   
