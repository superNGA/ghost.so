//=========================================================================
//                      Arena Allocator Manager
//=========================================================================
// by      : INSANE
// created : 27/02/2026
//
// purpose : Trace, initialize and uninitialize a bunch of ArenaAllocators ( ILIB ).
//-------------------------------------------------------------------------
#include "AAManager.h"

#include "../../../lib/ILIB/ILIB_ArenaAllocator.h"
#include "../Terminal/Terminal.h"


static ArenaAllocator_t g_vecAllocators[MAX_REGISTERED_ARENA_ALLOCATOR];
static size_t           g_nAllocators = 0;



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void RegisterArenaAllocator(struct ArenaAllocator_t** pAllocator)
{
    // Too many arenas?
    if(g_nAllocators < 0 || g_nAllocators > MAX_REGISTERED_ARENA_ALLOCATOR)
    {
        FAIL_LOG("Programmer error");
        FAIL_LOG("Couldn't create arena allocator index : %d, MAX_REGISTERED_ARENA_ALLOCATOR : %d", 
                g_nAllocators, MAX_REGISTERED_ARENA_ALLOCATOR);

        exit(1);
    }


    // Initialize arena.
    if(ArenaAllocator_Initialize(&g_vecAllocators[g_nAllocators], 2, STD_ARENA_SIZE) == false)
    {
        FAIL_LOG("Failed to initialize arena index : %d", g_nAllocators);
        
        exit(1);
    }


    *pAllocator = &g_vecAllocators[g_nAllocators];
    g_nAllocators++;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void AAManager_UninitializeAll()
{
    size_t iTotalSize     = 0;
    size_t iTotalCapacity = 0;
    size_t iTotalArena    = 0;

    for(size_t i = 0; i < g_nAllocators; i++)
    {
        ArenaAllocator_t* pAllocator = &g_vecAllocators[i];
        iTotalSize     += ArenaAllocator_SizeAll   (pAllocator);
        iTotalCapacity += ArenaAllocator_Capacity  (pAllocator);
        iTotalArena    += ArenaAllocator_ArenaCount(pAllocator);
        ArenaAllocator_Free(pAllocator);
    }

    WIN_LOG("Uninitialized %zu arena allocators ( %zu arenas ). Size : %zu, Capacity : %zu", 
            g_nAllocators, iTotalArena, iTotalSize, iTotalCapacity);

    g_nAllocators = 0;
}
