//=========================================================================
//                      Arena Allocator Manager
//=========================================================================
// by      : INSANE
// created : 27/02/2026
//
// purpose : Trace, initialize and uninitialize a bunch of ArenaAllocators ( ILIB ).
//-------------------------------------------------------------------------
#ifndef AAMANAGER_H
#define AAMANAGER_H

#include <stddef.h>


struct ArenaAllocator_t;
struct Arena_t;


/* Maximum number of arena allocators that can be registered.
   If we try to register more arena allocators than this, program 
   will exit with status 1. */
#define MAX_REGISTERED_ARENA_ALLOCATOR (5)
#define MAX_REGISTERED_ARENA           (5)

#define JOIN_IMPL(a, b) a##b
#define JOIN(a, b) JOIN_IMPL(a, b)

/* Register and Initialize an ArenaAllocator_t. */
#define REGISTER_ARENA_ALLOCATOR(Allocator)                       \
    static struct ArenaAllocator_t* Allocator = ((void*)0);       \
    __attribute__((constructor))                                  \
    static void JOIN(Register, JOIN(Allocator, __COUNTER__))() {  \
        RegisterArenaAllocator(&Allocator);                       \
    }


#define REGISTER_ARENA(Arena, iArenaSize)                    \
    static struct Arena_t* Arena = ((void*)0);               \
    __attribute__((constructor))                             \
    static void JOIN(Register, JOIN(Arena, __COUNTER__))() { \
        RegisterArena(&Arena, iArenaSize);                   \
    }


/* Initialize and register an ArenaAllocator_t and put it in PALLOCATOR. */
void RegisterArenaAllocator(struct ArenaAllocator_t** pAllocator);


/* Initialize and register an Arena_t and put it in *PARENA. */
void RegisterArena(struct Arena_t** pArena, size_t iArenaSize);


/* Free all registered ArenaAllocators */
void AAManager_UninitializeAll();


#endif
