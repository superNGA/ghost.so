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


/* Maximum number of arena allocators that can be registered.
   If we try to register more arena allocators than this, program 
   will exit with status 1. */
#define MAX_REGISTERED_ARENA_ALLOCATOR (5)

#define JOIN_IMPL(a, b) a##b
#define JOIN(a, b) JOIN_IMPL(a, b)

/* Register and Initialize an ArenaAllocator_t. */
#define REGISTER_ARENA_ALLOCATOR(Allocator)                       \
    __attribute__((constructor))                                  \
    static void JOIN(Register, JOIN(Allocator, __COUNTER__))() {  \
        RegisterArenaAllocator(&Allocator);                       \
    }


/* Initialize and register an ArenaAllocator_t and return put it in PALLOCATOR. */
void RegisterArenaAllocator(struct ArenaAllocator_t** pAllocator);


/* Free all registered ArenaAllocators */
void AAManager_UninitializeAll();


#endif
