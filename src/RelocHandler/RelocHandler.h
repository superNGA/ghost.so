//=========================================================================
//                      Relocation Handler
//=========================================================================
// by      : INSANE
// created : 04/03/2026
//
// purpose : Handle relocations for MappedObject_t ( thats loaded ) and its 
//           dependencies.
//-------------------------------------------------------------------------
#ifndef RELOCHANDLER_H
#define RELOCHANDLER_H

#include <stdbool.h>


struct MappedObject_t;
struct TargetBrief_t;


bool RelocHandler_Reloc(struct MappedObject_t* pHead, struct TargetBrief_t* pTarget);


#endif // RELOCHANDLER_H
