//=========================================================================
//                      Assertions
//=========================================================================
// by      : INSANE
// created : 19/02/2026
//
// purpose : assert.h rip-off so we can have assertions in release mode.
//-------------------------------------------------------------------------
#ifndef ASSERTIONS__H
#define ASSERTIONS__H


#include <stdio.h>
#include <stdlib.h>


#define ENABLE_ASSERTIONS 1


#if (ENABLE_ASSERTIONS == 1)
#define assertion(expression) { if((expression) == 0) AssertionFailed(#expression, __FILE__, __LINE__); }
#else
#define assertion(expression) (void)0
#endif



///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
static inline void AssertionFailed(const char* szExpression, const char* szFile, int iLine)
{
    printf("Assertion failed!\n");
    printf("Expression : %s\n", szExpression);
    printf("File       : %s\n", szFile);
    printf("Line       : %d\n", iLine);
    abort();
}


#endif // ASSERTIONS__H
