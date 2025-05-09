#include "util.h"

#include <stdlib.h>

#ifdef NEED_WIPEMEM_MEMSET
#  include <string.h>
void *(* volatile wipemem_memset)(void *, int, size_t) = memset;
#endif

void *xmalloc(size_t sz)
{
    void *p = malloc(sz);
    if (!p) abort();
    return p;
}

void *xrealloc(void *p, size_t sz)
{
    void *np = realloc(p, sz);
    if (!np) abort();
    return np;
}

