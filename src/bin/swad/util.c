#if defined(HAVE_MEMSET_S) && !defined(HAVE_MEMSET_EXP)
#  define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "util.h"

#include <ctype.h>
#include <poser/core/util.h>
#include <stdlib.h>
#include <string.h>

void appendchr(char **str, size_t *size, size_t *pos, size_t chunksz, char c)
{
    if (*pos >= *size)
    {
	*size += chunksz;
	*str = PSC_realloc(*str, *size);
    }
    (*str)[(*pos)++] = c;
}

#if defined(HAVE_MEMSET_EXP)

void wipemem(void *p, size_t s)
{
    memset_explicit(p, 0, s);
}

#elif defined(HAVE_MEMSET_S)

void wipemem(void *p, size_t s)
{
    memset_s(p, s, 0, s);
}

#else

static void *(* volatile memset_v)(void *, int, size_t) = memset;

void wipemem(void *p, size_t s)
{
    memset_v(p, 0, s);
}

#endif
