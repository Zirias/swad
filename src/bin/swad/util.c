#include "util.h"

#include <ctype.h>
#include <poser/core/util.h>
#include <stdlib.h>
#include <string.h>

#ifdef NEED_WIPEMEM_MEMSET
void *(* volatile wipemem_memset)(void *, int, size_t) = memset;
#endif

void appendchr(char **str, size_t *size, size_t *pos, size_t chunksz, char c)
{
    if (*pos >= *size)
    {
	*size += chunksz;
	*str = PSC_realloc(*str, *size);
    }
    (*str)[(*pos)++] = c;
}

