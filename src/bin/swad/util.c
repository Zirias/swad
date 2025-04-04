#include "util.h"

#include <ctype.h>
#include <poser/core/util.h>
#include <stdlib.h>
#include <string.h>

char *lowerstr(const char *src)
{
    char *lower = PSC_copystr(src);
    char *p = lower;
    if (p) while (*p)
    {
	*p = tolower(*p);
	++p;
    }
    return lower;
}

char *joinstr(const char *delim, char **strings)
{
    int n = 0;
    size_t rlen = 0;
    size_t dlen = strlen(delim);
    char **cur;
    for (cur = strings; *cur; ++cur)
    {
	++n;
	rlen += strlen(*cur);
    }
    if (!n) return 0;
    if (n > 1)
    {
	rlen += (n - 1) * dlen;
    }
    char *joined = PSC_malloc(rlen + 1);
    strcpy(joined, *strings);
    char *w = joined + strlen(*strings);
    cur = strings+1;
    while (*cur)
    {
	strcpy(w, delim);
	w += dlen;
	strcpy(w, *cur);
	w += strlen(*cur);
	++cur;
    }
    return joined;
}

#ifndef BUNDLED_POSER
uint8_t hashstr(const char *key, uint8_t mask)
{
    size_t h = 5381;
    while (*key)
    {
	h += (h << 5) + ((uint8_t)*key++);
    }
    return h & mask;
}
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
