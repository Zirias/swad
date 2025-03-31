#include "urlencode.h"

#include "util.h"

#include <poser/core/util.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define OUTCHUNK 512

char *urldecode(const char *str, size_t size)
{
    size_t outsz = strlen(str);
    size_t outpos = 0;
    size_t inpos = 0;
    char *out = PSC_malloc(outsz);
    while (inpos < size)
    {
	char c = str[inpos++];
	switch (c)
	{
	    case '+':
		appendchr(&out, &outsz, &outpos, OUTCHUNK, ' ');
		break;
	    case '%':
		if ((size - inpos > 1)
			&& ((str[inpos] >= 'A' && str[inpos] <= 'F')
			    || (str[inpos] >= '0' && str[inpos] <= '9'))
			&& ((str[inpos+1] >= 'A' && str[inpos+1] <= 'F')
			    || (str[inpos+1] >= '0' && str[inpos+1] <= '9')))
		{
		    char d = str[inpos++];
		    if (d <= '9') d-='0';
		    else d-=('A'-10);
		    c = str[inpos++];
		    if (c <= '9') c-='0';
		    else c-=('A'-10);
		    c |= (d<<4);
		}
		ATTR_FALLTHROUGH;
	    default:
		appendchr(&out, &outsz, &outpos, OUTCHUNK, c);
	}
    }
    appendchr(&out, &outsz, &outpos, 1, 0);
    out = PSC_realloc(out, outpos);
    return out;
}

void urlencodeto(char **out, size_t *outsz, size_t *outpos, const char *str)
{
    uint8_t c;
    while ((c = (uint8_t)*str++))
    {
	if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')
		||c=='-'||c=='.'||c=='_'||c=='~')
	{
	    appendchr(out, outsz, outpos, OUTCHUNK, (char)c);
	}
	else
	{
	    appendchr(out, outsz, outpos, OUTCHUNK, '%');
	    appendchr(out, outsz, outpos, OUTCHUNK,
		    (c>>4)>9?(c>>4)-10+'A':(c>>4)+'0');
	    appendchr(out, outsz, outpos, OUTCHUNK,
		    (c&15)>9?(c&15)-10+'A':(c&15)+'0');
	}
    }
}

char *urlencode(const char *str)
{
    size_t outsz = strlen(str) + OUTCHUNK;
    size_t outpos = 0;
    char *out = PSC_malloc(outsz);
    urlencodeto(&out, &outsz, &outpos, str);
    appendchr(&out, &outsz, &outpos, 1, 0);
    out = PSC_realloc(out, outpos);
    return out;
}

