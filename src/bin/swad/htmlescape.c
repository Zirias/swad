#include "htmlescape.h"

#include "util.h"

#include <poser/core/util.h>
#include <stddef.h>
#include <string.h>

#define OUTCHUNK 512

void htmlescapeto(char **out, size_t *outsz, size_t *outpos,
	const char *val, int newline)
{
    char c;
    while ((c = *val++)) switch (c)
    {
	case '&':
	    appendstrlit(out, outsz, outpos, OUTCHUNK, "&amp;");
	    break;
	case '<':
	    appendstrlit(out, outsz, outpos, OUTCHUNK, "&lt;");
	    break;
	case '>':
	    appendstrlit(out, outsz, outpos, OUTCHUNK, "&gt;");
	    break;
	case '"':
	    appendstrlit(out, outsz, outpos, OUTCHUNK, "&quot;");
	    break;
	case '\'':
	    appendstrlit(out, outsz, outpos, OUTCHUNK, "&#39;");
	    break;
	case '\n':
	    if (newline)
	    {
		appendstrlit(out, outsz, outpos, OUTCHUNK, "<br>");
		break;
	    }
	    ATTR_FALLTHROUGH;
	default:
	    appendchr(out, outsz, outpos, OUTCHUNK, c);
	    break;
    }
}

char *htmlescape(const char *str, int newline)
{
    size_t outsz = strlen(str) + OUTCHUNK;
    char *escaped = PSC_malloc(outsz);
    size_t outpos = 0;
    htmlescapeto(&escaped, &outsz, &outpos, str, newline);
    appendchr(&escaped, &outsz, &outpos, 1, 0);
    escaped = PSC_realloc(escaped, outpos);
    return escaped;
}

