#include "utf8.h"

static int utf8_checksan(char *str, size_t *len, int sanitize)
    ATTR_NONNULL((1));

static int utf8_checksan(char *str, size_t *len, int sanitize)
{
    size_t l;
    int rc = 0;
    for (l = 0; *str; ++str, ++l)
    {
	if (*str & 0x80)
	{
	    if ((*str & 0xf8) == 0xf8 || (*str & 0xc0) != 0xc0)
	    {
		rc = -1;
		if (!sanitize) return rc;
		*str = '?';
		continue;
	    }
	    unsigned x = *str;
	    unsigned s = 1;
	    while (x & 0x20)
	    {
		x <<= 1;
		++s;
	    }
	    for (unsigned b = 1; b <= s; ++b)
	    {
		if ((str[b] & 0xc0) != 0x80)
		{
		    rc = -1;
		    if (!sanitize) return rc;
		    *str = '?';
		    s = 0;
		    break;
		}
	    }
	    str+=s;
	}
    }
    if (len) *len = l;
    return rc;
}

int utf8_check(const char *str, size_t *len)
{
    return utf8_checksan((char *)str, len, 0);
}

int utf8_sanitize(char *str, size_t *len)
{
    return utf8_checksan(str, len, 1);
}

