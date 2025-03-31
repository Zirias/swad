#ifndef SWAD_HTMLESCAPE_H
#define SWAD_HTMLESCAPE_H

#include <poser/decl.h>
#include <stddef.h>

void htmlescapeto(char **out, size_t *outsz, size_t *outpos,
	const char *val, int newline)
    ATTR_NONNULL((1)) ATTR_NONNULL((2)) ATTR_NONNULL((3)) ATTR_NONNULL((4))
    ATTR_ACCESS((write_only, 1))
    ATTR_ACCESS((read_write, 2)) ATTR_ACCESS((read_write, 3));
char *htmlescape(const char *str, int newline)
    ATTR_MALLOC ATTR_NONNULL((1)) ATTR_RETNONNULL;

#endif
