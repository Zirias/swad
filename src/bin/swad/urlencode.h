#ifndef SWAD_URLENCODE_H
#define SWAD_URLENCODE_H

#include <poser/decl.h>
#include <stddef.h>

char *urldecode(const char *str, size_t size)
    ATTR_MALLOC ATTR_NONNULL((1)) ATTR_RETNONNULL;
void urlencodeto(char **out, size_t *outsz, size_t *outpos, const char *str)
    ATTR_NONNULL((1)) ATTR_NONNULL((2)) ATTR_NONNULL((3)) ATTR_NONNULL((4))
    ATTR_ACCESS((write_only, 1))
    ATTR_ACCESS((read_write, 2)) ATTR_ACCESS((read_write, 3));
char *urlencode(const char *str)
    ATTR_MALLOC ATTR_NONNULL((1)) ATTR_RETNONNULL;

#endif
