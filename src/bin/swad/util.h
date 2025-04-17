#ifndef SWAD_UTIL_H
#define SWAD_UTIL_H

#include <poser/decl.h>
#include <stddef.h>

#define STR(m) XSTR(m)
#define XSTR(m) #m

#define appendstrlit(str, size, pos, chunksz, strlit) \
    for (size_t i = 0; i < sizeof strlit - 1; ++i) \
    appendchr((str), (size), (pos), (chunksz), strlit[i])

void appendchr(char **str, size_t *size, size_t *pos, size_t chunksz, char c)
    ATTR_NONNULL((1)) ATTR_NONNULL((2)) ATTR_NONNULL((3))
    ATTR_ACCESS((read_write, 1)) ATTR_ACCESS((read_write, 2))
    ATTR_ACCESS((read_write, 3));

void wipemem(void *p, size_t s) ATTR_NONNULL((1));

#endif
