#ifndef SWAD_UTIL_H
#define SWAD_UTIL_H

#include <poser/decl.h>

#if defined(HAVE_MEMSET_EXP)
#  include <string.h>
#  define wipemem(p, s) (void)memset_explicit(p, 0, s)
#elif defined(HAVE_MEMSET_S)
#  define __STDC_WANT_LIB_EXT1__ 1
#  include <string.h>
#  define wipemem(p, s) (void)memset_s(p, s, 0, s)
#elif defined(HAVE_EXP_BZERO)
#  include <string.h>
#  define wipemem(p, s) (void)explicit_bzero(p, s)
#elif defined(HAVE_EXP_BZERO_G)
#  undef _POSIX_C_SOURCE
#  define _DEFAULT_SOURCE
#  include <string.h>
#  define wipemem(p, s) (void)explicit_bzero(p, s)
#elif defined(HAVE_EXP_BZERO_S)
#  include <strings.h>
#  define wipemem(p, s) (void)explicit_bzero(p, s)
#else
#  include <stddef.h>
#  include <string.h>
extern void *(* volatile wipemem_memset)(void *, int, size_t);
#  define wipemem(p, s) (void)wipemem_memset(p, 0, s)
#  define NEED_WIPEMEM_MEMSET
#endif

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

#endif
