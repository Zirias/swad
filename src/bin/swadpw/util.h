#ifndef SWADPW_UTIL_H
#define SWADPW_UTIL_H

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

void *xmalloc(size_t sz);
void *xrealloc(void *p, size_t sz);

#endif
