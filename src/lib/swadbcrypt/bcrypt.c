#define _POSIX_C_SOURCE 200112L
#if defined(HAVE_MEMSET_S) && !defined(HAVE_MEMSET_EXP)
#  define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <stddef.h>
#include <stdint.h>

#if defined(HAVE_MEMSET_EXP)
#  define explicit_bzero(p, s) memset_explicit(p, 0, s)
#elif defined(HAVE_MEMSET_S)
#  define explicit_bzero(p, s) memset_s(p, s, 0, s)
#elif !defined(HAVE_EXP_BZERO)
#  if defined(HAVE_EXP_BZERO_G) || defined(HAVE_EXP_BZERO_S)
void explicit_bzero(void *b, size_t len);
#  else
#  include <string.h>
static void *(* volatile wipemem_memset)(void *, int, size_t) = memset;
#    define explicit_bzero(p, s) wipemem_memset(p, 0, s)
#  endif
#endif

#if defined(HAVE_TS_BCMP) || defined(HAVE_TS_MEMCMP)
#  ifdef HAVE_TS_BCMP
int timingsafe_bcmp(const void *b1, const void *b2, size_t len);
#  else
int timingsafe_memcmp(const void *b1, const void *b2, size_t len);
#    define timingsafe_bcmp(p1, p2, s) (!!timingsafe_memcmp(p1, p2, s))
#  endif
#else
#  undef TSATTR
#  if __clang__
#    if __has_attribute(noinline) && __has_attribute(optnone)
#      define TSATTR __attribute__((optnone)) __attribute__((noinline))
#    endif
#  elif __GNUC__
#    if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)
#      define TSATTR __attribute__((optimize(0))) __attribute__((noinline))
#    endif
#  endif
#  undef TSVOL
#  undef NEEDVOLPTR
#  ifdef TSATTR
#    define TSVOL
#    define TSBCMPIMPL timingsafe_bcmp
#  else
#    define TSATTR
#    define TSVOL volatile
#    define TSBCMPIMPL timingsafe_bcmp_real
#    define NEEDVOLPTR
#  endif

TSATTR static int TSBCMPIMPL(
	const TSVOL void *p1, const TSVOL void *p2, size_t s)
{
    const unsigned TSVOL char *c1 = p1;
    const unsigned TSVOL char *c2 = p2;
    int result = 0;

    for (size_t i = 0; i < s; ++i)
    {
	result |= c1[i] ^ c2[i];
    }

    return !!result;
}

#  ifdef NEEDVOLPTR

static int (* volatile timingsafe_bcmp)(
	const volatile void *, const volatile void *, size_t) = TSBCMPIMPL;

#  endif

#endif

#include <time.h>
#ifndef CLOCK_THREAD_CPUTIME_ID
#  define CLOCK_THREAD_CPUTIME_ID CLOCK_MONOTONIC
#endif

#ifdef HAVE_ARC4R
void arc4random_buf(void *buf, size_t nbytes);
#else
#  include "random.h"
#  define arc4random_buf(p, s) swadbcrypt_random(p, s)
#endif

#include <pwd.h>
#ifndef _PASSWORD_LEN
#  define _PASSWORD_LEN 128
#endif

#include "defines.h"

#include "../../../contrib/openbsd/src/bcrypt.c"

#include <swadbcrypt.h>

int swad_bcrypt_check(const char *pw, const char *hash)
{
    char buf[BCRYPT_HASHSPACE];
    if (bcrypt_hashpass(pw, hash, buf, sizeof buf) != 0) return -1;
    int ok = 0;
    size_t hashlen = strlen(hash);
    if (strlen(buf) == hashlen && timingsafe_bcmp(buf, hash, hashlen) == 0)
    {
	ok = 1;
    }
    explicit_bzero(buf, sizeof buf);
    return ok;
}

int swad_bcrypt_hash(char *buf, size_t sz, int log_rounds, const char *pw)
{
    char salt[BCRYPT_SALTSPACE];
    if (bcrypt_initsalt(log_rounds, salt, sizeof salt) != 0) return -1;
    if (bcrypt_hashpass(pw, salt, buf, sz) != 0) return -1;
    return 0;
}

