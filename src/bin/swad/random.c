#define _POSIX_C_SOURCE 200112L

#include "random.h"

#include "base64.h"

#include <errno.h>
#include <poser/core/log.h>
#include <poser/core/util.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

static uint64_t prng(void)
{
    static int seeded = 0;
    static uint64_t s[4] = { 0 };

    if (!seeded)
    {
	seeded = 1;
	s[0] = (uint64_t)time(0);
	for (int i = 0; i < 100; ++i) prng();
    }

    uint64_t num = s[0] + s[3];
    uint64_t tmp = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= tmp;
    s[3] = (s[3]<<45) | (s[3]>>19);

    return num;
}

void getRndBytes(uint8_t *buf, size_t num)
{
    size_t pos = 0;
    while (pos < num)
    {
	errno = 0;
	ssize_t rc = getrandom(buf + pos, num - pos, 0);
	if (rc < 0)
	{
	    if (errno == EAGAIN || errno == EINTR) continue;
	    break;
	}
	pos += rc;
    }
    if (pos < num)
    {
	PSC_Log_msg(PSC_L_WARNING, "random: Could not obtain entropy from "
		"the OS, falling back to own PRNG.");
	size_t chunks = (num - pos) / sizeof(uint64_t);
	size_t bytes = (num - pos) % sizeof(uint64_t);
	if (bytes)
	{
	    uint64_t rn = prng();
	    memcpy(buf + pos, &rn, bytes);
	    pos += bytes;
	}
	for (size_t i = 0; i < chunks; ++i)
	{
	    uint64_t rn = prng();
	    memcpy(buf + pos, &rn, sizeof rn);
	    pos += sizeof rn;
	}
    }
}

void getRndStr(char *str, size_t size, size_t num)
{
    uint8_t buf[num];
    size_t reqsz = base64encsz(num) + 1;
    if (size < reqsz)
    {
	num = base64decsz(size - 1);
    }
    getRndBytes(buf, num);
    base64enc(str, buf, num);
}

char *createRndStr(size_t num)
{
    size_t strsz = base64encsz(num) + 1;
    char *str = PSC_malloc(strsz);
    getRndStr(str, strsz, num);
    return str;
}

