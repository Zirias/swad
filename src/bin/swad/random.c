#include "random.h"

#include "base64.h"

#include <poser/core/util.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>

void getRndBytes(uint8_t *buf, size_t num)
{
    if (num > MAXRNDBYTES) num = MAXRNDBYTES;
    getrandom(buf, num, 0);
}

void getRndStr(char *str, size_t size, size_t num)
{
    uint8_t buf[MAXRNDBYTES];
    if (num > MAXRNDBYTES) num = MAXRNDBYTES;
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
    if (num > MAXRNDBYTES) num = MAXRNDBYTES;
    size_t strsz = base64encsz(num) + 1;
    char *str = PSC_malloc(strsz);
    getRndStr(str, strsz, num);
    return str;
}

