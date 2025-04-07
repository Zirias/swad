#include "ipaddr.h"

#include <errno.h>
#include <poser/core/proto.h>
#include <poser/core/util.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct IpAddr
{
    uint8_t data[16];
    unsigned prefixlen;
    PSC_Proto proto;
    char str[44];
};

static int parsev4(uint8_t *data, const char *buf)
{
    uint8_t v4dat[4] = { 0 };
    const char *bufp = buf;
    for (int i = 0; i < 4; ++i)
    {
	errno = 0;
	char *endp = 0;
	long byte = strtol(bufp, &endp, 10);
	if (!endp || endp == bufp || (i == 3 ? *endp : *endp != '.')
		|| errno == ERANGE || byte < 0 || byte > 255) return -1;
	v4dat[i] = byte;
	bufp = endp + (i < 3);
    }
    memcpy(data + 12, v4dat, 4);
    return 0;
}

static int parsev6(uint8_t *data, const char *buf)
{
    uint8_t taildat[16] = { 0 };
    size_t len = 0;
    int taillen = -1;

    while (*buf)
    {
	if (taillen < 0 && buf[0] == ':' && buf[1] == ':')
	{
	    taillen = 0;
	    buf += 2;
	    continue;
	}

	errno = 0;
	char *endp = 0;
	long word = strtol(buf, &endp, 16);
	if (!endp || endp == buf || (*endp && *endp != ':')
		|| errno == ERANGE || word < 0 || word > 0xffff) return -1;
	if (len >= 16) return -1;
	buf = endp;
	if (taillen < 0)
	{
	    data[len++] = word >> 8;
	    data[len++] = word & 0xff;
	}
	else
	{
	    taildat[taillen++] = word >> 8;
	    taildat[taillen++] = word & 0xff;
	    len += 2;
	}

	if (*buf && *buf == ':' && buf[1] != ':') ++buf;
    }

    if (taillen > 0) memcpy(data + 16 - taillen, taildat, taillen);
    return 0;
}

IpAddr *IpAddr_create(const char *str)
{
    uint8_t data[16] = { 0 };
    char buf[44];
    size_t inlen = strlen(str);
    if (inlen < 2 || inlen > 43) return 0;
    strcpy(buf, str);

    unsigned prefixlen = (unsigned)-1;
    char *prstr = strchr(buf, '/');
    if (prstr)
    {
	*prstr++ = 0;
	errno = 0;
	char *endp = 0;
	long prefixval = strtol(prstr, &endp, 10);
	if (!endp || endp == prstr || *endp || errno == ERANGE
		|| prefixval < 0 || prefixval > 128) return 0;
	prefixlen = prefixval;
    }

    PSC_Proto proto = PSC_P_ANY;
    if (parsev4(data, buf) == 0)
    {
	if (prefixlen == (unsigned)-1) prefixlen = 32;
	else if (prefixlen > 32) return 0;
	proto = PSC_P_IPv4;
    }
    else if (parsev6(data, buf) == 0)
    {
	if (prefixlen == (unsigned)-1) prefixlen = 128;
	proto = PSC_P_IPv6;
    }
    else return 0;

    IpAddr *self = PSC_malloc(sizeof *self);
    memcpy(self->data, data, 16);
    self->prefixlen = prefixlen;
    self->proto = proto;
    self->str[0] = 0;

    return self;
}

IpAddr *IpAddr_nat64(const IpAddr *self, const IpAddr **prefixes)
{
    if (self->prefixlen != 128) return 0;

    int matches = 0;
    for (const IpAddr **prefix = prefixes; *prefix; ++prefix)
    {
	if (IpAddr_prefixlen(*prefix) == 96 && IpAddr_matches(self, *prefix))
	{
	    matches = 1;
	    break;
	}
    }
    if (!matches) return 0;

    IpAddr *mapped = PSC_malloc(sizeof *mapped);
    memset(mapped->data, 0, 12);
    memcpy(mapped->data+12, self->data+12, 4);
    mapped->prefixlen = 32;
    mapped->proto = PSC_P_IPv4;
    mapped->str[0] = 0;

    return mapped;
}

PSC_Proto IpAddr_proto(const IpAddr *self)
{
    return self->proto;
}

unsigned IpAddr_prefixlen(const IpAddr *self)
{
    return self->prefixlen;
}

static void toString(IpAddr *self)
{
    int len = 0;
    if (self->proto == PSC_P_IPv4)
    {
	len = sprintf(self->str, "%hhu.%hhu.%hhu.%hhu",
		self->data[12], self->data[13],
		self->data[14], self->data[15]);
	if (len < 0) len = 0;
	if (self->prefixlen < 32) sprintf(self->str + len,
		"/%u", self->prefixlen);
    }
    else
    {
	unsigned word[8];
	int gap = 0;
	int gaplen = 0;
	for (int i = 0; i < 8; ++i)
	{
	    if (!(word[i] = (self->data[2*i] << 8) | self->data[2*i+1]))
	    {
		if (i > gap + gaplen)
		{
		    gap = i;
		    gaplen = 1;
		}
		else ++gaplen;
	    }
	}
	int needcolon = 0;
	for (int i = 0; i < 8;)
	{
	    if (i == gap && gaplen > 0)
	    {
		self->str[len++] = ':';
		self->str[len++] = ':';
		self->str[len] = 0;
		needcolon = 0;
		i += gaplen;
		continue;
	    }
	    if (needcolon) self->str[len++] = ':';
	    needcolon = 1;
	    int rc = sprintf(self->str + len, "%x", word[i]);
	    if (rc < 0) self->str[len] = 0;
	    else len += rc;
	    ++i;
	}
	if (self->prefixlen < 128) sprintf(self->str+len,
		"/%u", self->prefixlen);
    }
}

const char *IpAddr_string(const IpAddr *self)
{
    if (!*self->str) toString((IpAddr *)self);
    return self->str;
}

int IpAddr_equals(const IpAddr *self, const IpAddr *other)
{
    if (self->proto != other->proto) return 0;
    if (self->prefixlen != other->prefixlen) return 0;
    return !memcmp(self->data, other->data, 16);
}

int IpAddr_matches(const IpAddr *self, const IpAddr *prefix)
{
    if (self->proto != prefix->proto) return 0;
    if (self->prefixlen < prefix->prefixlen) return 0;

    unsigned bytes = prefix->prefixlen / 8;
    if (memcmp(self->data, prefix->data, bytes)) return 0;
    unsigned bits = prefix->prefixlen % 8;
    if (!bits) return 1;
    uint8_t mask = (0xff << (8 - bits));
    return ((self->data[bytes] & mask) == (prefix->data[bytes] & mask));
}

void IpAddr_destroy(IpAddr *self)
{
    free(self);
}

