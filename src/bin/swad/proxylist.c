#define _POSIX_C_SOURCE 200112L

#include "proxylist.h"

#include "http/header.h"
#include "http/headerset.h"
#include "http/httpcontext.h"
#include "http/httprequest.h"

#include <poser/core.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define CTXKEY "_PROXYLIST"
#define CTXTRKEY "_PROXYLIST_TRUSTED"

#define arraysz(x) (sizeof (x) / sizeof *(x))

struct RemoteEntry
{
    char *addr;
    char *host;
};

static RemoteEntry *createRemoteEntry(char *addr, char *host)
{
    RemoteEntry *self = PSC_malloc(sizeof *self);
    self->addr = addr;
    self->host = host;
    return self;
}

static void deleteRemoteEntry(void *obj)
{
    if (!obj) return;
    RemoteEntry *self = obj;
    free(self->host);
    free(self->addr);
    free(self);
}

static void deleteProxyList(void *obj)
{
    PSC_List_destroy(obj);
}

static void stripRfc7239(char **entry, size_t *len)
{
    if (!*len) return;
    int quote = 0;
    int esc = 0;
    size_t comp = 0;
    for (size_t i = 0; i < *len; ++i)
    {
	if (esc)
	{
	    esc = 0;
	    continue;
	}

	switch ((*entry)[i])
	{
	    case '"':
		quote = !quote;
		break;

	    case '\\':
		esc = 1;
		break;

	    case ';':
		if (!quote)
		{
		    (*entry)[i] = 0;
		    if (!strncasecmp(*entry + comp, "for=", 4))
		    {
			comp += 4;
			*len = i - comp;
			*entry += comp;
			return;
		    }
		}
		comp = ++i;
		ATTR_FALLTHROUGH;

	    default:
		break;
	}
    }

    if (comp < *len && !strncasecmp(*entry + comp, "for=", 4))
    {
	comp += 4;
	*len -= comp;
	*entry += comp;
    }
    else *len = 0;
}

static char *parseEntry(char *entry, size_t len, int rfc7239)
{
    char buf[512];

    if (rfc7239) stripRfc7239(&entry, &len);
    if (!len) return 0;

    int quote = 0;
    int esc = 0;
    int bracket = 0;
    unsigned buflen = 0;
    unsigned ncolons = 0;
    unsigned lastcolon = 0;

    for (size_t i = 0; i < len; ++i)
    {
	if (esc)
	{
	    esc = 0;
	    buf[buflen++] = entry[i];
	    if (!bracket) bracket = -1;
	    continue;
	}

	switch (entry[i])
	{
	    case '\\':
		esc = 1;
		break;

	    case '"':
		quote = !quote;
		break;

	    case '[':
		if (bracket >= 0) ++bracket;
		else goto takechar;
		break;

	    case ']':
		if (bracket > 0)
		{
		    if (!--bracket) goto done;
		}
		else goto takechar;
		break;

	    case ':':
		lastcolon = buflen;
		++ncolons;
		ATTR_FALLTHROUGH;

	    default:
		if (!bracket) bracket = -1;
	    takechar:
		buf[buflen++] = entry[i];
		break;
	}
    }

done:
    if (ncolons == 1) buflen = lastcolon;
    buf[buflen] = 0;

    char *ret = 0;
    if (buflen)
    {
	ret = PSC_malloc(buflen + 1);
	memcpy(ret, buf, buflen + 1);
    }
    return ret;
}

static int escaped(char *buf, size_t i)
{
    size_t bscount = 0;
    while (i-- > 0)
    {
	if (buf[i] != '\\') break;
	++bscount;
    }
    return bscount % 2;
}

static int hdrEntry(char **start, size_t *len, char *buf, size_t *buflen,
	int rfc7239)
{
    int quote = 0;
    size_t i = *buflen;
    while (i > 0)
    {
	switch (buf[--i])
	{
	    case '"':
		if (rfc7239 && !escaped(buf, i)) quote = !quote;
		break;

	    case ',':
		if (!quote)
		{
		    buf[i] = 0;
		    size_t newlen = i;
		    while (buf[++i] == ' ');
		    *len = *buflen - i;
		    *start = buf + i;
		    *buflen = newlen;
		    return 0;
		}
		ATTR_FALLTHROUGH;

	    default:
		break;
	}
    }

    if (!quote)
    {
	*len = *buflen;
	*buflen = 0;
	*start = buf;
	return 0;
    }

    return -1;
}

static int parseHdrVal(unsigned *parsed, char **addr, unsigned n,
	const char *val, int rfc7239)
{
    char buf[8192];
    size_t hdrlen = strlen(val);
    if (hdrlen >= arraysz(buf))
    {
	size_t shift = hdrlen - arraysz(buf) + 1;
	hdrlen -= shift;
	val += shift;
    }
    memcpy(buf, val, hdrlen);
    buf[hdrlen] = 0;

    int rc = 0;
    unsigned ok = 0;
    char *entry;
    size_t entryLen;
    while (hdrlen && ok < n)
    {
	if (hdrEntry(&entry, &entryLen, buf, &hdrlen, rfc7239) < 0)
	{
	    rc = -1;
	    goto done;
	}
	char *entryAddr = parseEntry(entry, entryLen, rfc7239);
	if (!entryAddr)
	{
	    rc = -1;
	    goto done;
	}
	addr[ok++] = entryAddr;
    }

done:
    *parsed = ok;
    return rc;
}

static PSC_List *proxyAddr(HeaderIterator *i, int rfc7239)
{
    const char *hdrVal[16];
    size_t hdrValCount = 0;
    unsigned lastHdrVal;

    while (HeaderIterator_moveNext(i))
    {
	lastHdrVal = hdrValCount++ % arraysz(hdrVal);
	hdrVal[lastHdrVal] = Header_value(HeaderIterator_current(i));
    }
    if (hdrValCount > arraysz(hdrVal)) hdrValCount = arraysz(hdrVal);

    char *addr[16];
    unsigned addrCount = 0;

    while (hdrValCount--)
    {
	unsigned parsed;
	int rc = parseHdrVal(&parsed, addr + addrCount,
		arraysz(addr) - addrCount, hdrVal[lastHdrVal], rfc7239);
	addrCount += parsed;
	if (rc < 0 || !parsed) break;
	if (addrCount == arraysz(addr)) break;
	if (lastHdrVal) --lastHdrVal;
	else lastHdrVal = arraysz(hdrVal) - 1;
    }

    if (addrCount)
    {
	PSC_List *proxyList = PSC_List_create();
	while (addrCount)
	{
	    PSC_List_append(proxyList, createRemoteEntry(addr[--addrCount], 0),
		    deleteRemoteEntry);
	}
	return proxyList;
    }

    return 0;
}

const PSC_List *ProxyList_get(HttpContext *context)
{
    PSC_List *proxyList = HttpContext_get(context, CTXKEY);
    if (proxyList) return proxyList;
    const HeaderSet *hdrs = HttpRequest_headers(HttpContext_request(context));
    HeaderIterator *i = HeaderSet_any(hdrs, "Forwarded");
    proxyList = proxyAddr(i, 1);
    HeaderIterator_destroy(i);
    if (!proxyList)
    {
	i = HeaderSet_any(hdrs, "X-Forwarded-For");
	proxyList = proxyAddr(i, 0);
	HeaderIterator_destroy(i);
    }
    if (!proxyList) proxyList = PSC_List_create();
    PSC_List_append(proxyList, createRemoteEntry(
		PSC_copystr(HttpContext_remoteAddr(context)),
		PSC_copystr(HttpContext_remoteHost(context))),
	    deleteRemoteEntry);
    HttpContext_set(context, CTXKEY, proxyList, deleteProxyList);
    return proxyList;
}

void ProxyList_setTrusted(HttpContext *context, size_t trusted)
{
    HttpContext_set(context, CTXTRKEY, (void *)trusted, 0);
}

size_t ProxyList_firstTrusted(HttpContext *context)
{
    size_t ntrusted = (size_t) HttpContext_get(context, CTXTRKEY);
    size_t nremotes = PSC_List_size(ProxyList_get(context));
    return nremotes > ntrusted + 1 ? nremotes - ntrusted - 1 : 0;
}

const char *RemoteEntry_addr(const RemoteEntry *self)
{
    return self->addr;
}

const char *RemoteEntry_host(const RemoteEntry *self)
{
    return self->host;
}

