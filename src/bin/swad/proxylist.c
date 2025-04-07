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

static void findFor(const char **p, size_t *l)
{
    if (!*l) return;
    if (*l < 5) goto notFound;
    size_t s = 0;
    for (; s < *l - 5; ++s)
    {
	if (!strncasecmp(*p + s, "for=", 4))
	{
	    s += 4;
	    *l -= s;
	    *p += s;
	    s = 0;
	    for (; s < *l; ++s)
	    {
		if ((*p)[s] == ';') break;
	    }
	    *l = s;
	    return;
	}
    }

notFound:
    *l = 0;
}

static void stripAddr(const char **p, size_t *l)
{
    if (!*l) return;
    size_t s;

    if (**p == '[')
    {
	for (s = 1; s < *l; ++s)
	{
	    if ((*p)[s] == ']')
	    {
		*l = s - 1;
		++*p;
		return;
	    }
	}
	*l = 0;
	return;
    }

    size_t ncolons = 0;
    const char *lastcolon = 0;
    for (s = 0; s < *l; ++s)
    {
	if ((*p)[s] == ':')
	{
	    lastcolon = *p + s;
	    ++ncolons;
	}
    }

    if (ncolons == 1) *l = (lastcolon - *p);
}

static char *parseAddr(const char **p, int rfc7239)
{
    char buf[1024];
    size_t buflen = 0;
    int quot = 0;

    if (!**p) return 0;

    const char *rp = *p;
    for (; buflen < sizeof buf && *rp; ++rp)
    {
	switch (*rp)
	{
	    case '"':
		quot = !quot;
		break;

	    case ',':
		if (!quot) goto entryEnd;
		ATTR_FALLTHROUGH;

	    default:
		buf[buflen++] = *rp;
	}
    }

entryEnd:
    if (*rp && *rp != ',')
    {
	PSC_Log_msg(PSC_L_WARNING, "proxylist: overlong entry, truncating");
	while (*rp && *rp != ',') ++rp;
    }
    if (*rp == ',')
    {
	++rp;
	while (*rp && (*rp == ' ' || *rp == '\t')) ++rp;
    }
    *p = rp;

    const char *bufp = buf;
    if (rfc7239) findFor(&bufp, &buflen);
    stripAddr(&bufp, &buflen);

    if (!buflen) return 0;
    char *addr = PSC_malloc(buflen + 1);
    memcpy(addr, bufp, buflen);
    addr[buflen] = 0;
    return addr;
}

static PSC_List *proxyAddr(HeaderIterator *i, int rfc7239)
{
    PSC_List *proxyList = 0;
    while (HeaderIterator_moveNext(i))
    {
	const char *val = Header_value(HeaderIterator_current(i));
	char *addr;
	while ((addr = parseAddr(&val, rfc7239)))
	{
	    if (!proxyList) proxyList = PSC_List_create();
	    PSC_List_append(proxyList, createRemoteEntry(addr, 0),
		    deleteRemoteEntry);
	}
    }
    return proxyList;
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

const char *RemoteEntry_addr(const RemoteEntry *self)
{
    return self->addr;
}

const char *RemoteEntry_host(const RemoteEntry *self)
{
    return self->host;
}

