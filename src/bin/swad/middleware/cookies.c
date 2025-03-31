#include "cookies.h"

#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"

#include <poser/core.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXCOOKIES 8
#define PROPNAME "_COOKIES"

struct Cookies
{
    PSC_HashTable *in;
    PSC_HashTable *out;
};

static void cookiesDeleter(void *obj);

static void cookiesDeleter(void *obj)
{
    if (!obj) return;
    Cookies *self = obj;
    PSC_HashTable_destroy(self->out);
    PSC_HashTable_destroy(self->in);
    free(self);
}

Cookies *Cookies_get(const HttpContext *context)
{
    return HttpContext_get(context, PROPNAME);
}

const char *Cookies_getCookie(const Cookies *self, const char *name)
{
    if (!self->in) return 0;
    return PSC_HashTable_get(self->in, name);
}

void Cookies_setCookie(Cookies *self, const char *name, const char *value)
{
    if (!self->out) self->out = PSC_HashTable_create(5);
    PSC_HashTable_set(self->out, name, PSC_copystr(value), free);
}

void MW_Cookies(HttpContext *context)
{
    Cookies *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    HttpRequest *req = HttpContext_request(context);
    const Header *cookie = HeaderSet_first(HttpRequest_headers(req), "Cookie");
    if (cookie)
    {
	char name[2048];
	const char *cl = Header_value(cookie);
	while (*cl == ' ') ++cl;
	while (*cl)
	{
	    size_t dpos = strcspn(cl, ";");
	    if (!dpos) break;
	    size_t eqpos = strcspn(cl, "=");
	    if (eqpos && eqpos < sizeof name && eqpos < dpos)
	    {
		memcpy(name, cl, eqpos);
		name[eqpos] = 0;
		char *value = PSC_malloc(dpos-eqpos);
		memcpy(value, cl+eqpos+1, dpos-eqpos-1);
		value[dpos-eqpos-1] = 0;
		if (!self->in) self->in = PSC_HashTable_create(5);
		PSC_HashTable_set(self->in, name, value, free);
	    }
	    cl += dpos;
	    if (*cl == ';') do ++cl; while (*cl == ' ');
	}
    }
    HttpContext_set(context, PROPNAME, self, cookiesDeleter);
    HttpContext_callNext(context);
    HttpResponse *response = HttpContext_response(context);
    if (!response || !self->out) return;
    HeaderSet *respHdr = HttpResponse_headers(response);
    PSC_HashTableIterator *i = PSC_HashTable_iterator(self->out);
    while (PSC_HashTableIterator_moveNext(i))
    {
	char hdrval[4096];
	if ((size_t)snprintf(hdrval, 1024, "%s=%s; Path=/; HttpOnly",
		    PSC_HashTableIterator_key(i),
		    (const char *)PSC_HashTableIterator_current(i))
		< sizeof hdrval)
	{
	    HeaderSet_add(respHdr, Header_create("Set-Cookie", hdrval));
	}
    }
    PSC_HashTableIterator_destroy(i);
}

