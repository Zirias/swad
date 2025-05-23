#define _POSIX_C_SOURCE 200112L

#include "cookies.h"

#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../urlencode.h"

#include <poser/core.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAXNAMELEN 128
#define MAXENCNAMELEN (3 * MAXNAMELEN)

#define PROPNAME "_COOKIES"

struct Cookies
{
    PSC_HashTable *in;
    PSC_HashTable *out;
};

typedef struct SetCookie
{
    char *value;
    int64_t expires;
} SetCookie;

static void cookiesDeleter(void *obj)
{
    if (!obj) return;
    Cookies *self = obj;
    PSC_HashTable_destroy(self->out);
    PSC_HashTable_destroy(self->in);
    free(self);
}

static void deleteSetCookie(void *obj)
{
    if (!obj) return;
    SetCookie *cookie = obj;
    free(cookie->value);
    free(cookie);
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

void Cookies_setCookie(Cookies *self, const char *name, const char *value,
	int64_t expires)
{
    char encnm[MAXENCNAMELEN + 1];
    if (strlen(value) > MAXNAMELEN)
    {
	PSC_Log_msg(PSC_L_WARNING, "cookie: Name too long, ignoring");
	return;
    }
    size_t encsz = sizeof encnm;
    size_t encpos = 0;
    char *encbuf = encnm;
    urlencodeto(&encbuf, &encsz, &encpos, name);
    encnm[encpos] = 0;

    if (!self->out) self->out = PSC_HashTable_create(5);
    SetCookie *cookie = PSC_malloc(sizeof *cookie);
    cookie->value = PSC_copystr(value);
    cookie->expires = expires;
    PSC_HashTable_set(self->out, encnm, cookie, deleteSetCookie);
}

void Cookie_deleteCookie(Cookies *self, const char *name)
{
    if (!self->out) self->out = PSC_HashTable_create(5);
    SetCookie *cookie = PSC_malloc(sizeof *cookie);
    memset(cookie, 0, sizeof *cookie);
    PSC_HashTable_set(self->out, name, cookie, deleteSetCookie);
}

void MW_Cookies(HttpContext *context)
{
    Cookies *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    HttpRequest *req = HttpContext_request(context);
    const Header *cookie = HeaderSet_first(HttpRequest_headers(req), "Cookie");
    if (cookie)
    {
	const char *cl = Header_value(cookie);
	while (*cl == ' ') ++cl;
	while (*cl)
	{
	    size_t dpos = strcspn(cl, ";");
	    if (!dpos) break;
	    size_t eqpos = strcspn(cl, "=");
	    if (eqpos && eqpos < dpos)
	    {
		char *name = urldecode(cl, eqpos);
		char *value = PSC_malloc(dpos-eqpos);
		memcpy(value, cl+eqpos+1, dpos-eqpos-1);
		value[dpos-eqpos-1] = 0;
		if (!self->in) self->in = PSC_HashTable_create(5);
		PSC_HashTable_set(self->in, name, value, free);
		free(name);
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
	char expstr[32] = {0};
	SetCookie *scookie = PSC_HashTableIterator_current(i);
	size_t cookielen;
	if (scookie->value && scookie->expires)
	{
	    time_t expires = scookie->expires;
	    struct tm exp;
	    if (gmtime_r(&expires, &exp))
	    {
		if (!strftime(expstr, sizeof expstr,
			    "%a, %d %b %Y %T GMT", &exp))
		{
		    PSC_Log_msg(PSC_L_WARNING, "cookies: Cannot set expiry");
		    expstr[0] = 0;
		}
	    }
	}
	if (!scookie->value)
	{
	    cookielen = snprintf(hdrval, sizeof hdrval, "%s=; Path=/; "
		    "Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly",
		    PSC_HashTableIterator_key(i));
	}
	else if (!*expstr)
	{
	    cookielen = snprintf(hdrval, sizeof hdrval,
		    "%s=%s; Path=/; HttpOnly",
		    PSC_HashTableIterator_key(i), scookie->value);
	}
	else
	{
	    cookielen = snprintf(hdrval, sizeof hdrval,
		    "%s=%s; Path=/; Expires=%s; HttpOnly",
		    PSC_HashTableIterator_key(i), scookie->value, expstr);
	}
	if (cookielen < sizeof hdrval)
	{
	    HeaderSet_add(respHdr, Header_create("Set-Cookie", hdrval));
	}
	else
	{
	    PSC_Log_msg(PSC_L_WARNING, "cookies: Ignoring overlength cookie");
	}
    }
    PSC_HashTableIterator_destroy(i);
}

