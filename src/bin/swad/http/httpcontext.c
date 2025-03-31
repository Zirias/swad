#include "httpcontext.h"

#include "../util.h"
#include "header.h"
#include "headerset.h"
#include "httprequest.h"
#include "httpresponse.h"

#include <poser/core.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CPHT_BITS 6
#define CPHT_SIZE HT_SIZE(CPHT_BITS)

typedef struct HttpCtxProp HttpCtxProp;

struct HttpCtxProp
{
    HttpCtxProp *next;
    const char *key;
    void *obj;
    ObjDeleter deleter;
};

struct HttpContext
{
    HttpCtxProp *buckets[CPHT_SIZE];
    void *owner;
    HttpRequest *request;
    HttpResponse *response;
    PSC_Connection *conn;
    char *remoteAddr;
    char *remoteHost;
    MiddlewareLocator locator;
    HttpHandler handler;
    int pipelinePos;
    int reuse;
};

static HttpCtxProp *findProp(const HttpContext *self,
	const char *key, uint8_t *hashval)
    CMETHOD ATTR_NONNULL((2)) ATTR_ACCESS((write_only, 3));
static HttpCtxProp *insertOrUpdate(HttpContext *self, const char *key)
    CMETHOD ATTR_NONNULL((2)) ATTR_RETNONNULL;

static void nameResolved(void *receiver, void *sender, void *args)
{
    (void)args;

    HttpContext *self = receiver;
    PSC_Connection *conn = sender;

    self->remoteHost = PSC_copystr(PSC_Connection_remoteHost(conn));
}

static void connectionClosed(void *receiver, void *sender, void *args)
{
    (void)sender;
    (void)args;

    HttpContext *self = receiver;
    self->conn = 0;
}

HttpContext *HttpContext_create(HttpRequest *request, HttpHandler handler,
	void *owner, MiddlewareLocator locator, PSC_Connection *conn)
{
    HttpContext *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    self->owner = owner;
    self->request = request;
    self->conn = conn;
    self->locator = locator;
    self->handler = handler;
    if (conn)
    {
	self->remoteAddr = PSC_copystr(PSC_Connection_remoteAddr(conn));
	const char *remoteHost = PSC_Connection_remoteHost(conn);
	if (remoteHost)
	{
	    self->remoteHost = PSC_copystr(remoteHost);
	}
	else
	{
	    PSC_Event_register(PSC_Connection_nameResolved(conn), self,
		    nameResolved, 0);
	}
	PSC_Event_register(PSC_Connection_closed(conn), self,
		connectionClosed, 0);
    }
    return self;
}

void *HttpContext_owner(const HttpContext *self)
{
    return self->owner;
}

HttpRequest *HttpContext_request(HttpContext *self)
{
    return self->request;
}

HttpResponse *HttpContext_response(HttpContext *self)
{
    return self->response;
}

PSC_Connection *HttpContext_connection(HttpContext *self)
{
    return self->conn;
}

const char *HttpContext_remoteAddr(const HttpContext *self)
{
    return self->remoteAddr;
}

const char *HttpContext_remoteHost(const HttpContext *self)
{
    return self->remoteHost;
}

int HttpContext_reuseConnection(const HttpContext *self)
{
    return self->reuse;
}

void HttpContext_callNext(HttpContext *self)
{
    HttpHandler next = self->locator(self->owner, self->pipelinePos++);
    if (!next) next = self->handler;
    next(self);
}

static HttpCtxProp *findProp(const HttpContext *self,
	const char *key, uint8_t *hashval)
{
    uint8_t h = hash(key, CPHT_BITS);
    if (hashval) *hashval = h;
    HttpCtxProp *prop = self->buckets[h];
    while (prop)
    {
	if (!strcmp(prop->key, key)) break;
	prop = prop->next;
    }
    return prop;
}

static HttpCtxProp *insertOrUpdate(HttpContext *self, const char *key)
{
    uint8_t hashval;
    HttpCtxProp *prop = findProp(self, key, &hashval);
    if (!prop)
    {
	prop = PSC_malloc(sizeof *prop);
	prop->next = 0;
	prop->key = key;
	prop->obj = 0;
	prop->deleter = 0;
	HttpCtxProp *parent = self->buckets[hashval];
	if (parent)
	{
	    while (parent->next) parent = parent->next;
	    parent->next = prop;
	}
	else self->buckets[hashval] = prop;
    }
    if (prop->deleter) prop->deleter(prop->obj);
    return prop;
}

void *HttpContext_get(const HttpContext *self, const char *key)
{
    HttpCtxProp *prop = findProp(self, key, 0);
    return prop ? prop->obj : 0;
}

void HttpContext_set(HttpContext *self, const char *key,
	void *obj, ObjDeleter deleter)
{
    HttpCtxProp *prop = insertOrUpdate(self, key);
    prop->obj = obj;
    prop->deleter = deleter;
}

void HttpContext_setResponse(HttpContext *self, HttpResponse *response)
{
    HttpResponse_destroy(self->response);
    self->response = response;
    HttpVersion version = HttpRequest_version(self->request);
    HttpResponse_setVersion(response, version);
    const Header *connection = HeaderSet_first(
	    HttpRequest_headers(self->request), "Connection");
    if (!HttpResponse_bodySize(response)) self->reuse = 0;
    else if (version == HTTP_1_0)
    {
	if (connection && !strcmp(Header_value(connection), "keep-alive"))
	{
	    self->reuse = 1;
	}
	else
	{
	    self->reuse = 0;
	}
    }
    else if (version == HTTP_1_1)
    {
	if (connection && !strcmp(Header_value(connection), "close"))
	{
	    self->reuse = 0;
	}
	else
	{
	    self->reuse = 1;
	}
    }
    else
    {
	self->reuse = 0;
    }
}

void HttpContext_destroy(HttpContext *self)
{
    if (!self) return;
    for (uint8_t h = 0; h < CPHT_SIZE; ++h)
    {
	HttpCtxProp *prop = self->buckets[h];
	while (prop)
	{
	    HttpCtxProp *next = prop->next;
	    if (prop->deleter) prop->deleter(prop->obj);
	    free(prop);
	    prop = next;
	}
    }
    free(self->remoteHost);
    free(self->remoteAddr);
    free(self);
}

