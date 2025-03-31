#ifndef SWAD_HTTPCONTEXT_H
#define SWAD_HTTPCONTEXT_H

#include <poser/decl.h>
#include <stddef.h>

C_CLASS_DECL(HttpContext);
C_CLASS_DECL(HttpRequest);
C_CLASS_DECL(HttpResponse);
C_CLASS_DECL(PSC_Connection);

typedef void (*HttpHandler)(HttpContext *context) ATTR_NONNULL((1));
typedef void (*ObjDeleter)(void *obj);
typedef HttpHandler (*MiddlewareLocator)(void *owner, size_t pos);

HttpContext *HttpContext_create(HttpRequest *request, HttpHandler handler,
	void *owner, MiddlewareLocator locator, PSC_Connection *conn)
    ATTR_NONNULL((1)) ATTR_NONNULL((2)) ATTR_NONNULL((4)) ATTR_RETNONNULL;
void *HttpContext_owner(const HttpContext *self) CMETHOD ATTR_PURE;
HttpRequest *HttpContext_request(HttpContext *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
HttpResponse *HttpContext_response(HttpContext *self) CMETHOD ATTR_PURE;
PSC_Connection *HttpContext_connection(HttpContext *self) CMETHOD;
const char *HttpContext_remoteAddr(const HttpContext *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
const char *HttpContext_remoteHost(const HttpContext *self) CMETHOD;
int HttpContext_reuseConnection(const HttpContext *self) CMETHOD ATTR_PURE;
void HttpContext_callNext(HttpContext *self) CMETHOD;
void *HttpContext_get(const HttpContext *self, const char *key)
    CMETHOD ATTR_NONNULL((2)) ATTR_PURE;
void HttpContext_set(HttpContext *self, const char *key,
	void *obj, ObjDeleter deleter) CMETHOD ATTR_NONNULL((2));
void HttpContext_setResponse(HttpContext *self, HttpResponse *response)
    CMETHOD;
void HttpContext_destroy(HttpContext *self);

#endif
