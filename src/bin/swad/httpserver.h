#ifndef SWAD_HTTPSERVER_H
#define SWAD_HTTPSERVER_H

#include "http/httpmethod.h"

#include <poser/decl.h>

C_CLASS_DECL(HttpServer);
C_CLASS_DECL(HttpServerOpts);
C_CLASS_DECL(HttpContext);

typedef void (*HttpHandler)(HttpContext *context) ATTR_NONNULL((1));
typedef HttpMethod (*HttpMethodCheck)(const char *rawPath) ATTR_NONNULL((1));

HttpServerOpts *HttpServerOpts_create(int port)
    ATTR_RETNONNULL;
void HttpServerOpts_bind(HttpServerOpts *self, const char *bindhost)
    CMETHOD ATTR_NONNULL((2));
void HttpServerOpts_enableTls(HttpServerOpts *self,
	const char *certfile, const char *keyfile)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));
void HttpServerOpts_destroy(HttpServerOpts *self);

HttpServer *HttpServer_create(const HttpServerOpts *opts)
    ATTR_NONNULL((1));
void HttpServer_addRoute(HttpServer *self, const char *prefix,
	HttpHandler handler, HttpMethod methodMask,
	HttpMethodCheck methodCheck)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));
void HttpServer_addMiddleware(HttpServer *self, HttpHandler handler)
    CMETHOD ATTR_NONNULL((2));
void HttpServer_destroy(HttpServer *self);

#endif
