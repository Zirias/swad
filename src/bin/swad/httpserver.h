#ifndef SWAD_HTTPSERVER_H
#define SWAD_HTTPSERVER_H

#include "http/httpmethod.h"
#include "http/httpstatus.h"
#include "proxyheader.h"

#include <poser/decl.h>
#include <poser/core/log.h>
#include <poser/core/proto.h>

C_CLASS_DECL(HttpRequest);
C_CLASS_DECL(HttpServer);
C_CLASS_DECL(HttpServerOpts);
C_CLASS_DECL(HttpContext);
C_CLASS_DECL(IpAddr);

typedef void (*HttpHandler)(HttpContext *context) ATTR_NONNULL((1));
typedef HttpMethod (*HttpMethodCheck)(const char *rawPath) ATTR_NONNULL((1));
typedef PSC_LogLevel (*LogLevelCallback)(const HttpRequest *request,
	HttpStatus status) ATTR_NONNULL((1));

HttpServerOpts *HttpServerOpts_create(int port)
    ATTR_RETNONNULL;
void HttpServerOpts_bind(HttpServerOpts *self, const char *bindhost)
    CMETHOD ATTR_NONNULL((2));
void HttpServerOpts_enableTls(HttpServerOpts *self,
	const char *certfile, const char *keyfile)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));
void HttpServerOpts_numericHosts(HttpServerOpts *self) CMETHOD;
void HttpServerOpts_setProto(HttpServerOpts *self, PSC_Proto proto) CMETHOD;
void HttpServerOpts_trustedProxies(HttpServerOpts *self, int num) CMETHOD;
void HttpServerOpts_trustedHeader(HttpServerOpts *self, ProxyHeader trusted)
    CMETHOD;
void HttpServerOpts_nat64Prefix(HttpServerOpts *self, const IpAddr *prefix)
    CMETHOD ATTR_NONNULL((2));
void HttpServerOpts_destroy(HttpServerOpts *self);

HttpServer *HttpServer_create(const HttpServerOpts *opts)
    ATTR_NONNULL((1));
void HttpServer_addRoute(HttpServer *self, const char *prefix,
	HttpHandler handler, HttpMethod methodMask,
	HttpMethodCheck methodCheck)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));
void HttpServer_addMiddleware(HttpServer *self, HttpHandler handler)
    CMETHOD ATTR_NONNULL((2));
void HttpServer_setLogLevelCallback(HttpServer *self, LogLevelCallback cb)
    CMETHOD;
void HttpServer_destroy(HttpServer *self);

#endif
