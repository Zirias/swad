#include "httpserver.h"

#include "http/header.h"
#include "http/headerset.h"
#include "http/httpcontext.h"
#include "http/httpmethod.h"
#include "http/httprequest.h"
#include "http/httpresponse.h"
#include "http/httpstatus.h"
#include "mediatype.h"
#include "util.h"

#include <poser/core.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ROUTESCHUNK 32
#define MIDDLEWARESCHUNK 8
#define CONNTIMEOUT 10
#define REQUESTTIMEOUT 30

typedef struct HttpRoute
{
    const char *prefix;
    HttpHandler handler;
    HttpMethod mask;
    HttpMethodCheck check;
} HttpRoute;

struct HttpServer
{
    LogLevelCallback loglevel;
    PSC_Server *server;
    HttpRoute *routes;
    HttpHandler *middlewares;
    size_t routescount;
    size_t routescapa;
    size_t middlewarescount;
    size_t middlewarescapa;
};

struct HttpServerOpts
{
    PSC_TcpServerOpts *serverOpts;
};

typedef struct ConnectionContext
{
    PSC_Timer *timer;
    PSC_ThreadJob *job;
} ConnectionContext;

static ConnectionContext *createContext(PSC_Connection *conn);
static void destroyContext(void *ctx);
static void connActive(void *receiver, void *sender, void *args);
static void connTimeout(void *receiver, void *sender, void *args);
static void connClosed(void *receiver, void *sender, void *args);
static HttpHandler getMiddlewareAt(void *owner, size_t pos) ATTR_PURE;
static void httpResponseSentSingle(void *receiver, void *sender, void *args);
static void httpResponseSentReuse(void *receiver, void *sender, void *args);
static void logRequest(HttpServer *self, HttpContext *context)
    CMETHOD ATTR_NONNULL((1));
static void pipelineJob(void *arg);
static void pipelineJobDone(void *receiver, void *sender, void *args);
static void pipelineCanceledJobDone(void *receiver, void *sender, void *args);
static void pipelineJobCanceled(void *receiver, void *sender, void *args);
static void requestReceived(void *receiver, void *sender, void *args);
static void tcpClientConnected(void *receiver, void *sender, void *args);

static ConnectionContext *createContext(PSC_Connection *conn)
{
    ConnectionContext *self = PSC_malloc(sizeof *self);
    self->timer = PSC_Timer_create();
    self->job = 0;
    PSC_Timer_setMs(self->timer, CONNTIMEOUT * 1000U);
    PSC_Timer_start(self->timer, 0);
    PSC_Event_register(PSC_Timer_expired(self->timer), conn, connTimeout, 0);
    return self;
}

static void destroyContext(void *ctx)
{
    if (!ctx) return;
    ConnectionContext *self = ctx;
    PSC_Timer_destroy(self->timer);
    free(self);
}

static void connActive(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)args;

    PSC_Connection *conn = sender;
    ConnectionContext *ctx = PSC_Connection_data(conn);
    PSC_Timer_setMs(ctx->timer, CONNTIMEOUT * 1000U);
}

static void connTimeout(void *receiver, void *sender, void *args)
{
    (void)sender;
    (void)args;

    PSC_Connection *conn = receiver;
    PSC_Log_fmt(PSC_L_DEBUG, "http: closing idle connection from %s",
	    PSC_Connection_remoteAddr(conn));
    PSC_Connection_close(conn, 0);
}

static void connClosed(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)args;

    PSC_Connection *conn = sender;
    PSC_Log_fmt(PSC_L_DEBUG, "http: connection closed with %s",
	    PSC_Connection_remoteAddr(conn));
    PSC_Event_unregister(PSC_Connection_dataReceived(conn), 0, connActive, 0);
    PSC_Event_unregister(PSC_Connection_dataSent(conn), 0, connActive, 0);
    PSC_Event_unregister(PSC_Connection_closed(conn), 0, connClosed, 0);
}

static void httpResponseSentSingle(void *receiver, void *sender, void *args)
{
    (void)receiver;

    HttpResponse *response = sender;
    HttpResponse_deleteLater(response);

    PSC_Connection *conn = args;
    if (conn)
    {
	PSC_Log_fmt(PSC_L_DEBUG,
		"http: response sent to %s, closing connection",
		PSC_Connection_remoteAddr(conn));
	PSC_Connection_close(conn, 0);
    }
    else PSC_Log_msg(PSC_L_DEBUG,
	    "http: connection closed while sending response");
}

static void httpResponseSentReuse(void *receiver, void *sender, void *args)
{
    HttpResponse *response = sender;
    HttpContext *context = receiver;
    PSC_Connection *conn = args;

    if (conn)
    {
	PSC_Log_fmt(PSC_L_DEBUG,
		"http: response sent to %s, reusing connection",
		PSC_Connection_remoteAddr(conn));
	HttpRequest *req = HttpRequest_create(conn);
	PSC_Event_register(HttpRequest_received(req),
		HttpContext_owner(context), requestReceived, 0);
    }
    else PSC_Log_msg(PSC_L_DEBUG,
	    "http: connection closed while sending response");

    HttpResponse_deleteLater(response);
    HttpRequest_deleteLater(HttpContext_request(context));
    HttpContext_destroy(context);
}

static void pipelineJob(void *arg)
{
    HttpContext_callNext(arg);
}

static HttpHandler getMiddlewareAt(void *owner, size_t pos)
{
    HttpServer *self = owner;
    if (pos >= self->middlewarescount) return 0;
    return self->middlewares[pos];
}

static void logRequest(HttpServer *self, HttpContext *context)
{
    char raddr[1024];
    HttpRequest *request = HttpContext_request(context);
    HttpStatus status = HttpResponse_status(HttpContext_response(context));
    PSC_LogLevel level = PSC_L_INFO;
    if (self->loglevel) level = self->loglevel(request, status);
    const char *remoteAddr = HttpContext_remoteAddr(context);
    const Header *fwd = HeaderSet_first(HttpRequest_headers(request),
	    "X-Forwarded-For");
    if (fwd)
    {
	snprintf(raddr, sizeof raddr, "%s, %s", remoteAddr, Header_value(fwd));
	remoteAddr = raddr;
    }
    const char *remoteHost = HttpContext_remoteHost(context);
    if (!remoteHost) remoteHost = "";
    PSC_Log_fmt(level, "http: %u - %s %s HTTP/1.%u - %s [%s]", status,
	    HttpRequest_rawMethod(request), HttpRequest_path(request),
	    HttpRequest_version(request), remoteHost, remoteAddr);
}

static void pipelineJobDone(void *receiver, void *sender, void *args)
{
    HttpServer *self = receiver;
    PSC_ThreadJob *job = sender;
    HttpContext *context = args;
    PSC_Connection *conn = HttpContext_connection(context);

    HttpRequest *req = HttpContext_request(context);
    HttpResponse *response = HttpContext_response(context);

    if (job)
    {
	PSC_Event_unregister(PSC_Connection_closed(conn), self,
		pipelineJobCanceled, 0);
	if (!PSC_ThreadJob_hasCompleted(job))
	{
	    HttpResponse_destroy(response);
	    response = HttpResponse_createError(HTTP_SERVICEUNAVAILABLE,
		    "Request timed out.");
	}
    }

    if (!response)
    {
	response = HttpResponse_createError(HTTP_INTERNALSERVERERROR, 0);
    }

    logRequest(self, context);

    HeaderSet *headers = HttpResponse_headers(response);
    HttpStatus status = HttpResponse_status(response);
    if (conn && HttpContext_reuseConnection(context)
	    && status != HTTP_BADREQUEST && status != HTTP_TOOMANYREQUESTS
	    && status < HTTP_INTERNALSERVERERROR)
    {
        HeaderSet_set(headers, Header_create("Connection", "keep-alive"));
        HeaderSet_set(headers, Header_create("Keep-Alive",
                    "timeout=" STR(CONNTIMEOUT) ", max=1000"));
	PSC_Event_register(HttpResponse_sent(response), context,
		httpResponseSentReuse, 0);
    }
    else
    {
	HeaderSet_set(headers, Header_create("Connection", "close"));
	if (conn) PSC_Event_register(HttpResponse_sent(response), 0,
		httpResponseSentSingle, 0);
	else httpResponseSentSingle(0, response, 0);
	HttpContext_destroy(context);
	HttpRequest_deleteLater(req);
    }
    HttpResponse_send(response, conn);
}

static void pipelineCanceledJobDone(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;

    HttpContext *context = args;
    HttpRequest_deleteLater(HttpContext_request(context));
    HttpResponse_destroy(HttpContext_response(context));
    HttpContext_destroy(context);
}

static void pipelineJobCanceled(void *receiver, void *sender, void *args)
{
    (void)args;

    HttpServer *self = receiver;
    PSC_Connection *conn = sender;
    ConnectionContext *ctx = PSC_Connection_data(conn);

    PSC_Event_unregister(PSC_ThreadJob_finished(ctx->job), self,
	    pipelineJobDone, 0);
    PSC_Event_unregister(PSC_Connection_closed(conn), self,
	    pipelineJobCanceled, 0);
    PSC_Event_register(PSC_ThreadJob_finished(ctx->job), self,
	    pipelineCanceledJobDone, 0);
    PSC_ThreadPool_cancel(ctx->job);
}

static void requestReceived(void *receiver, void *sender, void *args)
{
    HttpServer *self = receiver;
    HttpRequest *req = sender;
    PSC_Connection *conn = args;

    PSC_Log_fmt(PSC_L_DEBUG, "http: received request from %s",
	    PSC_Connection_remoteAddr(conn));

    HttpContext *context = 0;
    HttpResponse *response = 0;
    HttpHandler hdl = 0;

    HttpStatus reqStatus = HttpRequest_status(req);
    if (reqStatus != HTTP_OK)
    {
	response = HttpResponse_createError(reqStatus, 0);
	goto done;
    }

    const char *reqPath = HttpRequest_path(req);
    HttpMethod mask;
    for (size_t i = 0; i < self->routescount; ++i)
    {
	if (!strncmp(reqPath, self->routes[i].prefix,
		    strlen(self->routes[i].prefix)))
	{
	    hdl = self->routes[i].handler;
	    mask = self->routes[i].check
		? self->routes[i].check(reqPath)
		: self->routes[i].mask;
	    break;
	}
    }
    if (!hdl)
    {
	response = HttpResponse_createError(HTTP_NOTFOUND, 0);
    }
    else if (!(HttpRequest_method(req) & mask))
    {
	response = HttpResponse_createError(HTTP_METHODNOTALLOWED, 0);
	HttpResponse_setAllowHeader(response, mask);
    }

done:
    context = HttpContext_create(req, hdl, self, getMiddlewareAt, conn);
    if (!response)
    {
	ConnectionContext *ctx = PSC_Connection_data(conn);
	ctx->job = PSC_ThreadJob_create(
		pipelineJob, context, REQUESTTIMEOUT);
	PSC_Event_register(PSC_ThreadJob_finished(ctx->job), self,
		pipelineJobDone, 0);
	PSC_Event_register(PSC_Connection_closed(conn), self,
		pipelineJobCanceled, 0);
	if (PSC_ThreadPool_enqueue(ctx->job) < 0)
	{
	    PSC_Event_unregister(PSC_Connection_closed(conn), self,
		    pipelineJobCanceled, 0);
	    PSC_ThreadJob_destroy(ctx->job);
	    response = HttpResponse_createError(HTTP_SERVICEUNAVAILABLE, 0);
	}
    }
    if (response)
    {
	HttpContext_setResponse(context, response);
	pipelineJobDone(self, 0, context);
    }
}

static void tcpClientConnected(void *receiver, void *sender, void *args)
{
    (void)sender;

    HttpServer *self = receiver;
    PSC_Connection *client = args;

    PSC_Log_fmt(PSC_L_DEBUG, "http: TCP client connected from %s",
	    PSC_Connection_remoteAddr(client));
    PSC_Event_register(PSC_Connection_dataReceived(client),
	    self, connActive, 0);
    PSC_Event_register(PSC_Connection_dataSent(client), self, connActive, 0);
    PSC_Event_register(PSC_Connection_closed(client), self, connClosed, 0);
    PSC_Connection_setData(client, createContext(client), destroyContext);
    HttpRequest *req = HttpRequest_create(client);
    PSC_Event_register(HttpRequest_received(req), self, requestReceived, 0);
}

HttpServerOpts *HttpServerOpts_create(int port)
{
    HttpServerOpts *self = PSC_malloc(sizeof *self);
    self->serverOpts = PSC_TcpServerOpts_create(port);
    return self;
}

void HttpServerOpts_bind(HttpServerOpts *self, const char *bindhost)
{
    PSC_TcpServerOpts_bind(self->serverOpts, bindhost);
}

void HttpServerOpts_enableTls(HttpServerOpts *self,
	const char *certfile, const char *keyfile)
{
    PSC_TcpServerOpts_enableTls(self->serverOpts, certfile, keyfile);
}

void HttpServerOpts_numericHosts(HttpServerOpts *self)
{
    PSC_TcpServerOpts_numericHosts(self->serverOpts);
}

void HttpServerOpts_setProto(HttpServerOpts *self, PSC_Proto proto)
{
    PSC_TcpServerOpts_setProto(self->serverOpts, proto);
}

void HttpServerOpts_destroy(HttpServerOpts *self)
{
    if (!self) return;
    PSC_TcpServerOpts_destroy(self->serverOpts);
    free(self);
}

HttpServer *HttpServer_create(const HttpServerOpts *opts)
{
    PSC_Server *server = PSC_Server_createTcp(opts->serverOpts);
    if (!server) return 0;

    HttpServer *self = PSC_malloc(sizeof *self);
    self->server = server;
    self->routes = PSC_malloc(ROUTESCHUNK * sizeof *self->routes);
    self->middlewares = PSC_malloc(
	    MIDDLEWARESCHUNK * sizeof *self->middlewares);
    self->routescount = 0;
    self->routescapa = ROUTESCHUNK;
    self->middlewarescount = 0;
    self->middlewarescapa = MIDDLEWARESCHUNK;

    PSC_Event_register(PSC_Server_clientConnected(server), self,
	    tcpClientConnected, 0);

    return self;
}

void HttpServer_addRoute(HttpServer *self, const char *prefix,
	HttpHandler handler, HttpMethod methodMask,
	HttpMethodCheck methodCheck)
{
    if (self->routescount == self->routescapa)
    {
	self->routescapa += ROUTESCHUNK;
	self->routes = PSC_realloc(self->routes,
		self->routescapa * sizeof *self->routes);
    }
    self->routes[self->routescount].prefix = prefix;
    self->routes[self->routescount].handler = handler;
    self->routes[self->routescount].mask = methodMask;
    self->routes[self->routescount].check = methodCheck;
    ++self->routescount;
}

void HttpServer_addMiddleware(HttpServer *self, HttpHandler handler)
{
    if (self->middlewarescount == self->middlewarescapa)
    {
	self->middlewarescapa += MIDDLEWARESCHUNK;
	self->middlewares = PSC_realloc(self->middlewares,
		self->middlewarescapa * sizeof *self->middlewares);
    }
    self->middlewares[self->middlewarescount++] = handler;
}

void HttpServer_setLogLevelCallback(HttpServer *self, LogLevelCallback cb)
{
    self->loglevel = cb;
}

void HttpServer_destroy(HttpServer *self)
{
    if (!self) return;
    PSC_Server_destroy(self->server);
    free(self->middlewares);
    free(self->routes);
    free(self);
}

