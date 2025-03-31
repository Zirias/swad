#include "handler/root.h"
#include "httpserver.h"
#include "middleware/compress.h"
#include "middleware/cookies.h"
#include "middleware/pathparser.h"
#include "middleware/session.h"

#include <poser/core.h>

static HttpServer *server;

static void prestartup(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;
    (void)args;

    MW_Session_init();

    HttpServerOpts *opts = HttpServerOpts_create(8080);
    server = HttpServer_create(opts);
    HttpServerOpts_destroy(opts);

    HttpServer_addMiddleware(server, MW_Compress);
    HttpServer_addMiddleware(server, MW_Cookies);
    HttpServer_addMiddleware(server, MW_PathParser);
    HttpServer_addMiddleware(server, MW_Session);

    HttpServer_addRoute(server, "/", rootHandler, HTTP_GET, 0);
}

static void shutdown(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;
    (void)args;

    HttpServer_destroy(server);
    MW_Session_done();
}

int main(void)
{
    PSC_RunOpts_foreground();
    PSC_RunOpts_enableDefaultLogging(0);
    PSC_Log_setMaxLogLevel(PSC_L_DEBUG);
    PSC_Event_register(PSC_Service_prestartup(), 0, prestartup, 0);
    PSC_Event_register(PSC_Service_shutdown(), 0, shutdown, 0);
    return PSC_Service_run();
}

