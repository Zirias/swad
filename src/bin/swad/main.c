#include "authenticator.h"
#include "handler/login.h"
#include "handler/root.h"
#include "httpserver.h"
#include "middleware/compress.h"
#include "middleware/cookies.h"
#include "middleware/csrfprotect.h"
#include "middleware/formdata.h"
#include "middleware/pathparser.h"
#include "middleware/session.h"

#include <poser/core.h>
#include <string.h>

static HttpServer *server;

static int checkDummy(void *self, const char *user, const char *pw,
	char **realname)
{
    (void)self;
    *realname = 0;
    return !strcmp(user, pw);
}

static CredentialsChecker dummyChecker = {
    .check = checkDummy,
    .destroy = 0
};

static void prestartup(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;
    (void)args;

    MW_FormData_setValidation(FDV_UTF8_SANITIZE);
    MW_Session_init();
    Authenticator_init();
    Authenticator_registerChecker("dummy", &dummyChecker);
    Authenticator_configureRealm(DEFAULT_REALM, "dummy");

    HttpServerOpts *opts = HttpServerOpts_create(8080);
    server = HttpServer_create(opts);
    HttpServerOpts_destroy(opts);

    HttpServer_addMiddleware(server, MW_Compress);
    HttpServer_addMiddleware(server, MW_Cookies);
    HttpServer_addMiddleware(server, MW_Session);
    HttpServer_addMiddleware(server, MW_PathParser);
    HttpServer_addMiddleware(server, MW_FormData);
    HttpServer_addMiddleware(server, MW_CSRFProtect);

    HttpServer_addRoute(server, "/login", loginHandler, HTTP_GET|HTTP_POST, 0);
    HttpServer_addRoute(server, "/", rootHandler, HTTP_GET, 0);
}

static void shutdown(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;
    (void)args;

    HttpServer_destroy(server);
    Authenticator_done();
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

