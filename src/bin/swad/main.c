#include "authenticator.h"
#include "config.h"
#include "cred/pamchecker.h"
#include "handler/login.h"
#include "handler/root.h"
#include "http/httprequest.h"
#include "http/httpstatus.h"
#include "httpserver.h"
#include "middleware/compress.h"
#include "middleware/cookies.h"
#include "middleware/csrfprotect.h"
#include "middleware/formdata.h"
#include "middleware/pathparser.h"
#include "middleware/session.h"

#include <poser/core.h>
#include <stdlib.h>
#include <string.h>

static HttpServer *server;

static PSC_LogLevel logLevelFor(const HttpRequest *request, HttpStatus status)
{
    if (status != HTTP_OK) return PSC_L_INFO;
    const char *path = HttpRequest_path(request);
    if (path[0] == '/' && (!path[1] || path[1] == '?')) return PSC_L_DEBUG;
    return PSC_L_INFO;
}

static void prestartup(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;
    (void)args;

    MW_FormData_setValidation(FDV_UTF8_SANITIZE);
    MW_Session_init();
    Authenticator_init();

    const CfgChecker *c;
    CredentialsChecker *checker;
    for (size_t i = 0; (c = Config_checker(i)); ++i)
    {
	switch (CfgChecker_class(c))
	{
	    case CC_NONE:
		break;

	    case CC_PAM:
		checker = CredentialsChecker_createPam(CfgChecker_arg(c, 0));
		Authenticator_registerChecker(CfgChecker_name(c), checker);
		break;
	}
    }

    const CfgRealm *r;
    for (size_t i = 0; (r = Config_realm(i)); ++i)
    {
	const char *cname;
	for (size_t j = 0; (cname = CfgRealm_checker(r, j)); ++j)
	{
	    Authenticator_configureRealm(CfgRealm_name(r), cname);
	}
    }

    HttpServerOpts *opts = HttpServerOpts_create(8080);
    HttpServerOpts_numericHosts(opts);
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

    HttpServer_setLogLevelCallback(server, logLevelFor);
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

int main(int argc, char **argv)
{
    if (Config_init(argc, argv) < 0) return EXIT_FAILURE;
    PSC_RunOpts_init(Config_pidfile());
    PSC_RunOpts_enableDefaultLogging("swad");
    PSC_RunOpts_runas(Config_uid(), Config_gid());
    PSC_Event_register(PSC_Service_prestartup(), 0, prestartup, 0);
    PSC_Event_register(PSC_Service_shutdown(), 0, shutdown, 0);
    return PSC_Service_run();
}

