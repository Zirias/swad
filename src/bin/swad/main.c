#include "authenticator.h"
#include "config.h"
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

#ifdef CRED_EXEC
#  include "cred/execchecker.h"
#endif

#ifdef CRED_FILE
#  include "cred/filechecker.h"
#endif

#ifdef CRED_PAM
#  include "cred/pamchecker.h"
#endif

#ifdef CRED_POW
#  include "handler/static.h"
#  include "cred/powchecker.h"
#endif

#include <errno.h>
#include <poser/core.h>
#include <stdlib.h>
#include <string.h>

static size_t servers_capa;
static size_t servers_count;
static HttpServer **servers;

static PSC_LogLevel logLevelFor(const HttpRequest *request, HttpStatus status)
{
    if (status != HTTP_OK) return PSC_L_INFO;
    const char *path = HttpRequest_path(request);
    if (path[0] == '/' && (!path[1] || path[1] == '?')) return PSC_L_DEBUG;
    return PSC_L_INFO;
}

static void setupPipeline(HttpServer *server)
{
    HttpServer_addMiddleware(server, MW_Compress);
    HttpServer_addMiddleware(server, MW_Cookies);
    HttpServer_addMiddleware(server, MW_Session);
    HttpServer_addMiddleware(server, MW_PathParser);
    HttpServer_addMiddleware(server, MW_FormData);
    HttpServer_addMiddleware(server, MW_CSRFProtect);

#ifdef CRED_POW
    HttpServer_addRoute(server, "/login/static", staticHandler, HTTP_GET, 0);
#endif
    HttpServer_addRoute(server, "/login", loginHandler, HTTP_GET|HTTP_POST, 0);
    HttpServer_addRoute(server, "/", rootHandler, HTTP_GET, 0);

    HttpServer_setLogLevelCallback(server, logLevelFor);
}

#ifdef CRED_EXEC
static CredentialsChecker *createExecChecker(const CfgChecker *cfg)
{
    int timeout = 10000;
    int killtimeout = 5000;
    const char *path;
    long intarg;

    const char *argstr = CfgChecker_arg(cfg, 0);
    if (!argstr)
    {
	PSC_Log_fmt(PSC_L_WARNING, "Credentials checker %s will always fail: "
		"missing argument `path' for `exec'", CfgChecker_name(cfg));
	return 0;
    }
    path = argstr;

    argstr = CfgChecker_arg(cfg, 1);
    if (argstr)
    {
	errno = 0;
	char *endp;
	intarg = strtol(argstr, &endp, 10);
	if (errno == ERANGE || endp == argstr || *endp
		|| intarg < 500 || intarg > 60000)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "Credentials checker %s: Invalid "
		    "timeout value `%s', using default of 10000 ms",
		    CfgChecker_name(cfg), argstr);
	}
	else timeout = intarg;

	argstr = CfgChecker_arg(cfg, 2);
	if (argstr)
	{
	    errno = 0;
	    intarg = strtol(argstr, &endp, 10);
	    if (errno == ERANGE || endp == argstr || *endp
		    || intarg < 500 || intarg > 10000)
	    {
		PSC_Log_fmt(PSC_L_WARNING, "Credentials checker %s: Invalid "
			"kill timeout value `%s', using default of 5000 ms",
			CfgChecker_name(cfg), argstr);
	    }
	    else killtimeout = intarg;
	}
    }

    return CredentialsChecker_createExec(path, timeout, killtimeout);
}
#endif

static void prestartup(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;

    PSC_EAStartup *ea = args;

    MW_FormData_setValidation(FDV_UTF8_SANITIZE);

    uint16_t seconds;
    uint16_t limit;
    for (size_t i = 0; Config_sessionLimit(i, &seconds, &limit); ++i)
    {
	MW_SessionOpts_addLimit(seconds, limit);
    }
    MW_Session_init();

    for (size_t i = 0; Config_loginFailLimit(i, &seconds, &limit); ++i)
    {
	Authenticator_addDefaultLimit(seconds, limit);
    }
    Authenticator_init();

    const CfgChecker *c;
#if defined(CRED_EXEC) || defined(CRED_FILE) \
    || defined(CRED_PAM) || defined(CRED_POW)
    CredentialsChecker *checker;
#endif
#if !defined(CRED_EXEC) || !defined(CRED_FILE) \
    || !defined(CRED_PAM) || !defined(CRED_POW)
    const char *checkerClassName;
    const char *checkerBuildOpt;
#endif
    for (size_t i = 0; (c = Config_checker(i)); ++i)
    {
	switch (CfgChecker_class(c))
	{
	    case CC_NONE:
		break;

	    case CC_EXEC:
#ifdef CRED_EXEC
		checker = createExecChecker(c);
		if (!checker) continue;
		goto doregister;
#else
		checkerClassName = "exec";
		checkerBuildOpt = "CRED_EXEC";
		goto dofail;
#endif

	    case CC_FILE:
#ifdef CRED_FILE
		checker = CredentialsChecker_createFile(CfgChecker_arg(c, 0));
		goto doregister;
#else
		checkerClassName = "file";
		checkerBuildOpt = "CRED_FILE";
		goto dofail;
#endif

	    case CC_PAM:
#ifdef CRED_PAM
		checker = CredentialsChecker_createPam(CfgChecker_arg(c, 0));
		goto doregister;
#else
		checkerClassName = "pam";
		checkerBuildOpt = "CRED_PAM";
		goto dofail;
#endif

	    case CC_POW:
#ifdef CRED_POW
		checker = CredentialsChecker_createPow();
		goto doregister;
#else
		checkerClassName = "pow";
		checkerBuildOpt = "CRED_POW";
		goto dofail;
#endif

#if defined(CRED_EXEC) || defined(CRED_FILE) \
    || defined(CRED_PAM) || defined(CRED_POW)
	    doregister:
		Authenticator_registerChecker(CfgChecker_name(c), checker);
		break;
#endif

#if !defined(CRED_EXEC) || !defined(CRED_FILE) \
    || !defined(CRED_PAM) || !defined(CRED_POW)
	    dofail:
		PSC_Log_fmt(PSC_L_WARNING, "Credentials checker %s will "
			"always fail, because swad was built without support "
			"for %s. Rebuild with %s enabled to fix this.",
			CfgChecker_name(c), checkerClassName, checkerBuildOpt);
		break;
#endif
	}
    }

    const CfgRealm *r;
    for (size_t i = 0; (r = Config_realm(i)); ++i)
    {
	Realm *realm = Realm_create(CfgRealm_name(r));
	const char *cname;
	for (size_t j = 0; (cname = CfgRealm_checker(r, j)); ++j)
	{
	    Realm_addChecker(realm, cname);
	}
	for (size_t j = 0;
		CfgRealm_loginFailLimit(r, j, &seconds, &limit); ++j)
	{
	    Realm_addLimit(realm, seconds, limit);
	}
	Authenticator_registerRealm(realm);
    }

    const CfgServer *s;
    for (size_t i = 0; (s = Config_server(i)); ++i)
    {
	HttpServerOpts *opts = HttpServerOpts_create(CfgServer_port(s));
	const char *l;
	for (size_t j = 0; (l = CfgServer_listen(s, j)); ++j)
	{
	    HttpServerOpts_bind(opts, l);
	}
	if (CfgServer_tls(s))
	{
	    HttpServerOpts_enableTls(opts,
		    CfgServer_tlsCert(s), CfgServer_tlsKey(s));
	}
	HttpServerOpts_setProto(opts, CfgServer_proto(s));
	if (Config_resolveHosts()) HttpServerOpts_resolveHosts(opts);
	HttpServerOpts_trustedProxies(opts, CfgServer_trustedProxies(s));
	HttpServerOpts_trustedHeader(opts, CfgServer_trustedHeader(s));
	HttpServerOpts_nat64Prefix(opts, CfgServer_nat64Prefix(s));
	HttpServer *server = HttpServer_create(opts);
	HttpServerOpts_destroy(opts);
	if (server)
	{
	    setupPipeline(server);
	    if (servers_count == servers_capa)
	    {
		servers_capa += 8;
		servers = PSC_realloc(servers, servers_capa * sizeof *servers);
	    }
	    servers[servers_count++] = server;
	}
	else
	{
	    const char *name = CfgServer_name(s);
	    if (name) PSC_Log_fmt(PSC_L_WARNING,
		    "Could not create server `%s'", name);
	    else PSC_Log_msg(PSC_L_WARNING, "Could not create default server");
	}
    }
    if (!servers_count)
    {
	PSC_Log_msg(PSC_L_ERROR, "Could not create any servers");
	PSC_EAStartup_return(ea, EXIT_FAILURE);
    }
}

static void shutdown(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;
    (void)args;

    for (size_t i = 0; i < servers_count; ++i)
    {
	HttpServer_destroy(servers[i]);
    }
    free(servers);
    servers = 0;

    Authenticator_done();
    MW_Session_done();
}

int main(int argc, char **argv)
{
    int rc = Config_init(argc, argv);
    if (rc < 0) return EXIT_FAILURE;
    if (rc > 0) return EXIT_SUCCESS;
    PSC_Log_setMaxLogLevel(Config_verbose() ? PSC_L_DEBUG : PSC_L_INFO);
    PSC_Log_setFileLogger(stderr);
    Config_readConfigFile();

    PSC_RunOpts_init(Config_pidfile());
    PSC_RunOpts_enableDefaultLogging("swad");
    PSC_RunOpts_runas(Config_uid(), Config_gid());
    if (Config_foreground()) PSC_RunOpts_foreground();
    PSC_Event_register(PSC_Service_prestartup(), 0, prestartup, 0);
    PSC_Event_register(PSC_Service_shutdown(), 0, shutdown, 0);
    return PSC_Service_run();
}

