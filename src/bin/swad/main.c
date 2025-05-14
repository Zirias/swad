#define _POSIX_C_SOURCE 200112L

#include "authenticator.h"
#include "config.h"
#include "handler/login.h"
#include "handler/root.h"
#include "handler/static.h"
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
#  include "cred/powchecker.h"
#endif

#include <errno.h>
#include <poser/core.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

static void serverRemoved(const CfgServer *olds);
static void realmRemoved(const CfgRealm *oldr);

static ConfigUpdateHandler cfgupdate = {
    .serverRemoved =	serverRemoved,
    .realmRemoved =	realmRemoved
};

static PSC_HashTable *servers;
static Config *cfg;

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

    HttpServer_addRoute(server, Config_staticRoute(cfg),
	    staticHandler, HTTP_GET, 0);
    HttpServer_addRoute(server, Config_loginRoute(cfg),
	    loginHandler, HTTP_GET|HTTP_POST, 0);
    HttpServer_addRoute(server, "/",
	    rootHandler, HTTP_GET, 0);

    HttpServer_setLogLevelCallback(server, logLevelFor);
}

#ifdef CRED_EXEC
static CredentialsChecker *createExecChecker(const CfgChecker *ccfg)
{
    int timeout = 10000;
    int killtimeout = 5000;
    const char *path;
    long intarg;

    const char *argstr = CfgChecker_arg(ccfg, 0);
    if (!argstr)
    {
	PSC_Log_fmt(PSC_L_WARNING, "Credentials checker %s will always fail: "
		"missing argument `path' for `exec'", CfgChecker_name(ccfg));
	return 0;
    }
    path = argstr;

    argstr = CfgChecker_arg(ccfg, 1);
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
		    CfgChecker_name(ccfg), argstr);
	}
	else timeout = intarg;

	argstr = CfgChecker_arg(ccfg, 2);
	if (argstr)
	{
	    errno = 0;
	    intarg = strtol(argstr, &endp, 10);
	    if (errno == ERANGE || endp == argstr || *endp
		    || intarg < 500 || intarg > 10000)
	    {
		PSC_Log_fmt(PSC_L_WARNING, "Credentials checker %s: Invalid "
			"kill timeout value `%s', using default of 5000 ms",
			CfgChecker_name(ccfg), argstr);
	    }
	    else killtimeout = intarg;
	}
    }

    return CredentialsChecker_createExec(path, timeout, killtimeout);
}
#endif

#ifdef CRED_POW
static CredentialsChecker *createPowChecker(const CfgChecker *ccfg)
{
    unsigned difficulty = 4;
    const char *user = "guest";
    const char *password = "guest";

    const char *argstr = CfgChecker_arg(ccfg, 0);
    if (argstr)
    {
	char *endp;
	errno = 0;
	long intarg = strtol(argstr, &endp, 10);
	if (errno == ERANGE || endp == argstr || *endp
		|| intarg < 2 || intarg > 20)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "Credentials checker %s: Invalid "
		    "difficulty value `%s', using default of 5",
		    CfgChecker_name(ccfg), argstr);
	}
	else difficulty = intarg;

	argstr = CfgChecker_arg(ccfg, 1);
	if (argstr)
	{
	    user = argstr;
	    password = argstr;

	    argstr = CfgChecker_arg(ccfg, 2);
	    if (argstr) password = argstr;
	}
    }

    return CredentialsChecker_createPow(difficulty, user, password);
}
#endif

static void configureSession(void)
{
    PSC_RateLimitOpts *limitOpts = 0;
    uint16_t seconds;
    uint16_t limit;
    for (size_t i = 0; Config_sessionLimit(cfg, i, &seconds, &limit); ++i)
    {
	if (!limitOpts) limitOpts = PSC_RateLimitOpts_create(1);
	PSC_RateLimitOpts_addLimit(limitOpts, seconds, limit);
    }
    MW_SessionOpts_setCreateLimit(limitOpts);
    MW_SessionOpts_setMaxAge(
	    Config_sessionMaxAge(cfg), Config_sessionMaxIdle(cfg));
}

static void configureAuthenticator(void)
{
    PSC_RateLimitOpts *limitOpts = 0;
    uint16_t seconds;
    uint16_t limit;
    for (size_t i = 0; Config_loginFailLimit(cfg, i, &seconds, &limit); ++i)
    {
	if (!limitOpts) limitOpts = PSC_RateLimitOpts_create(0);
	PSC_RateLimitOpts_addLimit(limitOpts, seconds, limit);
    }
    Authenticator_setDefaultLimit(limitOpts);
    limitOpts = 0;

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
    for (size_t i = 0; (c = Config_checker(cfg, i)); ++i)
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
		checker = createPowChecker(c);
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
    for (size_t i = 0; (r = Config_realm(cfg, i)); ++i)
    {
	PSC_List *checkerNames = PSC_List_create();
	const char *cname;
	for (size_t j = 0; (cname = CfgRealm_checker(r, j)); ++j)
	{
	    PSC_List_append(checkerNames, PSC_copystr(cname), free);
	}
	for (size_t j = 0;
		CfgRealm_loginFailLimit(r, j, &seconds, &limit); ++j)
	{
	    if (!limitOpts) limitOpts = PSC_RateLimitOpts_create(0);
	    PSC_RateLimitOpts_addLimit(limitOpts, seconds, limit);
	}
	Authenticator_registerRealm(CfgRealm_name(r),
		Config_resourceDir(cfg), checkerNames, limitOpts);
	limitOpts = 0;
    }
}

static HttpServerOpts *createServerOpts(const CfgServer *s)
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
    if (Config_resolveHosts(cfg)) HttpServerOpts_resolveHosts(opts);
    HttpServerOpts_trustedProxies(opts, CfgServer_trustedProxies(s));
    HttpServerOpts_trustedHeader(opts, CfgServer_trustedHeader(s));
    HttpServerOpts_nat64Prefix(opts, CfgServer_nat64Prefix(s));
    HttpServerOpts_connTimeout(opts, CfgServer_connectionTimeout(s));
    HttpServerOpts_reqTimeout(opts, CfgServer_requestTimeout(s));
    return opts;
}

static HttpServer *createServer(const CfgServer *s)
{
    HttpServerOpts *opts = createServerOpts(s);
    HttpServer *server = HttpServer_create(opts);
    HttpServerOpts_destroy(opts);
    if (server) setupPipeline(server);
    return server;
}

static void destroyServer(void *obj)
{
    HttpServer_shutdown(obj);
}

static void realmRemoved(const CfgRealm *oldr)
{
    Authenticator_removeRealm(CfgRealm_name(oldr));
}

static void serverRemoved(const CfgServer *olds)
{
    const char *nm = CfgServer_name(olds);
    if (!nm) nm = "";
    PSC_HashTable_delete(servers, nm);
}

static void reloadConfig(int signo)
{
    (void)signo;

    struct ConfigUpdateData data;
    Authenticator_lockAndClear();
    Config_reread(cfg, &cfgupdate, &data);
    loginHandler_setRoute(Config_loginRoute(cfg));
    staticHandler_init(Config_resourceDir(cfg));
    configureAuthenticator();
    Authenticator_unlock();
    configureSession();

    const CfgServer *s;
    for (size_t i = 0; (s = Config_server(cfg, i)); ++i)
    {
	const char *nm = CfgServer_name(s);
	if (!nm) nm = "";
	HttpServer *server = PSC_HashTable_get(servers, nm);
	if (!server)
	{
	    server = createServer(s);
	    if (server) PSC_HashTable_set(servers, nm, server, destroyServer);
	    return;
	}

	HttpServerOpts *opts = createServerOpts(s);
	if (HttpServer_configure(server, opts) < 0)
	{
	    PSC_HashTable_delete(servers, nm);
	    server = HttpServer_create(opts);
	    if (server)
	    {
		setupPipeline(server);
		PSC_HashTable_set(servers, nm, server, destroyServer);
	    }
	}
	else
	{
	    HttpServer_updateRoute(server, data.oldLoginRoute, loginHandler,
		    Config_loginRoute(cfg));
	    HttpServer_updateRoute(server, data.oldStaticRoute, staticHandler,
		    Config_staticRoute(cfg));
	}
	HttpServerOpts_destroy(opts);
    }

    free(data.oldLoginRoute);
    free(data.oldStaticRoute);

    PSC_Log_setMaxLogLevel(Config_logLevel(cfg));
}

static void prestartup(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;

    PSC_EAStartup *ea = args;

    MW_FormData_setValidation(FDV_UTF8_SANITIZE);
    loginHandler_setRoute(Config_loginRoute(cfg));
    staticHandler_init(Config_resourceDir(cfg));

    configureSession();
    MW_Session_init();

    Authenticator_init();
    configureAuthenticator();

    const CfgServer *s;
    for (size_t i = 0; (s = Config_server(cfg, i)); ++i)
    {
	HttpServer *server = createServer(s);
	if (server)
	{
	    if (!servers) servers = PSC_HashTable_create(5);
	    const char *nm = CfgServer_name(s);
	    if (!nm) nm = "";
	    PSC_HashTable_set(servers, nm, server, destroyServer);
	}
	else
	{
	    const char *name = CfgServer_name(s);
	    if (name) PSC_Log_fmt(PSC_L_WARNING,
		    "Could not create server `%s'", name);
	    else PSC_Log_msg(PSC_L_WARNING, "Could not create default server");
	}
    }
    if (!servers)
    {
	PSC_Log_msg(PSC_L_ERROR, "Could not create any servers");
	PSC_EAStartup_return(ea, EXIT_FAILURE);
    }
    else
    {
	PSC_Log_setMaxLogLevel(Config_logLevel(cfg));
	PSC_Service_registerSignal(SIGHUP, reloadConfig);
    }
}

static void shutdown(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;
    (void)args;

    PSC_HashTable_destroy(servers);
    servers = 0;

    staticHandler_done();
    Authenticator_done();
    MW_Session_done();
    Config_destroy(cfg);
}

int main(int argc, char **argv)
{
    cfg = Config_create(argc, argv);
    PSC_Log_setMaxLogLevel(Config_logLevel(cfg));
    PSC_Log_setFileLogger(stderr);
    Config_readConfigFile(cfg);

    PSC_ThreadOpts_init(Config_defaultThreads(cfg));
    PSC_ThreadOpts_threadsPerCpu(Config_threadsPerCpu(cfg));
    PSC_ThreadOpts_maxThreads(Config_maxThreads(cfg));
    PSC_ThreadOpts_queuePerThread(Config_jobQueuePerThread(cfg));
    PSC_ThreadOpts_maxQueue(Config_maxJobQueue(cfg));

    PSC_RunOpts_init(Config_pidfile(cfg));
    PSC_RunOpts_enableDefaultLogging("swad");
    PSC_RunOpts_runas(Config_uid(cfg), Config_gid(cfg));
    if (Config_foreground(cfg)) PSC_RunOpts_foreground();
    PSC_Event_register(PSC_Service_prestartup(), 0, prestartup, 0);
    PSC_Event_register(PSC_Service_shutdown(), 0, shutdown, 0);
    return PSC_Service_run();
}

