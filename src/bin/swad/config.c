#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "help.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poser/core/ipaddr.h>
#include <poser/core/log.h>
#include <poser/core/threadpool.h>
#include <poser/core/util.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define ARGBUFSZ 8

#define DEFCONFFILE	SYSCONFDIR "/swad.conf"
#define DEFPIDFILE	RUNSTATEDIR "/swad.pid"
#define DEFRESDIR	SYSCONFDIR "/swad"
#define DEFNTHREADS	8
#define DEFCPUNTHR	1
#define DEFMAXTHREADS	256
#define DEFCPUNTHRBLOCK	2
#define DEFTHRJOBQUEUE	4
#define DEFMAXJOBQUEUE	512

struct CfgChecker
{
    char *name;
    size_t nargs;
    CheckerClass class;
    char *args[];
};

struct CfgRealm
{
    char *name;
    size_t ncheckers;
    size_t nlimits;
    uint16_t seconds[8];
    uint16_t limits[8];
    char *checkers[];
};

struct CfgServer
{
    char *name;
    char *tlsCert;
    char *tlsKey;
    PSC_IpAddr *nat64Prefix;
    char **listen;
    size_t nlisten;
    PSC_Proto proto;
    ProxyHeader trustedHeader;
    int port;
    int tls;
    int trustedProxies;
};

typedef enum CfgSection
{
    CS_INVALID,
    CS_GLOBAL,
    CS_CHECKERS,
    CS_REALMS,
    CS_SERVER
} CfgSection;

struct Config
{
    CfgChecker **checkers;
    CfgRealm **realms;
    CfgServer **servers;
    const char *cfgfile;
    char *cfg_pidfile;
    const char *pidfile;
    char *loginRoute;
    char *staticRoute;
    char *resourceDir;
    size_t checkers_count;
    size_t checkers_capa;
    size_t realms_count;
    size_t realms_capa;
    size_t servers_count;
    size_t servers_capa;
    size_t nsessionLimits;
    size_t nloginLimits;
    long uid;
    long gid;
    int resolveHosts;
    int foreground;
    int verbose;
    int defaultThreads;
    int threadsPerCpu;
    int maxThreads;
    int jobQueuePerThread;
    int maxJobQueue;
    uint16_t sessionSeconds[8];
    uint16_t sessionLimits[8];
    uint16_t loginSeconds[8];
    uint16_t loginLimits[8];
};

static PSC_IpAddr *nat64Prefix;
static unsigned lineno;
static unsigned instcnt;
static CfgSection section;
static CfgServer *server;

#define skipws(p) while (isspace((unsigned char)*(p))) ++(p)

static int longArg(long *setting, const char *op)
{
    char *endp;
    errno = 0;
    long val = strtol(op, &endp, 10);
    if (errno == ERANGE || *endp) return -1;
    *setting = val;
    return 0;
}

static int intArg(int *setting, const char *op, int min, int max, int base)
{
    char *endp;
    errno = 0;
    long val = strtol(op, &endp, base);
    if (errno == ERANGE || *endp || val < min || val > max) return -1;
    *setting = val;
    return 0;
}

static int boolArg(int *setting, const char *str)
{
    if (!strcasecmp(str, "1")
	    || !strcasecmp(str, "on")
	    || !strcasecmp(str, "yes")
	    || !strcasecmp(str, "true"))
    {
	*setting = 1;
	return 0;
    }
    if (!strcasecmp(str, "0")
	    || !strcasecmp(str, "no")
	    || !strcasecmp(str, "off")
	    || !strcasecmp(str, "false"))
    {
	*setting = 0;
	return 0;
    }
    return -1;
}

static int limitsArg(uint16_t *seconds, uint16_t *limit, char *value)
{
    int rc = -1;
    char *limitstr = strchr(value, ':');
    if (!limitstr) goto done;
    *limitstr = 0;
    int pval;
    rc = intArg(&pval, value, 1, 86400, 10);
    *limitstr++ = ':';
    if (rc < 0) goto done;
    *seconds = pval;
    rc = intArg(&pval, limitstr, 1, 1024, 10);
    if (rc < 0) goto done;
    *limit = pval;
done:
    return rc;
}

static int readKeyValue(Config *self, char *lp, char **key, char **value)
{
    if (*lp == '=') goto error;
    char *k = lp;
    char *v = strchr(lp, '=');
    if (!v) goto error;
    char *kend = v;
    while (isspace((unsigned char)*(kend-1))) --kend;
    ++v;
    skipws(v);
    if (!*v || *v == ';' || *v == '#') goto error;
    size_t vlen = strcspn(v, ";#");
    while (isspace((unsigned char)v[vlen-1])) --vlen;
    *kend = 0;
    v[vlen] = 0;
    *key = k;
    *value = v;
    return 1;

error:
    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] malformed line, ignoring",
	    self->cfgfile, lineno);
    return 0;
}

static CfgServer *getServer(Config *self, const char *name)
{
    if (name && !*name)
    {
	PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] empty server name is not "
		"allowed, assuming the default server", self->cfgfile, lineno);
	name = 0;
    }

    CfgServer *s = 0;
    for (size_t i = 0; i < self->servers_count; ++i)
    {
	if ((!name && !self->servers[i]->name) ||
		(self->servers[i]->name &&
		 !strcmp(name, self->servers[i]->name)))
	{
	    s = self->servers[i];
	    break;
	}
    }

    if (!s)
    {
	s = PSC_malloc(sizeof *s);
	memset(s, 0, sizeof *s);
	if (name) s->name = PSC_copystr(name);
	s->port = 8080;
	s->trustedHeader = PH_XFWD | PH_RFC;
	if (self->servers_count == self->servers_capa)
	{
	    self->servers_capa += 8;
	    self->servers = PSC_realloc(self->servers,
		    self->servers_capa * sizeof *self->servers);
	}
	self->servers[self->servers_count++] = s;
    }

    return s;
}

static void readChecker(Config *self, char *lp)
{
    char *key;
    char *value;
    if (!readKeyValue(self, lp, &key, &value)) return;

    char *args[8];
    size_t nargs = 0;
    char *classname = strtok(value, ":");
    char *arg;
    while ((arg = strtok(0, ":")))
    {
	if (nargs == sizeof args)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] too many arguments "
		    "for checker `%s', ignoring", self->cfgfile, lineno, key);
	    return;
	}
	args[nargs++] = arg;
    }

    CfgChecker *checker = PSC_malloc(sizeof *checker
	    + nargs * sizeof *checker->args);
    checker->name = PSC_copystr(key);
    checker->nargs = nargs;
    if (!strcmp(classname, "exec")) checker->class = CC_EXEC;
    else if (!strcmp(classname, "file")) checker->class = CC_FILE;
    else if (!strcmp(classname, "pam")) checker->class = CC_PAM;
    else if (!strcmp(classname, "pow")) checker->class = CC_POW;
    else
    {
	PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] unknown credentials "
		"checker class `%s', this checker will always fail",
		self->cfgfile, lineno, key);
	checker->class = CC_NONE;
    }
    for (size_t i = 0; i < nargs; ++i)
    {
	checker->args[i] = PSC_copystr(args[i]);
    }
    
    if (self->checkers_count == self->checkers_capa)
    {
	self->checkers_capa += 8;
	self->checkers = PSC_realloc(self->checkers,
		self->checkers_capa * sizeof *self->checkers);
    }
    self->checkers[self->checkers_count++] = checker;
}

static void readRealm(Config *self, char *lp)
{
    char *key;
    char *value;
    if (!readKeyValue(self, lp, &key, &value)) return;

    char *opt = strstr(key, "_login_fail_limit");
    if (opt && strlen(opt) == sizeof "_login_fail_limit" - 1)
    {
	*opt++ = 0;
	CfgRealm *realm = 0;
	for (size_t i = 0; i < self->realms_count; ++i)
	{
	    if (!strcmp(self->realms[i]->name, key))
	    {
		realm = self->realms[i];
		break;
	    }
	}
	if (!realm)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] %s for unknown realm "
		    "`%s' found, ignoring", self->cfgfile, lineno, opt, key);
	    return;
	}
	if (realm->nlimits == sizeof realm->limits)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] too many login fail "
		    "limit entries, ignoring", self->cfgfile, lineno);
	    return;
	}
	if (limitsArg(realm->seconds + realm->nlimits,
		    realm->limits + realm->nlimits, value) < 0)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] invalid setting `%s' "
		    "for %s, ignoring", self->cfgfile, lineno, value, opt);
	}
	++realm->nlimits;
	return;
    }

    char *chck[8];
    size_t nchck = 0;
    char *checker;
    while ((checker = strtok(value, ":")))
    {
	if (nchck == sizeof chck)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] too many checkers "
		    "for realm `%s', ignoring", self->cfgfile, lineno, key);
	    return;
	}
	chck[nchck++] = checker;
	value = 0;
    }

    CfgRealm *realm = PSC_malloc(sizeof *realm
	    + nchck * sizeof *realm->checkers);
    realm->name = PSC_copystr(key);
    realm->ncheckers = nchck;
    realm->nlimits = 0;
    for (size_t i = 0; i < nchck; ++i)
    {
	realm->checkers[i] = PSC_copystr(chck[i]);
    }

    if (self->realms_count == self->realms_capa)
    {
	self->realms_capa += 8;
	self->realms = PSC_realloc(self->realms,
		self->realms_capa * sizeof *self->realms);
    }
    self->realms[self->realms_count++] = realm;
}

static void readServer(Config *self, char *lp)
{
    char *key;
    char *value;
    if (!readKeyValue(self, lp, &key, &value)) return;

    if (!strcmp(key, "port"))
    {
	if (intArg(&server->port, value, 1, 65535, 10) < 0) goto inval;
	return;
    }
    if (!strcmp(key, "listen"))
    {
	server->listen = PSC_realloc(server->listen,
		(server->nlisten + 1) * sizeof *server->listen);
	server->listen[server->nlisten++] = PSC_copystr(value);
	return;
    }
    if (!strcmp(key, "proto"))
    {
	if (!strcasecmp(value, "any")) server->proto = PSC_P_ANY;
	else if (!strcasecmp(value, "ipv4")) server->proto = PSC_P_IPv4;
	else if (!strcasecmp(value, "ipv6")) server->proto = PSC_P_IPv6;
	else goto inval;
	return;
    }
    if (!strcmp(key, "tls"))
    {
	if (boolArg(&server->tls, value) < 0) goto inval;
	return;
    }
    if (!strcmp(key, "tls_cert_file"))
    {
	free(server->tlsCert);
	server->tlsCert = PSC_copystr(value);
	return;
    }
    if (!strcmp(key, "tls_key_file"))
    {
	free(server->tlsKey);
	server->tlsKey = PSC_copystr(value);
	return;
    }
    if (!strcmp(key, "trusted_proxies"))
    {
	if (intArg(&server->trustedProxies, value, 0, 16, 10) < 0) goto inval;
	return;
    }
    if (!strcmp(key, "trusted_header"))
    {
	if (!strcmp(value, "xfwd")) server->trustedHeader = PH_XFWD;
	else if (!strcmp(value, "rfc")) server->trustedHeader = PH_RFC;
	else if (!strcmp(value, "prefer_xfwd"))
	{
	    server->trustedHeader = PH_XFWD | PH_RFC;
	}
	else if (!strcmp(value, "prefer_rfc"))
	{
	    server->trustedHeader = PH_XFWD | PH_RFC | PH_PREFRFC;
	}
	else goto inval;
	return;
    }
    if (!strcmp(key, "nat64_prefix"))
    {
	if (server->nat64Prefix) PSC_IpAddr_destroy(server->nat64Prefix);
	if ((server->nat64Prefix = PSC_IpAddr_create(value)) &&
		PSC_IpAddr_prefixlen(server->nat64Prefix) != 96)
	{
	    PSC_IpAddr_destroy(server->nat64Prefix);
	    server->nat64Prefix = 0;
	}
	if (!server->nat64Prefix) goto inval;
	return;
    }

    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] unknown server option `%s', "
	    "ignoring", self->cfgfile, lineno, key);
    return;

inval:
    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] invalid setting `%s' for %s, "
	    "ignoring", self->cfgfile, lineno, value, key);
}

static int parseUser(Config *self, const char *str)
{
    struct passwd *p;
    long tuid;

    if (longArg(&tuid, str) < 0)
    {
	if (!(p = getpwnam(str))) return -1;
	tuid = p->pw_uid;
    }
    else if (!(p = getpwuid(tuid))) return -1;
    self->uid = tuid;
    if (self->gid == -1) self->gid = p->pw_gid;
    return 0;
}

static int parseGroup(Config *self, const char *str)
{
    struct group *g;
    long tgid;

    if (longArg(&tgid, str) < 0)
    {
	if (!(g = getgrnam(str))) return -1;
	tgid = g->gr_gid;
    }
    else if (!(g = getgrgid(tgid))) return -1;
    self->gid = tgid;
    return 0;
}

static void readOption(Config *self, char *lp)
{
    char *key;
    char *value;
    if (!readKeyValue(self, lp, &key, &value)) return;

    if (!strcmp(key, "user"))
    {
	if (self->uid < 0 && parseUser(self, value) < 0)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] unknown user `%s', "
		    "ignoring", self->cfgfile, lineno, value);
	}
	return;
    }
    if (!strcmp(key, "group"))
    {
	if (self->gid < 0 && parseGroup(self, value) < 0)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] unknown group `%s', "
		    "ignoring", self->cfgfile, lineno, value);
	}
	return;
    }
    if (!strcmp(key, "pidfile"))
    {
	if (!self->pidfile)
	{
	    self->cfg_pidfile = PSC_copystr(value);
	    self->pidfile = self->cfg_pidfile;
	}
    }
    if (!strcmp(key, "resolve_hosts"))
    {
	if (self->resolveHosts < 0 &&
		boolArg(&self->resolveHosts, value) < 0) goto inval;
	return;
    }
    if (!strcmp(key, "session_limit"))
    {
	if (self->nsessionLimits == sizeof self->sessionLimits)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] too many session "
		    "limit entries, ignoring", self->cfgfile, lineno);
	    return;
	}
	if (limitsArg(self->sessionSeconds + self->nsessionLimits,
		    self->sessionLimits + self->nsessionLimits, value)
		< 0) goto inval;
	++self->nsessionLimits;
	return;
    }
    if (!strcmp(key, "login_fail_limit"))
    {
	if (self->nloginLimits == sizeof self->loginLimits)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] too many login fail "
		    "limit entries, ignoring", self->cfgfile, lineno);
	    return;
	}
	if (limitsArg(self->loginSeconds + self->nloginLimits,
		    self->loginLimits + self->nloginLimits, value)
		< 0) goto inval;
	++self->nloginLimits;
	return;
    }
    if (!strcmp(key, "login_route"))
    {
	free(self->loginRoute);
	free(self->staticRoute);
	size_t routelen = strlen(value);
	self->loginRoute = PSC_malloc(routelen + 1);
	memcpy(self->loginRoute, value, routelen + 1);
	self->staticRoute = PSC_malloc(routelen + sizeof "/static");
	memcpy(self->staticRoute, value, routelen);
	memcpy(self->staticRoute+routelen, "/static", sizeof "/static");
	return;
    }
    if (!strcmp(key, "resource_dir"))
    {
	free(self->resourceDir);
	self->resourceDir = PSC_copystr(value);
	return;
    }
    if (!strcmp(key, "threads_per_cpu"))
    {
	if (intArg(&self->threadsPerCpu, value, 1, 256, 10) < 0) goto inval;
	return;
    }
    if (!strcmp(key, "default_threads"))
    {
	if (intArg(&self->defaultThreads, value, 1, 4096, 10) < 0) goto inval;
	return;
    }
    if (!strcmp(key, "max_threads"))
    {
	if (intArg(&self->maxThreads, value, 1, 4096, 10) < 0) goto inval;
	return;
    }
    if (!strcmp(key, "job_queue_per_thread"))
    {
	if (intArg(&self->jobQueuePerThread, value, 1, 64, 10) < 0) goto inval;
	return;
    }
    if (!strcmp(key, "max_job_queue"))
    {
	if (intArg(&self->maxJobQueue, value, 1, 8192, 10) < 0) goto inval;
	return;
    }

    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] unknown global option `%s', "
	    "ignoring", self->cfgfile, lineno, key);
    return;

inval:
    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] invalid setting `%s' for %s, "
	    "ignoring", self->cfgfile, lineno, value, key);
}

static CfgSection readSection(Config *self, char *lp)
{
    ++lp;
    skipws(lp);
    if (!*lp || *lp == ']') goto error;
    char *start = lp;
    while (!isspace((unsigned char)*lp) && *lp != ']') ++lp;
    char *end = lp;
    skipws(lp);
    if (*lp != ']') goto error;
    ++lp;
    skipws(lp);
    if (*lp && *lp != ';' && *lp != '#') goto error;

    *end = 0;
    if (!strcmp(start, "global")) return CS_GLOBAL;
    if (!strcmp(start, "checkers")) return CS_CHECKERS;
    if (!strcmp(start, "realms")) return CS_REALMS;
    if (!strncmp(start, "server", sizeof "server" - 1))
    {
	char *name = start + (sizeof "server" - 1);
	if (*name == ':') *name++ = 0;
	else if (!*name) name = 0;
	else goto unknown;
	server = getServer(self, name);
	return CS_SERVER;
    }

unknown:
    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] unknown section `%s', "
	    "ignoring the following values", self->cfgfile, lineno, start);
    return CS_INVALID;

error:
    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] malformed section, ignoring",
	    self->cfgfile, lineno);
    return section;
}

static void readConfigFile(Config *self, FILE *f)
{
    char linebuf[1024];
    lineno = 0;
    section = CS_GLOBAL;

    char *lp;
    while ((lp = fgets(linebuf, sizeof linebuf, f)))
    {
	++lineno;
	char *nl = strchr(lp, '\n');
	if (!nl)
	{
	    PSC_Log_fmt(PSC_L_WARNING,
		    "config: [%s:%u] line exceeds maximum length, ignoring",
		    self->cfgfile, lineno);
	    while ((lp = fgets(linebuf, sizeof linebuf, f)))
	    {
		if (strchr(lp, '\n')) break;
	    }
	    continue;
	}
	*nl = 0;
	skipws(lp);
	if (!*lp || *lp == ';' || *lp == '#') continue;
	if (*lp == '[')
	{
	    section = readSection(self, lp);
	}
	else switch(section)
	{
	    case CS_INVALID:	break;
	    case CS_GLOBAL:	readOption(self, lp); break;
	    case CS_CHECKERS:	readChecker(self, lp); break;
	    case CS_REALMS:	readRealm(self, lp); break;
	    case CS_SERVER:	readServer(self, lp); break;
	}
    }
    
    if (ferror(f) || !feof(f))
    {
	PSC_Log_fmt(PSC_L_ERROR,
		"config: Error reading config file %s", self->cfgfile);
    }
}

static void printusage(FILE *file, const char *prgname)
{
    fprintf(file, SWAD_USAGE_FMT, SWAD_USAGE_ARGS(prgname));
}

static void usage(const char *prgname, const char *error)
{
    printusage(stderr, prgname);
    if (error) fprintf(stderr, "\nError: %s\n", error);
}

static void help(const char *prgname)
{
    printusage(stdout, prgname);
    fputs(SWAD_HELP, stdout);
}

static int addArg(char *args, int *idx, char opt)
{
    if (*idx == ARGBUFSZ) return -1;
    memmove(args+1, args, (*idx)++);
    args[0] = opt;
    return 0;
}

static int optArg(Config *self, char *args, int *idx, char *op,
	const char **error)
{
    *error = 0;
    if (!*idx) return -1;
    switch (args[--*idx])
    {
	case 'c':
	    self->cfgfile = op;
	    break;
	case 'g':
	    if (parseGroup(self, op) < 0)
	    {
		*error = "Unknown group";
		return -1;
	    }
	    break;
	case 'p':
	    self->pidfile = op;
	    break;
	case 'u':
	    if (parseUser(self, op) < 0)
	    {
		*error = "Unknown user";
		return -1;
	    }
	    break;
	default:
	    return -1;
    }
    return 0;
}

static int readArguments(Config *self, int argc, char **argv)
{
    int escapedash = 0;
    int arg;
    int naidx = 0;
    char needargs[ARGBUFSZ];
    const char onceflags[] = "cgpu";
    char seen[sizeof onceflags - 1] = {0};

    const char *prgname = "swad";
    if (argc > 0) prgname = argv[0];

    const char *errstr;
    for (arg = 1; arg < argc; ++arg)
    {
	char *o = argv[arg];
	if (!escapedash && *o == '-' && o[1] == '-' && !o[2])
	{
	    escapedash = 1;
	    continue;
	}

	if (!escapedash && *o == '-' && o[1])
	{
	    if (naidx)
	    {
		usage(prgname, "Missing argument(s) for given flags");
		return -1;
	    }

	    for (++o; *o; ++o)
	    {
		const char *sip = strchr(onceflags, *o);
		if (sip)
		{
		    int si = (int)(sip - onceflags);
		    if (seen[si])
		    {
			if (optArg(self, needargs, &naidx, o, &errstr) < 0)
			{
			    usage(prgname, errstr);
			    return -1;
			}
			else goto next;
		    }
		    seen[si] = 1;
		}
		switch (*o)
		{
		    case 'c':
		    case 'g':
		    case 'u':
			if (addArg(needargs, &naidx, *o) < 0) return -1;
			break;

		    case 'R':
			self->resolveHosts = 0;
			break;

		    case 'f':
			self->foreground = 1;
			break;

		    case 'h':
			help(prgname);
			return 1;

		    case 'r':
			self->resolveHosts = 1;
			break;

		    case 'V':
			puts("swad v" VERSION);
			return 1;

		    case 'v':
			self->verbose = 1;
			break;

		    default:
			if (optArg(self, needargs, &naidx, o, &errstr) < 0)
			{
			    usage(prgname, errstr);
			    return -1;
			}
			goto next;
		}
	    }
	}
	else if (!escapedash && naidx)
	{
	    if (optArg(self, needargs, &naidx, o, &errstr) < 0)
	    {
		usage(prgname, errstr);
		return -1;
	    }
	}
	else
	{
	    usage(prgname, "Extra arguments found");
	    return -1;
	}
next:	;
    }
    if (naidx)
    {
	usage(prgname, "Missing argument(s) for given flags");
	return -1;
    }
    return 0;
}

Config *Config_create(int argc, char **argv)
{
    Config *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    self->uid = -1;
    self->gid = -1;
    self->resolveHosts = -1;

    server = getServer(self, 0);
    int rc = readArguments(self, argc, argv);
    if (rc)
    {
	Config_destroy(self);
	if (rc < 0) exit(EXIT_FAILURE);
	else exit(EXIT_SUCCESS);
    }
    if (!self->cfgfile) self->cfgfile = DEFCONFFILE;
    ++instcnt;
    return self;
}

void Config_readConfigFile(Config *self)
{
    FILE *f = fopen(self->cfgfile, "r");
    if (f)
    {
	readConfigFile(self, f);
	fclose(f);
    }
    else
    {
	PSC_Log_fmt(PSC_L_WARNING, "config: Cannot open config file %s",
		self->cfgfile);
    }
}

static void destroyServer(CfgServer *s)
{
    for (size_t i = 0; i < s->nlisten; ++i)
    {
	free(s->listen[i]);
    }
    free(s->tlsKey);
    free(s->tlsCert);
    free(s->listen);
    free(s->name);
    free(s);
}

void Config_reread(Config *self, ConfigUpdateHandler *handlers)
{
    Config *other = PSC_malloc(sizeof *other);
    memset(other, 0, sizeof *other);
    other->resolveHosts = -1;
    other->cfgfile = self->cfgfile;
    int fd = open(other->cfgfile, O_RDONLY|O_CLOEXEC);
    FILE *f = 0;
    if (fd < 0 || !(f = fdopen(fd, "r")))
    {
	if (fd >= 0) close(fd);
	PSC_Log_fmt(PSC_L_WARNING, "config: Cannot open config file %s",
		other->cfgfile);
	Config_destroy(other);
	return;
    }
    server = getServer(other, 0);
    readConfigFile(other, f);
    fclose(f);

    self->resolveHosts = other->resolveHosts;

    for (size_t i = 0; i < self->servers_count; ++i)
    {
	CfgServer *os = 0;
	for (size_t j = 0; j < other->servers_count; ++j)
	{
	    if ((!self->servers[i]->name && !other->servers[j]->name) ||
		    (self->servers[i]->name && other->servers[j]->name &&
		     !strcmp(self->servers[i]->name, other->servers[j]->name)))
	    {
		os = other->servers[j];
		break;
	    }
	}
	if (!os)
	{
	    CfgServer *rs = self->servers[i];
	    if (handlers->serverRemoved) handlers->serverRemoved(rs);
	}
    }

    size_t newcount = other->servers_count;
    size_t newcapa = other->servers_capa;
    void *newlist = other->servers;
    other->servers_count = self->servers_count;
    other->servers_capa = self->servers_capa;
    other->servers = self->servers;
    self->servers_count = newcount;
    self->servers_capa = newcapa;
    self->servers = newlist;

    newcount = other->checkers_count;
    newcapa = other->checkers_capa;
    newlist = other->checkers;
    other->checkers_count = self->checkers_count;
    other->checkers_capa = self->checkers_capa;
    other->checkers = self->checkers;
    self->checkers_count = newcount;
    self->checkers_capa = newcapa;
    self->checkers = newlist;

    Config_destroy(other);
}

const CfgChecker *Config_checker(const Config *self, size_t num)
{
    if (num >= self->checkers_count) return 0;
    return self->checkers[num];
}

const char *CfgChecker_name(const CfgChecker *self)
{
    return self->name;
}

CheckerClass CfgChecker_class(const CfgChecker *self)
{
    return self->class;
}

const char *CfgChecker_arg(const CfgChecker *self, size_t num)
{
    if (num >= self->nargs) return 0;
    return self->args[num];
}

const CfgRealm *Config_realm(const Config *self, size_t num)
{
    if (num >= self->realms_count) return 0;
    return self->realms[num];
}

const char *CfgRealm_name(const CfgRealm *self)
{
    return self->name;
}

const char *CfgRealm_checker(const CfgRealm *self, size_t num)
{
    if (num >= self->ncheckers) return 0;
    return self->checkers[num];
}

int CfgRealm_loginFailLimit(const CfgRealm *self, size_t num,
	uint16_t *seconds, uint16_t *limit)
{
    if (num >= self->nlimits) return 0;
    *seconds = self->seconds[num];
    *limit = self->limits[num];
    return 1;
}

const CfgServer *Config_server(const Config *self, size_t num)
{
    if (num >= self->servers_count) return 0;
    return self->servers[num];
}

const char *CfgServer_name(const CfgServer *self)
{
    return self->name;
}

int CfgServer_port(const CfgServer *self)
{
    return self->port;
}

const char *CfgServer_listen(const CfgServer *self, size_t num)
{
    if (num >= self->nlisten) return 0;
    return self->listen[num];
}

PSC_Proto CfgServer_proto(const CfgServer *self)
{
    return self->proto;
}

int CfgServer_tls(const CfgServer *self)
{
    return self->tls;
}

const char *CfgServer_tlsCert(const CfgServer *self)
{
    return self->tlsCert;
}

const char *CfgServer_tlsKey(const CfgServer *self)
{
    return self->tlsKey;
}

int CfgServer_trustedProxies(const CfgServer *self)
{
    return self->trustedProxies;
}

ProxyHeader CfgServer_trustedHeader(const CfgServer *self)
{
    return self->trustedHeader;
}

const PSC_IpAddr *CfgServer_nat64Prefix(const CfgServer *self)
{
    if (self->nat64Prefix) return self->nat64Prefix;
    if (!nat64Prefix) nat64Prefix = PSC_IpAddr_create("64:ff9b::/96");
    return nat64Prefix;
}

long Config_uid(const Config *self)
{
    return self->uid;
}

long Config_gid(const Config *self)
{
    return self->gid;
}

const char *Config_pidfile(const Config *self)
{
    if (!self->pidfile) return DEFPIDFILE;
    return self->pidfile;
}

int Config_resolveHosts(const Config *self)
{
    return self->resolveHosts < 0 ? 0 : self->resolveHosts;
}

int Config_foreground(const Config *self)
{
    return self->foreground;
}

int Config_verbose(const Config *self)
{
    return self->verbose;
}

int Config_sessionLimit(const Config *self,
	size_t num, uint16_t *seconds, uint16_t *limit)
{
    if (num >= self->nsessionLimits) return 0;
    *seconds = self->sessionSeconds[num];
    *limit = self->sessionLimits[num];
    return 1;
}

int Config_loginFailLimit(const Config *self,
	size_t num, uint16_t *seconds, uint16_t *limit)
{
    if (num >= self->nloginLimits) return 0;
    *seconds = self->loginSeconds[num];
    *limit = self->loginLimits[num];
    return 1;
}

int Config_defaultThreads(const Config *self)
{
    if (self->defaultThreads) return self->defaultThreads;
    return DEFNTHREADS;
}

int Config_threadsPerCpu(const Config *self)
{
    if (self->threadsPerCpu) return self->threadsPerCpu;
    if (PSC_AsyncTask_awaitIsBlocking()) return DEFCPUNTHRBLOCK;
    return DEFCPUNTHR;
}

int Config_maxThreads(const Config *self)
{
    if (self->maxThreads) return self->maxThreads;
    return DEFMAXTHREADS;
}

int Config_jobQueuePerThread(const Config *self)
{
    if (self->jobQueuePerThread) return self->jobQueuePerThread;
    return DEFTHRJOBQUEUE;
}

int Config_maxJobQueue(const Config *self)
{
    if (self->maxJobQueue) return self->maxJobQueue;
    return DEFMAXJOBQUEUE;
}

const char *Config_loginRoute(const Config *self)
{
    if (!self->loginRoute) return "/login";
    return self->loginRoute;
}

const char *Config_staticRoute(const Config *self)
{
    if (!self->staticRoute) return "/login/static";
    return self->staticRoute;
}

const char *Config_resourceDir(const Config *self)
{
    if (!self->resourceDir) return DEFRESDIR;
    return self->resourceDir;
}

void Config_destroy(Config *self)
{
    if (!self) return;
    for (size_t i = 0; i < self->realms_count; ++i)
    {
	CfgRealm *r = self->realms[i];
	for (size_t j = 0; j < r->ncheckers; ++j)
	{
	    free(r->checkers[j]);
	}
	free(r->name);
	free(r);
    }
    free(self->realms);

    for (size_t i = 0; i < self->checkers_count; ++i)
    {
	CfgChecker *c = self->checkers[i];
	for (size_t j = 0; j < c->nargs; ++j)
	{
	    free(c->args[j]);
	}
	free(c->name);
	free(c);
    }
    free(self->checkers);

    for (size_t i = 0; i < self->servers_count; ++i)
    {
	destroyServer(self->servers[i]);
    }
    free(self->servers);
    free(self->cfg_pidfile);
    free(self->resourceDir);
    free(self->staticRoute);
    free(self->loginRoute);
    free(self);

    if (!--instcnt)
    {
	PSC_IpAddr_destroy(nat64Prefix);
	nat64Prefix = 0;
    }
}

