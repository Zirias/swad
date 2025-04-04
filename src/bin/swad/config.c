#define _POSIX_C_SOURCE 200112L

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <poser/core/log.h>
#include <poser/core/util.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define ARGBUFSZ 8

#define DEFCONFFILE SYSCONFDIR "/swad.conf"
#define DEFPIDFILE RUNSTATEDIR "/swad.pid"

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
    char *checkers[];
};

typedef enum CfgSection
{
    CS_INVALID,
    CS_GLOBAL,
    CS_CHECKERS,
    CS_REALMS
} CfgSection;

static size_t checkers_count;
static size_t checkers_capa;
static size_t realms_count;
static size_t realms_capa;

static CfgChecker **checkers;
static CfgRealm **realms;

static const char *cfgfile;
static char *cfg_pidfile;
static const char *pidfile;
static long uid = -1;
static long gid = -1;
static int resolveHosts = -1;
static int foreground = 0;
static int verbose = 0;

static unsigned lineno;
static CfgSection section;

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

static int readKeyValue(char *lp, char **key, char **value)
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
	    cfgfile, lineno);
    return 0;
}

static void readChecker(char *lp)
{
    char *key;
    char *value;
    if (!readKeyValue(lp, &key, &value)) return;

    char *args[8];
    size_t nargs = 0;
    char *classname = strtok(value, ":");
    char *arg;
    while ((arg = strtok(0, ":")))
    {
	if (nargs == sizeof args)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] too many arguments "
		    "for checker `%s', ignoring", cfgfile, lineno, key);
	    return;
	}
	args[nargs++] = arg;
    }

    CfgChecker *checker = PSC_malloc(sizeof *checker
	    + nargs * sizeof *checker->args);
    checker->name = PSC_copystr(key);
    checker->nargs = nargs;
    if (!strcmp(classname, "pam")) checker->class = CC_PAM;
    else checker->class = CC_NONE;
    for (size_t i = 0; i < nargs; ++i)
    {
	checker->args[i] = PSC_copystr(args[i]);
    }
    
    if (checkers_count == checkers_capa)
    {
	checkers_capa += 8;
	checkers = PSC_realloc(checkers, checkers_capa * sizeof *checkers);
    }
    checkers[checkers_count++] = checker;
}

static void readRealm(char *lp)
{
    char *key;
    char *value;
    if (!readKeyValue(lp, &key, &value)) return;

    char *chck[8];
    size_t nchck = 0;
    char *checker;
    while ((checker = strtok(value, ":")))
    {
	if (nchck == sizeof chck)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] too many checkers "
		    "for realm `%s', ignoring", cfgfile, lineno, key);
	    return;
	}
	chck[nchck++] = checker;
	value = 0;
    }

    CfgRealm *realm = PSC_malloc(sizeof *realm
	    + nchck * sizeof *realm->checkers);
    realm->name = PSC_copystr(key);
    realm->ncheckers = nchck;
    for (size_t i = 0; i < nchck; ++i)
    {
	realm->checkers[i] = PSC_copystr(chck[i]);
    }

    if (realms_count == realms_capa)
    {
	realms_capa += 8;
	realms = PSC_realloc(realms, realms_capa * sizeof *realms);
    }
    realms[realms_count++] = realm;
}

static int parseUser(const char *str)
{
    struct passwd *p;
    long tuid;

    if (longArg(&tuid, str) < 0)
    {
	if (!(p = getpwnam(str))) return -1;
	tuid = p->pw_uid;
    }
    else if (!(p = getpwuid(tuid))) return -1;
    uid = tuid;
    if (gid == -1) gid = p->pw_gid;
    return 0;
}

static int parseGroup(const char *str)
{
    struct group *g;
    long tgid;

    if (longArg(&tgid, str) < 0)
    {
	if (!(g = getgrnam(str))) return -1;
	tgid = g->gr_gid;
    }
    else if (!(g = getgrgid(tgid))) return -1;
    gid = tgid;
    return 0;
}

static void readOption(char *lp)
{
    char *key;
    char *value;
    if (!readKeyValue(lp, &key, &value)) return;

    if (!strcmp(key, "user"))
    {
	if (uid < 0 && parseUser(value) < 0)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] unknown user `%s', "
		    "ignoring", cfgfile, lineno, value);
	}
	return;
    }
    if (!strcmp(key, "group"))
    {
	if (gid < 0 && parseGroup(value) < 0)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] unknown group `%s', "
		    "ignoring", cfgfile, lineno, value);
	}
	return;
    }
    if (!strcmp(key, "pidfile"))
    {
	if (!pidfile)
	{
	    cfg_pidfile = PSC_copystr(value);
	    pidfile = cfg_pidfile;
	}
    }
    if (!strcmp(key, "resolveHosts"))
    {
	if (resolveHosts < 0 && boolArg(&resolveHosts, value) < 0)
	{
	    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] invalid setting `%s', "
		    "ignoring", cfgfile, lineno, value);
	}
	return;
    }

    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] unknown global option `%s', "
	    "ignoring", cfgfile, lineno, key);
}

static CfgSection readSection(char *lp)
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

    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] unknown section `%s', "
	    "ignoring the following values", cfgfile, lineno, start);
    return CS_INVALID;

error:
    PSC_Log_fmt(PSC_L_WARNING, "config: [%s:%u] malformed section, ignoring",
	    cfgfile, lineno);
    return section;
}

static void readConfigFile(FILE *f)
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
		    cfgfile, lineno);
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
	    section = readSection(lp);
	}
	else switch(section)
	{
	    case CS_INVALID:	break;
	    case CS_GLOBAL:	readOption(lp); break;
	    case CS_CHECKERS:	readChecker(lp); break;
	    case CS_REALMS:	readRealm(lp); break;
	}
    }
    
    if (ferror(f) || !feof(f))
    {
	PSC_Log_fmt(PSC_L_ERROR,
		"config: Error reading config file %s", cfgfile);
    }
}

static void usage(const char *prgname, const char *error)
{
    fprintf(stderr, "usage: %s [-Rfrv] [-u user] [-g group]\n", prgname);
    if (error) fprintf(stderr, "\nError: %s\n", error);
}

static int addArg(char *args, int *idx, char opt)
{
    if (*idx == ARGBUFSZ) return -1;
    memmove(args+1, args, (*idx)++);
    args[0] = opt;
    return 0;
}

static int optArg(char *args, int *idx, char *op, const char **error)
{
    *error = 0;
    if (!*idx) return -1;
    switch (args[--*idx])
    {
	case 'c':
	    cfgfile = op;
	    break;
	case 'g':
	    if (parseGroup(op) < 0)
	    {
		*error = "Unknown group";
		return -1;
	    }
	    break;
	case 'p':
	    pidfile = op;
	    break;
	case 'u':
	    if (parseUser(op) < 0)
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

static int readArguments(int argc, char **argv)
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
			if (optArg(needargs, &naidx, o, &errstr) < 0)
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
			resolveHosts = 0;
			break;

		    case 'f':
			foreground = 1;
			break;

		    case 'r':
			resolveHosts = 1;
			break;

		    case 'v':
			verbose = 1;
			break;

		    default:
			if (optArg(needargs, &naidx, o, &errstr) < 0)
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
	    if (optArg(needargs, &naidx, o, &errstr) < 0)
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

int Config_init(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    int rc = readArguments(argc, argv);
    if (!cfgfile) cfgfile = DEFCONFFILE;
    return rc;
}

void Config_readConfigFile(void)
{
    FILE *f = fopen(cfgfile, "r");
    if (f)
    {
	readConfigFile(f);
	fclose(f);
    }
    else
    {
	PSC_Log_fmt(PSC_L_WARNING, "config: Cannot open config file %s",
		cfgfile);
    }
}

const CfgChecker *Config_checker(size_t num)
{
    if (num >= checkers_count) return 0;
    return checkers[num];
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

const CfgRealm *Config_realm(size_t num)
{
    if (num >= realms_count) return 0;
    return realms[num];
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

long Config_uid(void)
{
    return uid;
}

long Config_gid(void)
{
    return gid;
}

const char *Config_pidfile(void)
{
    if (!pidfile) return DEFPIDFILE;
    return pidfile;
}

int Config_resolveHosts(void)
{
    return resolveHosts < 0 ? 0 : resolveHosts;
}

int Config_foreground(void)
{
    return foreground;
}

int Config_verbose(void)
{
    return verbose;
}

void Config_done(void)
{
    for (size_t i = 0; i < realms_count; ++i)
    {
	CfgRealm *r = realms[i];
	for (size_t j = 0; j < r->ncheckers; ++j)
	{
	    free(r->checkers[j]);
	}
	free(r->name);
	free(r);
    }
    free(realms);

    for (size_t i = 0; i < checkers_count; ++i)
    {
	CfgChecker *c = checkers[i];
	for (size_t j = 0; j < c->nargs; ++j)
	{
	    free(c->args[j]);
	}
	free(c->name);
	free(c);
    }
    free(checkers);

    free(cfg_pidfile);

    realms_count = 0;
    realms_capa = 0;
    checkers_count = 0;
    checkers_capa = 0;
    realms = 0;
    checkers = 0;
    uid = -1;
    gid = -1;
    cfg_pidfile = 0;
    pidfile = 0;
    resolveHosts = -1;
    foreground = 0;
    verbose = 0;
}

