#include "config.h"

#include "help.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARGBUFSZ 8

static ConfigMode mode = CM_EDIT;
static ConfigPwMethod method = CPM_TERM;
static ConfigHashType type = CHT_DEFAULT;
static int cost = 12;
static const char *path = 0;
static const char *user = 0;
static const char *name = 0;

static void printusage(FILE *file, const char *prgname)
{
    fprintf(file, SWADPW_USAGE_FMT, SWADPW_USAGE_ARGS(prgname));
}

static void usage(const char *prgname, const char *error)
{
    printusage(stderr, prgname);
    if (error) fprintf(stderr, "\nError: %s\n", error);
}

static void help(const char *prgname)
{
    printusage(stdout, prgname);
    fputs(SWADPW_HELP, stdout);
}

static int addArg(char *args, int *idx, char opt)
{
    if (*idx == ARGBUFSZ) return -1;
    memmove(args+1, args, (*idx)++);
    args[0] = opt;
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

static int optArg(char *args, int *idx, char *op, const char **error)
{
    *error = 0;
    if (!*idx) return -1;
    switch (args[--*idx])
    {
	case 'c':
	    if (intArg(&cost, op, 10, 99, 10) < 0)
	    {
		*error = "Invalid value for cost (-c)";
		return -1;
	    }
	    break;
	case 'f':
	    path = op;
	    break;
	case 'n':
	    name = op;
	    break;
	default:
	    return -1;
    }
    return 0;
}

int Config_init(int argc, char **argv)
{
    int escapedash = 0;
    int arg;
    int naidx = 0;
    char needargs[ARGBUFSZ];
    const char onceflags[] = "cfn";
    char seen[sizeof onceflags - 1] = { 0 };

    const char *prgname = "swadpw";
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
		    case 'f':
		    case 'n':
			if (addArg(needargs, &naidx, *o) < 0) return -1;
			break;

		    case 'a':
			mode = CM_APPEND;
			break;

		    case 'b':
			type = CHT_OPENBSD;
			break;

		    case 'd':
			mode = CM_DELETE;
			break;

		    case 'h':
			help(prgname);
			return 1;

		    case 's':
			method = CPM_STDIN;
			break;

		    case 'y':
			type = CHT_APACHE;
			break;

		    case 'V':
			puts("swadpw v" VERSION);
			return 1;

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
	else if (!user)
	{
	    user = o;
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
    if (!path)
    {
	usage(prgname, "Required flag `file` (`-f`) not given");
	return -1;
    }
    if (!user)
    {
	usage(prgname, "Required parameter `user' not given");
	return -1;
    }
    return 0;
}

ConfigMode Config_mode(void)
{
    return mode;
}

ConfigPwMethod Config_method(void)
{
    return method;
}

ConfigHashType Config_type(void)
{
    return type;
}

int Config_cost(void)
{
    return cost;
}

const char *Config_path(void)
{
    return path;
}

const char *Config_user(void)
{
    return user;
}

const char *Config_name(void)
{
    return name;
}

