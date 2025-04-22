#include "filechecker.h"

#include "../util.h"

#include "../authenticator.h"

#include <poser/core/log.h>
#include <poser/core/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <swadbcrypt.h>

typedef struct FileChecker
{
    CredentialsChecker base;
    char *path;
} FileChecker;

static int check(void *obj, const char *user, const char *pw, char **realname)
{
    char buf[512];
    int ok = 0;

    FileChecker *self = obj;
    FILE *pwf = fopen(self->path, "r");

    if (pwf)
    {
	while (fgets(buf, sizeof buf, pwf))
	{
	    char *hash = strchr(buf, ':');
	    if (!hash) continue;
	    *hash++ = 0;
	    if (strcmp(buf, user)) continue;
	    char *rn = strchr(hash, ':');
	    char *nl = 0;
	    if (rn)
	    {
		*rn++ = 0;
		nl = strchr(rn, '\n');
	    }
	    else nl = strchr(hash, '\n');
	    if (nl) *nl = 0;
	    // verify we DO have a bcrypt hash
	    if (hash[0] != '$' || hash[1] != '2') continue;
	    // treat apache/php "2y" flavor as "2b"
	    if (hash[2] == 'y') hash[2] = 'b';
	    if (swad_bcrypt_check(pw, hash) == 1)
	    {
		ok = 1;
		*realname = rn ? PSC_copystr(rn) : 0;
	    }
	    break;
	}
	fclose(pwf);
	wipemem(buf, sizeof buf);
    }
    else
    {
	PSC_Log_fmt(PSC_L_WARNING, "filechecker: Cannot open `%s' for reading",
		self->path);
    }

    return ok;
}

static void destroyChecker(void *obj)
{
    FileChecker *self = obj;
    free(self->path);
    free(self);
}

CredentialsChecker *CredentialsChecker_createFile(const char *path)
{
    FileChecker *self = PSC_malloc(sizeof *self);
    self->base.check = check;
    self->base.destroy = destroyChecker;
    self->path = PSC_copystr(path);
    return (CredentialsChecker *)self;
}

