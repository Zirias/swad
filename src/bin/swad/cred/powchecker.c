#include "powchecker.h"

#include "../authenticator.h"

#include <poser/core/util.h>
#include <stdlib.h>

typedef struct PowChecker
{
    CredentialsChecker base;
} PowChecker;

static AuthResult check(void *obj, const char *user, const char *pw,
	char **realname)
{
    (void)obj;
    (void)user;
    (void)pw;
    (void)realname;

    return AR_FAILED;
}

static void destroyChecker(void *obj)
{
    PowChecker *self = obj;
    free(self);
}

CredentialsChecker *CredentialsChecker_createPow(void)
{
    PowChecker *self = PSC_malloc(sizeof *self);
    self->base.check = check;
    self->base.deviate = 0;
    self->base.destroy = destroyChecker;
    return (CredentialsChecker *)self;
}

