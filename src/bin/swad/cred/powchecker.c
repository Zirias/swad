#include "powchecker.h"

#include "../authenticator.h"

#include <poser/core/util.h>
#include <stdlib.h>

typedef struct PowChecker
{
    CredentialsChecker base;
    char *user;
    char *password;
    unsigned difficulty;
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
    free(self->password);
    free(self->user);
    free(self);
}

CredentialsChecker *CredentialsChecker_createPow(unsigned difficulty,
	const char *user, const char *password)
{
    PowChecker *self = PSC_malloc(sizeof *self);
    self->base.check = check;
    self->base.deviate = 0;
    self->base.destroy = destroyChecker;
    self->user = PSC_copystr(user);
    self->password = PSC_copystr(password);
    self->difficulty = difficulty;
    return (CredentialsChecker *)self;
}

