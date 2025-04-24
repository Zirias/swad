#include "powchecker.h"

#include "../authenticator.h"
#include "../http/httpcontext.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/pathparser.h"
#include "../template.h"
#include "../tmpl.h"

#include <poser/core/util.h>
#include <stdlib.h>
#include <string.h>

typedef struct PowChecker
{
    CredentialsChecker base;
    char *user;
    char *password;
    unsigned difficulty;
} PowChecker;

static void deviate(void *obj, const Authenticator *auth, HttpContext *context)
{
    (void)obj;
    (void)auth;

    const PathParser *pathParser = PathParser_get(context);
    if (!pathParser) return;

    Template *tmpl = Template_createStatic(tmpl_pow_html, tmpl_pow_html_sz);
    Template_setStaticVar(tmpl, "SELF", PathParser_path(pathParser), TF_NONE);
    HttpResponse *response = HttpResponse_create(HTTP_OK, MT_HTML);
    HttpResponse_passTextBody(response, Template_process(tmpl));
    Template_destroy(tmpl);
    HttpContext_setResponse(context, response);
}

static AuthResult check(void *obj, const char *user, const char *pw,
	const Authenticator *auth, char **realname)
{
    (void)auth;

    PowChecker *self = obj;
    *realname = 0;

    if (!strcmp(user, self->user))
    {
	if (!strcmp(pw, self->password)) return AR_DEVIATE;
	return AR_FAILED;
    }
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
    self->base.deviate = deviate;
    self->base.destroy = destroyChecker;
    self->user = PSC_copystr(user);
    self->password = PSC_copystr(password);
    self->difficulty = difficulty;
    return (CredentialsChecker *)self;
}

