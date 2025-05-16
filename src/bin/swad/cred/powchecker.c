#include "powchecker.h"

#include "../authenticator.h"
#include "../csrfprotect.h"
#include "../handler/static.h"
#include "../http/httpcontext.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/formdata.h"
#include "../middleware/pathparser.h"
#include "../middleware/session.h"
#include "../template.h"
#include "../tmpl.h"

#include <openssl/sha.h>
#include <poser/core/random.h>
#include <poser/core/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct PowChecker
{
    CredentialsChecker base;
    char *user;
    char *password;
    unsigned difficulty;
} PowChecker;

static void deviate(void *obj, const Authenticator *auth)
{
    PowChecker *self = obj;

    HttpContext *context = Authenticator_context(auth);
    const FormData *form = FormData_get(context);
    if (!form) return;
    const PathParser *pathParser = PathParser_get(context);
    if (!pathParser) return;
    Session *session = Session_start(context);
    if (!session) return;
    char *challenge = PSC_Random_createStr(32, PSC_RF_NONBLOCK);
    Session_setProp(session, "_POW_CHALLENGE", challenge, free);

    char difficulty[8];
    char stylelink[256];
    char scriptlink[256];
    snprintf(difficulty, sizeof difficulty, "%u", self->difficulty);
    const char *path = PathParser_path(pathParser);
    staticHandler_link(stylelink, sizeof stylelink, path, "style.css");
    staticHandler_link(scriptlink, sizeof scriptlink, path, "pow.mjs");

    const char *rdr = FormData_single(form, "rdr", 0);
    if (!rdr || !*rdr) rdr = "/";
    Template *tmpl = Template_createStatic(tmpl_pow_html, tmpl_pow_html_sz);
    Template_setStaticVar(tmpl, "REALM", Authenticator_realm(auth), TF_HTML);
    Template_setStaticVar(tmpl, "RDR", rdr, TF_HTML);
    Template_setStaticVar(tmpl, "SELF", path, TF_NONE);
    Template_setStaticVar(tmpl, "USER", self->user, TF_HTML);
    Template_setStaticVar(tmpl, "CHALLENGE", challenge, TF_NONE);
    Template_setStaticVar(tmpl, "DIFFICULTY", difficulty, TF_NONE);
    Template_setStaticVar(tmpl, "STYLELINK", stylelink, TF_NONE);
    Template_setStaticVar(tmpl, "SCRIPTLINK", scriptlink, TF_NONE);
    HttpResponse *response = HttpResponse_create(HTTP_OK, MT_HTML);
    HttpResponse_passTextBody(response, Template_processHtml(tmpl));
    Template_destroy(tmpl);
    HttpContext_setResponse(context, response);
}

static AuthResult check(void *obj, const char *user, const char *pw,
	const Authenticator *auth, char **realname)
{
    PowChecker *self = obj;
    *realname = 0;

    if (!strcmp(user, self->user))
    {
	Session *session = Session_start(Authenticator_context(auth));
	if (!session) return AR_FAILED;
	const char *challenge = Session_getProp(session, "_POW_CHALLENGE");
	if (!challenge) goto checkdeviate;
	char tohash[128];
	int tohashlen = snprintf(tohash, sizeof tohash, "%s%s", challenge, pw);
	Session_setProp(session, "_POW_CHALLENGE", 0, 0);
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256((const unsigned char *)tohash, tohashlen, hash);
	for (unsigned i = 0; i < self->difficulty; ++i)
	{
	    unsigned char nibble = (hash[i/2] >> 4 * !(i % 2)) & 0xf;
	    if (nibble != 0) goto checkdeviate;
	}
	return AR_OK;

checkdeviate:
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

