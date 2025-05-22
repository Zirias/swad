#define _POSIX_C_SOURCE 200112L

#include "powchecker.h"

#include "../authenticator.h"
#include "../csrfprotect.h"
#include "../handler/static.h"
#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/formdata.h"
#include "../middleware/pathparser.h"
#include "../proxylist.h"
#include "../template.h"
#include "../tmpl.h"

#include <openssl/sha.h>
#include <poser/core/base64.h>
#include <poser/core/hash.h>
#include <poser/core/ipaddr.h>
#include <poser/core/list.h>
#include <poser/core/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct PowChecker
{
    CredentialsChecker base;
    char *user;
    char *password;
    unsigned difficulty;
} PowChecker;

static void addHeader(char *buf, unsigned sz, unsigned *pos,
	const HeaderSet *headers, const char *name)
{
    const Header *hdr;
    if (*pos < sz && (hdr = HeaderSet_first(headers, name)))
    {
	const char *val = Header_value(hdr);
	size_t len = strlen(val);
	if (*pos + len > sz) len = sz - *pos;
	memcpy(buf + *pos, val, len);
	*pos += len;
    }
}

static char *createChallenge(HttpContext *context, time_t exp)
{
    char buf[4096];
    unsigned bufpos = 0;

    const HeaderSet *headers = HttpRequest_headers(
	    HttpContext_request(context));
    if (!headers) return 0;
    const PSC_List *remotes = ProxyList_get(context);
    if (!remotes) return 0;
    const RemoteEntry *entry = PSC_List_at(remotes,
	    ProxyList_firstTrusted(context));
    if (!entry) return 0;
    const char *remoteHost = PSC_IpAddr_string(RemoteEntry_addr(entry));

    memcpy(buf, &exp, sizeof exp);
    bufpos = sizeof exp;
    size_t rhlen = strlen(remoteHost);
    memcpy(buf+bufpos, remoteHost, rhlen);
    bufpos += rhlen;
    addHeader(buf, sizeof buf, &bufpos, headers, "User-Agent");
    addHeader(buf, sizeof buf, &bufpos, headers, "Accept");
    addHeader(buf, sizeof buf, &bufpos, headers, "Accept-Language");
    addHeader(buf, sizeof buf, &bufpos, headers, "Accept-Encoding");

    PSC_Hash *hasher = PSC_Hash_create(0, 1);
    uint64_t hash = PSC_Hash_bytes(hasher, buf, bufpos);
    PSC_Hash_destroy(hasher);
    return PSC_Base64_encode(&hash, sizeof hash, PSC_B64_URLSAFE);
}

static void deviate(void *obj, const Authenticator *auth)
{
    PowChecker *self = obj;

    HttpContext *context = Authenticator_context(auth);
    const FormData *form = FormData_get(context);
    if (!form) return;
    const PathParser *pathParser = PathParser_get(context);
    if (!pathParser) return;
    time_t exp = time(0) + 5U * 50U;
    char *challenge = createChallenge(context, exp);
    if (!challenge) return;

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
    Template_passVar(tmpl, "EXP",
	    PSC_Base64_encode(&exp, sizeof exp, PSC_B64_URLSAFE), TF_NONE);
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
	HttpContext *context = Authenticator_context(auth);
	const FormData *form = FormData_get(context);
	if (!form) return AR_FAILED;
	const char *expstr = FormData_single(form, "exp", 0);
	if (!expstr) goto checkdeviate;
	time_t exp;
	PSC_Base64_decodeTo(&exp, expstr, PSC_Base64_encodedLen(sizeof exp));
	if (time(0) >= exp) goto checkdeviate;
	const char *challenge = createChallenge(context, exp);
	if (!challenge) goto checkdeviate;
	char tohash[128];
	int tohashlen = snprintf(tohash, sizeof tohash, "%s%s", challenge, pw);
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

