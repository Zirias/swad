#include "login.h"

#include "../authenticator.h"
#include "../csrfprotect.h"
#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/formdata.h"
#include "../middleware/pathparser.h"
#include "../template.h"
#include "../urlencode.h"
#include "static.h"

#include <poser/core.h>
#include <stdlib.h>
#include <string.h>

#define QP_RDR	    "rdr"
#define QP_REALM    "realm"
#define QP_ERRNO    "err"
#define QP_USER	    "user"
#define HDR_RDR	    "X-SWAD-Rdr"
#define HDR_REALM   "X-SWAD-Realm"

#define ERR_OK	    0
#define ERR_FAILED  1
#define ERR_BLOCKED 2

static const char defroute[] = "/login";
static const char *route = defroute;

static void doLogin(HttpContext *context)
{
    HttpStatus status = HTTP_SEEOTHER;
    const char *rdr = loginHandler_route();
    const char *rdrUser = 0;
    int rdrErr = ERR_OK;
    FormData *form = FormData_get(context);
    if (!form) goto done;

    size_t len = 0;
    const char *authrdr = FormData_single(form, "rdr", &len);
    if (!authrdr || len < 1 || len > 16384) goto done;

    const char *realm = FormData_single(form, "realm", &len);
    if (!realm || len < 1 || len > 1024) goto done;

    if (FormData_single(form, "login", 0))
    {
	const char *user = FormData_single(form, "user", &len);
	if (!user || len < 1 || len > 32) goto done;

	const char *pw = FormData_single(form, "pw", &len);
	if (!pw || len < 1 || len > 32) goto done;

	Authenticator *auth = Authenticator_create(context, realm);
	AuthResult result = Authenticator_login(auth, user, pw);
	FormData_wipe(form, "pw");
	if (result == AR_OK)
	{
	    status = HTTP_OK;
	    rdr = authrdr;
	    PSC_Log_fmt(PSC_L_INFO, "login: %s logged in for %s",
		    user, realm);
	}
	else if (result == AR_DEVIATE)
	{
	    Authenticator_deviate(auth);
	    Authenticator_destroy(auth);
	    return;
	}
	else
	{
	    if (result == AR_BLOCKED)
	    {
		rdrErr = ERR_BLOCKED;
		PSC_Log_fmt(PSC_L_WARNING, "login: Blocked login as %s for %s",
			user, realm);
	    }
	    else
	    {
		rdrErr = ERR_FAILED;
		PSC_Log_fmt(PSC_L_WARNING, "login: Failed login as %s for %s",
			user, realm);
	    }
	    rdrUser = user;
	}
	Authenticator_destroy(auth);
    }
    else if (FormData_single(form, "logout", 0))
    {
	Authenticator *auth = Authenticator_create(context, realm);
	if (Authenticator_user(auth))
	{
	    Authenticator_logout(auth);
	    status = HTTP_OK;
	    rdr = authrdr;
	}
	Authenticator_destroy(auth);
    }

done:
    if (!rdr) rdr = "/";
    if (rdrErr || rdrUser)
    {
	char *encRealm = urlencode(realm);
	char *encRdr = urlencode(authrdr);
	char *encUser = 0;
	size_t qslen = strlen(rdr) + strlen(encRealm) + strlen(encRdr)
	    + sizeof "?&=" QP_RDR QP_REALM;
	if (rdrErr)
	{
	    qslen += sizeof "?" QP_ERRNO "=";
	}
	if (rdrUser)
	{
	    encUser = urlencode(rdrUser);
	    qslen += strlen(encUser) + sizeof "?" QP_USER;
	}
	char *rdrqs = PSC_malloc(qslen + 1);
	if (rdrErr)
	{
	    if (encUser) sprintf(rdrqs, "%s?" QP_REALM "=%s&" QP_RDR "=%s&"
		    QP_ERRNO "=%d&" QP_USER "=%s",
		    rdr, encRealm, encRdr, rdrErr, encUser);
	    else sprintf(rdrqs, "%s?" QP_REALM "=%s&" QP_RDR "=%s&"
		    QP_ERRNO "=%d", rdr, encRealm, encRdr, rdrErr);
	}
	else sprintf(rdrqs, "%s?" QP_REALM "=%s&" QP_RDR "=%s&"
		QP_USER "=%s", rdr, encRealm, encRdr, encUser);
	free(encUser);
	free(encRdr);
	free(encRealm);
	HttpContext_setResponse(context,
		HttpResponse_createRedirect(status, rdrqs));
	free(rdrqs);
    }
    else HttpContext_setResponse(context,
	    HttpResponse_createRedirect(status, rdr));
}

static void showForm(HttpContext *context, const PathParser *pathParser)
{
    const HeaderSet *hdr = HttpRequest_headers(HttpContext_request(context));
    const char *realm = loginHandler_realm(hdr, pathParser);
    Authenticator *auth = Authenticator_create(context, realm);
    const User *user = Authenticator_user(auth);
    if (!user && Authenticator_silentLogin(auth) == AR_OK)
    {
	user = Authenticator_user(auth);
	Authenticator_destroy(auth);
	PSC_Log_fmt(PSC_L_INFO, "login: %s silently logged in for %s",
		User_username(user), realm);
	HttpContext_setResponse(context,
		HttpResponse_createRedirect(HTTP_OK,
		    loginHandler_rdr(hdr, pathParser)));
	return;
    }
    const uint8_t *tdata;
    size_t tsz;
    if (user) tdata = Authenticator_logoutTmpl(auth, &tsz);
    else tdata = Authenticator_loginTmpl(auth, &tsz);
    Authenticator_destroy(auth);

    Template *tmpl = Template_createStatic(tdata, tsz);
    if (user)
    {
	const char *username = User_username(user);
	const char *realname = User_realname(user);
	if (!realname || !*realname) realname = "<Unknown name>";
	Template_setStaticVar(tmpl, "USER", username, TF_HTML);
	Template_setStaticVar(tmpl, "REALNAME", realname, TF_HTML);
    }
    else
    {
	const QueryParam *errnoParam = PathParser_param(
		pathParser, QP_ERRNO, 0);
	if (errnoParam)
	{
	    int err = atoi(QueryParam_value(errnoParam));
	    const char *errstr = 0;
	    switch (err)
	    {
		case ERR_FAILED:
		    errstr = "Invalid credentials";
		    break;

		case ERR_BLOCKED:
		    errstr = "Too many failed attempts, try again later";
		    break;
	    }
	    if (errstr) Template_setStaticVar(tmpl, "ERRMSG", errstr, TF_NONE);
	}
	const QueryParam *userParam = PathParser_param(
		pathParser, QP_USER, 0);
	if (userParam)
	{
	    const char *userstr = QueryParam_value(userParam);
	    size_t userlen = strlen(userstr);
	    if (userlen > 0 && userlen <= 32)
	    {
		Template_setStaticVar(tmpl, "USER", userstr, TF_HTML);
	    }
	}
    }
    Template_setStaticVar(tmpl, "REALM", realm, TF_HTML);
    Template_setStaticVar(tmpl, "RDR",
	    loginHandler_rdr(hdr, pathParser), TF_HTML);
    Template_setStaticVar(tmpl, "SELF", PathParser_path(pathParser), TF_NONE);
    char stylelink[256];
    staticHandler_link(stylelink, sizeof stylelink,
	    PathParser_path(pathParser), "style.css");
    Template_setStaticVar(tmpl, "STYLELINK", stylelink, TF_NONE);
    HttpResponse *response = HttpResponse_create(HTTP_OK, MT_HTML);
    HttpResponse_passTextBody(response, Template_processHtml(tmpl));
    Template_destroy(tmpl);
    HttpContext_setResponse(context, response);
}

void loginHandler(HttpContext *context)
{
    const PathParser *pathParser = PathParser_get(context);
    if (!pathParser) return;

    const char *path = PathParser_path(pathParser);
    if (!strcmp(route, path))
    {
	HttpMethod method = HttpRequest_method(HttpContext_request(context));
	if (method == HTTP_POST) doLogin(context);
	else showForm(context, pathParser);
    }
    else HttpContext_setResponse(context,
	    HttpResponse_createError(HTTP_NOTFOUND, 0));
}

void loginHandler_setRoute(const char *loginRoute)
{
    if (loginRoute) route = loginRoute;
    else route = defroute;
}

const char *loginHandler_route(void)
{
    return route;
}

const char *loginHandler_realm(const HeaderSet *hdr,
	const PathParser *pathParser)
{
    const Header *realmHdr = HeaderSet_single(hdr, HDR_REALM);
    const char *realm = 0;
    if (realmHdr) realm = Header_value(realmHdr);
    else
    {
	const QueryParam *realmParam = PathParser_param(
		pathParser, QP_REALM, 0);
	if (realmParam) realm = QueryParam_value(realmParam);
    }
    if (!realm || !*realm) realm = DEFAULT_REALM;
    return realm;
}

const char *loginHandler_rdr(const HeaderSet *hdr,
	const PathParser *pathParser)
{
    const Header *rdrHdr = HeaderSet_single(hdr, HDR_RDR);
    const char *rdr = 0;
    if (rdrHdr) rdr = Header_value(rdrHdr);
    else
    {
	const QueryParam *rdrParam = PathParser_param(pathParser, QP_RDR, 0);
	if (rdrParam) rdr = QueryParam_value(rdrParam);
    }
    if (!rdr || !*rdr) rdr = "/";
    return rdr;
}

