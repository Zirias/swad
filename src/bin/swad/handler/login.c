#include "login.h"

#include "../authenticator.h"
#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/csrfprotect.h"
#include "../middleware/formdata.h"
#include "../middleware/pathparser.h"
#include "../middleware/session.h"
#include "../template.h"
#include "../tmpl.h"

#include <poser/core.h>
#include <stdlib.h>
#include <string.h>

#define SK_FORM	    "login_form"
#define SK_RDR	    "login_rdr"
#define SK_ARDR	    "auth_rdr"
#define SK_REALM    "login_realm"
#define SK_AREALM   "auth_realm"
#define SK_USER	    "login_user"
#define SK_ERROR    "login_error"

#define QP_RDR	    "rdr"
#define QP_REALM    "realm"
#define HDR_RDR	    "X-SWAD-Rdr"
#define HDR_REALM   "X-SWAD-Realm"

static const char defroute[] = "/login";
static const char *route = defroute;

static void doLogin(HttpContext *context, Session *session)
{
    HttpStatus status = HTTP_SEEOTHER;
    const FormData *form = FormData_get(context);
    if (!form || !FormData_valid(form)) goto done;

    const char *realm = Session_getProp(session, SK_REALM);
    const char *rdr = Session_getProp(session, SK_FORM);
    if  (!realm || !rdr) goto done;

    size_t len = 0;

    if (FormData_single(form, "login", 0))
    {
	const char *user = FormData_single(form, "user", &len);
	if (!user || len < 1 || len > 32) goto done;

	const char *pw = FormData_single(form, "pw", &len);
	if (!pw || len < 1 || len > 32) goto done;

	const char *authrdr = Session_getProp(session, SK_RDR);
	if (!authrdr) authrdr = "/";

	Authenticator *auth = Authenticator_create(session, realm);
	if (Authenticator_login(auth, user, pw))
	{
	    status = HTTP_OK;
	    rdr = authrdr;
	    Session_setProp(session, SK_ERROR, 0, 0);
	    PSC_Log_fmt(PSC_L_INFO, "login: %s logged in for %s",
		    user, realm);
	}
	else
	{
	    Session_setProp(session, SK_ERROR, "Invalid credentials", 0);
	    Session_setProp(session, SK_AREALM, PSC_copystr(realm), free);
	    Session_setProp(session, SK_ARDR, PSC_copystr(authrdr), free);
	    PSC_Log_fmt(PSC_L_WARNING, "login: Failed login as %s for %s",
		    user, realm);
	}
	Session_setProp(session, SK_USER, PSC_copystr(user), free);
	Authenticator_destroy(auth);
    }
    else if (FormData_single(form, "logout", 0))
    {
	Authenticator *auth = Authenticator_create(session, realm);
	if (Authenticator_user(auth))
	{
	    Authenticator_logout(auth);
	    status = HTTP_OK;
	    rdr = Session_getProp(session, SK_RDR);
	}
	Authenticator_destroy(auth);
    }

done:
    HttpContext_setResponse(context, HttpResponse_createRedirect(status, rdr));
}

static void showForm(HttpContext *context, Session *session,
	const char *realm, const char *path)
{
    Authenticator *auth = Authenticator_create(session, realm);
    const User *user = Authenticator_user(auth);
    Authenticator_destroy(auth);

    Template *tmpl = 0;
    if (user)
    {
	tmpl = Template_createStatic(tmpl_logout_html, tmpl_logout_html_sz);
	const char *username = User_username(user);
	const char *realname = User_realname(user);
	if (!realname || !*realname) realname = "<Unknown name>";
	Template_setStaticVar(tmpl, "USER", username, TF_HTML);
	Template_setStaticVar(tmpl, "REALNAME", realname, TF_HTML);
    }
    else
    {
	tmpl = Template_createStatic(tmpl_login_html, tmpl_login_html_sz);
	const char *le = Session_getProp(session, SK_ERROR);
	if (le) Template_setStaticVar(tmpl, "ERRMSG", le, TF_HTML);
	const char *lu = Session_getProp(session, SK_USER);
	if (lu) Template_setStaticVar(tmpl, "USER", lu, TF_HTML);
    }
    Template_setStaticVar(tmpl, "CSRFNAME", CSRFProtect_name(), TF_NONE);
    Template_setStaticVar(tmpl, "CSRFTOKEN",
	    CSRFProtect_token(context), TF_NONE);
    Template_setStaticVar(tmpl, "REALM", realm, TF_HTML);
    Template_setStaticVar(tmpl, "SELF", path, TF_NONE);
    HttpResponse *response = HttpResponse_create(HTTP_OK, MT_HTML);
    HttpResponse_passTextBody(response, Template_process(tmpl));
    Template_destroy(tmpl);
    HttpContext_setResponse(context, response);
}

static const char *updateSession(HttpContext *context,
	const PathParser *pathParser, Session *session)
{
    Session_setProp(session, SK_FORM, PSC_copystr(
		HttpRequest_path(HttpContext_request(context))), free);

    const HeaderSet *hdr = HttpRequest_headers(HttpContext_request(context));
    const char *realm = Session_getProp(session, SK_AREALM);
    if (!realm) realm = loginHandler_realm(hdr, pathParser);

    const char *lr = Session_getProp(session, SK_REALM);
    if (lr && strcmp(lr, realm))
    {
	Session_setProp(session, SK_USER, 0, 0);
	Session_setProp(session, SK_ERROR, 0, 0);
    }
    char *loginrealm = PSC_copystr(realm);
    Session_setProp(session, SK_REALM, loginrealm, free);
    Session_setProp(session, SK_AREALM, 0, 0);

    const char *rdr = Session_getProp(session, SK_ARDR);
    if (!rdr) rdr = loginHandler_rdr(hdr, pathParser);
    Session_setProp(session, SK_RDR, PSC_copystr(rdr), free);
    Session_setProp(session, SK_ARDR, 0, 0);

    return loginrealm;
}

void loginHandler(HttpContext *context)
{
    const PathParser *pathParser = PathParser_get(context);
    Session *session = Session_get(context);
    if (!pathParser || !session) return;

    const char *path = PathParser_path(pathParser);
    if (!strcmp(route, path))
    {
	HttpMethod method = HttpRequest_method(HttpContext_request(context));
	if (method == HTTP_POST) doLogin(context, session);
	else
	{
	    const char *realm = updateSession(context, pathParser, session);
	    showForm(context, session, realm, path);
	}
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

