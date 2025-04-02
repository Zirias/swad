#include "login.h"

#include "../authenticator.h"
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

static const char defroute[] = "/login";
static const char *route = defroute;

static void doLogin(HttpContext *context, const char *realm)
{
    HttpStatus status = HTTP_SEEOTHER;
    const char *rdr = HttpRequest_path(HttpContext_request(context));

    const FormData *form = FormData_get(context);
    if (!form || !FormData_valid(form)) goto done;

    Session *session = Session_get(context);
    if (!session) goto done;

    size_t len = 0;

    if (FormData_single(form, "login", 0))
    {
	const char *user = FormData_single(form, "user", &len);
	if (!user || len < 1 || len > 32) goto done;

	const char *pw = FormData_single(form, "pw", &len);
	if (!pw || len < 1 || len > 32) goto done;

	Authenticator *auth = Authenticator_create(session, realm);
	if (Authenticator_login(auth, user, pw))
	{
	    status = HTTP_OK;
	    rdr = Session_getProp(session, "login_rdr");
	    Session_setProp(session, "login_error", 0, 0);
	    Session_setProp(session, "login_user", 0, 0);
	}
	else
	{
	    Session_setProp(session, "login_error", "Invalid credentials", 0);
	    Session_setProp(session, "login_user", PSC_copystr(user), free);
	}
	Authenticator_destroy(auth);
    }
    else if (FormData_single(form, "logout", 0))
    {
	Authenticator *auth = Authenticator_create(session, realm);
	if (Authenticator_user(auth))
	{
	    Authenticator_logout(auth);
	    status = HTTP_OK;
	    rdr = Session_getProp(session, "login_rdr");
	}
	Authenticator_destroy(auth);
    }

done:
    HttpContext_setResponse(context, HttpResponse_createRedirect(status, rdr));
}

static void showForm(HttpContext *context, const char *realm, const char *rdr)
{
    HttpResponse *response = 0;

    Session *session = Session_get(context);
    if (!session) goto done;
    Session_setProp(session, "login_rdr", PSC_copystr(rdr), free);

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
	const char *le = Session_getProp(session, "login_error");
	if (le) Template_setStaticVar(tmpl, "ERRMSG", le, TF_HTML);
	const char *lu = Session_getProp(session, "login_user");
	if (lu) Template_setStaticVar(tmpl, "USER", lu, TF_HTML);
    }
    Template_setStaticVar(tmpl, "CSRFNAME", CSRFProtect_name(), TF_NONE);
    Template_setStaticVar(tmpl, "CSRFTOKEN",
	    CSRFProtect_token(context), TF_NONE);
    Template_setStaticVar(tmpl, "REALM", realm, TF_HTML);
    Template_setStaticVar(tmpl, "SELF", HttpRequest_path(
		HttpContext_request(context)), TF_HTML);
    response = HttpResponse_create(HTTP_OK, MT_HTML);
    HttpResponse_passTextBody(response, Template_process(tmpl));
    Template_destroy(tmpl);

done:
    if (!response) response = HttpResponse_createError(
	    HTTP_INTERNALSERVERERROR, 0);
    HttpContext_setResponse(context, response);
}

void loginHandler(HttpContext *context)
{
    const PathParser *pathParser = PathParser_get(context);
    const char *path = PathParser_path(pathParser);
    if (!strcmp(route, path))
    {
	const QueryParam *realmParam = PathParser_param(
		pathParser, "realm", 0);
	const char *realm = 0;
	if (realmParam) realm = QueryParam_value(realmParam);
	if (!realm || !*realm) realm = DEFAULT_REALM;
	HttpMethod method = HttpRequest_method(HttpContext_request(context));
	if (method == HTTP_POST) doLogin(context, realm);
	else
	{
	    const QueryParam *rdrParam = PathParser_param(
		    pathParser, "rdr", 0);
	    const char *rdr = 0;
	    if (rdrParam) rdr = QueryParam_value(rdrParam);
	    if (!rdr || !*rdr) rdr = "/";
	    showForm(context, realm, rdr);
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

