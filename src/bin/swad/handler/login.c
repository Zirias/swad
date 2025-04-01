#include "login.h"

#include "../authenticator.h"
#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
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

static void doLogin(HttpContext *context)
{
    HttpResponse *response = 0;

    const FormData *form = FormData_get(context);
    if (!form || !FormData_valid(form)) goto done;

    size_t len = 0;
    const char *user = FormData_single(form, "user", &len);
    if (!user || len < 1 || len > 32) goto done;

    const char *pw = FormData_single(form, "pw", &len);
    if (!pw || len < 1 || len > 32) goto done;

    Session *session = Session_get(context);
    if (!session) goto done;

    Session_setProp(session, "login_user", PSC_copystr(user), free);
    Authenticator *auth = Authenticator_create(session, 0);

    if (Authenticator_login(auth, pw, user))
    {
	response = HttpResponse_create(HTTP_OK, MT_TEXT);
	HttpResponse_setTextBody(response, user);
    }

    Authenticator_destroy(auth);

done:
    if (!response)
    {
	response = HttpResponse_createRedirect(HTTP_SEEOTHER, route);
    }
    HttpContext_setResponse(context, response);
}

static void showForm(HttpContext *context)
{
    Template *tmpl = Template_createStatic(
	    tmpl_login_html, tmpl_login_html_sz);
    Template_setStaticVar(tmpl, "REALM", DEFAULT_REALM, TF_NONE);
    Template_setStaticVar(tmpl, "SELF", route, TF_HTML);
    Session *session = Session_get(context);
    if (session)
    {
	const char *user = Session_getProp(session, "login_user");
	if (user) Template_setStaticVar(tmpl, "USER", user, TF_HTML);
    }
    HttpResponse *response = HttpResponse_create(HTTP_OK, MT_HTML);
    HttpResponse_passTextBody(response, Template_process(tmpl));
    Template_destroy(tmpl);
    HttpContext_setResponse(context, response);
}

void loginHandler(HttpContext *context)
{
    const char *path = PathParser_path(PathParser_get(context));
    if (!strcmp(route, path))
    {
	HttpMethod method = HttpRequest_method(HttpContext_request(context));
	if (method == HTTP_POST) doLogin(context);
	else showForm(context);
    }
    else HttpContext_setResponse(context,
	    HttpResponse_createError(HTTP_NOTFOUND, 0));
}

void loginHandler_setRoute(const char *loginRoute)
{
    if (loginRoute) route = loginRoute;
    else route = defroute;
}

