#include "login.h"

#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/formdata.h"
#include "../middleware/pathparser.h"
#include "../middleware/session.h"
#include "../template.h"
#include "../tmpl.h"

#include <poser/core/util.h>
#include <stdlib.h>
#include <string.h>

static void doLogin(HttpContext *context)
{
    const FormData *form = FormData_get(context);
    if (!form || !FormData_valid(form)) goto error;

    size_t len = 0;
    const char *user = FormData_single(form, "user", &len);
    if (!user || len < 1 || len > 32) goto error;

    const char *pw = FormData_single(form, "pw", &len);
    if (!pw || len < 1 || len > 32) goto error;

    Session *session = Session_get(context);
    if (!session) goto error;
    Session_setProp(session, "login_user", PSC_copystr(user), free);
    
    if (!strcmp(pw, user))
    {
	HttpResponse *response = HttpResponse_create(HTTP_OK, MT_TEXT);
	HttpResponse_setTextBody(response, user);
	HttpContext_setResponse(context, response);
	return;
    }

error:
    HttpContext_setResponse(context,
	    HttpResponse_createRedirect(HTTP_SEEOTHER, "/login"));
}

static void showForm(HttpContext *context)
{
    Template *tmpl = Template_createStatic(
	    tmpl_login_html, tmpl_login_html_sz);
    Template_setStaticVar(tmpl, "SELF", "/login", TF_NONE);
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
    if (!strcmp("/login", path))
    {
	HttpMethod method = HttpRequest_method(HttpContext_request(context));
	if (method == HTTP_POST) doLogin(context);
	else showForm(context);
    }
    else HttpContext_setResponse(context,
	    HttpResponse_createError(HTTP_NOTFOUND, 0));
}

