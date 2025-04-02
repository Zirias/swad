#include "root.h"

#include "../authenticator.h"
#include "../handler/login.h"
#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/pathparser.h"
#include "../middleware/session.h"

#include <stdio.h>
#include <string.h>

void rootHandler(HttpContext *context)
{
    char responsebuf[4096];
    HttpResponse *response = 0;

    const PathParser *pathParser = PathParser_get(context);
    if (!pathParser) goto done;

    if (strcmp("/", PathParser_path(pathParser)))
    {
	response = HttpResponse_createError(HTTP_NOTFOUND, 0);
	goto done;
    }

    Session *session = Session_get(context);
    if (!session) goto done;

    const QueryParam *realmParam = PathParser_param(pathParser, "realm", 0);
    const char *realm = 0;
    if (realmParam) realm = QueryParam_value(realmParam);
    if (!realm || !*realm) realm = DEFAULT_REALM;

    Authenticator *auth = Authenticator_create(session, realm);
    const User *user = Authenticator_user(auth);
    Authenticator_destroy(auth);

    if (user)
    {
	const char *username = User_username(user);
	const char *realname = User_realname(user);
	if (realname)
	{
	    snprintf(responsebuf, sizeof responsebuf, "%s\n%s\n",
		    username, realname);
	}
	else
	{
	    snprintf(responsebuf, sizeof responsebuf, "%s\n", username);
	}
	response = HttpResponse_create(HTTP_OK, MT_TEXT);
	HttpResponse_setTextBody(response, responsebuf);
    }
    else
    {
	snprintf(responsebuf, sizeof responsebuf, "%s?realm=%s&rdr=%s",
		loginHandler_route(), realm,
		HttpRequest_path(HttpContext_request(context)));
	response = HttpResponse_createRedirect(HTTP_FORBIDDEN, responsebuf);
    }

done:
    if (!response) response = HttpResponse_createError(
	    HTTP_INTERNALSERVERERROR, 0);
    HttpContext_setResponse(context, response);
}

