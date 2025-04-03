#include "root.h"

#include "../authenticator.h"
#include "../handler/login.h"
#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/pathparser.h"
#include "../middleware/session.h"

#include <poser/core/log.h>
#include <poser/core/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rootHandler(HttpContext *context)
{
    char responsebuf[4096];
    HttpResponse *response = 0;

    const PathParser *pathParser = PathParser_get(context);
    if (!pathParser) return;

    if (strcmp("/", PathParser_path(pathParser)))
    {
	response = HttpResponse_createError(HTTP_NOTFOUND, 0);
	goto done;
    }

    Session *session = Session_get(context);
    if (!session) return;

    const HeaderSet *hdr = HttpRequest_headers(HttpContext_request(context));
    const char *realm = loginHandler_realm(hdr, pathParser);

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
	const char *loginRoute = 0;
	const Header *loginHdr = HeaderSet_single(hdr, "X-SWAD-Login");
	if (loginHdr) loginRoute = Header_value(loginHdr);
	if (!loginRoute || !*loginRoute) loginRoute = loginHandler_route();
	const char *rdr = loginHandler_rdr(hdr, pathParser);
	Session_setProp(session, "auth_realm", PSC_copystr(realm), free);
	Session_setProp(session, "auth_rdr", PSC_copystr(rdr), free);
	const Header *uaHdr = HeaderSet_first(hdr, "User-Agent");
	const char *ua = 0;
	if (uaHdr) ua = Header_value(uaHdr);
	if (!ua || !*ua) ua = "<Unknown>";
	PSC_Log_fmt(PSC_L_INFO, "auth: requesting login: [realm] %s - "
		"[path] %s - [user agent] %s", realm, rdr, ua);
	response = HttpResponse_createRedirect(HTTP_FORBIDDEN, loginRoute);
    }

done:
    HttpContext_setResponse(context, response);
}

