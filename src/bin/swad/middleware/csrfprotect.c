#include "csrfprotect.h"

#include "../http/httpcontext.h"
#include "../http/httpresponse.h"
#include "../http/httpstatus.h"
#include "../random.h"
#include "formdata.h"
#include "session.h"

#include <poser/core/log.h>
#include <stdlib.h>
#include <string.h>

#define PROPNAME "_CSRFPROTECT"

const char *CSRFProtect_name(void)
{
    return PROPNAME;
}

const char *CSRFProtect_token(HttpContext *context)
{
    Session *session = Session_get(context);
    if (!session) return 0;
    char *token = createRndStr(32);
    Session_setProp(session, PROPNAME, token, free);
    return token;
}

void MW_CSRFProtect(HttpContext *context)
{
    const FormData *form = FormData_get(context);
    if (form)
    {
	Session *session = Session_get(context);
	if (!session)
	{
	    PSC_Log_msg(PSC_L_ERROR,
		    "CSRFProtect middleware depends on Session middleware.");
	    goto done;
	}
	const char *token = Session_getProp(session, PROPNAME);
	const char *tokenVal = FormData_single(form, PROPNAME, 0);
	if (!token || !tokenVal || strcmp(token, tokenVal))
	{
	    HttpContext_setResponse(context, HttpResponse_createError(
			HTTP_FORBIDDEN, "Request tampering detected. "
			"Not here, man."));
	    return;
	}
	Session_setProp(session, PROPNAME, 0, 0);
    }
done:
    HttpContext_callNext(context);
}

