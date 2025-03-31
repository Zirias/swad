#include "root.h"

#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/pathparser.h"

#include <string.h>

void rootHandler(HttpContext *context)
{
    const char *path = PathParser_path(PathParser_get(context));

    if (!strcmp("/", path))
    {
	HttpResponse *response = HttpResponse_create(HTTP_OK, MT_HTML);
	HttpResponse_setTextBody(response, "<html><head><title>"
		"Hello, World!</title></head><body><h1>"
		"Hello, World!</h1><p>"
		"Dummy hello response.</p></body></html>");
	HttpContext_setResponse(context, response);
    }
    else HttpContext_setResponse(context,
	    HttpResponse_createError(HTTP_NOTFOUND, 0));
}

