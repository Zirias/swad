#include "static.h"

#include "../http/httpcontext.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/pathparser.h"
#include "../staticfiles.h"
#include "login.h"

#include <stdio.h>
#include <string.h>

struct StaticFile
{
    const char *path;
    const unsigned char **content;
    const size_t *contentsz;
    MediaType type;
};

static const struct StaticFile files[] = {
#ifdef CRED_POW
    { "pow.mjs", &static_pow_mjs, &static_pow_mjs_sz, MT_JS },
#endif
    { "style.css", &static_style_css, &static_style_css_sz, MT_CSS }
};

void staticHandler(HttpContext *context)
{
    HttpResponse *response = 0;

    const PathParser *pathParser = PathParser_get(context);
    if (!pathParser) return;
    char baseroute[256];
    int routelen = snprintf(baseroute, sizeof baseroute, "%s/static/",
	    loginHandler_route());
    const char *path = PathParser_path(pathParser);
    if (routelen > 0 && !strncmp(path, baseroute, routelen))
    {
	path += routelen;
	for (unsigned i = 0; i < sizeof files / sizeof *files; ++i)
	{
	    if (!strcmp(files[i].path, path))
	    {
		response = HttpResponse_create(HTTP_OK, files[i].type);
		HttpResponse_setBody(response, *files[i].content,
			*files[i].contentsz);
		break;
	    }
	}
    }

    if (!response) response = HttpResponse_createError(HTTP_NOTFOUND, 0);

    HttpContext_setResponse(context, response);
}

