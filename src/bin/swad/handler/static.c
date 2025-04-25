#define _POSIX_C_SOURCE 200112L

#include "static.h"

#include "../http/httpcontext.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/pathparser.h"
#include "../staticfiles.h"
#include "login.h"

#include <fcntl.h>
#include <poser/core/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct StaticFile
{
    const char *path;
    const uint8_t **content;
    const size_t *contentsz;
    MediaType type;
};

static uint8_t *style_css_file;
static const uint8_t *style_css;
static size_t style_css_sz;

static struct StaticFile files[] = {
#ifdef CRED_POW
    { "pow.mjs", &static_pow_mjs, &static_pow_mjs_sz, MT_JS },
#endif
    { "style.css", &style_css, &style_css_sz, MT_CSS }
};

void staticHandler_init(const char *resdir)
{
    char buf[1024];
    struct stat st;
    snprintf(buf, sizeof buf, "%s/style.css", resdir);
    int fd = open(buf, O_RDONLY);
    if (fd < 0) goto skip;
    if (fstat(fd, &st) < 0) goto done;
    style_css_sz = st.st_size;
    style_css_file = PSC_malloc(style_css_sz);
    if (read(fd, style_css_file, style_css_sz) != (ssize_t)style_css_sz)
    {
	free(style_css_file);
	style_css_file = 0;
	goto done;
    }
    style_css = style_css_file;

done:
    close(fd);
skip:
    if (!style_css)
    {
	style_css = static_style_css;
	style_css_sz = static_style_css_sz;
    }
}

void staticHandler_done(void)
{
    free(style_css_file);
    style_css_file = 0;
    style_css = 0;
}

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

