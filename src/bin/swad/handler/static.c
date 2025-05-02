#define _POSIX_C_SOURCE 200809L

#include "static.h"

#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httpresponse.h"
#include "../mediatype.h"
#include "../middleware/pathparser.h"
#include "../staticfiles.h"
#include "login.h"

#include <fcntl.h>
#include <poser/core/base64.h>
#include <poser/core/hash.h>
#include <poser/core/util.h>
#include <pthread.h>
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
    char **verstr;
    const unsigned *vers;
    MediaType type;
};

static uint8_t *style_css_file;
static char *style_css_filevers;
static const uint8_t *style_css;
static size_t style_css_sz;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static struct StaticFile files[] = {
#ifdef CRED_POW
    { "pow.mjs", &static_pow_mjs, &static_pow_mjs_sz,
	0, &static_pow_mjs_vers, MT_JS },
#endif
    { "style.css", &style_css, &style_css_sz,
	&style_css_filevers, &static_style_css_vers, MT_CSS }
};

void staticHandler_init(const char *resdir)
{
    char buf[1024];
    struct stat st;
    pthread_mutex_lock(&lock);
    free(style_css_filevers);
    free(style_css_file);
    style_css_file = 0;
    snprintf(buf, sizeof buf, "%s/style.css", resdir);
    int fd = open(buf, O_RDONLY|O_CLOEXEC);
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
    if (style_css)
    {
	PSC_Hash *hasher = PSC_Hash_create(0, 0);
	uint64_t hash = PSC_Hash_bytes(hasher, style_css, style_css_sz);
	PSC_Hash_destroy(hasher);
	style_css_filevers = PSC_Base64_encode(&hash, sizeof hash);
	for (char *c = style_css_filevers; *c; ++c) if (*c == '/') *c = '_';
    }
    else
    {
	style_css = static_style_css;
	style_css_sz = static_style_css_sz;
    }
    pthread_mutex_unlock(&lock);
}

void staticHandler_done(void)
{
    free(style_css_filevers);
    free(style_css_file);
    style_css_filevers = 0;
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
		pthread_mutex_lock(&lock);
		HttpResponse_setBody(response, *files[i].content,
			*files[i].contentsz);
		pthread_mutex_unlock(&lock);
		HeaderSet_set(HttpResponse_headers(response),
			Header_create("Cache-Control",
			    "public, max-age=31536000, immutable"));
		break;
	    }
	}
    }

    if (!response) response = HttpResponse_createError(HTTP_NOTFOUND, 0);

    HttpContext_setResponse(context, response);
}

int staticHandler_link(char *buf, size_t bufsz,
	const char *base, const char *name)
{
    struct StaticFile *f = 0;
    for (unsigned i = 0; i < sizeof files / sizeof *files; ++i)
    {
	if (!strcmp(files[i].path, name))
	{
	    f = files + i;
	    break;
	}
    }
    if (!f) return -1;
    if (f->verstr && *f->verstr)
    {
	snprintf(buf, bufsz, "%s/static/%s?%s", base, f->path, *f->verstr);
    }
    else
    {
	snprintf(buf, bufsz, "%s/static/%s?%x", base, f->path, *f->vers);
    }
    return 0;
}

