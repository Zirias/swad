#include "pathparser.h"

#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../urlencode.h"

#include <poser/core/util.h>
#include <stdlib.h>
#include <string.h>

#define MAXPARAM 32
#define PROPNAME "_PATHPARSER"

struct QueryParam
{
    char *name;
    char *value;
    uint8_t pos;
};

struct PathParser
{
    char *path;
    QueryParam params[MAXPARAM];
    uint8_t nparams;
};

static void pathParserDeleter(void *obj);

static void pathParserDeleter(void *obj)
{
    if (!obj) return;
    PathParser *self = obj;
    free(self->path);
    for (uint8_t p = 0; p < self->nparams; ++p)
    {
	free(self->params[p].name);
	free(self->params[p].value);
    }
    free(self);
}

const PathParser *PathParser_get(const HttpContext *context)
{
    return HttpContext_get(context, PROPNAME);
}

const char *PathParser_path(const PathParser *self)
{
    return self->path;
}

const QueryParam *PathParser_param(const PathParser *self,
	const char *name, const QueryParam *curr)
{
    uint8_t pos = 0;
    if (curr) pos = curr->pos + 1;
    while (pos < self->nparams)
    {
	if (!strcmp(name, self->params[pos].name)) break;
	++pos;
    }
    if (pos >= self->nparams) return 0;
    return self->params + pos;
}

const char *QueryParam_name(const QueryParam *self)
{
    return self->name;
}

const char *QueryParam_value(const QueryParam *self)
{
    return self->value;
}

void MW_PathParser(HttpContext *context)
{
    PathParser *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    const char *reqPath = HttpRequest_path(HttpContext_request(context));
    size_t dpos = strcspn(reqPath, "?");
    self->path = urldecode(reqPath, dpos);
    reqPath += dpos;
    while (*reqPath && self->nparams < MAXPARAM)
    {
	++reqPath;
	dpos = strcspn(reqPath, "&");
	size_t eqpos = strcspn(reqPath, "=");
	if (eqpos < dpos)
	{
	    self->params[self->nparams].name = urldecode(reqPath, eqpos);
	    self->params[self->nparams].value = urldecode(
		    reqPath + eqpos + 1, dpos - eqpos - 1);
	}
	else
	{
	    self->params[self->nparams].name = urldecode(reqPath, dpos);
	}
	self->params[self->nparams].pos = self->nparams;
	++self->nparams;
	reqPath += dpos;
    }
    HttpContext_set(context, PROPNAME, self, pathParserDeleter);
    HttpContext_callNext(context);
}
