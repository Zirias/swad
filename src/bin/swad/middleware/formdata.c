#include "formdata.h"

#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../urlencode.h"
#include "../utf8.h"

#include <poser/core/util.h>
#include <stdlib.h>
#include <string.h>

#define MAXPARAM 64
#define PROPNAME "_FORMDATA"

struct FormParam
{
    char *name;
    char *value;
    size_t namelen;
    size_t valuelen;
    uint8_t namevalid;
    uint8_t valuevalid;
    uint8_t pos;
};

struct FormData
{
    FormParam params[MAXPARAM];
    uint8_t valid;
    uint8_t nparams;
};

static FormDataValidate validate = FDV_NONE;

static void formDataDeleter(void *obj);
static size_t indexOf(const uint8_t *buf, size_t size, char c)
    ATTR_NONNULL((1)) ATTR_ACCESS((read_only, 1, 2)) ATTR_PURE;

static void formDataDeleter(void *obj)
{
    if (!obj) return;
    FormData *self = obj;
    for (uint8_t p = 0; p < self->nparams; ++p)
    {
	free(self->params[p].name);
	free(self->params[p].value);
    }
    free(self);
}

const FormData *FormData_get(const HttpContext *context)
{
    return HttpContext_get(context, PROPNAME);
}

int FormData_valid(const FormData *self)
{
    return self->valid;
}

const FormParam *FormData_param(const FormData *self,
	const char *name, const FormParam *curr)
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

const char *FormData_first(const FormData *self,
	const char *name, size_t *len)
{
    for (uint8_t i = 0; i < self->nparams; ++i)
    {
	if (!strcmp(name, self->params[i].name))
	{
	    if (len) *len = self->params[i].valuelen;
	    return self->params[i].value;
	}
    }
    return 0;
}

const char *FormData_single(const FormData *self,
	const char *name, size_t *len)
{
    uint8_t pos = 0;
    const char *val = 0;
    size_t l;
    while (pos < self->nparams)
    {
	if (!strcmp(name, self->params[pos].name))
	{
	    l = self->params[pos].valuelen;
	    val = self->params[pos].value;
	    break;
	}
	++pos;
    }
    if (!val) return 0;
    while (++pos < self->nparams)
    {
	if (!strcmp(name, self->params[pos].name)) return 0;
    }
    if (len) *len = l;
    return val;
}

const char *FormParam_name(const FormParam *self)
{
    return self->name;
}

size_t FormParam_nameLen(const FormParam *self)
{
    return self->namelen;
}

int FormParam_nameValid(const FormParam *self)
{
    return self->namevalid;
}

const char *FormParam_value(const FormParam *self)
{
    return self->value;
}

size_t FormParam_valueLen(const FormParam *self)
{
    return self->valuelen;
}

int FormParam_valueValid(const FormParam *self)
{
    return self->valuevalid;
}

static size_t indexOf(const uint8_t *buf, size_t size, char c)
{
    size_t pos = 0;
    while (pos < size && (char)buf[pos] != c) ++pos;
    return pos;
}

void MW_FormData_setValidation(FormDataValidate validation)
{
    validate = validation;
}

void MW_FormData(HttpContext *context)
{
    HttpRequest *req = HttpContext_request(context);
    size_t bodySize = HttpRequest_bodySize(req);
    if (!bodySize) goto done;
    const Header *reqType = HeaderSet_first(
	    HttpRequest_headers(req), "Content-Type");
    if (!reqType) goto done;
    if (strcmp(Header_value(reqType),
		"application/x-www-form-urlencoded")) goto done;
    FormData *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    self->valid = 1;
    const uint8_t *body = HttpRequest_body(req);
    size_t dpos = 0;
    while (bodySize && self->nparams < MAXPARAM)
    {
	dpos = indexOf(body, bodySize, '&');
	size_t eqpos = indexOf(body, bodySize, '=');
	self->params[self->nparams].namevalid = 1;
	if (eqpos < dpos)
	{
	    self->params[self->nparams].namelen = eqpos;
	    self->params[self->nparams].name = urldecode(
		    (const char *)body, eqpos);
	    self->params[self->nparams].valuelen = dpos - eqpos - 1;
	    self->params[self->nparams].value = urldecode(
		    (const char *)body + eqpos + 1, dpos - eqpos - 1);
	    self->params[self->nparams].valuevalid = 1;
	}
	else
	{
	    self->params[self->nparams].namelen = dpos;
	    self->params[self->nparams].name = urldecode(
		    (const char *)body, dpos);
	}
	self->params[self->nparams].pos = self->nparams;
	switch (validate)
	{
	    case FDV_NONE:
		break;

	    case FDV_UTF8:
		if (utf8_check(self->params[self->nparams].name,
			    &self->params[self->nparams].namelen) < 0)
		{
		    self->valid = 0;
		    self->params[self->nparams].namevalid = 0;
		}
		if (self->params[self->nparams].valuevalid &&
			utf8_check(self->params[self->nparams].value,
			    &self->params[self->nparams].valuelen) < 0)
		{
		    self->valid = 0;
		    self->params[self->nparams].valuevalid = 0;
		}
		break;

	    case FDV_UTF8_SANITIZE:
		if (utf8_sanitize(self->params[self->nparams].name,
			    &self->params[self->nparams].namelen) < 0)
		{
		    self->valid = 0;
		    self->params[self->nparams].namevalid = 0;
		}
		if (self->params[self->nparams].valuevalid &&
			utf8_sanitize(self->params[self->nparams].value,
			    &self->params[self->nparams].valuelen) < 0)
		{
		    self->valid = 0;
		    self->params[self->nparams].valuevalid = 0;
		}
		break;
	}
	++self->nparams;
	bodySize -= dpos;
	body += dpos;
	if (bodySize)
	{
	    ++body;
	    --bodySize;
	}
    }
    HttpContext_set(context, PROPNAME, self, formDataDeleter);
done:
    HttpContext_callNext(context);
}
