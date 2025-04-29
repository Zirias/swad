#define _POSIX_C_SOURCE 200112L

#include "template.h"

#include "htmlescape.h"
#include "urlencode.h"
#include "util.h"

#include <poser/core.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define OUTCHUNK 8192

typedef struct TmplVar
{
    const char *name;
    union {
	char *val;
	const char *sval;
    };
    TmplFilter filter;
    int owned;
} TmplVar;

struct Template
{
    size_t size;
    union {
	uint8_t *tmpl;
	const uint8_t *stmpl;
    };
    PSC_Dictionary *vars;
    int owned;
};

static void processVar(TmplVar *var, char **out, size_t *outsz,
	size_t *outpos) CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3))
    ATTR_NONNULL((4)) ATTR_ACCESS((read_write, 2))
    ATTR_ACCESS((read_write, 3)) ATTR_ACCESS((read_write, 4));

static void deleteVar(void *obj)
{
    if (!obj) return;
    TmplVar *var = obj;
    if (var->owned) free(var->val);
    free(var);
}

Template *Template_create(const uint8_t *tmpl, size_t tmplSize)
{
    Template *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    self->size = tmplSize;
    self->tmpl = PSC_malloc(tmplSize);
    memcpy(self->tmpl, tmpl, tmplSize);
    self->vars = PSC_Dictionary_create(deleteVar);
    self->owned = 1;
    return self;
}

Template *Template_createStr(const char *tmpl)
{
    return Template_create((const uint8_t *)tmpl, strlen(tmpl));
}

Template *Template_createStatic(const uint8_t *tmpl, size_t tmplSize)
{
    Template *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    self->size = tmplSize;
    self->stmpl = tmpl;
    self->vars = PSC_Dictionary_create(deleteVar);
    return self;
}

Template *Template_createStaticStr(const char *tmpl)
{
    return Template_createStatic((const uint8_t *)tmpl, strlen(tmpl));
}

void Template_setVar(Template *self,
	const char *name, const char *val, TmplFilter filter)
{
    TmplVar *var = PSC_malloc(sizeof *var);
    var->name = name;
    var->val = PSC_copystr(val);
    var->filter = filter;
    var->owned = 1;
    PSC_Dictionary_set(self->vars, name, strlen(name), var, 0);
}

void Template_passVar(Template *self,
	const char *name, char *val, TmplFilter filter)
{
    TmplVar *var = PSC_malloc(sizeof *var);
    var->name = name;
    var->val = val;
    var->filter = filter;
    var->owned = 1;
    PSC_Dictionary_set(self->vars, name, strlen(name), var, 0);
}

void Template_setStaticVar(Template *self,
	const char *name, const char *val, TmplFilter filter)
{
    TmplVar *var = PSC_malloc(sizeof *var);
    var->name = name;
    var->sval = val;
    var->filter = filter;
    var->owned = 0;
    PSC_Dictionary_set(self->vars, name, strlen(name), var, 0);
}

static void processVar(TmplVar *var, char **out, size_t *outsz, size_t *outpos)
{
    const char *varval = var->owned ? var->val : var->sval;
    size_t vallen;

    switch (var->filter)
    {
	case TF_NONE:
	    vallen = strlen(varval);
	    if (*outsz - *outpos < vallen)
	    {
		do *outsz += OUTCHUNK; while (*outsz - *outpos < vallen);
		*out = PSC_realloc(*out, *outsz);
	    }
	    memcpy(*out + *outpos, varval, vallen);
	    *outpos += vallen;
	    return;

	case TF_HTML:
	case TF_HTMLNL:
	    htmlescapeto(out, outsz, outpos, varval, var->filter == TF_HTMLNL);
	    return;

	case TF_URL:
	    urlencodeto(out, outsz, outpos, varval);
	    return;
    }
}

static char *process(const Template *self, int html)
{
    char varnm[64];
    char *out = 0;
    size_t outsz = 0;
    size_t outpos = 0;
    size_t pos = 0;
    const char *tmpl = (const char *)(self->owned ? self->tmpl : self->stmpl);
    size_t sz = self->size;
    if (html)
    {
	while (*tmpl && (*tmpl == ' ' || *tmpl == '\t'
		    || *tmpl == '\r' || *tmpl == '\n'))
	{
	    ++tmpl;
	    --sz;
	}
	if (strncasecmp("<!doctype ", tmpl, sizeof "<!doctype"))
	{
	    appendstrlit(&out, &outsz, &outpos, OUTCHUNK, "<!DOCTYPE html>\n");
	}
    }
    while (pos < sz)
    {
	if (tmpl[pos] == '%' && pos+2 < self->size
		&& tmpl[pos+1] == '%' && tmpl[pos+2] != '%')
	{
	    size_t endpos = (pos += 2);
	    int havevar = 0;
	    TmplVar *var = 0;
	    while (endpos < self->size && endpos - pos < sizeof varnm)
	    {
		if (tmpl[endpos] == '%' && endpos+1 < self->size
			&& tmpl[endpos+1] == '%')
		{
		    size_t nmlen = endpos - pos;
		    memcpy(varnm, tmpl+pos, nmlen);
		    havevar = 1;
		    var = PSC_Dictionary_get(self->vars, varnm, nmlen);
		    break;
		}
		++endpos;
	    }
	    if (havevar)
	    {
		if (var) processVar(var, &out, &outsz, &outpos);
		pos = endpos+2;
	    }
	    else
	    {
		appendchr(&out, &outsz, &outpos, OUTCHUNK, '%');
		appendchr(&out, &outsz, &outpos, OUTCHUNK, '%');
	    }
	}
	else appendchr(&out, &outsz, &outpos, OUTCHUNK, tmpl[pos++]);
    }
    appendchr(&out, &outsz, &outpos, 1, 0);
    out = PSC_realloc(out, outsz);
    return out;
}

char *Template_process(const Template *self)
{
    return process(self, 0);
}

char *Template_processHtml(const Template *self)
{
    return process(self, 1);
}

void Template_destroy(Template *self)
{
    if (!self) return;
    PSC_Dictionary_destroy(self->vars);
    if (self->owned) free(self->tmpl);
    free(self);
}

