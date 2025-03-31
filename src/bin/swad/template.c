#include "template.h"

#include "htmlescape.h"
#include "urlencode.h"
#include "util.h"

#include <poser/core/util.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define OUTCHUNK 8192

#define TVHT_BITS 6
#define TVHT_SIZE HT_SIZE(TVHT_BITS)

typedef struct TmplVar TmplVar;
struct TmplVar
{
    const char *name;
    union {
	char *val;
	const char *sval;
    };
    TmplVar *next;
    TmplFilter filter;
    int owned;
};

struct Template
{
    size_t size;
    union {
	uint8_t *tmpl;
	const uint8_t *stmpl;
    };
    TmplVar *buckets[TVHT_SIZE];
    int owned;
};

static TmplVar *findVar(const Template *self,
	const char *name, uint8_t *hashval)
    CMETHOD ATTR_NONNULL((2)) ATTR_ACCESS((write_only, 3));
static TmplVar *insertOrUpdate(Template *self, const char *name)
    CMETHOD ATTR_NONNULL((2)) ATTR_RETNONNULL;
static void processVar(TmplVar *var, char **out, size_t *outsz,
	size_t *outpos) CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3))
    ATTR_NONNULL((4)) ATTR_ACCESS((read_write, 2))
    ATTR_ACCESS((read_write, 3)) ATTR_ACCESS((read_write, 4));

Template *Template_create(const uint8_t *tmpl, size_t tmplSize)
{
    Template *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    self->size = tmplSize;
    self->tmpl = PSC_malloc(tmplSize);
    memcpy(self->tmpl, tmpl, tmplSize);
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
    return self;
}

Template *Template_createStaticStr(const char *tmpl)
{
    return Template_createStatic((const uint8_t *)tmpl, strlen(tmpl));
}

static TmplVar *findVar(const Template *self,
	const char *name, uint8_t *hashval)
{
    uint8_t h = hash(name, TVHT_BITS);
    if (hashval) *hashval = h;
    TmplVar *var = self->buckets[h];
    while (var)
    {
	if (!strcmp(var->name, name)) break;
	var = var->next;
    }
    return var;
}

static TmplVar *insertOrUpdate(Template *self, const char *name)
{
    uint8_t hashval;
    TmplVar *var = findVar(self, name, &hashval);
    if (!var)
    {
	var = PSC_malloc(sizeof *var);
	var->name = name;
	var->next = 0;
	var->owned = 0;
	TmplVar *parent = self->buckets[hashval];
	if (parent)
	{
	    while (parent->next) parent = parent->next;
	    parent->next = var;
	}
	else self->buckets[hashval] = var;
    }
    if (var->owned) free(var->val);
    return var;
}

void Template_setVar(Template *self,
	const char *name, const char *val, TmplFilter filter)
{
    TmplVar *var = insertOrUpdate(self, name);
    var->val = PSC_copystr(val);
    var->filter = filter;
    var->owned = 1;
}

void Template_passVar(Template *self,
	const char *name, char *val, TmplFilter filter)
{
    TmplVar *var = insertOrUpdate(self, name);
    var->val = val;
    var->filter = filter;
    var->owned = 1;
}

void Template_setStaticVar(Template *self,
	const char *name, const char *val, TmplFilter filter)
{
    TmplVar *var = insertOrUpdate(self, name);
    var->sval = val;
    var->filter = filter;
    var->owned = 0;
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

char *Template_process(const Template *self)
{
    char varnm[64];
    char *out = 0;
    size_t outsz = 0;
    size_t outpos = 0;
    size_t pos = 0;
    const char *tmpl = (const char *)(self->owned ? self->tmpl : self->stmpl);
    while (pos < self->size)
    {
	if (tmpl[pos] == '%' && pos+2 < self->size
		&& tmpl[pos+1] == '%' && tmpl[pos+2] != '%')
	{
	    size_t endpos = (pos += 2);
	    int havevar = 0;
	    TmplVar *var = 0;
	    while (endpos < self->size && endpos - pos < 63)
	    {
		if (tmpl[endpos] == '%' && endpos+1 < self->size
			&& tmpl[endpos+1] == '%')
		{
		    size_t nmlen = endpos - pos;
		    memcpy(varnm, tmpl+pos, nmlen);
		    varnm[nmlen] = 0;
		    havevar = 1;
		    var = findVar(self, varnm, 0);
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

void Template_destroy(Template *self)
{
    if (!self) return;
    for (uint8_t h = 0; h < TVHT_SIZE; ++h)
    {
	TmplVar *var = self->buckets[h];
	while (var)
	{
	    TmplVar *next = var->next;
	    if (var->owned) free(var->val);
	    free(var);
	    var = next;
	}
    }
    if (self->owned) free(self->tmpl);
    free(self);
}

