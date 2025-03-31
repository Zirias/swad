#ifndef SWAD_TEMPLATE_H
#define SWAD_TEMPLATE_H

#include <poser/decl.h>
#include <stddef.h>
#include <stdint.h>

C_CLASS_DECL(Template);

typedef enum TmplFilter
{
    TF_NONE,
    TF_HTML,
    TF_HTMLNL,
    TF_URL
} TmplFilter;

Template *Template_create(const uint8_t *tmpl, size_t tmplSize)
    ATTR_NONNULL((1)) ATTR_RETNONNULL;
Template *Template_createStr(const char *tmpl)
    ATTR_NONNULL((1)) ATTR_RETNONNULL;
Template *Template_createStatic(const uint8_t *tmpl, size_t tmplSize)
    ATTR_NONNULL((1)) ATTR_RETNONNULL;
Template *Template_createStaticStr(const char *tmpl)
    ATTR_NONNULL((1)) ATTR_RETNONNULL;
void Template_setVar(Template *self,
	const char *name, const char *val, TmplFilter filter)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));
void Template_passVar(Template *self,
	const char *name, char *val, TmplFilter filter)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));
void Template_setStaticVar(Template *self,
	const char *name, const char *val, TmplFilter filter)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));
char *Template_process(const Template *self) CMETHOD ATTR_MALLOC;
void Template_destroy(Template *self);

#endif
