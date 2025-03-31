#ifndef SWAD_MIDDLEWARE_PATHPARSER_H
#define SWAD_MIDDLEWARE_PATHPARSER_H

#include <poser/decl.h>

C_CLASS_DECL(QueryParam);
C_CLASS_DECL(PathParser);
C_CLASS_DECL(HttpContext);

const PathParser *PathParser_get(const HttpContext *context)
    ATTR_NONNULL((1)) ATTR_PURE;
const char *PathParser_path(const PathParser *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
const QueryParam *PathParser_param(const PathParser *self,
	const char *name, const QueryParam *curr)
    CMETHOD ATTR_NONNULL((2)) ATTR_PURE;
const char *QueryParam_name(const QueryParam *param)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
const char *QueryParam_value(const QueryParam *param) CMETHOD ATTR_PURE;

void MW_PathParser(HttpContext *context) ATTR_NONNULL((1));

#endif
