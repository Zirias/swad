#ifndef SWAD_MIDDLEWARE_CSRFPROTECT_H
#define SWAD_MIDDLEWARE_CSRFPROTECT_H

#include <poser/decl.h>

C_CLASS_DECL(HttpContext);

const char *CSRFProtect_name(void) ATTR_RETNONNULL ATTR_CONST;
const char *CSRFProtect_token(HttpContext *context)
    ATTR_NONNULL((1)) ATTR_PURE;

void MW_CSRFProtect(HttpContext *context) ATTR_NONNULL((1));

#endif
