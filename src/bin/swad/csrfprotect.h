#ifndef SWAD_CSRFPROTECT_H
#define SWAD_CSRFPROTECT_H

#include <poser/decl.h>

C_CLASS_DECL(HttpContext);

const char *CSRFProtect_name(void) ATTR_RETNONNULL ATTR_CONST;
const char *CSRFProtect_token(HttpContext *context, const char *path)
    ATTR_NONNULL((1)) ATTR_NONNULL((2)) ATTR_PURE;
int CSRFProtect_verify(HttpContext *context) ATTR_NONNULL((1));

#endif
