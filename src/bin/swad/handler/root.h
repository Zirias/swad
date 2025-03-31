#ifndef SWAD_HANDLER_ROOT_H
#define SWAD_HANDLER_ROOT_H

#include <poser/decl.h>

C_CLASS_DECL(HttpContext);

void rootHandler(HttpContext *context) ATTR_NONNULL((1));

#endif
