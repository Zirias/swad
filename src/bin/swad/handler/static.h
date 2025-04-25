#ifndef SWAD_HANDLER_STATIC_H
#define SWAD_HANDLER_STATIC_H

#include <poser/decl.h>

C_CLASS_DECL(HttpContext);

void staticHandler_init(const char *resdir) ATTR_NONNULL((1));
void staticHandler_done(void);

void staticHandler(HttpContext *context) ATTR_NONNULL((1));

#endif
