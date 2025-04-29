#ifndef SWAD_HANDLER_STATIC_H
#define SWAD_HANDLER_STATIC_H

#include <poser/decl.h>
#include <stddef.h>

C_CLASS_DECL(HttpContext);

void staticHandler_init(const char *resdir) ATTR_NONNULL((1));
void staticHandler_done(void);

void staticHandler(HttpContext *context) ATTR_NONNULL((1));
int staticHandler_link(char *buf, size_t bufsz,
	const char *base, const char *name)
    ATTR_NONNULL((1)) ATTR_NONNULL((3)) ATTR_NONNULL((4));

#endif
