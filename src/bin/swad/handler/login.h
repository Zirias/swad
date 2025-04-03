#ifndef SWAD_HANDLER_LOGIN_H
#define SWAD_HANDLER_LOGIN_H

#include <poser/decl.h>

C_CLASS_DECL(HeaderSet);
C_CLASS_DECL(HttpContext);
C_CLASS_DECL(PathParser);

void loginHandler(HttpContext *context) ATTR_NONNULL((1));

void loginHandler_setRoute(const char *loginRoute);
const char *loginHandler_route(void);
const char *loginHandler_realm(const HeaderSet *hdr,
	const PathParser *pathParser)
    ATTR_NONNULL((1)) ATTR_NONNULL((2));
const char *loginHandler_rdr(const HeaderSet *hdr,
	const PathParser *pathParser)
    ATTR_NONNULL((1)) ATTR_NONNULL((2));

#endif
