#ifndef SWAD_MIDDLEWARE_SESSION_H
#define SWAD_MIDDLEWARE_SESSION_H

#include <poser/decl.h>

C_CLASS_DECL(Session);
C_CLASS_DECL(HttpContext);

typedef void (*ObjDeleter)(void *obj);

Session *Session_get(const HttpContext *context) ATTR_NONNULL((1)) ATTR_PURE;
const char *Session_id(const Session *self) CMETHOD ATTR_RETNONNULL ATTR_PURE;
const char *Session_referrer(const Session *self) CMETHOD ATTR_PURE;
void *Session_getProp(Session *self, const char *name)
    CMETHOD ATTR_NONNULL((2)) ATTR_PURE;
void Session_setProp(Session *self, const char *name,
	void *obj, ObjDeleter deleter) CMETHOD ATTR_NONNULL((2));

void MW_Session_init(void);
void MW_Session(HttpContext *context) ATTR_NONNULL((1));
void MW_Session_done(void);

#endif
