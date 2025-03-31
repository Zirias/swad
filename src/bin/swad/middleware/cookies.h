#ifndef SWAD_MIDDLEWARE_COOKIES_H
#define SWAD_MIDDLEWARE_COOKIES_H

#include <poser/decl.h>

C_CLASS_DECL(Cookies);
C_CLASS_DECL(HttpContext);

Cookies *Cookies_get(const HttpContext *context) ATTR_NONNULL((1)) ATTR_PURE;
const char *Cookies_getCookie(const Cookies *self, const char *name)
    CMETHOD ATTR_NONNULL((2)) ATTR_PURE;
void Cookies_setCookie(Cookies *self, const char *name, const char *value)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));

void MW_Cookies(HttpContext *context) ATTR_NONNULL((1));

#endif
