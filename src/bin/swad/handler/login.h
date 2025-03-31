#ifndef SWAD_HANDLER_LOGIN_H
#define SWAD_HANDLER_LOGIN_H

#include <poser/decl.h>

C_CLASS_DECL(HttpContext);

void loginHandler(HttpContext *context) ATTR_NONNULL((1));

#endif
