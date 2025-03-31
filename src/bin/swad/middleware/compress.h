#ifndef SWAD_MIDDLEWARE_COMPRESS_H
#define SWAD_MIDDLEWARE_COMPRESS_H

#include <poser/decl.h>

C_CLASS_DECL(HttpContext);

void MW_Compress(HttpContext *context) ATTR_NONNULL((1));

#endif
