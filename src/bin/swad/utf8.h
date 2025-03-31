#ifndef SWAD_UTF8_H
#define SWAD_UTF8_H

#include <poser/decl.h>
#include <stddef.h>

int utf8_check(const char *str, size_t *len) ATTR_NONNULL((1));
int utf8_sanitize(char *str, size_t *len) ATTR_NONNULL((1));

#endif
