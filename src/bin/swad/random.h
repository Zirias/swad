#ifndef SWAD_RANDOM_H
#define SWAD_RANDOM_H

#include <poser/decl.h>
#include <stddef.h>
#include <stdint.h>

void getRndBytes(uint8_t *buf, size_t num)
    ATTR_NONNULL((1)) ATTR_ACCESS((write_only, 1, 2));
void getRndStr(char *str, size_t size, size_t num)
    ATTR_NONNULL((1)) ATTR_ACCESS((write_only, 1, 2));
char *createRndStr(size_t num) ATTR_MALLOC ATTR_RETNONNULL;

#endif
