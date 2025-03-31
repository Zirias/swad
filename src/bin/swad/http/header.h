#ifndef SWAD_HEADER_H
#define SWAD_HEADER_H

#include <poser/decl.h>
#include <stdint.h>

C_CLASS_DECL(Header);

Header *Header_create(const char *name, const char *value)
    ATTR_NONNULL((1)) ATTR_NONNULL((2));
Header *Header_createPassVal(const char *name, char *value)
    ATTR_NONNULL((1)) ATTR_NONNULL((2));
const char *Header_name(const Header *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
const char *Header_value(const Header *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
uint16_t Header_size(const Header *self) CMETHOD ATTR_PURE;
uint16_t Header_writeTo(const Header *self, uint8_t *buf)
    CMETHOD ATTR_NONNULL((2));
void Header_destroy(Header *self);

#endif
