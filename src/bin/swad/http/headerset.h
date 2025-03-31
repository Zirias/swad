#ifndef SWAD_HEADERSET_H
#define SWAD_HEADERSET_H

#include <poser/decl.h>
#include <stdint.h>

C_CLASS_DECL(HeaderSet);
C_CLASS_DECL(HeaderIterator);
C_CLASS_DECL(Header);

HeaderSet *HeaderSet_create(void) ATTR_RETNONNULL;
void HeaderSet_set(HeaderSet *self, Header *header) CMETHOD ATTR_NONNULL((2));
void HeaderSet_add(HeaderSet *self, Header *header) CMETHOD ATTR_NONNULL((2));
int HeaderSet_remove(HeaderSet *self, const Header *header)
    CMETHOD ATTR_NONNULL((2));
int HeaderSet_removeAll(HeaderSet *self, const char *headerName)
    CMETHOD ATTR_NONNULL((2));
HeaderIterator *HeaderSet_all(const HeaderSet *self) CMETHOD ATTR_RETNONNULL;
HeaderIterator *HeaderSet_any(const HeaderSet *self, const char *headerName)
    CMETHOD ATTR_NONNULL((2)) ATTR_RETNONNULL;
const Header *HeaderSet_first(const HeaderSet *self, const char *headerName)
    CMETHOD ATTR_NONNULL((2));
uint16_t HeaderSet_size(const HeaderSet *self) CMETHOD ATTR_PURE;
void HeaderSet_destroy(HeaderSet *self);

int HeaderIterator_moveNext(HeaderIterator *self) CMETHOD;
const Header *HeaderIterator_current(const HeaderIterator *self)
    CMETHOD ATTR_PURE;
void HeaderIterator_destroy(HeaderIterator *self);

#endif
