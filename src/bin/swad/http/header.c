#include "header.h"

#include <poser/core/util.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct Header {
    char *name;
    char *value;
    uint16_t namesize;
    uint16_t valuesize;
};

static Header *create(char *name, char *value,
	size_t namesize, size_t valuesize)
    ATTR_NONNULL((1)) ATTR_NONNULL((2)) ATTR_RETNONNULL;
static int validate(const char *name, const char *value,
	size_t *namesize, size_t *valuesize)
    ATTR_NONNULL((1)) ATTR_NONNULL((2)) ATTR_NONNULL((3)) ATTR_NONNULL((4))
    ATTR_ACCESS((write_only, 3)) ATTR_ACCESS((write_only, 4));

static int validate(const char *name, const char *value,
	size_t *namesize, size_t *valuesize)
{
    *namesize = strlen(name);
    if (*namesize > UINT16_MAX) return -1;
    *valuesize = strlen(value);
    if (*valuesize > UINT16_MAX) return -1;
    if (*namesize + *valuesize + 4 > UINT16_MAX) return -1;
    return 0;
}

static Header *create(char *name, char *value,
	size_t namesize, size_t valuesize)
{
    Header *self = PSC_malloc(sizeof *self);
    self->name = name;
    self->value = value;
    self->namesize = (uint16_t)namesize;
    self->valuesize = (uint16_t)valuesize;

    return self;
}

Header *Header_create(const char *name, const char *value)
{
    size_t namesize;
    size_t valuesize;
    if (validate(name, value, &namesize, &valuesize) < 0) return 0;

    char *hdrname = PSC_malloc(namesize+1);
    memcpy(hdrname, name, namesize+1);
    char *hdrvalue = PSC_malloc(valuesize+1);
    memcpy(hdrvalue, value, valuesize+1);
    return create(hdrname, hdrvalue, namesize, valuesize);
}

Header *Header_createPassVal(const char *name, char *value)
{
    size_t namesize;
    size_t valuesize;
    if (validate(name, value, &namesize, &valuesize) < 0)
    {
	free(value);
	return 0;
    }

    char *hdrname = PSC_malloc(namesize+1);
    memcpy(hdrname, name, namesize+1);
    return create(hdrname, value, namesize, valuesize);
}

const char *Header_name(const Header *self)
{
    return self->name;
}

const char *Header_value(const Header *self)
{
    return self->value;
}

uint16_t Header_size(const Header *self)
{
    return self->namesize + self->valuesize + 4;
}

uint16_t Header_writeTo(const Header *self, uint8_t *buf)
{
    memcpy(buf, self->name, self->namesize);
    memcpy(buf + self->namesize, ": ", 2);
    memcpy(buf + self->namesize + 2, self->value, self->valuesize);
    memcpy(buf + self->namesize + self->valuesize + 2, "\r\n", 2);
    return Header_size(self);
}

void Header_destroy(Header *self)
{
    if (!self) return;
    free(self->value);
    free(self->name);
    free(self);
}

