#include "headerset.h"
#include "header.h"
#include "../util.h"

#include <poser/core/util.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define HSHT_BITS 5
#define HSHT_SIZE HT_SIZE(HSHT_BITS)

typedef struct HeaderSetEntry HeaderSetEntry;

struct HeaderSetEntry
{
    char *key;
    Header *header;
    HeaderSetEntry *next;
};

struct HeaderSet
{
    size_t count;
    HeaderSetEntry *buckets[HSHT_SIZE];
    uint16_t size;
};

struct HeaderIterator
{
    const HeaderSet *headerSet;
    char *key;
    const HeaderSetEntry *entry;
    uint8_t hash;
};

static void removeEntry(HeaderSet *self, uint8_t hash,
	HeaderSetEntry *parent, HeaderSetEntry *entry)
    CMETHOD ATTR_NONNULL((4));

static void removeEntry(HeaderSet *self, uint8_t hash,
	HeaderSetEntry *parent, HeaderSetEntry *entry)
{
    --self->count;
    self->size -= Header_size(entry->header);
    Header_destroy(entry->header);
    if (parent) parent->next = entry->next;
    else self->buckets[hash] = entry->next;
    free(entry->key);
    free(entry);
}

HeaderSet *HeaderSet_create(void)
{
    HeaderSet *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    return self;
}

void HeaderSet_set(HeaderSet *self, Header *header)
{
    HeaderSet_removeAll(self, Header_name(header));
    HeaderSet_add(self, header);
}

void HeaderSet_add(HeaderSet *self, Header *header)
{
    HeaderSetEntry *entry = PSC_malloc(sizeof *entry);
    entry->key = lowerstr(Header_name(header));
    entry->header = header;
    entry->next = 0;

    uint8_t hashval = hash(entry->key, HSHT_BITS);
    if (self->buckets[hashval])
    {
	HeaderSetEntry *parent = self->buckets[hashval];
	while (parent->next) parent = parent->next;
	parent->next = entry;
    }
    else
    {
	self->buckets[hashval] = entry;
    }
    ++self->count;
    self->size += Header_size(header);
}

int HeaderSet_remove(HeaderSet *self, const Header *header)
{
    char *key = lowerstr(Header_name(header));
    uint8_t hashval = hash(key, HSHT_BITS);
    int rc = 0;

    HeaderSetEntry *current = self->buckets[hashval];
    HeaderSetEntry *parent = 0;
    while (current)
    {
	if (!strcmp(key, current->key) &&
		!strcmp(Header_value(header), Header_value(current->header)))
	{
	    removeEntry(self, hashval, parent, current);
	    rc = 1;
	    break;
	}
	parent = current;
	current = current->next;
    }

    free(key);
    return rc;
}

int HeaderSet_removeAll(HeaderSet *self, const char *headerName)
{
    char *key = lowerstr(headerName);
    uint8_t hashval = hash(key, HSHT_BITS);
    int rc = 0;

    HeaderSetEntry *current = self->buckets[hashval];
    HeaderSetEntry *parent = 0;
    while (current)
    {
	if (!strcmp(key, current->key))
	{
	    HeaderSetEntry *next = current->next;
	    removeEntry(self, hashval, parent, current);
	    current = next;
	    ++rc;
	}
	else
	{
	    parent = current;
	    current = current->next;
	}
    }

    free(key);
    return rc;
}

HeaderIterator *HeaderSet_all(const HeaderSet *self)
{
    HeaderIterator *it = PSC_malloc(sizeof *it);
    it->headerSet = self;
    it->key = 0;
    it->entry = 0;
    it->hash = 0xff;
    return it;
}

HeaderIterator *HeaderSet_any(const HeaderSet *self, const char *headerName)
{
    HeaderIterator *it = PSC_malloc(sizeof *it);
    it->headerSet = self;
    it->key = lowerstr(headerName);
    it->entry = 0;
    it->hash = hash(it->key, HSHT_BITS);
    return it;
}

const Header *HeaderSet_first(const HeaderSet *self, const char *headerName)
{
    char *key = lowerstr(headerName);
    uint8_t hashval = hash(key, HSHT_BITS);

    const Header *header = 0;
    for (HeaderSetEntry *entry = self->buckets[hashval];
	    entry; entry = entry->next)
    {
	if (!strcmp(key, entry->key))
	{
	    header = entry->header;
	    break;
	}
    }

    free(key);
    return header;
}

const Header *HeaderSet_single(const HeaderSet *self, const char *headerName)
{
    char *key = lowerstr(headerName);
    uint8_t hashval = hash(key, HSHT_BITS);

    const Header *header = 0;
    for (HeaderSetEntry *entry = self->buckets[hashval];
	    entry; entry = entry->next)
    {
	if (!strcmp(key, entry->key))
	{
	    if (!header) header = entry->header;
	    else
	    {
		header = 0;
		break;
	    }
	}
    }

    free(key);
    return header;
}


uint16_t HeaderSet_size(const HeaderSet *self)
{
    return self->size;
}

void HeaderSet_destroy(HeaderSet *self)
{
    if (!self) return;
    for (uint8_t hash = 0; hash < HSHT_SIZE; ++hash)
    {
	HeaderSetEntry *next = 0;
	for (HeaderSetEntry *current = self->buckets[hash];
		current; current = next)
	{
	    next = current->next;
	    Header_destroy(current->header);
	    free(current->key);
	    free(current);
	}
    }
    free(self);
}

int HeaderIterator_moveNext(HeaderIterator *self)
{
    if (self->entry)
    {
	while (self->entry->next)
	{
	    self->entry = self->entry->next;
	    if (!self->key) return 1;
	    if (!strcmp(self->key, self->entry->key)) return 1;
	}
	if (self->key)
	{
	    self->entry = 0;
	    return 0;
	}
	while (self->hash < HSHT_SIZE-1)
	{
	    ++self->hash;
	    if (self->headerSet->buckets[self->hash])
	    {
		self->entry = self->headerSet->buckets[self->hash];
		return 1;
	    }
	}
	self->hash = 0xff;
	self->entry = 0;
	return 0;
    }

    if (self->key)
    {
	self->entry = self->headerSet->buckets[self->hash];
	if (!self->entry) return 0;
	while (self->entry)
	{
	    if (!strcmp(self->key, self->entry->key)) return 1;
	    self->entry = self->entry->next;
	}
	return 0;
    }

    do
    {
	++self->hash;
	self->entry = self->headerSet->buckets[self->hash];
	if (self->entry) return 1;
    } while (self->hash < HSHT_SIZE);

    self->hash = 0xff;
    return 0;
}

const Header *HeaderIterator_current(const HeaderIterator *self)
{
    if (self->entry) return self->entry->header;
    return 0;
}

void HeaderIterator_destroy(HeaderIterator *self)
{
    if (!self) return;
    free(self->key);
    free(self);
}

