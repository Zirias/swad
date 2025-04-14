#define _POSIX_C_SOURCE 200112L
#include "headerset.h"

#include "header.h"

#include <poser/core.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct HeaderSetEntry HeaderSetEntry;

struct HeaderSetEntry
{
    Header *header;
    HeaderSetEntry *next;
};

struct HeaderSet
{
    PSC_HashTable *entries;
    size_t size;
};

struct HeaderIterator
{
    PSC_HashTableIterator *iter;
    HeaderSetEntry *first;
    HeaderSetEntry *current;
};

static void entryDeleter(void *obj)
{
    if (!obj) return;
    HeaderSetEntry *entry = obj;
    while (entry)
    {
	HeaderSetEntry *next = entry->next;
	Header_destroy(entry->header);
	free(entry);
	entry = next;
    }
}

HeaderSet *HeaderSet_create(void)
{
    HeaderSet *self = PSC_malloc(sizeof *self);
    self->entries = PSC_HashTable_create(5);
    self->size = 0;
    return self;
}

void HeaderSet_set(HeaderSet *self, Header *header)
{
    char *key = PSC_lowerstr(Header_name(header));
    HeaderSetEntry *old = PSC_HashTable_get(self->entries, key);
    while (old)
    {
	self->size -= Header_size(old->header);
	old = old->next;
    }
    HeaderSetEntry *entry = PSC_malloc(sizeof *entry);
    entry->header = header;
    entry->next = 0;
    PSC_HashTable_set(self->entries, key, entry, entryDeleter);
    self->size += Header_size(header);
    free(key);
}

void HeaderSet_add(HeaderSet *self, Header *header)
{
    char *key = PSC_lowerstr(Header_name(header));
    HeaderSetEntry *entry = PSC_malloc(sizeof *entry);
    entry->header = header;
    entry->next = 0;
    HeaderSetEntry *parent = PSC_HashTable_get(self->entries, key);
    if (parent)
    {
	while (parent->next) parent = parent->next;
	parent->next = entry;
    }
    else PSC_HashTable_set(self->entries, key, entry, entryDeleter);
    self->size += Header_size(header);
    free(key);
}

int HeaderSet_remove(HeaderSet *self, const Header *header)
{
    char *key = PSC_lowerstr(Header_name(header));
    int rc = 0;

    HeaderSetEntry *entry = PSC_HashTable_get(self->entries, key);
    HeaderSetEntry *parent = 0;
    if (!entry) goto done;
    while (entry)
    {
	HeaderSetEntry *next = entry->next;
	if (!strcasecmp(Header_name(entry->header), key) &&
		!strcmp(Header_value(entry->header), Header_value(header)))
	{
	    rc = 1;
	    self->size -= Header_size(entry->header);
	    Header_destroy(entry->header);
	    free(entry);
	    if (parent) parent->next = next;
	    else if (next)
	    {
		PSC_HashTable_set(self->entries, key, next, entryDeleter);
	    }
	    else PSC_HashTable_delete(self->entries, key);
	    break;
	}
	parent = entry;
	entry = next;
    }

done:
    free(key);
    return rc;
}

size_t HeaderSet_removeAll(HeaderSet *self, const char *headerName)
{
    char *key = PSC_lowerstr(headerName);
    HeaderSetEntry *old = PSC_HashTable_get(self->entries, key);
    size_t removed = 0;
    while (old)
    {
	self->size -= Header_size(old->header);
	++removed;
	old = old->next;
    }
    PSC_HashTable_delete(self->entries, key);
    free(key);
    return removed;
}

HeaderIterator *HeaderSet_all(const HeaderSet *self)
{
    HeaderIterator *it = PSC_malloc(sizeof *it);
    it->iter = PSC_HashTable_iterator(self->entries);
    it->first = 0;
    it->current = 0;
    return it;
}

HeaderIterator *HeaderSet_any(const HeaderSet *self, const char *headerName)
{
    HeaderIterator *it = PSC_malloc(sizeof *it);
    it->iter = 0;
    char *key = PSC_lowerstr(headerName);
    it->first = PSC_HashTable_get(self->entries, key);
    free(key);
    it->current = 0;
    return it;
}

const Header *HeaderSet_first(const HeaderSet *self, const char *headerName)
{
    char *key = PSC_lowerstr(headerName);
    HeaderSetEntry *entry = PSC_HashTable_get(self->entries, key);
    free(key);
    return entry ? entry->header : 0;
}

const Header *HeaderSet_single(const HeaderSet *self, const char *headerName)
{
    char *key = PSC_lowerstr(headerName);
    HeaderSetEntry *entry = PSC_HashTable_get(self->entries, key);
    free(key);
    return entry && !entry->next ? entry->header : 0;
}

size_t HeaderSet_size(const HeaderSet *self)
{
    return self->size;
}

void HeaderSet_destroy(HeaderSet *self)
{
    if (!self) return;
    PSC_HashTable_destroy(self->entries);
    free(self);
}

int HeaderIterator_moveNext(HeaderIterator *self)
{
    if (self->current)
    {
	if (self->current->next)
	{
	    self->current = self->current->next;
	    return 1;
	}
	else if (self->iter)
	{
	    if (PSC_HashTableIterator_moveNext(self->iter))
	    {
		self->current = PSC_HashTableIterator_current(self->iter);
		return 1;
	    }
	    else
	    {
		self->current = 0;
		return 0;
	    }
	}
	else
	{
	    self->current = 0;
	    return 0;
	}
    }
    else if (self->first)
    {
	self->current = self->first;
	return 1;
    }
    else if (self->iter)
    {
	if (PSC_HashTableIterator_moveNext(self->iter))
	{
	    self->current = PSC_HashTableIterator_current(self->iter);
	    return 1;
	}
	else return 0;
    } else return 0;
}

const Header *HeaderIterator_current(const HeaderIterator *self)
{
    return self->current ? self->current->header : 0;
}

void HeaderIterator_destroy(HeaderIterator *self)
{
    if (!self) return;
    PSC_HashTableIterator_destroy(self->iter);
    free(self);
}

