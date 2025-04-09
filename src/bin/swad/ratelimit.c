#define _POSIX_C_SOURCE 200809L

#include "ratelimit.h"

#include <poser/core.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAXCOUNTS 512

typedef struct Entry
{
    uint16_t last;
    uint16_t total;
    uint16_t countpos;
    uint16_t counts[];
} Entry;

typedef struct Limit
{
    PSC_HashTable *entries;
    uint16_t seconds;
    uint16_t limit;
    uint16_t res;
    uint16_t ncounts;
} Limit;

struct RateLimit
{
    size_t nlimits;
    pthread_mutex_t lock;
    int locked;
    Limit limits[];
};

struct RateLimitOpts
{
    int locked;
    size_t limits_count;
    size_t limits_capa;
    Limit *limits;
};

RateLimit *RateLimit_create(const RateLimitOpts *opts)
{
    RateLimit *self = PSC_malloc(sizeof *self
	    + opts->limits_count * sizeof *self->limits);
    self->nlimits = opts->limits_count;
    if (opts->locked) pthread_mutex_init(&self->lock, 0);
    self->locked = opts->locked;
    memcpy(self->limits, opts->limits, self->nlimits * sizeof *self->limits);
    return self;
}

struct expiredarg
{
    const char *id;
    uint16_t now;
    uint16_t ncounts;
};

static int expired(const char *key, void *obj, const void *arg)
{
    const struct expiredarg *ea = arg;
    Entry *e = obj;

    if (strcmp(key, ea->id) && ea->now - e->last >= ea->ncounts) return 1;
    return 0;
}

static int checkLimit(Limit *self, struct timespec *ts, const char *id)
{
    uint16_t now = ts->tv_sec / self->res;
    if (!self->entries) self->entries = PSC_HashTable_create(6);
    else
    {
	struct expiredarg ea = {
	    .id = id,
	    .now = now,
	    .ncounts = self->ncounts
	};
	PSC_HashTable_deleteAll(self->entries, expired, &ea);
    }
    Entry *e = PSC_HashTable_get(self->entries, id);
    if (!e)
    {
	e = PSC_malloc(sizeof *e + self->ncounts * sizeof *e->counts);
	memset(e, 0, sizeof *e + self->ncounts * sizeof *e->counts);
	e->last = now;
	PSC_HashTable_set(self->entries, id, e, free);
    }
    for (; e->last != now; ++e->last)
    {
	e->total -= e->counts[e->countpos++];
	if (e->countpos == self->ncounts) e->countpos = 0;
    }
    if (e->total < self->limit)
    {
	++e->counts[e->countpos];
	++e->total;
	return 1;
    }
    return 0;
}

int RateLimit_check(RateLimit *self, const char *id)
{
    int ok = 1;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) return 0;
    if (self->locked) pthread_mutex_lock(&self->lock);
    for (size_t i = 0; i < self->nlimits; ++i)
    {
	if (!checkLimit(self->limits + i, &ts, id)) ok = 0;
    }
    if (self->locked) pthread_mutex_unlock(&self->lock);
    return ok;
}

void RateLimit_destroy(RateLimit *self)
{
    if (!self) return;
    for (size_t i = 0; i < self->nlimits; ++i)
    {
	PSC_HashTable_destroy(self->limits[i].entries);
    }
    if (self->locked) pthread_mutex_destroy(&self->lock);
    free(self);
}

RateLimitOpts *RateLimitOpts_create(int locked)
{
    RateLimitOpts *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    self->locked = locked;
    return self;
}

void RateLimitOpts_addLimit(RateLimitOpts *self,
	uint16_t seconds, uint16_t limit)
{
    if (self->limits_count == self->limits_capa)
    {
	self->limits_capa += 8;
	self->limits = PSC_realloc(self->limits,
		self->limits_capa * sizeof *self->limits);
    }
    Limit *l = self->limits + self->limits_count++;
    l->entries = 0;
    l->seconds = seconds;
    l->limit = limit;
    l->res = (seconds + MAXCOUNTS - 1) / MAXCOUNTS;
    l->ncounts = (seconds + l->res - 1) / l->res;
}

void RateLimitOpts_destroy(RateLimitOpts *self)
{
    if (!self) return;
    free(self->limits);
    free(self);
}

