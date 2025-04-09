#ifndef SWAD_RATELIMIT_H
#define SWAD_RATELIMIT_H

#include <poser/decl.h>
#include <stdint.h>

C_CLASS_DECL(RateLimit);
C_CLASS_DECL(RateLimitOpts);

RateLimit *RateLimit_create(const RateLimitOpts *opts) ATTR_RETNONNULL;
int RateLimit_check(RateLimit *self, const char *id) CMETHOD ATTR_NONNULL((1));
void RateLimit_destroy(RateLimit *self);

RateLimitOpts *RateLimitOpts_create(int locked) ATTR_RETNONNULL;
void RateLimitOpts_addLimit(RateLimitOpts *self,
	uint16_t seconds, uint16_t limit) CMETHOD;
void RateLimitOpts_destroy(RateLimitOpts *self);

#endif
