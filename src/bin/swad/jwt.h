#ifndef SWAD_JWT_H
#define SWAD_JWT_H

#include <poser/decl.h>
#include <stdint.h>

C_CLASS_DECL(Jwt);
C_CLASS_DECL(PSC_Json);

typedef enum JwtSigAlg
{
    JSA_NONE,
    JSA_HS256
} JwtSigAlg;

void Jwt_createHmacKey(void);

Jwt *Jwt_create(const char *iss, const char *sub, uint32_t seconds)
    ATTR_NONNULL((1)) ATTR_NONNULL((2)) ATTR_RETNONNULL;
Jwt *Jwt_parse(const char *str)
    ATTR_NONNULL((1));
void Jwt_set(Jwt *self, const char *claim, PSC_Json *value)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));
char *Jwt_issue(Jwt *self, int64_t now, JwtSigAlg alg)
    CMETHOD;
int Jwt_valid(const Jwt *self)
    CMETHOD ATTR_PURE;
const char *Jwt_iss(const Jwt *self)
    CMETHOD ATTR_PURE;
const char *Jwt_sub(const Jwt *self)
    CMETHOD ATTR_PURE;
int64_t Jwt_exp(const Jwt *self)
    CMETHOD ATTR_PURE;
const PSC_Json *Jwt_json(const Jwt *self)
    CMETHOD ATTR_PURE;
void Jwt_destroy(Jwt *self);

#endif
