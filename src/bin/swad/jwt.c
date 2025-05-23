#include "jwt.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <poser/core/base64.h>
#include <poser/core/json.h>
#include <poser/core/util.h>
#include <string.h>

struct Jwt
{
    PSC_Json *json;
    PSC_Json *jose;
    PSC_Json *iss;
    PSC_Json *sub;
    PSC_Json *exp;
    uint32_t seconds;
    int valid;
};

static char key[64];

Jwt *Jwt_create(const char *iss, const char *sub, uint32_t seconds)
{
    Jwt *self = PSC_malloc(sizeof *self);
    self->json = PSC_Json_createObject();
    self->jose = 0;
    self->iss = PSC_Json_createString(iss, 0);
    self->sub = PSC_Json_createString(sub, 0);
    self->exp = 0;
    self->seconds = seconds;
    self->valid = 0;

    PSC_Json_setProperty(self->json, "iss", 3, self->iss);
    PSC_Json_setProperty(self->json, "sub", 3, self->sub);

    return self;
}

Jwt *Jwt_parse(const char *str)
{
    char *dot1 = strchr(str, '.');
    if (!dot1) return 0;
    char *dot2 = strchr(dot1+1, '.');
    if (!dot2) return 0;

    PSC_JsonSerializer *ser = PSC_JsonSerializer_create(0);
    *dot1 = 0;
    char *josestr = PSC_Base64_decode(str, 0);
    *dot1 = '.';
    PSC_Json *jose = PSC_JsonSerializer_deserialize(ser, josestr);
    free(josestr);
    if (!jose) goto error;
    const PSC_Json *typ = PSC_Json_property(jose, "typ", 3);
    if (!typ || strcmp(PSC_Json_string(typ), "JWT")) goto error;
    *dot2 = 0;
    char *jsonstr = PSC_Base64_decode(dot1+1, 0);
    *dot2 = '.';
    PSC_Json *json = PSC_JsonSerializer_deserialize(ser, jsonstr);
    free(jsonstr);
    if (!json) goto error;
    PSC_JsonSerializer_destroy(ser);

    Jwt *self = PSC_malloc(sizeof *self);
    self->json = json;
    self->jose = jose;
    self->iss = (PSC_Json *)PSC_Json_property(json, "iss", 3);
    self->sub = (PSC_Json *)PSC_Json_property(json, "sub", 3);
    self->exp = (PSC_Json *)PSC_Json_property(json, "exp", 3);
    self->seconds = 0;
    self->valid = 0;

    const PSC_Json *alg = PSC_Json_property(jose, "alg", 3);
    if (alg && !strcmp(PSC_Json_string(alg), "HS256"))
    {
	unsigned char chksig[32];
	unsigned chksigsz = sizeof chksig;
	size_t sigsz;
	unsigned char *sig = PSC_Base64_decode(dot2+1, &sigsz);
	if (sigsz == chksigsz)
	{
	    HMAC(EVP_sha256(), key, sizeof key, (void *)str, dot2-str,
		    chksig, &chksigsz);
	    unsigned char diff = 0;
	    for (unsigned i = 0; i < sigsz; ++i)
	    {
		diff |= (sig[i] ^ chksig[i]);
	    }
	    if (!diff) self->valid = 1;
	}
	free(sig);
    }

    return self;

error:
    PSC_Json_destroy(jose);
    PSC_JsonSerializer_destroy(ser);
    return 0;
}

void Jwt_set(Jwt *self, const char *claim, PSC_Json *value)
{
    PSC_Json_setProperty(self->json, claim, 0, value);
}

char *Jwt_issue(Jwt *self, int64_t now, JwtSigAlg alg)
{
    if (alg != JSA_HS256) return 0;
    if (self->jose || self->exp || self->valid) return 0;
    self->exp = PSC_Json_createInteger(now + self->seconds);
    PSC_Json_setProperty(self->json, "exp", 3, self->exp);
    self->jose = PSC_Json_createObject();
    PSC_Json_setProperty(self->jose, "typ", 3,
	    PSC_Json_createString("JWT", 3));
    PSC_Json_setProperty(self->jose, "alg", 3,
	    PSC_Json_createString("HS256", 5));

    PSC_JsonSerializer *ser = PSC_JsonSerializer_create(0);
    char *josestr = PSC_JsonSerializer_serialize(ser, self->jose);
    char *jsonstr = PSC_JsonSerializer_serialize(ser, self->json);
    PSC_JsonSerializer_destroy(ser);

    size_t joseslen = strlen(josestr);
    size_t joselen = PSC_Base64_encodedLen(joseslen);
    size_t jsonslen = strlen(jsonstr);
    size_t jsonlen = PSC_Base64_encodedLen(jsonslen);
    unsigned char sig[32];
    unsigned sigsz = sizeof sig;
    size_t siglen = PSC_Base64_encodedLen(sigsz);
    size_t len = joselen + jsonlen + siglen + 3;
    char *str = PSC_malloc(len + 1);
    PSC_Base64_encodeTo(str, josestr, joseslen, PSC_B64_URLSAFE);
    size_t strpos = joselen;
    str[strpos++] = '.';
    PSC_Base64_encodeTo(str+strpos, jsonstr, jsonslen, PSC_B64_URLSAFE);
    strpos += jsonlen;
    free(jsonstr);
    free(josestr);
    HMAC(EVP_sha256(), key, sizeof key, (void *)str, strpos, sig, &sigsz);
    str[strpos++] = '.';
    PSC_Base64_encodeTo(str+strpos, sig, sigsz, PSC_B64_URLSAFE);
    strpos += siglen;
    str[strpos] = 0;

    self->valid = 1;
    return str;
}

int Jwt_valid(const Jwt *self)
{
    return self->valid;
}

const char *Jwt_iss(const Jwt *self)
{
    if (!self->iss) return 0;
    return PSC_Json_string(self->iss);
}

const char *Jwt_sub(const Jwt *self)
{
    if (!self->sub) return 0;
    return PSC_Json_string(self->sub);
}

int64_t Jwt_exp(const Jwt *self)
{
    if (!self->exp) return 0;
    return PSC_Json_integer(self->exp);
}

const PSC_Json *Jwt_json(const Jwt *self)
{
    return self->json;
}

void Jwt_destroy(Jwt *self)
{
    if (!self) return;
    PSC_Json_destroy(self->jose);
    PSC_Json_destroy(self->json);
    free(self);
}

