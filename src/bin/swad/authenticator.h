#ifndef SWAD_AUTHENTICATOR_H
#define SWAD_AUTHENTICATOR_H

#include <poser/decl.h>
#include <stddef.h>
#include <stdint.h>

#define DEFAULT_REALM "SWAD"

C_CLASS_DECL(Authenticator);
C_CLASS_DECL(CredentialsChecker);
C_CLASS_DECL(User);

C_CLASS_DECL(HttpContext);
C_CLASS_DECL(PSC_List);
C_CLASS_DECL(PSC_RateLimitOpts);

typedef enum AuthResult
{
    AR_OK,
    AR_FAILED,
    AR_BLOCKED,
    AR_DEVIATE
} AuthResult;

struct CredentialsChecker
{
    AuthResult (*check)(void *self, const char *user, const char *pw,
	    const Authenticator *auth, char **realname)
	CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3))
	ATTR_NONNULL((4)) ATTR_NONNULL((5));
    void (*deviate)(void *self, const Authenticator *auth)
	CMETHOD ATTR_NONNULL((1));
    void (*destroy)(void *self);
};

Authenticator *Authenticator_create(HttpContext *context, const char *realm)
    ATTR_RETNONNULL;
const User *Authenticator_user(const Authenticator *self) CMETHOD;
const char *Authenticator_realm(const Authenticator *self) CMETHOD;
const uint8_t *Authenticator_loginTmpl(const Authenticator *self, size_t *sz)
    CMETHOD ATTR_NONNULL((2));
const uint8_t *Authenticator_logoutTmpl(const Authenticator *self, size_t *sz)
    CMETHOD ATTR_NONNULL((2));
HttpContext *Authenticator_context(const Authenticator *self)
    CMETHOD ATTR_RETNONNULL;
AuthResult Authenticator_silentLogin(Authenticator *self) CMETHOD;
AuthResult Authenticator_login(Authenticator *self,
	const char *user, const char *pw)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));
int Authenticator_deviate(Authenticator *self) CMETHOD;
void Authenticator_logout(Authenticator *self) CMETHOD;
void Authenticator_destroy(Authenticator *self);

const char *User_username(const User *self) CMETHOD ATTR_RETNONNULL;
const char *User_realname(const User *self) CMETHOD;

void Authenticator_init(const char *cookieNs, const char *issUrn,
	uint64_t tokenLifetime, uint64_t tokenRefresh, uint64_t authMaxAge)
    ATTR_NONNULL((1)) ATTR_NONNULL((2));
void Authenticator_setDefaultLimit(PSC_RateLimitOpts *limitOpts);
void Authenticator_registerChecker(
	const char *name, CredentialsChecker *checker)
    ATTR_NONNULL((1)) ATTR_NONNULL((2));
void Authenticator_registerRealm(const char *name, const char *tmplPath,
	PSC_List *checkers, PSC_RateLimitOpts *limitOpts)
    ATTR_NONNULL((1)) ATTR_NONNULL((2)) ATTR_NONNULL((3));
void Authenticator_lockAndClear(void);
void Authenticator_removeRealm(const char *name) ATTR_NONNULL((1));
void Authenticator_unlock(void);
void Authenticator_done(void);

#endif
