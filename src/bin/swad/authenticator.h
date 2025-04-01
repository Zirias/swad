#ifndef SWAD_AUTHENTICATOR_H
#define SWAD_AUTHENTICATOR_H

#include <poser/decl.h>

#define DEFAULT_REALM "SWAD"

C_CLASS_DECL(Authenticator);
C_CLASS_DECL(CredentialsChecker);
C_CLASS_DECL(User);

C_CLASS_DECL(Session);

struct CredentialsChecker
{
    int (*check)(void *self, const char *user, const char *pw, char **realname)
	CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3)) ATTR_NONNULL((4));
    void (*destroy)(void *self);
};

Authenticator *Authenticator_create(Session *session, const char *realm)
    ATTR_RETNONNULL;
const User *Authenticator_user(const Authenticator *self) CMETHOD;
const char *Authenticator_realm(const Authenticator *self) CMETHOD;
int Authenticator_silentLogin(Authenticator *self) CMETHOD;
int Authenticator_login(Authenticator *self, const char *user, const char *pw)
    CMETHOD ATTR_NONNULL((2)) ATTR_NONNULL((3));
void Authenticator_logout(Authenticator *self) CMETHOD;
void Authenticator_destroy(Authenticator *self);

const char *User_username(const User *user) CMETHOD ATTR_RETNONNULL;
const char *User_realname(const User *user) CMETHOD;

void Authenticator_init(void);
void Authenticator_registerChecker(
	const char *name, CredentialsChecker *checker)
    ATTR_NONNULL((1)) ATTR_NONNULL((2));
void Authenticator_configureRealm(
	const char *realm, const char *checker)
    ATTR_NONNULL((1)) ATTR_NONNULL((2));
void Authenticator_done(void);

#endif
