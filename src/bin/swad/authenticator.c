#include "authenticator.h"

#include "middleware/session.h"
#include "ratelimit.h"

#include <poser/core.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define SESSKEY "swad_authinfo"
#define SESSBLOCKKEY "swad_auth_blocked"
#define SESSLIMITKEY "swad_auth_limits"

struct Authenticator
{
    Session *session;
    PSC_HashTable *authinfo;
    PSC_HashTable *blockinfo;
    const char *realm;
};

struct User
{
    char *username;
    char *realname;
    const char *checker;
};

static PSC_HashTable *checkers;
static PSC_HashTable *realms;

static pthread_mutex_t checkerlock;
static pthread_mutex_t realmlock;
static pthread_mutex_t authlock;

static User *createUser(const char *username, char *realname,
	const char *checker)
{
    User *user = PSC_malloc(sizeof *user);
    user->username = PSC_copystr(username);
    user->realname = realname;
    user->checker = checker;
    return user;
}

static User *copyUser(const User *other)
{
    User *user = PSC_malloc(sizeof *user);
    user->username = PSC_copystr(other->username);
    user->realname = PSC_copystr(other->realname);
    user->checker = other->checker;
    return user;
}

static void deleteUser(void *obj)
{
    if (!obj) return;
    User *user = obj;
    free(user->realname);
    free(user->username);
    free(user);
}

static void deleteHT(void *obj)
{
    PSC_HashTable_destroy(obj);
}

static void deleteRealmConfig(void *obj)
{
    PSC_List_destroy(obj);
}

static PSC_HashTable *getAuthInfo(Session *session)
{
    PSC_HashTable *authinfo = Session_getProp(session, SESSKEY);
    if (!authinfo)
    {
	authinfo = PSC_HashTable_create(4);
	Session_setProp(session, SESSKEY, authinfo, deleteHT);
    }
    return authinfo;
}

static PSC_HashTable *getBlockInfo(Session *session)
{
    PSC_HashTable *blockinfo = Session_getProp(session, SESSBLOCKKEY);
    if (!blockinfo)
    {
	blockinfo = PSC_HashTable_create(4);
	Session_setProp(session, SESSBLOCKKEY, blockinfo, deleteHT);
    }
    return blockinfo;
}

Authenticator *Authenticator_create(Session *session, const char *realm)
{
    Authenticator *self = PSC_malloc(sizeof *self);
    self->session = session;
    self->authinfo = getAuthInfo(session);
    self->blockinfo = getBlockInfo(session);
    self->realm = realm ? realm : DEFAULT_REALM;
    return self;
}

const User *Authenticator_user(const Authenticator *self)
{
    pthread_mutex_lock(&authlock);
    User *user = PSC_HashTable_get(self->authinfo, self->realm);
    pthread_mutex_unlock(&authlock);
    return user;
}

const char *Authenticator_realm(const Authenticator *self)
{
    return self->realm;
}

int Authenticator_silentLogin(Authenticator *self)
{
    pthread_mutex_lock(&authlock);
    pthread_mutex_lock(&realmlock);
    PSC_HashTableIterator *i = 0;
    PSC_ListIterator *j = 0;
    User *user = PSC_HashTable_get(self->authinfo, self->realm);
    if (user) goto done;
    PSC_List *realmConfig = PSC_HashTable_get(realms, self->realm);
    if (!realmConfig || PSC_List_size(realmConfig) == 0) goto done;
    j = PSC_List_iterator(realmConfig);
    for (i = PSC_HashTable_iterator(self->authinfo);
	    PSC_HashTableIterator_moveNext(i); )
    {
	const User *otherUser = PSC_HashTableIterator_current(i);
	while (PSC_ListIterator_moveNext(j))
	{
	    if (strcmp(otherUser->checker,
			PSC_ListIterator_current(j))) continue;
	    user = copyUser(otherUser);
	    PSC_HashTable_set(self->authinfo, self->realm, user, deleteUser);
	    goto done;
	}
    }
done:
    PSC_HashTableIterator_destroy(i);
    PSC_ListIterator_destroy(j);
    pthread_mutex_unlock(&realmlock);
    pthread_mutex_unlock(&authlock);
    return user ? 1 : 0;
}

static void deleteLimit(void *obj)
{
    RateLimit_destroy(obj);
}

static RateLimit *getLimits(Session *session)
{
    RateLimit *authLimits = Session_getProp(session, SESSLIMITKEY);
    if (!authLimits)
    {
	RateLimitOpts *limitOpts = RateLimitOpts_create(1);
	RateLimitOpts_addLimit(limitOpts, 15 * 60, 5);
	authLimits = RateLimit_create(limitOpts);
	RateLimitOpts_destroy(limitOpts);
	Session_setProp(session, SESSLIMITKEY,
		authLimits, deleteLimit);
    }
    return authLimits;
}

int Authenticator_login(Authenticator *self, const char *user, const char *pw)
{
    int ok = 0;
    pthread_mutex_lock(&authlock);
    pthread_mutex_lock(&realmlock);
    if (PSC_HashTable_get(self->blockinfo, user))
    {
	if (RateLimit_check(getLimits(self->session), user))
	{
	    PSC_HashTable_delete(self->blockinfo, user);
	}
	else
	{
	    ok = -1;
	    goto done;
	}
    }
    PSC_List *realmConfig = PSC_HashTable_get(realms, self->realm);
    if (!realmConfig || !PSC_List_size(realmConfig)) goto done;
    PSC_ListIterator *i = PSC_List_iterator(realmConfig);
    while (!ok && PSC_ListIterator_moveNext(i))
    {
	const char *checkerName = PSC_ListIterator_current(i);
	pthread_mutex_lock(&checkerlock);
	CredentialsChecker *checker = PSC_HashTable_get(checkers, checkerName);
	pthread_mutex_unlock(&checkerlock);
	if (checker)
	{
	    char *realname = 0;
	    if (checker->check(checker, user, pw, &realname))
	    {
		PSC_HashTable_set(self->authinfo, self->realm,
			createUser(user, realname, checkerName), deleteUser);
		ok = 1;
	    }
	}
    }
    PSC_ListIterator_destroy(i);

    if (!ok)
    {
	if (!RateLimit_check(getLimits(self->session), user))
	{
	    ok = -1;
	    PSC_HashTable_set(self->blockinfo, user, (void *)1, 0);
	}
    }

done:
    pthread_mutex_unlock(&realmlock);
    pthread_mutex_unlock(&authlock);

    return ok;
}

void Authenticator_logout(Authenticator *self)
{
    pthread_mutex_lock(&authlock);
    PSC_HashTable_delete(self->authinfo, self->realm);
    pthread_mutex_unlock(&authlock);
}

void Authenticator_destroy(Authenticator *self)
{
    free(self);
}

const char *User_username(const User *self)
{
    return self->username;
}

const char *User_realname(const User *self)
{
    return self->realname;
}

void Authenticator_init(void)
{
    checkers = PSC_HashTable_create(4);
    realms = PSC_HashTable_create(4);
    pthread_mutex_init(&checkerlock, 0);
    pthread_mutex_init(&realmlock, 0);
    pthread_mutex_init(&authlock, 0);
}

void Authenticator_registerChecker(
	const char *name, CredentialsChecker *checker)
{
    pthread_mutex_lock(&checkerlock);
    PSC_HashTable_set(checkers, name, checker, checker->destroy);
    pthread_mutex_unlock(&checkerlock);
}

void Authenticator_configureRealm(const char *realm, const char *checker)
{
    pthread_mutex_lock(&realmlock);
    PSC_List *realmConfig = PSC_HashTable_get(realms, realm);
    if (!realmConfig)
    {
	realmConfig = PSC_List_create();
	PSC_HashTable_set(realms, realm, realmConfig, deleteRealmConfig);
    }
    PSC_List_append(realmConfig, PSC_copystr(checker), free);
    pthread_mutex_unlock(&realmlock);
}

void Authenticator_done(void)
{
    pthread_mutex_destroy(&authlock);
    pthread_mutex_destroy(&realmlock);
    pthread_mutex_destroy(&checkerlock);
    PSC_HashTable_destroy(realms);
    PSC_HashTable_destroy(checkers);
}

