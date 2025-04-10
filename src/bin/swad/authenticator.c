#include "authenticator.h"

#include "middleware/session.h"
#include "ratelimit.h"

#include <poser/core.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define SESSKEY "swad_authinfo"

typedef struct AuthInfo
{
    User *user;
    PSC_HashTable *blocks;
    RateLimit *failLimit;
} AuthInfo;

struct Authenticator
{
    PSC_HashTable *authInfos;
    const char *realm;
};

struct User
{
    char *username;
    char *realname;
    const char *checker;
};

struct Realm
{
    const char *name;
    PSC_List *checkers;
    RateLimitOpts *limitOpts;
};

static PSC_HashTable *checkers;
static PSC_HashTable *realms;
static RateLimitOpts *defaultLimitOpts;

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

static void deleteRealm(void *obj)
{
    if (!obj) return;
    Realm *realm = obj;
    RateLimitOpts_destroy(realm->limitOpts);
    PSC_List_destroy(realm->checkers);
    free(realm);
}

static void deleteAuthInfo(void *obj)
{
    if (!obj) return;
    AuthInfo *self = obj;
    RateLimit_destroy(self->failLimit);
    PSC_HashTable_destroy(self->blocks);
    deleteUser(self->user);
    free(self);
}

static void deleteAuthInfos(void *obj)
{
    PSC_HashTable_destroy(obj);
}

static PSC_HashTable *getAuthInfos(Session *session)
{
    PSC_HashTable *authInfos = Session_getProp(session, SESSKEY);
    if (!authInfos)
    {
	authInfos = PSC_HashTable_create(4);
	Session_setProp(session, SESSKEY, authInfos, deleteAuthInfos);
    }
    return authInfos;
}

Authenticator *Authenticator_create(Session *session, const char *realm)
{
    Authenticator *self = PSC_malloc(sizeof *self);
    self->authInfos = getAuthInfos(session);
    self->realm = realm ? realm : DEFAULT_REALM;
    return self;
}

static AuthInfo *getAuthInfo(Authenticator *self, int create)
{
    AuthInfo *authInfo = PSC_HashTable_get(self->authInfos, self->realm);
    if (create && !authInfo)
    {
	authInfo = PSC_malloc(sizeof *authInfo);
	memset(authInfo, 0, sizeof *authInfo);
	PSC_HashTable_set(self->authInfos, self->realm,
		authInfo, deleteAuthInfo);
    }
    return authInfo;
}

const User *Authenticator_user(const Authenticator *self)
{
    pthread_mutex_lock(&authlock);
    AuthInfo *authInfo = getAuthInfo((Authenticator *)self, 0);
    User *user = authInfo ? authInfo->user : 0;
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
    AuthInfo *authInfo = getAuthInfo(self, 0);
    if (!authInfo || authInfo->user) goto done;
    Realm *realm = PSC_HashTable_get(realms, self->realm);
    if (!realm || PSC_List_size(realm->checkers) == 0) goto done;
    j = PSC_List_iterator(realm->checkers);
    for (i = PSC_HashTable_iterator(self->authInfos);
	    PSC_HashTableIterator_moveNext(i); )
    {
	const AuthInfo *otherInfo = PSC_HashTableIterator_current(i);
	if (!otherInfo->user) continue;
	while (PSC_ListIterator_moveNext(j))
	{
	    if (strcmp(otherInfo->user->checker,
			PSC_ListIterator_current(j))) continue;
	    authInfo->user = copyUser(otherInfo->user);
	    goto done;
	}
    }
done:
    PSC_HashTableIterator_destroy(i);
    PSC_ListIterator_destroy(j);
    int ok = authInfo && authInfo->user;
    pthread_mutex_unlock(&realmlock);
    pthread_mutex_unlock(&authlock);
    return ok;
}

static RateLimit *getLimits(Authenticator *self, Realm *realm)
{
    AuthInfo *authInfo = getAuthInfo(self, 1);
    if (!authInfo->failLimit)
    {
	RateLimitOpts *limitOpts = realm->limitOpts;
	if (!limitOpts)
	{
	    if (!defaultLimitOpts)
	    {
		defaultLimitOpts = RateLimitOpts_create(0);
		RateLimitOpts_addLimit(defaultLimitOpts, 15 * 60, 5);
	    }
	    limitOpts = defaultLimitOpts;
	}
	authInfo->failLimit = RateLimit_create(limitOpts);
    }
    return authInfo->failLimit;
}

int Authenticator_login(Authenticator *self, const char *user, const char *pw)
{
    int ok = 0;
    pthread_mutex_lock(&authlock);
    pthread_mutex_lock(&realmlock);
    Realm *realm = PSC_HashTable_get(realms, self->realm);
    if (!realm || !PSC_List_size(realm->checkers)) goto done;
    AuthInfo *authInfo = getAuthInfo(self, 0);
    if (authInfo && authInfo->blocks &&
	    PSC_HashTable_get(authInfo->blocks, user))
    {
	if (RateLimit_check(getLimits(self, realm), user))
	{
	    PSC_HashTable_delete(authInfo->blocks, user);
	}
	else
	{
	    ok = -1;
	    goto done;
	}
    }
    PSC_ListIterator *i = PSC_List_iterator(realm->checkers);
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
		if (!authInfo) authInfo = getAuthInfo(self, 1);
		deleteUser(authInfo->user);
		authInfo->user = createUser(user, realname, checkerName);
		ok = 1;
	    }
	}
    }
    PSC_ListIterator_destroy(i);

    if (!ok)
    {
	if (!RateLimit_check(getLimits(self, realm), user))
	{
	    ok = -1;
	    if (!authInfo) authInfo = getAuthInfo(self, 1);
	    if (!authInfo->blocks) authInfo->blocks = PSC_HashTable_create(4);
	    PSC_HashTable_set(authInfo->blocks, user, (void *)1, 0);
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
    AuthInfo *authInfo = getAuthInfo(self, 0);
    if (authInfo && authInfo->user)
    {
	deleteUser(authInfo->user);
	authInfo->user = 0;
    }
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

Realm *Realm_create(const char *name)
{
    Realm *self = PSC_malloc(sizeof *self);
    self->name = name;
    self->checkers = PSC_List_create();
    self->limitOpts = 0;
    return self;
}

void Realm_addChecker(Realm *self, const char *checker)
{
    PSC_List_append(self->checkers, PSC_copystr(checker), free);
}

void Realm_addLimit(Realm *self, uint16_t seconds, uint16_t limit)
{
    if (!self->limitOpts) self->limitOpts = RateLimitOpts_create(0);
    RateLimitOpts_addLimit(self->limitOpts, seconds, limit);
}

void Authenticator_init(void)
{
    checkers = PSC_HashTable_create(4);
    realms = PSC_HashTable_create(4);
    pthread_mutex_init(&checkerlock, 0);
    pthread_mutex_init(&realmlock, 0);
    pthread_mutex_init(&authlock, 0);
}

void Authenticator_addDefaultLimit(uint16_t seconds, uint16_t limit)
{
    pthread_mutex_lock(&realmlock);
    if (!defaultLimitOpts) defaultLimitOpts = RateLimitOpts_create(0);
    RateLimitOpts_addLimit(defaultLimitOpts, seconds, limit);
    pthread_mutex_unlock(&realmlock);
}

void Authenticator_registerChecker(
	const char *name, CredentialsChecker *checker)
{
    pthread_mutex_lock(&checkerlock);
    PSC_HashTable_set(checkers, name, checker, checker->destroy);
    pthread_mutex_unlock(&checkerlock);
}

void Authenticator_registerRealm(Realm *realm)
{
    pthread_mutex_lock(&realmlock);
    PSC_HashTable_set(realms, realm->name, realm, deleteRealm);
    pthread_mutex_unlock(&realmlock);
}

void Authenticator_done(void)
{
    pthread_mutex_destroy(&authlock);
    pthread_mutex_destroy(&realmlock);
    pthread_mutex_destroy(&checkerlock);
    PSC_HashTable_destroy(realms);
    PSC_HashTable_destroy(checkers);
    RateLimitOpts_destroy(defaultLimitOpts);
    defaultLimitOpts = 0;
}

