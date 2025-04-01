#include "authenticator.h"

#include "middleware/session.h"

#include <poser/core.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define SESSKEY "swad_authinfo"

struct Authenticator
{
    PSC_HashTable *authinfo;
    const char *realm;
};

struct User
{
    char *username;
    char *realname;
};

static PSC_HashTable *checkers;
static PSC_HashTable *realms;

static pthread_mutex_t checkerlock;
static pthread_mutex_t realmlock;
static pthread_mutex_t authlock;

static User *createUser(const char *username, char *realname)
{
    User *user = PSC_malloc(sizeof *user);
    user->username = PSC_copystr(username);
    user->realname = realname;
    return user;
}

static User *copyUser(const User *other)
{
    User *user = PSC_malloc(sizeof *user);
    user->username = PSC_copystr(other->username);
    user->realname = PSC_copystr(other->realname);
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

static void deleteAuthInfo(void *obj)
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
	Session_setProp(session, SESSKEY, authinfo, deleteAuthInfo);
    }
    return authinfo;
}

Authenticator *Authenticator_create(Session *session, const char *realm)
{
    Authenticator *self = PSC_malloc(sizeof *self);
    self->authinfo = getAuthInfo(session);
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

static int realmMatches(const char *realm, PSC_List *realmConfig)
{
    int matches = 0;
    PSC_List *otherRealmConfig = PSC_HashTable_get(realms, realm);
    if (!otherRealmConfig || PSC_List_size(otherRealmConfig)) return matches;

    PSC_ListIterator *i = PSC_List_iterator(realmConfig);
    while (!matches && PSC_ListIterator_moveNext(i))
    {
	const char *a = PSC_ListIterator_current(i);
	PSC_ListIterator *j = PSC_List_iterator(otherRealmConfig);
	while (!matches && PSC_ListIterator_moveNext(j))
	{
	    const char *b = PSC_ListIterator_current(j);
	    matches = !strcmp(a, b);
	}
	PSC_ListIterator_destroy(j);
    }
    PSC_ListIterator_destroy(i);
    return matches;
}

int Authenticator_silentLogin(Authenticator *self)
{
    PSC_HashTableIterator *i = 0;
    pthread_mutex_lock(&authlock);
    pthread_mutex_lock(&realmlock);
    User *user = PSC_HashTable_get(self->authinfo, self->realm);
    if (user) goto done;
    PSC_List *realmConfig = PSC_HashTable_get(realms, self->realm);
    if (!realmConfig || !PSC_List_size(realmConfig)) goto done;
    for (i = PSC_HashTable_iterator(self->authinfo);
	    PSC_HashTableIterator_moveNext(i); )
    {
	if (realmMatches(PSC_HashTableIterator_key(i), realmConfig))
	{
	    user = copyUser(PSC_HashTableIterator_current(i));
	    PSC_HashTable_set(self->authinfo, self->realm,
		    user, deleteUser);
	    goto done;
	}
    }
done:
    PSC_HashTableIterator_destroy(i);
    pthread_mutex_unlock(&realmlock);
    pthread_mutex_unlock(&authlock);
    return user ? 1 : 0;
}

int Authenticator_login(Authenticator *self, const char *user, const char *pw)
{
    int ok = 0;
    pthread_mutex_lock(&authlock);
    pthread_mutex_lock(&realmlock);
    PSC_List *realmConfig = PSC_HashTable_get(realms, self->realm);
    if (!realmConfig || !PSC_List_size(realmConfig)) goto done;
    PSC_ListIterator *i = PSC_List_iterator(realmConfig);
    while (!ok && PSC_ListIterator_moveNext(i))
    {
	pthread_mutex_lock(&checkerlock);
	CredentialsChecker *checker = PSC_HashTable_get(
		checkers, PSC_ListIterator_current(i));
	pthread_mutex_unlock(&checkerlock);
	if (checker)
	{
	    char *realname = 0;
	    if (checker->check(checker, user, pw, &realname))
	    {
		PSC_HashTable_set(self->authinfo, self->realm,
			createUser(user, realname), deleteUser);
		ok = 1;
	    }
	}
    }
    PSC_ListIterator_destroy(i);

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

