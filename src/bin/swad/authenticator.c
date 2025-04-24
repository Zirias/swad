#define _POSIX_C_SOURCE 200112L

#include "authenticator.h"

#include "middleware/session.h"
#include "ratelimit.h"
#include "tmpl.h"

#include <fcntl.h>
#include <poser/core.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SESSKEY "swad_authinfo"

typedef struct AuthInfo
{
    User *user;
    PSC_HashTable *blocks;
    RateLimit *failLimit;
} AuthInfo;

struct Authenticator
{
    Session *session;
    PSC_HashTable *authInfos;
    const char *realmnm;
    const Realm *realm;
    CredentialsChecker *deviate;
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
    uint8_t *t_login;
    uint8_t *t_logout;
    size_t t_login_sz;
    size_t t_logout_sz;
};

static PSC_HashTable *checkers;
static PSC_HashTable *realms;
static RateLimitOpts *defaultLimitOpts;

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
    free(realm->t_logout);
    free(realm->t_login);
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
    self->session = session;
    self->authInfos = getAuthInfos(session);
    self->realmnm = realm ? realm : DEFAULT_REALM;
    self->realm = PSC_HashTable_get(realms, self->realmnm);
    self->deviate = 0;
    return self;
}

static AuthInfo *getAuthInfo(Authenticator *self, int create)
{
    AuthInfo *authInfo = PSC_HashTable_get(self->authInfos, self->realmnm);
    if (create && !authInfo)
    {
	authInfo = PSC_malloc(sizeof *authInfo);
	memset(authInfo, 0, sizeof *authInfo);
	PSC_HashTable_set(self->authInfos, self->realmnm,
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
    return self->realmnm;
}

const uint8_t *Authenticator_loginTmpl(const Authenticator *self, size_t *sz)
{
    if (self->realm && self->realm->t_login)
    {
	*sz = self->realm->t_login_sz;
	return self->realm->t_login;
    }
    *sz = tmpl_login_html_sz;
    return tmpl_login_html;
}

const uint8_t *Authenticator_logoutTmpl(const Authenticator *self, size_t *sz)
{
    if (self->realm && self->realm->t_logout)
    {
	*sz = self->realm->t_logout_sz;
	return self->realm->t_logout;
    }
    *sz = tmpl_logout_html_sz;
    return tmpl_logout_html;
}

Session *Authenticator_session(const Authenticator *self)
{
    return self->session;
}

AuthResult Authenticator_silentLogin(Authenticator *self)
{
    AuthResult result = AR_FAILED;
    if (!self->realm || !PSC_List_size(self->realm->checkers)) return result;
    pthread_mutex_lock(&authlock);
    PSC_HashTableIterator *i = 0;
    PSC_ListIterator *j = 0;
    AuthInfo *authInfo = getAuthInfo(self, 0);
    if (authInfo && authInfo->user) goto done;
    j = PSC_List_iterator(self->realm->checkers);
    for (i = PSC_HashTable_iterator(self->authInfos);
	    PSC_HashTableIterator_moveNext(i); )
    {
	const AuthInfo *otherInfo = PSC_HashTableIterator_current(i);
	if (!otherInfo->user) continue;
	while (PSC_ListIterator_moveNext(j))
	{
	    if (strcmp(otherInfo->user->checker,
			PSC_ListIterator_current(j))) continue;
	    if (!authInfo) authInfo = getAuthInfo(self, 1);
	    authInfo->user = copyUser(otherInfo->user);
	    goto done;
	}
    }
done:
    PSC_HashTableIterator_destroy(i);
    PSC_ListIterator_destroy(j);
    if (authInfo && authInfo->user) result = AR_OK;
    pthread_mutex_unlock(&authlock);
    return result;
}

static RateLimit *getLimits(Authenticator *self)
{
    AuthInfo *authInfo = getAuthInfo(self, 1);
    if (!authInfo->failLimit)
    {
	RateLimitOpts *limitOpts = self->realm->limitOpts;
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

AuthResult Authenticator_login(Authenticator *self,
	const char *user, const char *pw)
{
    AuthResult result = AR_FAILED;
    if (!self->realm || !PSC_List_size(self->realm->checkers)) return result;
    pthread_mutex_lock(&authlock);
    self->deviate = 0;
    AuthInfo *authInfo = getAuthInfo(self, 0);
    if (authInfo && authInfo->blocks &&
	    PSC_HashTable_get(authInfo->blocks, user))
    {
	if (RateLimit_check(getLimits(self), user))
	{
	    PSC_HashTable_delete(authInfo->blocks, user);
	}
	else
	{
	    result = AR_BLOCKED;
	    goto done;
	}
    }
    PSC_ListIterator *i = PSC_List_iterator(self->realm->checkers);
    while (result == AR_FAILED && PSC_ListIterator_moveNext(i))
    {
	const char *checkerName = PSC_ListIterator_current(i);
	CredentialsChecker *checker = PSC_HashTable_get(checkers, checkerName);
	if (checker)
	{
	    char *realname = 0;
	    result = checker->check(checker, user, pw, self, &realname);
	    if (result == AR_OK || result == AR_DEVIATE)
	    {
		if (!authInfo) authInfo = getAuthInfo(self, 1);
		deleteUser(authInfo->user);
		if (result == AR_OK)
		{
		    authInfo->user = createUser(user, realname, checkerName);
		}
		else
		{
		    self->deviate = checker;
		}
	    }
	}
    }
    PSC_ListIterator_destroy(i);

    if (result == AR_FAILED)
    {
	if (!RateLimit_check(getLimits(self), user))
	{
	    result = AR_BLOCKED;
	    if (!authInfo) authInfo = getAuthInfo(self, 1);
	    if (!authInfo->blocks) authInfo->blocks = PSC_HashTable_create(4);
	    PSC_HashTable_set(authInfo->blocks, user, (void *)1, 0);
	}
    }

done:
    pthread_mutex_unlock(&authlock);

    return result;
}

int Authenticator_deviate(Authenticator *self, HttpContext *context)
{
    if (!self->deviate || !self->deviate->deviate) return -1;
    self->deviate->deviate(self->deviate, self, context);
    return 0;
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

static uint8_t *readTmpl(int fd, size_t *sz)
{
    struct stat st;
    uint8_t *data = 0;
    if (fstat(fd, &st) < 0) goto done;
    *sz = st.st_size;
    data = PSC_malloc(*sz);
    if (read(fd, data, *sz) != (ssize_t)*sz)
    {
	free(data);
	data = 0;
    }
done:
    close(fd);
    return data;
}

static void initTmpl(const char *tmplPath, const char *nm, const char *realm,
	uint8_t **data, size_t *datasz)
{
    char buf[1024];
    snprintf(buf, sizeof buf, "%s/%s.%s.html", tmplPath, nm, realm);
    int fd = open(buf, O_RDONLY);
    if (fd < 0 || !(*data = readTmpl(fd, datasz)))
    {
	snprintf(buf, sizeof buf, "%s/%s.html", tmplPath, nm);
	fd = open(buf, O_RDONLY);
	if (fd < 0 || !(*data = readTmpl(fd, datasz)))
	{
	    *data = 0;
	    *datasz = 0;
	}
    }
}

Realm *Realm_create(const char *name, const char *tmplPath)
{
    Realm *self = PSC_malloc(sizeof *self);
    self->name = name;
    self->checkers = PSC_List_create();
    self->limitOpts = 0;
    initTmpl(tmplPath, "login", name, &self->t_login, &self->t_login_sz);
    initTmpl(tmplPath, "logout", name, &self->t_logout, &self->t_logout_sz);
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
    pthread_mutex_init(&authlock, 0);
}

void Authenticator_addDefaultLimit(uint16_t seconds, uint16_t limit)
{
    if (!defaultLimitOpts) defaultLimitOpts = RateLimitOpts_create(0);
    RateLimitOpts_addLimit(defaultLimitOpts, seconds, limit);
}

void Authenticator_registerChecker(
	const char *name, CredentialsChecker *checker)
{
    PSC_HashTable_set(checkers, name, checker, checker->destroy);
}

void Authenticator_registerRealm(Realm *realm)
{
    PSC_HashTable_set(realms, realm->name, realm, deleteRealm);
}

void Authenticator_done(void)
{
    pthread_mutex_destroy(&authlock);
    PSC_HashTable_destroy(realms);
    PSC_HashTable_destroy(checkers);
    RateLimitOpts_destroy(defaultLimitOpts);
    defaultLimitOpts = 0;
}

