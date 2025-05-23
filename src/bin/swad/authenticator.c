#define _POSIX_C_SOURCE 200809L

#include "authenticator.h"

#include "jwt.h"
#include "middleware/cookies.h"
#include "tmpl.h"

#include <fcntl.h>
#include <poser/core.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define COOKIE_NS "swad."
#define ISS_NS "urn:fdc:sekrit.de:2025:swad:"
#define TOKEN_LIFETIME 86400U

typedef struct Realm
{
    const char *name;
    PSC_List *checkers;
    PSC_RateLimitOpts *limitOpts;
    PSC_Dictionary *blocks;
    PSC_RateLimit *failLimit;
    uint8_t *t_login;
    uint8_t *t_logout;
    size_t t_login_sz;
    size_t t_logout_sz;
    int64_t version;
} Realm;

struct Authenticator
{
    HttpContext *context;
    Cookies *cookies;
    const char *realmnm;
    Realm *realm;
    char *cookienm;
    Jwt *token;
    User *user;
    CredentialsChecker *deviate;
};

struct User
{
    const char *username;
    const char *realname;
};

static PSC_HashTable *checkers;
static PSC_HashTable *realms;
static PSC_RateLimitOpts *defaultLimitOpts;

static pthread_mutex_t authlock;

static void deleteRealm(void *obj)
{
    if (!obj) return;
    Realm *realm = obj;
    free(realm->t_logout);
    free(realm->t_login);
    PSC_Dictionary_destroy(realm->blocks);
    PSC_RateLimit_destroy(realm->failLimit);
    PSC_RateLimitOpts_destroy(realm->limitOpts);
    PSC_List_destroy(realm->checkers);
    free(realm);
}

static char *createCookieName(const char *realm)
{
    size_t realmlen = strlen(realm);
    char *nm = PSC_malloc(realmlen + sizeof COOKIE_NS);
    memcpy(nm, COOKIE_NS, sizeof COOKIE_NS - 1);
    memcpy(nm + sizeof COOKIE_NS - 1, realm, realmlen + 1);
    return nm;
}

static char *createIssuer(const char *checker)
{
    size_t checkerlen = strlen(checker);
    char *nm = PSC_malloc(checkerlen + sizeof ISS_NS);
    memcpy(nm, ISS_NS, sizeof ISS_NS - 1);
    memcpy(nm + sizeof ISS_NS - 1, checker, checkerlen + 1);
    return nm;
}

static int verifyToken(Jwt *token, const Realm *realm)
{
    if (!Jwt_valid(token)) return 0;
    if (!Jwt_sub(token)) return 0;
    const char *iss = Jwt_iss(token);
    if (!iss) return 0;
    if (strncmp(iss, ISS_NS, sizeof ISS_NS - 1)) return 0;
    int64_t exp = Jwt_exp(token);
    if (time(0) >= exp) return 0;
    const PSC_Json *json = Jwt_json(token);
    const PSC_Json *authtime = PSC_Json_property(json, "auth_time", 9);
    if (!authtime) return 0;
    if (PSC_Json_integer(authtime) < realm->version) return 0;
    return 1;
}

static Jwt *getVerifiedToken(Cookies *cookies, const Realm *realm,
	const char *cookienm)
{
    if (!realm) return 0;
    const char *tokenstr = Cookies_getCookie(cookies, cookienm);
    if (!tokenstr) return 0;
    Jwt *token = 0;
    if (!(token = Jwt_parse(tokenstr)) || !verifyToken(token, realm))
    {
	Cookies_deleteCookie(cookies, cookienm);
	Jwt_destroy(token);
	token = 0;
    }
    return token;
}

static User *createFromToken(Jwt *token)
{
    if (!token) return 0;
    User *user = PSC_malloc(sizeof *user);
    user->username = Jwt_sub(token);
    const PSC_Json *json = Jwt_json(token);
    const PSC_Json *nameclaim = PSC_Json_property(json, "name", 4);
    user->realname = nameclaim ? PSC_Json_string(nameclaim) : 0;
    return user;
}

Authenticator *Authenticator_create(HttpContext *context, const char *realm)
{
    Authenticator *self = PSC_malloc(sizeof *self);
    self->context = context;
    self->realmnm = realm ? realm : DEFAULT_REALM;
    pthread_mutex_lock(&authlock);
    self->realm = PSC_HashTable_get(realms, self->realmnm);
    pthread_mutex_unlock(&authlock);
    self->cookies = Cookies_get(context);
    self->cookienm = createCookieName(realm);
    self->token = getVerifiedToken(self->cookies, self->realm, self->cookienm);
    self->user = createFromToken(self->token);
    self->deviate = 0;
    return self;
}

const User *Authenticator_user(const Authenticator *self)
{
    return self->user;
}

const char *Authenticator_realm(const Authenticator *self)
{
    return self->realmnm;
}

const uint8_t *Authenticator_loginTmpl(const Authenticator *self, size_t *sz)
{
    const uint8_t *tmpl = tmpl_login_html;
    pthread_mutex_lock(&authlock);
    if (self->realm && self->realm->t_login)
    {
	*sz = self->realm->t_login_sz;
	tmpl = self->realm->t_login;
    }
    else *sz = tmpl_login_html_sz;
    pthread_mutex_unlock(&authlock);
    return tmpl;
}

const uint8_t *Authenticator_logoutTmpl(const Authenticator *self, size_t *sz)
{
    const uint8_t *tmpl = tmpl_logout_html;
    pthread_mutex_lock(&authlock);
    if (self->realm && self->realm->t_logout)
    {
	*sz = self->realm->t_logout_sz;
	tmpl = self->realm->t_logout;
    }
    else *sz = tmpl_logout_html_sz;
    pthread_mutex_unlock(&authlock);
    return tmpl;
}

HttpContext *Authenticator_context(const Authenticator *self)
{
    return self->context;
}

AuthResult Authenticator_silentLogin(Authenticator *self)
{
    if (self->user) return AR_OK;
    AuthResult result = AR_FAILED;
    if (!self->realm || !PSC_List_size(self->realm->checkers)) return result;
    pthread_mutex_lock(&authlock);
    PSC_HashTableIterator *i = 0;
    PSC_ListIterator *j = 0;
    j = PSC_List_iterator(self->realm->checkers);
    for (i = PSC_HashTable_iterator(realms);
	    PSC_HashTableIterator_moveNext(i); )
    {
	const Realm *otherRealm = PSC_HashTableIterator_current(i);
	if (otherRealm == self->realm) continue;
	Jwt *otherToken = getVerifiedToken(self->cookies,
		otherRealm, self->cookienm);
	if (!otherToken) continue;
	const char *checker = Jwt_iss(otherToken) + (sizeof ISS_NS - 1);
	while (PSC_ListIterator_moveNext(j))
	{
	    if (strcmp(checker, PSC_ListIterator_current(j))) continue;
	    self->token = Jwt_create(Jwt_iss(otherToken),
		    Jwt_sub(otherToken), TOKEN_LIFETIME);
	    time_t now = time(0);
	    PSC_Json *authtime = PSC_Json_createInteger(now);
	    Jwt_set(self->token, "auth_time", authtime);
	    const PSC_Json *json = Jwt_json(otherToken);
	    const PSC_Json *otherName = PSC_Json_property(json, "name", 4);
	    if (otherName)
	    {
		PSC_Json *name = PSC_Json_createString(
			PSC_Json_string(otherName), 0);
		Jwt_set(self->token, "name", name);
	    }
	    char *tokenstr = Jwt_issue(self->token, now, JSA_HS256);
	    Cookies_setCookie(self->cookies, self->cookienm,
		    tokenstr, now + TOKEN_LIFETIME);
	    self->user = createFromToken(self->token);
	    result = AR_OK;
	    break;
	}
	Jwt_destroy(otherToken);
    }
    PSC_HashTableIterator_destroy(i);
    PSC_ListIterator_destroy(j);
    pthread_mutex_unlock(&authlock);
    return result;
}

static PSC_RateLimit *getLimits(Authenticator *self)
{
    if (!self->realm->failLimit)
    {
	PSC_RateLimitOpts *limitOpts = self->realm->limitOpts;
	if (!limitOpts)
	{
	    if (!defaultLimitOpts)
	    {
		defaultLimitOpts = PSC_RateLimitOpts_create(0);
		PSC_RateLimitOpts_addLimit(defaultLimitOpts, 15 * 60, 5);
	    }
	    limitOpts = defaultLimitOpts;
	}
	self->realm->failLimit = PSC_RateLimit_create(limitOpts);
    }
    return self->realm->failLimit;
}

AuthResult Authenticator_login(Authenticator *self,
	const char *user, const char *pw)
{
    AuthResult result = AR_FAILED;
    if (!self->realm || !PSC_List_size(self->realm->checkers)) return result;
    size_t userLen = strlen(user);
    size_t realmLen = strlen(self->realmnm);
    size_t rateKeyLen = userLen + realmLen + 1;
    char *rateKey = PSC_malloc(rateKeyLen);
    memcpy(rateKey, user, userLen);
    rateKey[userLen] = 0;
    memcpy(rateKey+userLen+1, self->realmnm, realmLen);
    pthread_mutex_lock(&authlock);
    self->deviate = 0;
    if (self->realm->blocks &&
	    PSC_Dictionary_get(self->realm->blocks, rateKey, rateKeyLen))
    {
	if (PSC_RateLimit_check(getLimits(self), rateKey, rateKeyLen))
	{
	    PSC_Dictionary_set(self->realm->blocks, rateKey, rateKeyLen, 0, 0);
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
	    if (result == AR_OK)
	    {
		free(self->user);
		Jwt_destroy(self->token);
		char *iss = createIssuer(checkerName);
		self->token = Jwt_create(iss, user, TOKEN_LIFETIME);
		time_t now = time(0);
		PSC_Json *authtime = PSC_Json_createInteger(now);
		Jwt_set(self->token, "auth_time", authtime);
		if (realname)
		{
		    PSC_Json *name = PSC_Json_createString(realname, 0);
		    Jwt_set(self->token, "name", name);
		}
		char *tokenstr = Jwt_issue(self->token, now, JSA_HS256);
		Cookies_setCookie(self->cookies, self->cookienm,
			tokenstr, now + TOKEN_LIFETIME);
		self->user = createFromToken(self->token);
	    }
	    else if (result == AR_DEVIATE)
	    {
		self->deviate = checker;
	    }
	}
    }
    PSC_ListIterator_destroy(i);

    if (result == AR_FAILED)
    {
	if (!PSC_RateLimit_check(getLimits(self), rateKey, rateKeyLen))
	{
	    result = AR_BLOCKED;
	    if (!self->realm->blocks)
	    {
		self->realm->blocks = PSC_Dictionary_create(PSC_DICT_NODELETE);
	    }
	    PSC_Dictionary_set(self->realm->blocks, rateKey, rateKeyLen,
		    (void *)1, 0);
	}
    }

done:
    pthread_mutex_unlock(&authlock);
    free(rateKey);

    return result;
}

int Authenticator_deviate(Authenticator *self)
{
    if (!self->deviate || !self->deviate->deviate) return -1;
    self->deviate->deviate(self->deviate, self);
    return 0;
}

void Authenticator_logout(Authenticator *self)
{
    if (self->token)
    {
	free(self->user);
	self->user = 0;
	Jwt_destroy(self->token);
	self->token = 0;
	Cookies_deleteCookie(self->cookies, self->cookienm);
    }
}

void Authenticator_destroy(Authenticator *self)
{
    if (!self) return;
    free(self->user);
    Jwt_destroy(self->token);
    free(self->cookienm);
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
    int fd = open(buf, O_RDONLY|O_CLOEXEC);
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

void Authenticator_init(void)
{
    checkers = PSC_HashTable_create(4);
    realms = PSC_HashTable_create(4);
    pthread_mutex_init(&authlock, 0);
    Jwt_createHmacKey();
}

void Authenticator_setDefaultLimit(PSC_RateLimitOpts *limitOpts)
{
    pthread_mutex_lock(&authlock);
    if ((!defaultLimitOpts && !limitOpts) ||
	    (defaultLimitOpts && limitOpts &&
	     PSC_RateLimitOpts_equals(defaultLimitOpts, limitOpts)))
    {
	PSC_RateLimitOpts_destroy(limitOpts);
    }
    else
    {
	PSC_RateLimitOpts_destroy(defaultLimitOpts);
	defaultLimitOpts = limitOpts;
	PSC_HashTableIterator *i = PSC_HashTable_iterator(realms);
	while (PSC_HashTableIterator_moveNext(i))
	{
	    Realm *r = PSC_HashTableIterator_current(i);
	    if (!r->limitOpts)
	    {
		PSC_RateLimit_destroy(r->failLimit);
		r->failLimit = 0;
		PSC_Dictionary_destroy(r->blocks);
		r->blocks = 0;
	    }
	}
	PSC_HashTableIterator_destroy(i);
    }
    pthread_mutex_unlock(&authlock);
}

void Authenticator_registerChecker(
	const char *name, CredentialsChecker *checker)
{
    PSC_HashTable_set(checkers, name, checker, checker->destroy);
}

void Authenticator_registerRealm(const char *name, const char *tmplPath,
	PSC_List *checkerNames, PSC_RateLimitOpts *limitOpts)
{
    pthread_mutex_lock(&authlock);
    Realm *realm = PSC_HashTable_get(realms, name);
    if (realm)
    {
	free(realm->t_login);
	free(realm->t_logout);
	PSC_ListIterator *oc = PSC_List_iterator(realm->checkers);
	PSC_ListIterator *nc = PSC_List_iterator(checkerNames);
	int ok = 1;
	while (ok)
	{
	    int omn = PSC_ListIterator_moveNext(oc);
	    int nmn = PSC_ListIterator_moveNext(nc);
	    if (!omn && !nmn) break;
	    if (!omn || !nmn) ok = 0;
	    else if (strcmp(PSC_ListIterator_current(oc),
			PSC_ListIterator_current(nc))) ok = 0;
	}
	PSC_ListIterator_destroy(nc);
	PSC_ListIterator_destroy(oc);
	if (ok) PSC_List_destroy(checkerNames);
	else
	{
	    PSC_List_destroy(realm->checkers);
	    realm->checkers = checkerNames;
	    realm->version = time(0);
	}
	if ((!realm->limitOpts && !limitOpts) ||
		(realm->limitOpts && limitOpts &&
		 PSC_RateLimitOpts_equals(realm->limitOpts, limitOpts)))
	{
	    PSC_RateLimitOpts_destroy(limitOpts);
	}
	else
	{
	    PSC_RateLimit_destroy(realm->failLimit);
	    realm->failLimit = 0;
	    PSC_Dictionary_destroy(realm->blocks);
	    realm->blocks = 0;
	    PSC_RateLimitOpts_destroy(realm->limitOpts);
	    realm->limitOpts = limitOpts;
	}
    }
    else
    {
	realm = PSC_malloc(sizeof *realm);
	realm->name = name;
	realm->checkers = checkerNames;
	realm->limitOpts = limitOpts;
	realm->failLimit = 0;
	realm->blocks = 0;
	realm->version = time(0);
	PSC_HashTable_set(realms, realm->name, realm, deleteRealm);
    }
    initTmpl(tmplPath, "login", name, &realm->t_login, &realm->t_login_sz);
    initTmpl(tmplPath, "logout", name, &realm->t_logout, &realm->t_logout_sz);
    pthread_mutex_unlock(&authlock);
}

void Authenticator_lockAndClear(void)
{
    pthread_mutex_lock(&authlock);
    PSC_HashTable_destroy(checkers);
    checkers = PSC_HashTable_create(4);
}

void Authenticator_removeRealm(const char *name)
{
    PSC_HashTable_delete(realms, name);
}

void Authenticator_unlock(void)
{
    pthread_mutex_unlock(&authlock);
}

void Authenticator_done(void)
{
    pthread_mutex_destroy(&authlock);
    PSC_HashTable_destroy(realms);
    PSC_HashTable_destroy(checkers);
    PSC_RateLimitOpts_destroy(defaultLimitOpts);
    defaultLimitOpts = 0;
}

