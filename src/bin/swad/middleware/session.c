#include "session.h"

#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httpmethod.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../http/httpstatus.h"
#include "../proxylist.h"
#include "../random.h"
#include "../ratelimit.h"
#include "../util.h"
#include "cookies.h"

#include <poser/core.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PROPNAME "_SESSION"
#define COOKIENAME "PSW_SID"
#define MAXAGE 12*3600
#define MAXIDLE 3600
#define CLEANINTERVAL 900

#define SPHT_BITS 4
#define SPHT_SIZE HT_SIZE(SPHT_BITS)
#define SHT_BITS 8
#define SHT_SIZE HT_SIZE(SHT_BITS)

typedef struct SessionProp SessionProp;
struct SessionProp
{
    const char *name;
    void *value;
    SessionProp *next;
    ObjDeleter deleter;
};

struct Session
{
    SessionProp *buckets[SPHT_SIZE];
    char *id;
    char *referrer;
    Session *next;
    pthread_mutex_t lock;
    time_t ctime;
    time_t atime;
};

#define sessionExpired(s, n) ((n) - (s).atime > MAXIDLE \
	|| (n) - (s).ctime > MAXAGE)

static Session *buckets[SHT_SIZE];
static RateLimit *createLimit;
static pthread_mutex_t bucklocks[SHT_SIZE];
static time_t cleantime;
static pthread_mutex_t cleanlock;

static void clean(time_t now);
static Session *createSession(time_t now) ATTR_RETNONNULL;
static void deleteSession(Session *self);
static SessionProp *findProp(Session *self, const char *key, uint8_t *hashval)
    CMETHOD ATTR_NONNULL((2)) ATTR_ACCESS((write_only, 3));
static Session *findSession(const char *id, time_t now, uint8_t *hashval)
    ATTR_NONNULL((1)) ATTR_ACCESS((write_only, 3));
static SessionProp *insertOrUpdate(Session *self, const char *key)
    CMETHOD ATTR_NONNULL((2)) ATTR_RETNONNULL;

static void deleteSession(Session *self)
{
    if (!self) return;
    for (uint8_t p = 0; p < SPHT_SIZE; ++p)
    {
	SessionProp *prop = self->buckets[p];
	SessionProp *next;
	while (prop)
	{
	    next = prop->next;
	    if (prop->deleter) prop->deleter(prop->value);
	    free(prop);
	    prop = next;
	}
    }
    pthread_mutex_destroy(&self->lock);
    free(self->referrer);
    free(self->id);
    free(self);
}

static Session *findSession(const char *id, time_t now, uint8_t *hashval)
{
    uint8_t h = hash(id, SHT_BITS);
    if (hashval) *hashval = h;
    pthread_mutex_lock(&bucklocks[h]);
    Session *session = buckets[h];
    Session *parent = 0;
    while (session)
    {
	if (!strcmp(session->id, id))
	{
	    if (sessionExpired(*session, now))
	    {
		if (parent) parent->next = session->next;
		else buckets[h] = session->next;
		deleteSession(session);
		session = 0;
	    }
	    break;
	}
	parent = session;
	session = session->next;
    }
    pthread_mutex_unlock(&bucklocks[h]);
    return session;
}

static Session *createSession(time_t now)
{
    char *id = 0;
    uint8_t h;
    do
    {
	free(id);
	id = createRndStr(32);
    } while (findSession(id, now, &h));
    Session *parent = buckets[h];
    while (parent && parent->next) parent = parent->next;
    Session *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    self->id = id;
    pthread_mutex_init(&self->lock, 0);
    self->ctime = now;
    self->atime = now;
    if (parent) parent->next = self;
    else buckets[h] = self;
    return self;
}

static SessionProp *findProp(Session *self, const char *key, uint8_t *hashval)
{
    uint8_t h = hash(key, SPHT_BITS);
    if (hashval) *hashval = h;
    SessionProp *prop = self->buckets[h];
    while (prop)
    {
	if (!strcmp(prop->name, key)) break;
	prop = prop->next;
    }
    return prop;
}

static SessionProp *insertOrUpdate(Session *self, const char *key)
{
    uint8_t hashval;
    SessionProp *prop = findProp(self, key, &hashval);
    if (!prop)
    {
	prop = PSC_malloc(sizeof *prop);
	prop->name = key;
	prop->value = 0;
	prop->next = 0;
	prop->deleter = 0;
	SessionProp *parent = self->buckets[hashval];
	if (parent)
	{
	    while (parent->next) parent = parent->next;
	    parent->next = prop;
	}
	else self->buckets[hashval] = prop;
    }
    if (prop->deleter) prop->deleter(prop->value);
    return prop;
}

static void clean(time_t now)
{
    pthread_mutex_lock(&cleanlock);
    if (now - cleantime < CLEANINTERVAL)
    {
	pthread_mutex_unlock(&cleanlock);
	return;
    }
    cleantime = now;
    pthread_mutex_unlock(&cleanlock);
    for (unsigned h = 0; h < SHT_SIZE; ++h)
    {
	pthread_mutex_lock(&bucklocks[h]);
	Session *session = buckets[h];
	Session *parent = 0;
	while (session)
	{
	    if (sessionExpired(*session, now))
	    {
		Session *tmp = session->next;
		if (parent) parent->next = session->next;
		else buckets[h] = session->next;
		deleteSession(session);
		session = tmp;
	    }
	    else
	    {
		parent = session;
		session = session->next;
	    }
	}
	pthread_mutex_unlock(&bucklocks[h]);
    }
}

Session *Session_get(const HttpContext *context)
{
    return HttpContext_get(context, PROPNAME);
}

const char *Session_id(const Session *self)
{
    return self->id;
}

const char *Session_referrer(const Session *self)
{
    return self->referrer;
}

void *Session_getProp(Session *self, const char *name)
{
    pthread_mutex_lock(&self->lock);
    SessionProp *prop = findProp(self, name, 0);
    pthread_mutex_unlock(&self->lock);
    return prop ? prop->value : 0;
}

void Session_setProp(Session *self, const char *name,
	void *obj, ObjDeleter deleter)
{
    pthread_mutex_lock(&self->lock);
    SessionProp *prop = insertOrUpdate(self, name);
    prop->value = obj;
    prop->deleter = deleter;
    pthread_mutex_unlock(&self->lock);
}

void MW_Session_init(void)
{
    pthread_mutex_init(&cleanlock, 0);
    for (unsigned i = 0; i < SHT_SIZE; ++i)
    {
	pthread_mutex_init(&bucklocks[i], 0);
    }
    cleantime = time(0);
    RateLimitOpts *opts = RateLimitOpts_create(1);
    RateLimitOpts_addLimit(opts, 5, 2);
    RateLimitOpts_addLimit(opts, 60, 5);
    RateLimitOpts_addLimit(opts, 3600, 15);
    createLimit = RateLimit_create(opts);
    RateLimitOpts_destroy(opts);
}

void MW_Session(HttpContext *context)
{
    Session *self = 0;
    Cookies *cookies = Cookies_get(context);
    if (!cookies)
    {
	PSC_Log_msg(PSC_L_ERROR,
		"Session middleware depends on Cookies middleware!");
	goto done;
    }
    time_t now = time(0);
    clean(now);
    const char *sid = Cookies_getCookie(cookies, COOKIENAME);
    if (sid) self = findSession(sid, now, 0);
    if (self)
    {
	self->atime = now;
    }
    else
    {
	const PSC_List *remotes = ProxyList_get(context);
	size_t idx = 0;
	if (PSC_List_size(remotes) > 2) idx = PSC_List_size(remotes) -2;
	RemoteEntry *r = PSC_List_at(remotes, idx);
	const char *id = RemoteEntry_addr(r);
	if (!RateLimit_check(createLimit, id))
	{
	    HttpContext_setResponse(context,
		    HttpResponse_createError(HTTP_TOOMANYREQUESTS, 0));
	    return;
	}
	self = createSession(now);
	Cookies_setCookie(cookies, COOKIENAME, self->id);
    }
    HttpContext_set(context, PROPNAME, self, 0);

done:
    HttpContext_callNext(context);
    if (!self) return;
    HttpRequest *req = HttpContext_request(context);
    if (HttpRequest_method(req) != HTTP_GET) return;
    HttpResponse *response = HttpContext_response(context);
    if (!response) return;
    HttpStatus status = HttpResponse_status(response);
    if (status != HTTP_OK && status != HTTP_UNAUTHORIZED) return;
    const Header *ct = HeaderSet_first(
	    HttpResponse_headers(response), "Content-Type");
    if (!ct) return;
    if (!strncmp(Header_value(ct), "text/html", 9))
    {
	free(self->referrer);
	self->referrer = PSC_copystr(HttpRequest_path(req));
    }
}

void MW_Session_done(void)
{
    RateLimit_destroy(createLimit);
    for (unsigned i = 0; i < SHT_SIZE; ++i)
    {
	pthread_mutex_destroy(&bucklocks[i]);
	Session *s = buckets[i];
	while (s)
	{
	    Session *n = s->next;
	    deleteSession(s);
	    s = n;
	}
	buckets[i] = 0;
    }
    pthread_mutex_destroy(&cleanlock);
}
