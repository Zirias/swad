#include "session.h"

#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httpmethod.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"
#include "../http/httpstatus.h"
#include "../proxylist.h"
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

#define SID_LEN 43 // 32 bytes in base64

struct Session
{
    PSC_Dictionary *props;
    char *referrer;
    pthread_mutex_t lock;
    time_t ctime;
    time_t atime;
};

static unsigned maxage = MAXAGE;
static unsigned maxidle = MAXIDLE;

#define sessionExpired(s, n) ((n) - (s).atime > maxidle \
	|| (n) - (s).ctime > maxage)

static PSC_Dictionary *sessions;
static PSC_RateLimitOpts *createLimitOpts;
static PSC_RateLimit *createLimit;
static time_t cleantime;
static pthread_mutex_t sessionlock;
static pthread_mutex_t cleanlock;

static void deleteSession(void *obj)
{
    if (!obj) return;
    Session *self = obj;
    pthread_mutex_destroy(&self->lock);
    free(self->referrer);
    PSC_Dictionary_destroy(self->props);
    free(self);
}

static Session *findSession(const char *id, time_t now)
{
    Session *session = 0;
    pthread_mutex_lock(&sessionlock);
    session = PSC_Dictionary_get(sessions, id, SID_LEN);
    if (session && sessionExpired(*session, now))
    {
	PSC_Dictionary_set(sessions, id, SID_LEN, 0, 0);
	session = 0;
    }
    pthread_mutex_unlock(&sessionlock);
    return session;
}

static Session *createSession(time_t now, char *id)
{
    do
    {
	size_t sz = PSC_Random_string(id, SID_LEN+1, PSC_RF_SECURE);
	if (sz < SID_LEN+1) return 0;
    } while (findSession(id, now));
    Session *self = PSC_malloc(sizeof *self);
    self->props = PSC_Dictionary_create(0);
    self->referrer = 0;
    pthread_mutex_init(&self->lock, 0);
    self->ctime = now;
    self->atime = now;
    pthread_mutex_lock(&sessionlock);
    PSC_Dictionary_set(sessions, id, SID_LEN, self, 0);
    pthread_mutex_unlock(&sessionlock);
    return self;
}

static int isExpired(const void *key, size_t keysz, void *obj, const void *arg)
{
    (void)key;
    (void)keysz;

    Session *session = obj;
    const time_t *now = arg;
    return sessionExpired(*session, *now);
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
    pthread_mutex_lock(&sessionlock);
    PSC_Dictionary_removeAll(sessions, isExpired, &now);
    pthread_mutex_unlock(&sessionlock);
}

Session *Session_get(const HttpContext *context)
{
    return HttpContext_get(context, PROPNAME);
}

Session *Session_start(HttpContext *context)
{
    Session *session = Session_get(context);
    if (session) return session;

    Cookies *cookies = Cookies_get(context);
    if (!cookies)
    {
	PSC_Log_msg(PSC_L_ERROR,
		"Session middleware depends on Cookies middleware!");
	return 0;
    }
    if (createLimit)
    {
	const RemoteEntry *r = PSC_List_at(
		ProxyList_get(context), ProxyList_firstTrusted(context));
	const char *addr = PSC_IpAddr_string(RemoteEntry_addr(r));
	if (!PSC_RateLimit_check(createLimit, addr, strlen(addr)))
	{
	    HttpContext_setResponse(context,
		    HttpResponse_createError(HTTP_TOOMANYREQUESTS, 0));
	    return 0;
	}
    }
    char newsid[SID_LEN+1];
    time_t now = time(0);
    session = createSession(now, newsid);
    if (!session)
    {
	PSC_Log_msg(PSC_L_ERROR,
		"Cannot obtain random data for new session id!");
	return 0;
    }
    Cookies_setCookie(cookies, COOKIENAME, newsid);
    HttpContext_set(context, PROPNAME, session, 0);
    return session;
}

const char *Session_referrer(const Session *self)
{
    return self->referrer;
}

void *Session_getProp(Session *self, const char *name)
{
    pthread_mutex_lock(&self->lock);
    void *obj = PSC_Dictionary_get(self->props, name, strlen(name));
    pthread_mutex_unlock(&self->lock);
    return obj;
}

void Session_setProp(Session *self, const char *name,
	void *obj, ObjDeleter deleter)
{
    pthread_mutex_lock(&self->lock);
    PSC_Dictionary_set(self->props, name, strlen(name), obj, deleter);
    pthread_mutex_unlock(&self->lock);
}

void MW_SessionOpts_setCreateLimit(PSC_RateLimitOpts *opts)
{
    if ((!opts && !createLimitOpts) ||
	    (opts && createLimitOpts &&
	     PSC_RateLimitOpts_equals(createLimitOpts, opts)))
    {
	PSC_RateLimitOpts_destroy(opts);
	return;
    }

    pthread_mutex_lock(&sessionlock);
    PSC_RateLimit_destroy(createLimit);
    PSC_RateLimitOpts_destroy(createLimitOpts);
    createLimitOpts = opts;
    if (opts) createLimit = PSC_RateLimit_create(opts);
    else createLimit = 0;
    pthread_mutex_unlock(&sessionlock);
}

void MW_SessionOpts_setMaxAge(unsigned maxAge, unsigned maxIdle)
{
    if (maxAge >= 60) maxage = maxAge;
    if (maxIdle >= 60) maxidle = maxIdle;
}

void MW_Session_init(void)
{
    pthread_mutex_init(&sessionlock, 0);
    pthread_mutex_init(&cleanlock, 0);
    cleantime = time(0);
    sessions = PSC_Dictionary_create(deleteSession);
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
    if (sid) self = findSession(sid, now);
    if (self)
    {
	self->atime = now;
	HttpContext_set(context, PROPNAME, self, 0);
    }

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
    PSC_RateLimit_destroy(createLimit);
    PSC_RateLimitOpts_destroy(createLimitOpts);
    createLimit = 0;
    createLimitOpts = 0;
    PSC_Dictionary_destroy(sessions);
    sessions = 0;
    pthread_mutex_destroy(&cleanlock);
    pthread_mutex_destroy(&sessionlock);
}
