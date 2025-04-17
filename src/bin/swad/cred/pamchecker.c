#define _POSIX_C_SOURCE 200809L

#include "pamchecker.h"

#include "../authenticator.h"

#include <ctype.h>
#include <pthread.h>
#include <poser/core.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct PamChecker
{
    CredentialsChecker base;
    char *service;
} PamChecker;

typedef struct PamLoginRequest
{
    int ok;
    char qualifiedUser[256];
    char pw[256];
} PamLoginRequest;

static pthread_mutex_t pamLock = PTHREAD_MUTEX_INITIALIZER;
static PSC_Process *pamProcess;
static PSC_Connection *pamStdin;
static PSC_Connection *pamStdout;
static PSC_AsyncTask *currentTask;
static unsigned refcnt;


static void pamStdoutReceived(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)sender;

    if (!currentTask) return;

    PSC_AsyncTask *task = currentTask;
    PamLoginRequest *req = PSC_AsyncTask_arg(task);
    PSC_EADataReceived *ea = args;

    const char *line = PSC_EADataReceived_text(ea);
    switch (*line)
    {
	case 'P':
	    PSC_Connection_sendTextAsync(pamStdin, req->pw, 0);
	    break;

	case '1':
	    req->ok = 1;
	    ATTR_FALLTHROUGH;

	default:
	    currentTask = 0;
	    PSC_AsyncTask_complete(task, 0);
	    break;
    }
}

static void pamHelperDone(void *receiver, void *sender, void *args)
{
    (void)receiver;

    PSC_Process *process = sender;
    pthread_mutex_lock(&pamLock);
    if (process == pamProcess)
    {
	pamStdin = 0;
	if (pamStdout) PSC_Connection_close(pamStdout, 0);
	pamStdout = 0;
	pamProcess = 0;
    }
    pthread_mutex_unlock(&pamLock);

    PSC_EAProcessDone *ea = args;
    int signo = PSC_EAProcessDone_signal(ea);
    if (signo) PSC_Log_fmt(PSC_L_ERROR, "pamchecker: Child process killed by "
	    "signal %d (%s)", signo, strsignal(signo));
    else
    {
	int status = PSC_EAProcessDone_status(ea);
	if (status == PSC_ERR_EXEC) PSC_Log_msg(PSC_L_ERROR, "pamchecker: "
		"Cannot launch pam helper " LIBEXECDIR "/swad_pam");
	else if (status) PSC_Log_fmt(PSC_L_ERROR, "pamchecker: Child process "
		"exited with status %d", status);
    }
}

static void setPamStream(void *obj,
	PSC_StreamType stream, PSC_Connection *conn)
{
    (void)obj;

    if (stream == PSC_ST_STDIN)
    {
	pamStdin = conn;
	if (pamStdout) pthread_mutex_unlock(&pamLock);
    }
    else if (stream == PSC_ST_STDOUT)
    {
	pamStdout = conn;
	PSC_Connection_receiveLine(pamStdout);
	PSC_Event_register(PSC_Connection_dataReceived(pamStdout), 0,
		pamStdoutReceived, 0);
	if (pamStdin) pthread_mutex_unlock(&pamLock);
    }
}

static void createProcess(void)
{
    pthread_mutex_lock(&pamLock);
    if (refcnt)
    {
	if (!pamProcess) return;
	++refcnt;
	pthread_mutex_unlock(&pamLock);
	return;
    }
    refcnt = 1;
    PSC_ProcessOpts *opts = PSC_ProcessOpts_create();
    PSC_ProcessOpts_setName(opts, "swad: pam helper");
    PSC_ProcessOpts_streamAction(opts, PSC_ST_STDIN, PSC_SA_PIPE);
    PSC_ProcessOpts_streamAction(opts, PSC_ST_STDOUT, PSC_SA_PIPE);
    PSC_ProcessOpts_streamAction(opts, PSC_ST_STDERR, PSC_SA_CLOSE);
    pamProcess = PSC_Process_create(opts);
    PSC_Event_register(PSC_Process_done(pamProcess), 0, pamHelperDone, 0);
    PSC_Process_exec(pamProcess, 0, setPamStream, LIBEXECDIR "/swad_pam");
}

static void destroyChecker(void *obj)
{
    if (!obj) return;
    PamChecker *self = obj;
    free(self->service);
    free(self);
    pthread_mutex_lock(&pamLock);
    if (pamProcess && !--refcnt) PSC_Process_stop(pamProcess, 0);
    pthread_mutex_unlock(&pamLock);
}

static void checkAsync(PSC_AsyncTask *task)
{
    currentTask = task;
    PamLoginRequest *req = PSC_AsyncTask_arg(task);
    PSC_Connection_sendTextAsync(pamStdin, req->qualifiedUser, 0);
}

static int check(void *obj, const char *user, const char *pw, char **realname)
{
    *realname = 0;
    PamChecker *self = obj;
    pthread_mutex_lock(&pamLock);
    if (!pamProcess)
    {
	pthread_mutex_unlock(&pamLock);
	PSC_Log_msg(PSC_L_ERROR,
		"pamchecker: Authentication is unavailable because the "
		"helper process died. Restarting swad is advised.");
	return 0;
    }

    PamLoginRequest *req = PSC_malloc(sizeof *req);
    req->ok = 0;
    snprintf(req->qualifiedUser, sizeof req->qualifiedUser, "%s:%s\n",
	    self->service, user);
    snprintf(req->pw, sizeof req->pw, "%s\n", pw);

    PSC_AsyncTask *task = PSC_AsyncTask_create(checkAsync);
    PSC_AsyncTask_await(task, req);
    int ok = req->ok;
    free(req);

    pthread_mutex_unlock(&pamLock);

    if (ok)
    {
	struct passwd pwent;
	struct passwd *pwd;
	char buf[1024];
	if (getpwnam_r(user, &pwent, buf, sizeof buf, &pwd) == 0
		&& pwd && pwd->pw_gecos && *pwd->pw_gecos)
	{
	    char *comma = strchr(pwd->pw_gecos, ',');
	    if (comma) *comma = 0;
	    char *amp = strchr(pwd->pw_gecos, '&');
	    if (amp)
	    {
		*realname = PSC_malloc(strlen(pwd->pw_gecos)
			+ strlen(user));
		char *rnp = *realname;
		for (const char *gp = pwd->pw_gecos; *gp; ++gp)
		{
		    if (gp == amp)
		    {
			*rnp++ = toupper((unsigned char)*user);
			for (const char *up = user+1; *up; ++up)
			{
			    *rnp++ = *up;
			}
		    }
		    else *rnp++ = *gp;
		}
	    }
	    else *realname = PSC_copystr(pwd->pw_gecos);
	}
    }
    return ok;
}

CredentialsChecker *CredentialsChecker_createPam(const char *service)
{
    createProcess();
    PamChecker *self = PSC_malloc(sizeof *self);
    self->base.check = check;
    self->base.destroy = destroyChecker;
    self->service = PSC_copystr(service);
    return (CredentialsChecker *)self;
}

