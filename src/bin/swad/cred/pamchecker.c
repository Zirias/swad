#define _POSIX_C_SOURCE 200112L

#include "pamchecker.h"

#include "../authenticator.h"

#include <ctype.h>
#include <pthread.h>
#include <poser/core/log.h>
#include <poser/core/util.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct PamChecker
{
    CredentialsChecker base;
    char *service;
} PamChecker;

typedef struct PamThread
{
    const char *service;
    const char *user;
    const char *pw;
    pthread_mutex_t startlock;
    pthread_mutex_t donelock;
    pthread_cond_t start;
    pthread_cond_t done;
    pthread_t handle;
    int refcnt;
    int stoprq;
    int ok;
} PamThread;

static PamThread *pamThread;

static void *pamthreadproc(void *arg)
{
    (void)arg;

    pthread_mutex_lock(&pamThread->startlock);

    int readfd[2];
    int writefd[2];
    pipe(readfd);
    pipe(writefd);
    pid_t pid = fork();

    if (!pid)
    {
	close(readfd[0]);
	close(writefd[1]);
	dup2(readfd[1], STDOUT_FILENO);
	if (readfd[1] != STDOUT_FILENO) close(readfd[1]);
	dup2(writefd[0], STDIN_FILENO);
	if (writefd[0] != STDIN_FILENO) close (writefd[0]);
	close(STDERR_FILENO);
	execl(LIBEXECDIR "/swad_pam", "swad: pam helper", NULL);
    }

    close(readfd[1]);
    close(writefd[0]);

    while (!pamThread->stoprq)
    {
	char rdbuf[16];
	char wrbuf[256];
	pthread_cond_wait(&pamThread->start, &pamThread->startlock);
	if (pamThread->stoprq) break;
	PSC_Log_fmt(PSC_L_DEBUG, "pamchecker: sending authentication "
		"request for %s:%s", pamThread->service, pamThread->user);
	int wrlen = snprintf(wrbuf, sizeof wrbuf, "%s:%s\n",
		pamThread->service, pamThread->user);
	write(writefd[1], wrbuf, wrlen);
	ssize_t rdlen = read(readfd[0], rdbuf, sizeof rdbuf - 1);
	rdbuf[rdlen] = 0;
	if (!strcmp(rdbuf, "P\n"))
	{
	    PSC_Log_msg(PSC_L_DEBUG, "pamchecker: sending password");
	    wrlen = snprintf(wrbuf, sizeof wrbuf, "%s\n", pamThread->pw);
	    write(writefd[1], wrbuf, wrlen);
	    rdlen = read(readfd[0], rdbuf, sizeof rdbuf - 1);
	    rdbuf[rdlen] = 0;
	}
	pthread_mutex_lock(&pamThread->donelock);
	if (!strcmp(rdbuf, "1\n")) pamThread->ok = 1;
	else pamThread->ok = 0;
	pthread_cond_signal(&pamThread->done);
	pthread_mutex_unlock(&pamThread->donelock);
    }

    close(readfd[0]);
    close(writefd[1]);

    int status;
    waitpid(pid, &status, 0);

    return 0;
}

static void PamThread_create(void)
{
    if (pamThread) goto done;
    pamThread = PSC_malloc(sizeof *pamThread);
    memset(pamThread, 0, sizeof *pamThread);

    sigset_t blockmask;
    sigset_t mask;
    sigfillset(&blockmask);
    sigprocmask(SIG_BLOCK, &blockmask, &mask);
    pthread_mutex_init(&pamThread->startlock, 0);
    pthread_cond_init(&pamThread->start, 0);
    pthread_mutex_init(&pamThread->donelock, 0);
    pthread_cond_init(&pamThread->done, 0);
    pthread_create(&pamThread->handle, 0, pamthreadproc, 0);
    sigprocmask(SIG_SETMASK, &mask, 0);
done:
    ++pamThread->refcnt;
}

static void PamThread_destroy(void)
{
    if (!pamThread) return;
    if (--pamThread->refcnt) return;
    if (pthread_kill(pamThread->handle, 0) >= 0)
    {
	pamThread->stoprq = 1;
	pthread_cond_signal(&pamThread->start);
	pthread_mutex_unlock(&pamThread->startlock);
    }
    pthread_join(pamThread->handle, 0);
    pthread_cond_destroy(&pamThread->done);
    pthread_mutex_destroy(&pamThread->donelock);
    pthread_cond_destroy(&pamThread->start);
    pthread_mutex_destroy(&pamThread->startlock);
    free(pamThread);
    pamThread = 0;
}

static void destroyChecker(void *obj)
{
    if (!obj) return;
    PamChecker *self = obj;
    free(self->service);
    free(self);
    PamThread_destroy();
}

static int check(void *obj, const char *user, const char *pw, char **realname)
{
    *realname = 0;
    PamChecker *self = obj;
    pthread_mutex_lock(&pamThread->startlock);
    pamThread->service = self->service;
    pamThread->user = user;
    pamThread->pw = pw;
    pthread_cond_signal(&pamThread->start);
    pthread_mutex_unlock(&pamThread->startlock);
    pthread_mutex_lock(&pamThread->donelock);
    pthread_cond_wait(&pamThread->done, &pamThread->donelock);
    pthread_mutex_unlock(&pamThread->donelock);
    int ok = pamThread->ok;
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
    PamThread_create();
    PamChecker *self = PSC_malloc(sizeof *self);
    self->base.check = check;
    self->base.destroy = destroyChecker;
    self->service = PSC_copystr(service);
    return (CredentialsChecker *)self;
}

