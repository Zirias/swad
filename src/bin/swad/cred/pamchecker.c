#define _POSIX_C_SOURCE 200809L

#include "pamchecker.h"

#include "../authenticator.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <poser/core/log.h>
#include <poser/core/util.h>
#include <pwd.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define ERR_EXEC 127

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
    pthread_mutex_t lock;
    pthread_t handle;
    sem_t request;
    sem_t response;
    int refcnt;
    int stoprq;
    int ok;
} PamThread;

static PamThread *pamThread;

static volatile sig_atomic_t childExited;

static void handlechild(int signum)
{
    if (signum == SIGCHLD) childExited = 1;
}

static void *pamthreadproc(void *arg)
{
    (void)arg;

    struct sigaction handler;
    memset(&handler, 0, sizeof handler);
    sigemptyset(&handler.sa_mask);
    sigaddset(&handler.sa_mask, SIGCHLD);
    handler.sa_handler = handlechild;
    if (sigaction(SIGCHLD, &handler, 0) < 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamchecker: Cannot install SIGCHLD handler");
	goto done;
    }
    if (pthread_sigmask(SIG_UNBLOCK, &handler.sa_mask, 0) != 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamchecker: Cannot unblock SIGCHLD");
	goto done;
    }

    int readfd[2];
    int writefd[2];
    if (pipe(readfd) < 0 || pipe(writefd) < 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamchecker: Error creating pipes");
	goto done;
    }
    pid_t pid;
    if ((pid = fork()) < 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamchecker: Cannot fork child process");
	close(readfd[0]);
	close(readfd[1]);
	close(writefd[0]);
	close(writefd[1]);
	goto done;
    }

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
	exit(ERR_EXEC);
    }

    close(readfd[1]);
    close(writefd[0]);

    while (!childExited)
    {
	char rdbuf[16];
	char wrbuf[256];
	if (sem_wait(&pamThread->request) < 0) break;
	if (pthread_mutex_lock(&pamThread->lock) != 0) break;
	pamThread->ok = 0;
	if (pamThread->stoprq || childExited) break;
	PSC_Log_fmt(PSC_L_DEBUG, "pamchecker: sending authentication "
		"request for %s:%s", pamThread->service, pamThread->user);
	int wrlen = snprintf(wrbuf, sizeof wrbuf, "%s:%s\n",
		pamThread->service, pamThread->user);
	if (write(writefd[1], wrbuf, wrlen) < 0) break;
	ssize_t rdlen = read(readfd[0], rdbuf, sizeof rdbuf - 1);
	if (rdlen < 0) break;
	rdbuf[rdlen] = 0;
	if (!strcmp(rdbuf, "P\n"))
	{
	    PSC_Log_msg(PSC_L_DEBUG, "pamchecker: sending password");
	    wrlen = snprintf(wrbuf, sizeof wrbuf, "%s\n", pamThread->pw);
	    if (write(writefd[1], wrbuf, wrlen) < 0) break;
	    rdlen = read(readfd[0], rdbuf, sizeof rdbuf - 1);
	    if (rdlen < 0) break;
	    rdbuf[rdlen] = 0;
	}
	if (!strcmp(rdbuf, "1\n")) pamThread->ok = 1;
	if (sem_post(&pamThread->response) < 0) break;
	if (pthread_mutex_unlock(&pamThread->lock) != 0) break;
    }

    pthread_mutex_unlock(&pamThread->lock);
    close(readfd[0]);
    close(writefd[1]);

    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
    {
	PSC_Log_fmt(PSC_L_ERROR, "pamchecker: Child process terminated "
		"by signal %d (%s)", WTERMSIG(status),
		strsignal(WTERMSIG(status)));
    }
    else if (WIFEXITED(status))
    {
	int exitst = WEXITSTATUS(status);
	if (exitst == ERR_EXEC)
	{
	    PSC_Log_msg(PSC_L_ERROR, "pamchecker: Cannot launch helper "
		    LIBEXECDIR "/swad_pam");
	}
	else if (exitst != 0)
	{
	    PSC_Log_fmt(PSC_L_ERROR, "pamchecker: Child process exited with "
		    "status %d", exitst);
	}
    }
    else
    {
	PSC_Log_msg(PSC_L_ERROR, "pamchecker: Child process died in an "
		"unexpected way");
    }

done:
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
    if (sigprocmask(SIG_BLOCK, &blockmask, &mask) < 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamchecker: Cannot set signal block mask");
	goto done;
    }
    if (pthread_mutex_init(&pamThread->lock, 0) != 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamchecker: Cannot initialize mutex");
	goto restore;
    }
    if (sem_init(&pamThread->request, 0, 0) < 0
	    || sem_init(&pamThread->response, 0, 0) < 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamchecker: Cannot initialize semaphore");
	goto restore;
    }
    if (pthread_create(&pamThread->handle, 0, pamthreadproc, 0) != 0)
    {
	PSC_Log_msg(PSC_L_ERROR,
		"pamchecker: Cannot launch controlling thread");
    }
restore:
    sigaddset(&mask, SIGCHLD); /* keep SIGCHLD blocked on all other threads */
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
	pthread_mutex_lock(&pamThread->lock);
	pamThread->stoprq = 1;
	sem_post(&pamThread->request);
	pthread_mutex_unlock(&pamThread->lock);
    }
    pthread_join(pamThread->handle, 0);
    sem_destroy(&pamThread->response);
    sem_destroy(&pamThread->request);
    pthread_mutex_destroy(&pamThread->lock);
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
    if (pthread_kill(pamThread->handle, 0) == ESRCH)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamcheck: Authentication is unavailable "
		"because either the child process or the controlling thread "
		"died. Restarting swad is advised.");
	return 0;
    }
    if (pthread_mutex_lock(&pamThread->lock) != 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamcheck: Cannot lock mutex");
	return 0;
    }
    pamThread->service = self->service;
    pamThread->user = user;
    pamThread->pw = pw;
    if (sem_post(&pamThread->request) < 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamcheck: Cannot signal controlling thread");
	return 0;
    }
    if (pthread_mutex_unlock(&pamThread->lock) != 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamcheck: Cannot unlock mutex");
	return 0;
    }
    if (sem_wait(&pamThread->response) < 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamcheck: Error waiting for result");
	return 0;
    }
    if (pthread_mutex_lock(&pamThread->lock) != 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamcheck: Cannot lock mutex");
	return 0;
    }
    int ok = pamThread->ok;
    if (pthread_mutex_unlock(&pamThread->lock) != 0)
    {
	PSC_Log_msg(PSC_L_ERROR, "pamcheck: Cannot unlock mutex");
	return 0;
    }
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

