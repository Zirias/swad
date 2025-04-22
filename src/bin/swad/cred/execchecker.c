#define _POSIX_C_SOURCE 200809L

#include "execchecker.h"

#include "../authenticator.h"

#include <poser/core.h>
#include <stdlib.h>
#include <string.h>

typedef struct ExecChecker
{
    CredentialsChecker base;
    char *path;
} ExecChecker;

typedef struct ExecLoginRequest
{
    ExecChecker *checker;
    PSC_AsyncTask *task;
    PSC_Process *process;
    PSC_Connection *procStdout;
    PSC_Connection *procStderr;
    const char *pw;
    char *realname;
    int ok;
} ExecLoginRequest;

static void destroyChecker(void *obj)
{
    if (!obj) return;
    ExecChecker *self = obj;
    free(self->path);
    free(self);
}

static void processDone(void *receiver, void *sender, void *args)
{
    (void)sender;

    ExecLoginRequest *req = receiver;
    PSC_EAProcessDone *ea = args;

    int signo = PSC_EAProcessDone_signal(ea);
    if (signo) PSC_Log_fmt(PSC_L_ERROR, "execchecker: %s killed by signal "
	    "%d (%s)", req->checker->path, signo, strsignal(signo));
    else
    {
	int status = PSC_EAProcessDone_status(ea);
	if (status == PSC_ERR_EXEC) PSC_Log_fmt(PSC_L_ERROR, "execchecker: "
		"Cannot launch %s", req->checker->path);
	else if (status == 0) req->ok = 1;
    }

    req->process = 0;
    if (!req->procStdout && !req->procStderr)
    {
	PSC_AsyncTask_complete(req->task, 0);
    }
}

static void streamClosed(void *receiver, void *sender, void *args)
{
    (void)args;

    ExecLoginRequest *req = receiver;
    PSC_Connection *conn = sender;

    if (conn == req->procStdout) req->procStdout = 0;
    if (conn == req->procStderr) req->procStderr = 0;

    if (!req->procStdout && !req->procStderr && !req->process)
    {
	PSC_AsyncTask_complete(req->task, 0);
    }
}

static void receiveStdout(void *receiver, void *sender, void *args)
{
    (void)sender;

    ExecLoginRequest *req = receiver;
    PSC_EADataReceived *ea = args;
    char *txt = PSC_copystr(PSC_EADataReceived_text(ea));
    char *nl = strchr(txt, '\n');
    if (nl) *nl = 0;

    if (req->realname)
    {
	PSC_Log_fmt(PSC_L_WARNING, "execchecker: Extra output from %s: %s",
		req->checker->path, txt);
	free(txt);
    }
    else req->realname = txt;
}

static void receiveStderr(void *receiver, void *sender, void *args)
{
    (void)sender;

    ExecLoginRequest *req = receiver;
    PSC_EADataReceived *ea = args;
    char *txt = PSC_copystr(PSC_EADataReceived_text(ea));
    char *nl = strchr(txt, '\n');
    if (nl) *nl = 0;
    PSC_Log_fmt(PSC_L_WARNING, "execchecker: Error output from %s: %s",
	    req->checker->path, txt);
    free(txt);
}

static void pwSent(void *receiver, void *sender, void *args)
{
    (void)receiver;
    (void)args;

    PSC_Connection_close(sender, 0);
}

static void setProcStream(void *obj,
	PSC_StreamType stream, PSC_Connection *conn)
{
    ExecLoginRequest *req = obj;

    switch (stream)
    {
	case PSC_ST_STDIN:
	    PSC_Connection_sendTextAsync(conn, req->pw, 0);
	    PSC_Connection_sendTextAsync(conn, "\n", req);
	    PSC_Event_register(PSC_Connection_dataSent(conn), 0, pwSent, 0);
	    break;

	case PSC_ST_STDOUT:
	    PSC_Connection_receiveLine(conn);
	    PSC_Event_register(PSC_Connection_dataReceived(conn), req,
		    receiveStdout, 0);
	    PSC_Event_register(PSC_Connection_closed(conn), req,
		    streamClosed, 0);
	    req->procStdout = conn;
	    break;

	case PSC_ST_STDERR:
	    PSC_Connection_receiveLine(conn);
	    PSC_Event_register(PSC_Connection_dataReceived(conn), req,
		    receiveStderr, 0);
	    PSC_Event_register(PSC_Connection_closed(conn), req,
		    streamClosed, 0);
	    req->procStderr = conn;
	    break;
    }
}

static void checkAsync(PSC_AsyncTask *task)
{
    ExecLoginRequest *req = PSC_AsyncTask_arg(task);
    PSC_Event_register(PSC_Process_done(req->process), req, processDone, 0);
    PSC_Process_exec(req->process, req, setProcStream, req->checker->path);
}

static int check(void *obj, const char *user, const char *pw, char **realname)
{
    *realname = 0;
    ExecChecker *self = obj;

    PSC_ProcessOpts *opts = PSC_ProcessOpts_create();
    PSC_ProcessOpts_streamAction(opts, PSC_ST_STDIN, PSC_SA_PIPE);
    PSC_ProcessOpts_streamAction(opts, PSC_ST_STDOUT, PSC_SA_PIPE);
    PSC_ProcessOpts_streamAction(opts, PSC_ST_STDERR, PSC_SA_PIPE);
    PSC_ProcessOpts_addArg(opts, user);

    ExecLoginRequest *req = PSC_malloc(sizeof *req);
    req->checker = self;
    req->task = PSC_AsyncTask_create(checkAsync);
    req->process = PSC_Process_create(opts);
    req->procStdout = 0;
    req->procStderr = 0;
    req->pw = pw;
    req->realname = 0;
    req->ok = 0;

    PSC_ProcessOpts_destroy(opts);

    PSC_AsyncTask_await(req->task, req);

    int ok = req->ok;
    if (req->realname)
    {
	if (ok) *realname = req->realname;
	else free(req->realname);
    }
    free(req);
    return ok;
}

CredentialsChecker *CredentialsChecker_createExec(const char *path)
{
    ExecChecker *self = PSC_malloc(sizeof *self);
    self->base.check = check;
    self->base.destroy = destroyChecker;
    self->path = PSC_copystr(path);
    return (CredentialsChecker *)self;
}

