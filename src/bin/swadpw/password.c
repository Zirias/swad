#define _POSIX_C_SOURCE 200112L

#include "password.h"

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define PW_MAXSZ 128

struct Password
{
    char pw[PW_MAXSZ];
};

static int intrsigs[] = { SIGALRM, SIGHUP, SIGINT, SIGPIPE, SIGQUIT,
    SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU };

static volatile sig_atomic_t interrupted = 0;
static void handlesig(int signo)
{
    (void)signo;
    interrupted = 1;
}

static Password *readFromStdin(void)
{
    Password *self = xmalloc(sizeof *self);
    if (!fgets(self->pw, sizeof self->pw, stdin))
    {
	fputs("Error reading password from standard input.\n", stderr);
	Password_destroy(self);
	return 0;
    }
    char *nl = strchr(self->pw, '\n');
    if (nl) *nl = 0;
    return self;
}

static int writeprompt(int *fd, const void *buf, size_t nbytes,
	const char **error)
{
    if (*fd < 0) *fd = STDIN_FILENO;
    ssize_t rc;
    if ((rc = write(*fd, buf, nbytes)) < 0)
    {
	if (errno != EBADF) goto ioerr;
	char *ttynm = ttyname(STDIN_FILENO);
	if (!ttynm) goto ioerr;
	*fd = open(ttynm, O_WRONLY);
	if (*fd < 0)
	{
	    if (!isatty(STDERR_FILENO)) goto notty;
	    *fd = STDERR_FILENO;
	}
	if ((rc = write(*fd, buf, nbytes) < 0)) goto ioerr;
    }
    return rc;

notty:
    if (error)
    {
	*error = "Can't figure out how to write a prompt to the terminal.\n";
    }
ioerr:
    return -1;
}

static int readpw(char *buf, size_t bufsz,
	const struct termios *tios, int promptfd)
{
    unsigned char c;
    size_t pos = 0;
    int rc = -1;

    struct termios pwios;
    memcpy(&pwios, tios, sizeof pwios);
    pwios.c_lflag &= ~(ICANON | ECHO);
    pwios.c_cc[VMIN] = 1;
    pwios.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &pwios) < 0) return -1;

    for (;;)
    {
	if (read(STDIN_FILENO, &c, 1) < 1) break;
	switch (c)
	{
	    case '\r':
	    case '\n':
		rc = 0;
		buf[pos] = 0;
		break;

	    case '\b':
	    case 127:
		if (pos > 0) --pos;
		continue;

	    default:
		if (pos < bufsz - 1) buf[pos++] = c;
	}
	if (rc == 0) break;
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, tios) < 0) return -1;
    if (writeprompt(&promptfd, "\n", 1, 0) != 1) return -1;
    return rc;
}

static Password *readFromTerminal(const char *user)
{
    char prompt[512];
    char pw2[PW_MAXSZ];
    Password *self = 0;
    const char *error = 0;
    int pfd = -1;
    unsigned i;
    struct sigaction sa;
    struct sigaction origsa[sizeof intrsigs / sizeof *intrsigs];
    memset(&sa, 0, sizeof sa);
    for (i = 0; i < sizeof intrsigs / sizeof *intrsigs; ++i)
    {
	sigaddset(&sa.sa_mask, intrsigs[i]);
    }
    sa.sa_handler = handlesig;

    interrupted = 0;
    for (i = 0; i < sizeof intrsigs / sizeof *intrsigs; ++i)
    {
	if (sigaction(intrsigs[i], &sa, origsa+i) < 0)
	{
	    fprintf(stderr, "Error installing handler for signal %d.\n",
		    intrsigs[i]);
	    goto done;
	}
    }

    struct termios tios;
    if (tcgetattr(STDIN_FILENO, &tios) < 0)
    {
	error = "Error getting terminal attributes.\n";
	goto done;
    }

    if (interrupted) goto done;

    int len = snprintf(prompt, sizeof prompt, "NEW password for %s: ", user);
    if (writeprompt(&pfd, prompt, len, &error) < 0
	    || readpw(pw2, sizeof pw2, &tios, pfd) < 0)
    {
	if (!error) error = "Unexpected I/O error.\n";
	goto done;
    }
    if (!pw2[0])
    {
	error = "Empty password rejected, aborting.\n";
	goto done;
    }

    if (interrupted) goto done;

    self = xmalloc(sizeof *self);
    if (writeprompt(&pfd, "Confirm new password: ",
		sizeof "Confirm new password:", &error) < 0
	    || readpw(self->pw, sizeof self->pw, &tios, pfd) < 0)
    {
	if (!error) error = "Unexpected I/O error.\n";
	goto done;
    }

    if (strcmp(self->pw, pw2))
    {
	error = "Passwords do not match, aborting.\n";
    }

done:
    wipemem(pw2, sizeof pw2);
    for (unsigned j = 0; j < i; ++j) sigaction(intrsigs[j], origsa+j, 0);
    tcsetattr(STDIN_FILENO, TCSANOW, &tios);
    if (interrupted) error = "Password input interrupted.\n";
    if (error)
    {
	Password_destroy(self);
	self = 0;
	fputs(error, stderr);
    }
    if (pfd >= 0 && pfd != STDIN_FILENO && pfd != STDERR_FILENO) close(pfd);
    return self;
}

Password *Password_read(const char *user, int allowStdin)
{
    if (isatty(STDIN_FILENO))
    {
	return readFromTerminal(user);
    }
    else
    {
	if (!allowStdin)
	{
	    fputs("Refusing to read password when standard input is not a "
		    "terminal.\nGive the `-s' flag to allow this.\n", stderr);
	    return 0;
	}
	return readFromStdin();
    }
}

const char *Password_str(const Password *self)
{
    return self->pw;
}

void Password_destroy(Password *self)
{
    if (!self) return;
    wipemem(self->pw, sizeof self->pw);
    free(self);
}

