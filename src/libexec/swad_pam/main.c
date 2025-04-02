#define _POSIX_C_SOURCE 200112L

#include <errno.h>
#include <fcntl.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char pass[256];
static int passread;

static int pamconv(int num_msg, const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr)
{
    (void)appdata_ptr;

    *resp = malloc(num_msg * sizeof **resp);
    memset(*resp, 0, sizeof **resp);

    for (int i = 0; i < num_msg; ++i)
    {
	if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF)
	{
	    if (!passread)
	    {
		ssize_t rdsz;
		if (write(STDOUT_FILENO, "P\n", 2) == 2 &&
			(rdsz = read(STDIN_FILENO, pass, sizeof pass - 1)) > 0)
		{
		    pass[rdsz] = 0;
		    char *nl = strchr(pass, '\n');
		    if (nl) *nl = 0;
		}
		passread = 1;
	    }
	    if (*pass) resp[i]->resp = strdup(pass);
	}
    }

    return PAM_SUCCESS;
}

static struct pam_conv conv = { pamconv, 0 };

int main(int argc, char **argv)
{
    static char buf[512];

    if (argc != 1
	    || strcmp(argv[0], "swad: pam helper")
	    || fcntl(STDERR_FILENO, F_GETFL) >= 0
	    || errno != EBADF)
    {
	fprintf(stderr, "This tool is part of swad. "
		"It cannot be invoked directly.\n");
	return EXIT_FAILURE;
    }

    int fd = open("/dev/null", O_RDWR);
    if (fd != STDERR_FILENO)
    {
	if (fd < 0 ||
		dup2(fd, STDERR_FILENO) != STDERR_FILENO) return EXIT_FAILURE;
	close(fd);
    }

    errno = 0;
    ssize_t rdsz;
    while ((rdsz = read(STDIN_FILENO, buf, sizeof buf - 1)) > 0)
    {
	buf[rdsz] = 0;
	char *user = strchr(buf, ':');
	if (!user) return EXIT_FAILURE;
	*user++ = 0;
	char *nl = strchr(user, '\n');
	if (!nl) return EXIT_FAILURE;
	*nl = 0;

	passread = 0;
	*pass = 0;
	pam_handle_t *handle = 0;
	pam_start(buf, user, &conv, &handle);
	if (!handle) return EXIT_FAILURE;
	int result = pam_authenticate(handle,
		PAM_SILENT|PAM_DISALLOW_NULL_AUTHTOK);
	pam_end(handle, result);

	const char *retstr = (result == PAM_SUCCESS) ? "1\n" : "0\n";
	if (write(STDOUT_FILENO, retstr, 2) < 2) return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

