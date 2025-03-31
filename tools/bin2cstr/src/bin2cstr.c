#define _POSIX_C_SOURCE 200112L

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char hex[16] = "0123456789abcdef";
static const char lit[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			  "abcdefghijklmnopqrstuvwxyz"
			  "0123456789 !#%&'()*+,-./:;<=>[]^_{|}~";

static const char *esc(char c)
{
    static char xesc[5] = "\\x";
    switch (c)
    {
	case '\a':  return "\\a";
	case '\b':  return "\\b";
	case '\f':  return "\\f";
	case '\n':  return "\\n";
	case '\r':  return "\\r";
	case '\t':  return "\\t";
	case '\v':  return "\\v";
	case '\\':  return "\\\\";
	case '"':   return "\\\"";
	case '?':   return "\\?";
	default:    ;
    }
    xesc[2] = hex[c>>4];
    xesc[3] = hex[c&15];
    return xesc;
}

int main(int argc, char **argv)
{
    int rc = 1;
    if (argc != 3) return rc;

    int outfd = -1;
    int infd = -1;
    unsigned char *data = 0;
    char *datastr = 0;

    outfd = open(argv[1], O_WRONLY|O_CREAT|O_TRUNC, 0664);
    if (outfd < 0) goto done;
    infd = open(argv[2], O_RDONLY);
    if (infd < 0) goto done;
    struct stat st;
    if (fstat(infd, &st) < 0) goto done;

    size_t datasz = st.st_size;
    data = malloc(datasz);
    if (!data) goto done;
    size_t strsz = 4 * st.st_size + 3;
    datastr = malloc(strsz);
    if (!datastr) goto done;

    size_t rdpos = 0;
    ssize_t rdchunk = 0;
    while ((rdchunk = read(infd, data+rdpos, datasz-rdpos)) > 0)
    {
	if ((rdpos += rdchunk) == datasz) break;
    }
    if (rdpos < datasz) goto done;

    char *op = datastr;
    *op++ = '"';
    int triesc = 0;
    for (size_t i = 0; i < datasz; ++i)
    {
	if ((!triesc && data[i] == '?') || strchr(lit, data[i]))
	{
	    *op++ = data[i];
	}
	else
	{
	    const char *repl = esc(data[i]);
	    while (*repl) *op++ = *repl++;
	}
	if (data[i] == '?') triesc = !triesc;
	else triesc = 0;
    }
    *op++ = '"';
    *op++ = '\n';
    strsz = op - datastr;

    size_t wrpos = 0;
    ssize_t wrchunk = 0;
    while ((wrchunk = write(outfd, datastr+wrpos, strsz-wrpos)) > 0)
    {
	if ((wrpos += wrchunk) == strsz) break;
    }
    if (wrpos == strsz) rc = 0;

done:
    free(datastr);
    free(data);
    if (infd >= 0) close(infd);
    if (outfd >= 0) close(outfd);
    return rc;
}
