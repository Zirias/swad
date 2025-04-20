#define _DEFAULT_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_GETRANDOM
#  include <sys/random.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

static uint64_t prng(void)
{
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static int seeded = 0;
    static uint64_t s[4] = { 0 };

    pthread_mutex_lock(&mutex);

    if (!seeded)
    {
	seeded = 1;
	s[0] = (uint64_t)time(0);
	for (int i = 0; i < 100; ++i) prng();
    }

    uint64_t num = s[0] + s[3];
    uint64_t tmp = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= tmp;
    s[3] = (s[3]<<45) | (s[3]>>19);

    pthread_mutex_unlock(&mutex);

    return num;
}

void swadbcrypt_random(uint8_t *buf, size_t count)
{
    size_t pos = 0;

#ifdef HAVE_GETRANDOM
    unsigned grflags = GRND_NONBLOCK|GRND_RANDOM;
    unsigned grflags2 = GRND_NONBLOCK;
    int dolog = 0;
    while (pos < count)
    {
	if (dolog == 1)
	{
	    fputs("random: Could not obtain cryptographically secure random "
		    "data, trying alternative source (urandom) which might "
		    "not be secure.", stderr);
	    ++dolog;
	}
	errno = 0;
	ssize_t rc = getrandom(buf + pos, count - pos, grflags);
	if (rc < 0)
	{
	    if (errno == EINTR) continue;
	    if (errno == EAGAIN) rc = 0;
	    else break;
	}
	if (!dolog)
	{
	    grflags = grflags2;
	    ++dolog;
	}
	pos += rc;
    }
#else
    int rflags = O_RDONLY|O_NONBLOCK;
    int doswitch = 0;
    int rndfd = open("/dev/random", rflags);
    if (rndfd < 0)
    {
	rndfd = open("/dev/urandom", rflags);
	if (rndfd < 0) goto useprng;
	doswitch = 1;
    }
    while (pos < count)
    {
	if (doswitch == 1)
	{
	    fputs("random: Could not obtain cryptographically secure random "
		    "data, trying alternative source (urandom) which might "
		    "not be secure.", stderr);
	    ++doswitch;
	}
	errno = 0;
	ssize_t rc = read(rndfd, buf + pos, count - pos);
	if (rc < 0)
	{
	    if (errno == EINTR) continue;
	    if (errno == EAGAIN) rc = 0;
	    else break;
	}
	pos += rc;
	if (pos < count && !doswitch)
	{
	    close(rndfd);
	    rndfd = open("/dev/urandom", rflags);
	    if (rndfd < 0) goto useprng;
	    ++doswitch;
	}
    }
    close(rndfd);
useprng:
#endif

    if (pos < count)
    {
	fputs("random: Could not obtain random data, falling back to "
		"xorshift-based internal PRNG, which is NOT cryptographically "
		"secure.", stderr);
	size_t chunks = (count - pos) / sizeof(uint64_t);
	size_t bytes = (count - pos) % sizeof(uint64_t);
	if (bytes)
	{
	    uint64_t rn = prng();
	    memcpy(buf + pos, &rn, bytes);
	    pos += bytes;
	}
	for (size_t i = 0; i < chunks; ++i)
	{
	    uint64_t rn = prng();
	    memcpy(buf + pos, &rn, sizeof rn);
	    pos += sizeof rn;
	}
    }
}

