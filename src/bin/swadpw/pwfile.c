#define _POSIX_C_SOURCE 200112L

#include "pwfile.h"
#include "util.h"

#include <swadbcrypt.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char buf[16 * 1024];
static size_t bufpos;
static size_t bufused;
static int bufeof;

struct PwFile
{
    const char *path;
    PwEntry *entries;
    size_t entries_count;
    size_t entries_capa;
};

struct PwEntry
{
    char *unparsed;
    char *user;
    char *name;
    size_t unparsedlen;
    HashType type;
    char hash[BCRYPT_HASHSZ];
};

int ensurebuf(int fd)
{
    if (bufpos < bufused) return 0;
    ssize_t rc = read(fd, buf, sizeof buf);
    if (rc < 0) return -1;
    bufpos = 0;
    if (!(bufused = rc)) bufeof = 1;
    return 0;
}

int parseEntry(PwFile *self, int fd)
{
    if (self->entries_count == self->entries_capa)
    {
	self->entries_capa += 16;
	self->entries = xrealloc(self->entries,
		self->entries_capa * sizeof *self->entries);
    }
    do
    {
	while (bufpos < bufused && buf[bufpos] == '\n') ++bufpos;
	if (ensurebuf(fd) < 0) return -1;
	if (bufeof) return 0;
    } while (buf[bufpos] == '\n');

    PwEntry *entry = self->entries + self->entries_count++;
    entry->unparsed = 0;
    entry->user = 0;
    entry->name = 0;
    entry->unparsedlen = 0;
    entry->type = HT_UNKNOWN;
    entry->hash[0] = 0;

    char *nl = memchr(buf + bufpos, '\n', bufused - bufpos);
    while (!nl)
    {
	size_t newlen = entry->unparsedlen + (bufused - bufpos);
	entry->unparsed = xrealloc(entry->unparsed, newlen + 1);
	memcpy(entry->unparsed + entry->unparsedlen, buf + bufpos,
		bufused - bufpos);
	entry->unparsedlen = newlen;
	if (ensurebuf(fd) < 0) return -1;
	if (bufeof) nl = buf;
	else nl = memchr(buf, '\n', bufused);
    }
    size_t len = nl - (buf + bufpos);
    if (len)
    {
	entry->unparsed = xrealloc(entry->unparsed,
		entry->unparsedlen + len + 1);
	memcpy(entry->unparsed, buf + bufpos, len);
	bufpos += len + 1;
	entry->unparsedlen += len;
    }
    entry->unparsed[entry->unparsedlen] = 0;

    char *colon = strchr(entry->unparsed, ':');
    if (!colon || colon == entry->unparsed) return 1;
    size_t userlen = colon - entry->unparsed;
    entry->user = xmalloc(userlen + 1);
    memcpy(entry->user, entry->unparsed, userlen);
    entry->user[userlen] = 0;

    char *hash = colon+1;
    if (!*hash) return 1;
    if (hash[0] == '$' && hash[1] == '2' && hash[2] && hash[3] == '$')
    {
	switch (hash[2])
	{
	    case 'a':
	    case 'b':
		entry->type = HT_BCRYPT_OPENBSD;
		break;

	    case 'x':
	    case 'y':
		entry->type = HT_BCRYPT_APACHE;
		break;
	}
    }
    colon = strchr(hash, ':');
    if (!colon || colon == hash) return 1;
    if (!*++colon) return 1;
    size_t namelen = entry->unparsedlen - (colon - entry->unparsed);
    if (!namelen) return 1;
    entry->name = xmalloc(namelen + 1);
    memcpy(entry->name, colon, namelen);
    entry->name[namelen] = 0;
    return 1;
}

PwFile *PwFile_create(const char *path, int allowNew)
{
    int fd = -1;
    if (allowNew) fd = open(path, O_RDONLY|O_CREAT, 0600);
    else fd = open(path, O_RDONLY);

    if (fd < 0)
    {
	fprintf(stderr, "Error opening %s: %s\n", path, strerror(errno));
	return 0;
    }

    PwFile *self = xmalloc(sizeof *self);
    memset(self, 0, sizeof *self);
    self->path = path;
    bufeof = 0;
    int rc;
    while ((rc = parseEntry(self, fd)) == 1) if (bufeof) break;
    if (rc < 0)
    {
	fprintf(stderr, "Error reading %s: %s\n", path, strerror(errno));
	PwFile_destroy(self);
	self = 0;
    }
    close(fd);
    return self;
}

PwEntry *PwFile_entry(PwFile *self, const char *user, int missingOk)
{
    for (size_t i = 0; i < self->entries_count; ++i)
    {
	if (self->entries[i].user && !strcmp(self->entries[i].user, user))
	{
	    return self->entries + i;
	}
    }
    if (!missingOk) fprintf(stderr, "Error: user %s does not exist in %s.\n",
	    user, self->path);
    return 0;
}

PwEntry *PwFile_addEntry(PwFile *self, const char *user)
{
    if (PwFile_entry(self, user, 1))
    {
	fprintf(stderr, "Error adding %s to %s: User already exists.\n",
		user, self->path);
	return 0;
    }
    if (self->entries_count == self->entries_capa)
    {
	self->entries_capa += 16;
	self->entries = xrealloc(self->entries,
		self->entries_capa * sizeof *self->entries);
    }
    PwEntry *entry = self->entries + self->entries_count++;
    entry->unparsed = 0;
    entry->user = strdup(user);
    entry->name = 0;
    entry->hash[0] = 0;
    return entry;
}

int PwFile_deleteEntry(PwFile *self, const char *user)
{
    PwEntry *entry = PwFile_entry(self, user, 1);
    if (!entry || (!entry->unparsed && !entry->user))
    {
	fprintf(stderr, "Error deleting %s from %s: User not found.\n",
		user, self->path);
	return -1;
    }
    free(entry->user);
    entry->user = 0;
    if (entry->unparsed)
    {
	wipemem(entry->unparsed, entry->unparsedlen);
	free(entry->unparsed);
	entry->unparsed = 0;
    }
    entry->hash[0] = 0;
    return 0;
}

static int flushbuf(int fd)
{
    if (!bufused) return 0;
    for (size_t wrpos = 0; wrpos < bufused; )
    {
	ssize_t written = write(fd, buf + wrpos, bufused - wrpos);
	if (written < 0) return -1;
	wrpos += written;
    }
    bufused = 0;
    return 0;
}

static int writeEntry(int fd, PwEntry *entry)
{
    if (!entry->unparsed && !entry->user) return 0;
    if (bufused == sizeof buf)
    {
	if (flushbuf(fd) < 0) return -1;
    }
    if (entry->user && entry->hash[0] && entry->unparsed)
    {
	wipemem(entry->unparsed, entry->unparsedlen);
	free(entry->unparsed);
	entry->unparsed = 0;
    }
    if (!entry->unparsed)
    {
	entry->unparsedlen = strlen(entry->user) + 1 + strlen(entry->hash)
	    + (entry->name ? 1 + strlen(entry->name) : 0);
	entry->unparsed = xmalloc(entry->unparsedlen + 1);
	if (entry->name)
	{
	    snprintf(entry->unparsed, entry->unparsedlen + 1, "%s:%s:%s",
		    entry->user, entry->hash, entry->name);
	}
	else
	{
	    snprintf(entry->unparsed, entry->unparsedlen + 1, "%s:%s",
		    entry->user, entry->hash);
	}
	entry->hash[0] = 0;
    }
    size_t wrpos = 0;
    while (wrpos < entry->unparsedlen)
    {
	size_t maxwr = sizeof buf - bufused;
	if (!maxwr)
	{
	    if (flushbuf(fd) < 0) return -1;
	    continue;
	}
	size_t wrsz = maxwr < entry->unparsedlen - wrpos
	    ? maxwr : entry->unparsedlen - wrpos;
	memcpy(buf + bufused, entry->unparsed + wrpos, wrsz);
	bufused += wrsz;
	wrpos += wrsz;
    }
    if (bufused == sizeof buf)
    {
	if (flushbuf(fd) < 0) return -1;
    }
    buf[bufused++] = '\n';
    return 0;
}

int PwFile_write(PwFile *self)
{
    static const char tmpfmt[] = "%s.swadpw.%07u.tmp";
    size_t tmpsz = strlen(self->path) + sizeof tmpfmt + 1;
    char *tmpnm = xmalloc(tmpsz + 1);
    snprintf(tmpnm, tmpsz, tmpfmt, self->path, (unsigned)getpid());

    struct stat st;
    int havest = 0;
    if (stat(self->path, &st) == 0) havest = 1;

    int rc = -1;
    int tmpfd = open(tmpnm, O_WRONLY|O_CREAT|O_EXCL,
	    havest ? st.st_mode :  0600);
    if (tmpfd < 0)
    {
	fprintf(stderr, "Error creating temp file for %s: %s\n",
		self->path, strerror(errno));
	goto done;
    }

    bufused = 0;
    for (size_t i = 0; i < self->entries_count; ++i)
    {
	if (writeEntry(tmpfd, self->entries + i) < 0)
	{
	    fprintf(stderr, "Error writing temp file for %s: %s\n",
		    self->path, strerror(errno));
	    goto done;
	}
    }
    if (bufused)
    {
	if (flushbuf(tmpfd) < 0)
	{
	    fprintf(stderr, "Error writing temp file for %s: %s\n",
		    self->path, strerror(errno));
	    goto done;
	}
    }
    close(tmpfd);
    tmpfd = -1;

    if (rename(tmpnm, self->path) < 0)
    {
	fprintf(stderr, "Error overwriting %s: %s\n",
		self->path, strerror(errno));
    }
    if (havest)
    {
	if (chown(self->path, st.st_uid, st.st_gid) < 0)
	{
	    fprintf(stderr, "Warning: Could not preserve the original owner "
		    "of %s\n", self->path);
	}
    }
    rc = 0;

done:
    if (tmpfd >= 0) close(tmpfd);
    unlink(tmpnm);
    free(tmpnm);
    return rc;
}

void PwFile_destroy(PwFile *self)
{
    if (!self) return;
    for (size_t i = 0; i < self->entries_count; ++i)
    {
	wipemem(self->entries[i].hash, sizeof self->entries[i].hash);
	free(self->entries[i].name);
	free(self->entries[i].user);
	if (self->entries[i].unparsed)
	{
	    wipemem(self->entries[i].unparsed, self->entries[i].unparsedlen);
	    free(self->entries[i].unparsed);
	}
    }
    free(self->entries);
    free(self);
    wipemem(buf, sizeof buf);
}

const char *PwEntry_name(const PwEntry *self)
{
    return self->name;
}

HashType PwEntry_hashType(const PwEntry *self)
{
    return self->type;
}

char *PwEntry_hash(PwEntry *self)
{
    return self->hash;
}

void PwEntry_setName(PwEntry *self, const char *name)
{
    free(self->name);
    self->name = strdup(name);
}

