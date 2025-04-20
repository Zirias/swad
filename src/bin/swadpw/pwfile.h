#ifndef SWADPW_PWFILE_H
#define SWADPW_PWFILE_H

typedef struct PwEntry PwEntry;
typedef struct PwFile PwFile;

typedef enum HashType
{
    HT_UNKNOWN,
    HT_BCRYPT_OPENBSD,
    HT_BCRYPT_APACHE
} HashType;

PwFile *PwFile_create(const char *path, int allowNew);
PwEntry *PwFile_entry(PwFile *self, const char *user, int missingOk);
PwEntry *PwFile_addEntry(PwFile *self, const char *user);
int PwFile_deleteEntry(PwFile *self, const char *user);
int PwFile_write(PwFile *self);
void PwFile_destroy(PwFile *self);

const char *PwEntry_name(const PwEntry *self);
HashType PwEntry_hashType(const PwEntry *self);
char *PwEntry_hash(PwEntry *self);
void PwEntry_setName(PwEntry *self, const char *name);

#endif
