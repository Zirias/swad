#ifndef SWADBCRYPT_SWADBCRYPT_H
#define SWADBCRYPT_SWADBCRYPT_H

#define BCRYPT_HASHSZ 61

int swad_bcrypt_check(const char *pw, const char *hash);
int swad_bcrypt_hash(char *buf, size_t sz, int log_rounds, const char *pw);

#endif
