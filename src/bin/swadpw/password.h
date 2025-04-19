#ifndef SWADPW_PASSWORD_H
#define SWADPW_PASSWORD_H

typedef struct Password Password;

Password *Password_read(const char *user, int allowStdin);
const char *Password_str(const Password *self);
void Password_destroy(Password *self);

#endif
