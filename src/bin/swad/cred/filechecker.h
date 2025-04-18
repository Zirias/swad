#ifndef SWAD_CRED_FILECHECKER_H
#define SWAD_CRED_FILECHECKER_H

#include <poser/decl.h>

C_CLASS_DECL(CredentialsChecker);

CredentialsChecker *CredentialsChecker_createFile(const char *path)
    ATTR_NONNULL((1));

#endif
