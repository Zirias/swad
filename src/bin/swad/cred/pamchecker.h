#ifndef SWAD_CRED_PAMCHECKER_H
#define SWAD_CRED_PAMCHECKER_H

#include <poser/decl.h>

C_CLASS_DECL(CredentialsChecker);

CredentialsChecker *CredentialsChecker_createPam(const char *service)
    ATTR_NONNULL((1));

#endif
