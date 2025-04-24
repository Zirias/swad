#ifndef SWAD_CRED_POWCHECKER_H
#define SWAD_CRED_POWCHECKER_H

#include <poser/decl.h>

C_CLASS_DECL(CredentialsChecker);

CredentialsChecker *CredentialsChecker_createPow(unsigned difficulty,
	const char *user, const char *password)
    ATTR_NONNULL((2)) ATTR_NONNULL((3));

#endif
