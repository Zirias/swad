#ifndef SWAD_CRED_EXECCHECKER_H
#define SWAD_CRED_EXECCHECKER_H

#include <poser/decl.h>

C_CLASS_DECL(CredentialsChecker);

CredentialsChecker *CredentialsChecker_createExec(const char *path,
	int timeout, int killtimeout)
    ATTR_NONNULL((1));

#endif
