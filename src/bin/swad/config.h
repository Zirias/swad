#ifndef SWAD_CONFIG_H
#define SWAD_CONFIG_H

#include <poser/decl.h>
#include <stddef.h>

C_CLASS_DECL(CfgChecker);
C_CLASS_DECL(CfgRealm);

typedef enum CheckerClass
{
    CC_NONE,
    CC_PAM
} CheckerClass;

int Config_init(int argc, char **argv) ATTR_NONNULL((2));

const CfgChecker *Config_checker(size_t num);
const char *CfgChecker_name(const CfgChecker *self) CMETHOD ATTR_RETNONNULL;
CheckerClass CfgChecker_class(const CfgChecker *self) CMETHOD;
const char *CfgChecker_arg(const CfgChecker *self, size_t num) CMETHOD;

const CfgRealm *Config_realm(size_t num);
const char *CfgRealm_name(const CfgRealm *self) CMETHOD ATTR_RETNONNULL;
const char *CfgRealm_checker(const CfgRealm *self, size_t num) CMETHOD;

const char *Config_pidfile(void) ATTR_RETNONNULL;

void Config_done(void);

#endif
