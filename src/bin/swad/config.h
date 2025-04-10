#ifndef SWAD_CONFIG_H
#define SWAD_CONFIG_H

#include "proxyheader.h"

#include <poser/core/proto.h>
#include <poser/decl.h>
#include <stddef.h>
#include <stdint.h>

C_CLASS_DECL(CfgChecker);
C_CLASS_DECL(CfgRealm);
C_CLASS_DECL(CfgServer);
C_CLASS_DECL(IpAddr);

typedef enum CheckerClass
{
    CC_NONE,
    CC_PAM
} CheckerClass;

int Config_init(int argc, char **argv) ATTR_NONNULL((2));
void Config_readConfigFile(void);

const CfgChecker *Config_checker(size_t num);
const char *CfgChecker_name(const CfgChecker *self) CMETHOD ATTR_RETNONNULL;
CheckerClass CfgChecker_class(const CfgChecker *self) CMETHOD;
const char *CfgChecker_arg(const CfgChecker *self, size_t num) CMETHOD;

const CfgRealm *Config_realm(size_t num);
const char *CfgRealm_name(const CfgRealm *self) CMETHOD ATTR_RETNONNULL;
const char *CfgRealm_checker(const CfgRealm *self, size_t num) CMETHOD;
int CfgRealm_loginFailLimit(const CfgRealm *self, size_t num,
	uint16_t *seconds, uint16_t *limit) CMETHOD;

const CfgServer *Config_server(size_t num);
const char *CfgServer_name(const CfgServer *self) CMETHOD;
int CfgServer_port(const CfgServer *self) CMETHOD;
const char *CfgServer_listen(const CfgServer *self, size_t num) CMETHOD;
PSC_Proto CfgServer_proto(const CfgServer *self) CMETHOD;
int CfgServer_tls(const CfgServer *self) CMETHOD;
const char *CfgServer_tlsCert(const CfgServer *self) CMETHOD;
const char *CfgServer_tlsKey(const CfgServer *self) CMETHOD;
int CfgServer_trustedProxies(const CfgServer *self) CMETHOD;
ProxyHeader CfgServer_trustedHeader(const CfgServer *self) CMETHOD;
const IpAddr *CfgServer_nat64Prefix(const CfgServer *self)
    CMETHOD ATTR_RETNONNULL;

long Config_uid(void);
long Config_gid(void);
const char *Config_pidfile(void) ATTR_RETNONNULL;
int Config_resolveHosts(void);
int Config_foreground(void);
int Config_verbose(void);
int Config_sessionLimit(size_t num, uint16_t *seconds, uint16_t *limit);
int Config_loginFailLimit(size_t num, uint16_t *seconds, uint16_t *limit);

void Config_done(void);

#endif
