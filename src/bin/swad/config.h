#ifndef SWAD_CONFIG_H
#define SWAD_CONFIG_H

#include "proxyheader.h"

#include <poser/core/proto.h>
#include <poser/decl.h>
#include <stddef.h>
#include <stdint.h>

C_CLASS_DECL(Config);
C_CLASS_DECL(CfgChecker);
C_CLASS_DECL(CfgRealm);
C_CLASS_DECL(CfgServer);
C_CLASS_DECL(PSC_IpAddr);

typedef enum CheckerClass
{
    CC_NONE,
    CC_EXEC,
    CC_FILE,
    CC_PAM,
    CC_POW
} CheckerClass;

Config *Config_create(int argc, char **argv) ATTR_NONNULL((2));
void Config_readConfigFile(Config *self) CMETHOD;

const CfgChecker *Config_checker(const Config *self, size_t num) CMETHOD;
const char *CfgChecker_name(const CfgChecker *self) CMETHOD ATTR_RETNONNULL;
CheckerClass CfgChecker_class(const CfgChecker *self) CMETHOD;
const char *CfgChecker_arg(const CfgChecker *self, size_t num) CMETHOD;

const CfgRealm *Config_realm(const Config *self, size_t num) CMETHOD;
const char *CfgRealm_name(const CfgRealm *self) CMETHOD ATTR_RETNONNULL;
const char *CfgRealm_checker(const CfgRealm *self, size_t num) CMETHOD;
int CfgRealm_loginFailLimit(const CfgRealm *self, size_t num,
	uint16_t *seconds, uint16_t *limit) CMETHOD;

const CfgServer *Config_server(const Config *self, size_t num) CMETHOD;
const char *CfgServer_name(const CfgServer *self) CMETHOD;
int CfgServer_port(const CfgServer *self) CMETHOD;
const char *CfgServer_listen(const CfgServer *self, size_t num) CMETHOD;
PSC_Proto CfgServer_proto(const CfgServer *self) CMETHOD;
int CfgServer_tls(const CfgServer *self) CMETHOD;
const char *CfgServer_tlsCert(const CfgServer *self) CMETHOD;
const char *CfgServer_tlsKey(const CfgServer *self) CMETHOD;
int CfgServer_trustedProxies(const CfgServer *self) CMETHOD;
ProxyHeader CfgServer_trustedHeader(const CfgServer *self) CMETHOD;
const PSC_IpAddr *CfgServer_nat64Prefix(const CfgServer *self)
    CMETHOD ATTR_RETNONNULL;

long Config_uid(const Config *self) CMETHOD;
long Config_gid(const Config *self) CMETHOD;
const char *Config_pidfile(const Config *self) CMETHOD ATTR_RETNONNULL;
int Config_resolveHosts(const Config *self) CMETHOD;
int Config_foreground(const Config *self) CMETHOD;
int Config_verbose(const Config *self) CMETHOD;
int Config_sessionLimit(const Config *self,
	size_t num, uint16_t *seconds, uint16_t *limit) CMETHOD;
int Config_loginFailLimit(const Config *self,
	size_t num, uint16_t *seconds, uint16_t *limit) CMETHOD;
int Config_defaultThreads(const Config *self) CMETHOD;
int Config_threadsPerCpu(const Config *self) CMETHOD;
int Config_maxThreads(const Config *self) CMETHOD;
int Config_jobQueuePerThread(const Config *self) CMETHOD;
int Config_maxJobQueue(const Config *self) CMETHOD;
const char *Config_loginRoute(const Config *self) CMETHOD ATTR_RETNONNULL;
const char *Config_staticRoute(const Config *self) CMETHOD ATTR_RETNONNULL;
const char *Config_resourceDir(const Config *self) CMETHOD ATTR_RETNONNULL;

void Config_destroy(Config *self);

#endif
