#ifndef SWAD_IPADDR_H
#define SWAD_IPADDR_H

#include <poser/core/proto.h>
#include <poser/decl.h>

C_CLASS_DECL(IpAddr);

IpAddr *IpAddr_create(const char *str)
    ATTR_NONNULL((1));
IpAddr *IpAddr_nat64(const IpAddr *self, const IpAddr **prefixes)
    CMETHOD ATTR_NONNULL((2));
PSC_Proto IpAddr_proto(const IpAddr *self)
    CMETHOD ATTR_PURE;
unsigned IpAddr_prefixlen(const IpAddr *self)
    CMETHOD ATTR_PURE;
const char *IpAddr_string(const IpAddr *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
int IpAddr_equals(const IpAddr *self, const IpAddr *other)
    CMETHOD ATTR_NONNULL((2)) ATTR_PURE;
int IpAddr_matches(const IpAddr *self, const IpAddr *prefix)
    CMETHOD ATTR_NONNULL((2)) ATTR_PURE;
void IpAddr_destroy(IpAddr *self);

#endif
