#ifndef SWAD_PROXYLIST_H
#define SWAD_PROXYLIST_H

#include <poser/decl.h>

C_CLASS_DECL(HttpContext);
C_CLASS_DECL(PSC_List);
C_CLASS_DECL(RemoteEntry);

const PSC_List *ProxyList_get(HttpContext *context) CMETHOD ATTR_RETNONNULL;

const char *RemoteEntry_addr(const RemoteEntry *self) CMETHOD ATTR_RETNONNULL;
const char *RemoteEntry_host(const RemoteEntry *self) CMETHOD;

#endif
