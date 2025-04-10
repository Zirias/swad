#ifndef SWAD_PROXYHEADER_H
#define SWAD_PROXYHEADER_H

typedef enum ProxyHeader
{
    PH_NONE	= 0,
    PH_XFWD	= (1 << 0),
    PH_RFC	= (1 << 1),
    PH_PREFRFC	= (1 << 2)
} ProxyHeader;

#endif
