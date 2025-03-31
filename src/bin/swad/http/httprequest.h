#ifndef SWAD_HTTPREQUEST_H
#define SWAD_HTTPREQUEST_H

#include "httpmethod.h"
#include "httpstatus.h"
#include "httpversion.h"

#include <poser/decl.h>
#include <stddef.h>
#include <stdint.h>

C_CLASS_DECL(HttpRequest);
C_CLASS_DECL(HeaderSet);
C_CLASS_DECL(PSC_Connection);
C_CLASS_DECL(PSC_Event);

HttpRequest *HttpRequest_create(PSC_Connection *conn)
    ATTR_NONNULL((1)) ATTR_RETNONNULL;
HeaderSet *HttpRequest_headers(HttpRequest *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
const char *HttpRequest_path(const HttpRequest *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
HttpMethod HttpRequest_method(const HttpRequest *self)
    CMETHOD ATTR_PURE;
HttpStatus HttpRequest_status(const HttpRequest *self)
    CMETHOD ATTR_PURE;
HttpVersion HttpRequest_version(const HttpRequest *self)
    CMETHOD ATTR_PURE;
const char *HttpRequest_rawMethod(const HttpRequest *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
const uint8_t *HttpRequest_body(const HttpRequest *self)
    CMETHOD ATTR_PURE;
size_t HttpRequest_bodySize(const HttpRequest *self)
    CMETHOD ATTR_PURE;
PSC_Event *HttpRequest_received(HttpRequest *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
void HttpRequest_deleteLater(HttpRequest *self);
void HttpRequest_destroy(HttpRequest *self);

#endif
