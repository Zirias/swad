#ifndef SWAD_HTTPRESPONSE_H
#define SWAD_HTTPRESPONSE_H

#include "../mediatype.h"
#include "httpmethod.h"
#include "httpstatus.h"
#include "httpversion.h"

#include <poser/decl.h>
#include <stddef.h>
#include <stdint.h>

C_CLASS_DECL(HeaderSet);
C_CLASS_DECL(HttpResponse);
C_CLASS_DECL(PSC_Connection);
C_CLASS_DECL(PSC_Event);

HttpResponse *HttpResponse_create(HttpStatus status, MediaType bodyType);
HttpResponse *HttpResponse_createError(HttpStatus status, const char *message);
HttpResponse *HttpResponse_createRedirect(
	HttpStatus status, const char *location) ATTR_NONNULL((2));
HeaderSet *HttpResponse_headers(HttpResponse *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
HttpVersion HttpResponse_version(const HttpResponse *self) CMETHOD ATTR_PURE;
HttpStatus HttpResponse_status(const HttpResponse *self) CMETHOD ATTR_PURE;
const uint8_t *HttpResponse_body(const HttpResponse *self) CMETHOD ATTR_PURE;
size_t HttpResponse_bodySize(const HttpResponse *self) CMETHOD ATTR_PURE;
void HttpResponse_setAllowHeader(HttpResponse *self, HttpMethod mask) CMETHOD;
void HttpResponse_setVersion(HttpResponse *self, HttpVersion version) CMETHOD;
void HttpResponse_setBody(HttpResponse *self, const uint8_t *buf, size_t size)
    CMETHOD ATTR_NONNULL((2));
void HttpResponse_passBody(HttpResponse *self, uint8_t *buf, size_t size)
    CMETHOD ATTR_NONNULL((2));
void HttpResponse_setTextBody(HttpResponse *self, const char *body)
    CMETHOD ATTR_NONNULL((2));
void HttpResponse_passTextBody(HttpResponse *self, char *body)
    CMETHOD ATTR_NONNULL((2));
int HttpResponse_send(HttpResponse *self, PSC_Connection *conn)
    CMETHOD ATTR_NONNULL((2));
PSC_Event *HttpResponse_sent(HttpResponse *self)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
void HttpResponse_deleteLater(HttpResponse *self);
void HttpResponse_destroy(HttpResponse *self);

#endif
