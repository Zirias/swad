#include "httpresponse.h"

#include "../util.h"
#include "header.h"
#include "headerset.h"
#include "httpstatus.h"
#include "httpversion.h"

#include <poser/core.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERROR_FORMAT "<html><head><title>%s</title></head>" \
    "<body><h1>%s</h1><p>%s</p></body></html>"
#define ERROR_SIZE (sizeof ERROR_FORMAT - 7)
#define REDIRECT_FORMAT "<html><head><title>%s</title>" \
    "<meta http-equiv=\"refresh\" content=\"0; URL=%s\"></head>" \
    "<body><a href=\"%s\">%s</a></body></html>"
#define REDIRECT_SIZE (sizeof REDIRECT_FORMAT - 9)

static void abortSending(void *receiver, void *sender, void *args);
static void deleteResponse(void *receiver, void *sender, void *args);
static char *methodsStr(HttpMethod mask) ATTR_MALLOC;
static const char *methodStr(HttpMethod method) ATTR_CONST;
static void sendBody(void *receiver, void *sender, void *args);
static const char *statusMsg(HttpStatus status) ATTR_CONST ATTR_RETNONNULL;
static const char *statusStr(HttpStatus status) ATTR_CONST;
static const char *versionStr(HttpVersion version) ATTR_CONST ATTR_RETNONNULL;

struct HttpResponse
{
    size_t bodySize;
    size_t sendPos;
    HeaderSet *headers;
    uint8_t *body;
    uint8_t *headerBuf;
    PSC_Event *sent;
    HttpStatus status;
    HttpVersion version;
    uint8_t deleteScheduled;
};

static const char *methodStr(HttpMethod method)
{
    switch (method)
    {
	case HTTP_OPTIONS: return "OPTIONS";
	case HTTP_GET: return "GET";
	case HTTP_HEAD: return "HEAD";
	case HTTP_POST: return "POST";
	case HTTP_PUT: return "PUT";
	case HTTP_DELETE: return "DELETE";
	case HTTP_TRACE: return "TRACE";
	case HTTP_CONNECT: return "CONNECT";
	default: return 0;
    }
}

static char *methodsStr(HttpMethod mask)
{
    char *methods[9] = {0};
    int i = 0;
    for (int b = 0; b < 8; ++b)
    {
	if (mask & (1 << b)) methods[i++] = (char *)methodStr(1 << b);
    }
    if (!i) return 0;
    return joinstr(", ", methods);
}

static const char *versionStr(HttpVersion version)
{
    switch (version)
    {
	case HTTP_1_0: return "HTTP/1.0";
	default: return "HTTP/1.1";
    }
}

static const char *statusStr(HttpStatus status)
{
    switch (status)
    {
	case HTTP_OK: return "200 OK";
	case HTTP_CREATED: return "201 Created";
	case HTTP_FOUND: return "302 Found";
	case HTTP_SEEOTHER: return "303 See Other";
	case HTTP_BADREQUEST: return "400 Bad Request";
	case HTTP_UNAUTHORIZED: return "401 Unauthorized";
	case HTTP_FORBIDDEN: return "403 Forbidden";
	case HTTP_NOTFOUND: return "404 Not Found";
	case HTTP_METHODNOTALLOWED: return "405 Method Not Allowed";
	case HTTP_LENGTHREQUIRED: return "411 Length Required";
	case HTTP_REQUESTENTITYTOOLARGE: return "413 Request Entity Too Large";
	case HTTP_TOOMANYREQUESTS: return "429 Too Many Requests";
	case HTTP_INTERNALSERVERERROR: return "500 Internal Server Error";
	case HTTP_SERVICEUNAVAILABLE: return "503 Service Unavailable";
	default: return 0;
    }
}

static const char *statusMsg(HttpStatus status)
{
    switch (status)
    {
	case HTTP_BADREQUEST: return "Uhm, no.";
	case HTTP_FORBIDDEN: return "No, no!";
	case HTTP_NOTFOUND: return "Nothing here.";
	case HTTP_METHODNOTALLOWED: return "No, no.";
	case HTTP_LENGTHREQUIRED: return "No streams.";
	case HTTP_REQUESTENTITYTOOLARGE: return "Don't exaggerate.";
	case HTTP_TOOMANYREQUESTS: return "Gimme a break.";
	case HTTP_SERVICEUNAVAILABLE: return "Sorry, too busy, try later.";
	default: return "Oops.";
    }
}

HttpResponse *HttpResponse_create(HttpStatus status, MediaType bodyType)
{
    if (!statusStr(status)) return 0;
    HttpResponse *self = PSC_malloc(sizeof *self);
    self->bodySize = 0;
    self->sendPos = 0;
    self->headers = HeaderSet_create();
    self->body = 0;
    self->headerBuf = 0;
    self->sent = PSC_Event_create(self);
    self->status = status;
    self->version = HTTP_1_1;
    self->deleteScheduled = 0;
    const char *contentType = MediaType_str(bodyType);
    if (contentType)
    {
	HeaderSet_add(self->headers,
		Header_create("Content-Type", contentType));
    }
    return self;
}

HttpResponse *HttpResponse_createError(HttpStatus status, const char *message)
{
    HttpResponse *self = HttpResponse_create(status, MT_HTML);
    if (!self) return 0;
    if (!message) message = statusMsg(status);
    const char *ststr = statusStr(status);
    self->bodySize = ERROR_SIZE + 2 * strlen(ststr) + strlen(message);
    char *html = PSC_malloc(self->bodySize + 1);
    sprintf(html, ERROR_FORMAT, ststr, ststr, message);
    self->body = (uint8_t *)html;
    char sizeStr[64];
    snprintf(sizeStr, 64, "%zu", self->bodySize);
    HeaderSet_set(self->headers, Header_create("Content-Length", sizeStr));
    return self;
}

HttpResponse *HttpResponse_createRedirect(
	HttpStatus status, const char *location)
{
    HttpResponse *self = HttpResponse_create(status, MT_HTML);
    if (!self) return 0;
    const char *ststr = statusStr(status);
    size_t contentSize = REDIRECT_SIZE + strlen(ststr) + 3* strlen(location);
    char *rdrContent = PSC_malloc(contentSize + 1);
    sprintf(rdrContent, REDIRECT_FORMAT, ststr, location, location, location);
    self->bodySize = contentSize;
    self->body = (uint8_t *)rdrContent;
    char sizeStr[64];
    snprintf(sizeStr, 64, "%zu", contentSize);
    HeaderSet_set(self->headers, Header_create("Content-Length", sizeStr));
    if (status == HTTP_UNAUTHORIZED)
    {
	HeaderSet_set(self->headers, Header_create("WWW-Authenticate",
		    "PBLoginForm realm=\"PB\""));
    }
    else
    {
	HeaderSet_set(self->headers, Header_create("Location", location));
    }
    return self;
}

HeaderSet *HttpResponse_headers(HttpResponse *self)
{
    return self->headers;
}

HttpVersion HttpResponse_version(const HttpResponse *self)
{
    return self->version;
}

HttpStatus HttpResponse_status(const HttpResponse *self)
{
    return self->status;
}

const uint8_t *HttpResponse_body(const HttpResponse *self)
{
    return self->body;
}

size_t HttpResponse_bodySize(const HttpResponse *self)
{
    return self->bodySize;
}

void HttpResponse_setAllowHeader(HttpResponse *self, HttpMethod mask)
{
    HeaderSet_set(self->headers, Header_createPassVal("Allow",
		methodsStr(mask)));
}

void HttpResponse_setVersion(HttpResponse *self, HttpVersion version)
{
    self->version = version;
}

void HttpResponse_setBody(HttpResponse *self, const uint8_t *buf, size_t size)
{
    uint8_t *body = PSC_malloc(size);
    memcpy(body, buf, size);
    HttpResponse_passBody(self, body, size);
}

void HttpResponse_passBody(HttpResponse *self, uint8_t *buf, size_t size)
{
    char sizeStr[64];
    snprintf(sizeStr, 64, "%zu", size);
    free(self->body);
    self->body = buf;
    self->bodySize = size;
    HeaderSet_set(self->headers, Header_create("Content-Length", sizeStr));
}

void HttpResponse_setTextBody(HttpResponse *self, const char *body)
{
    HttpResponse_setBody(self, (const uint8_t *)body, strlen(body));
}

void HttpResponse_passTextBody(HttpResponse *self, char *body)
{
    HttpResponse_passBody(self, (uint8_t *)body, strlen(body));
}

static void sendBody(void *receiver, void *sender, void *args)
{
    (void) args;

    HttpResponse *self = receiver;
    PSC_Connection *conn = sender;
    size_t remaining = self->bodySize - self->sendPos;
    if (!remaining)
    {
	PSC_Event_unregister(PSC_Connection_closed(conn), self,
		abortSending, 0);
	PSC_Event_unregister(PSC_Connection_dataSent(conn), self, sendBody, 0);
	PSC_Event_raise(self->sent, 0, conn);
	return;
    }
    if (remaining > UINT16_MAX) remaining = UINT16_MAX;
    PSC_Connection_sendAsync(conn, self->body + self->sendPos,
	    (uint16_t)remaining, self);
    self->sendPos += remaining;
}

static void abortSending(void *receiver, void *sender, void *args)
{
    (void) args;

    HttpResponse *self = receiver;
    PSC_Connection *conn = sender;

    self->sendPos = 0;
    PSC_Event_unregister(PSC_Connection_closed(conn), self, abortSending, 0);
    PSC_Event_unregister(PSC_Connection_dataSent(conn), self, sendBody, 0);
    PSC_Event_raise(self->sent, 0, 0);
}

int HttpResponse_send(HttpResponse *self, PSC_Connection *conn)
{
    if (self->version == HTTP_1_0)
    {
	switch (self->status)
	{
	    case HTTP_SEEOTHER:
		self->status = HTTP_FOUND;
		break;

	    case HTTP_REQUESTENTITYTOOLARGE:
		self->status = HTTP_BADREQUEST;
		break;

	    default:
		break;
	}
    }
    if (!HeaderSet_first(self->headers, "Cache-Control"))
    {
	HeaderSet_add(self->headers, Header_create("Cache-Control",
		    "no-cache, no-store, must-revalidate"));
    }
    size_t statuslen = strlen(statusStr(self->status));
    uint16_t headersize = HeaderSet_size(self->headers);
    free(self->headerBuf);
    self->headerBuf = PSC_malloc(headersize + statuslen + 13);
    sprintf((char *)self->headerBuf, "%s %s\r\n",
	    versionStr(self->version), statusStr(self->status));
    uint8_t *buf = self->headerBuf + statuslen + 11;
    HeaderIterator *it = HeaderSet_all(self->headers);
    while (HeaderIterator_moveNext(it))
    {
	buf += Header_writeTo(HeaderIterator_current(it), buf);
    }
    HeaderIterator_destroy(it);
    *buf++ = (uint8_t)'\r';
    *buf = (uint8_t)'\n';
    PSC_Event_register(PSC_Connection_dataSent(conn), self, sendBody, 0);
    PSC_Event_register(PSC_Connection_closed(conn), self, abortSending, 0);
    self->sendPos = 0;
    PSC_Connection_sendAsync(conn, self->headerBuf,
	    headersize + statuslen + 13, self);
    return 1;
}

static void deleteResponse(void *receiver, void *sender, void *args)
{
    (void)sender;
    (void)args;

    HttpResponse *self = receiver;
    self->deleteScheduled = 2;
    HttpResponse_destroy(self);
}

PSC_Event *HttpResponse_sent(HttpResponse *self)
{
    return self->sent;
}

void HttpResponse_deleteLater(HttpResponse *self)
{
    if (!self) return;
    if (!self->deleteScheduled)
    {
	PSC_Event_register(PSC_Service_eventsDone(), self, deleteResponse, 0);
	self->deleteScheduled = 1;
    }
}

void HttpResponse_destroy(HttpResponse *self)
{
    if (!self) return;
    if (self->deleteScheduled == 1) return;
    HeaderSet_destroy(self->headers);
    if (self->deleteScheduled)
    {
	PSC_Event_unregister(PSC_Service_eventsDone(), self,
		deleteResponse, 0);
    }
    free(self->body);
    free(self->headerBuf);
    PSC_Event_destroy(self->sent);
    free(self);
}

