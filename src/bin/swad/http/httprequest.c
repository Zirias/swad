#include "header.h"

#include "headerset.h"
#include "httpmethod.h"
#include "httprequest.h"
#include "httpstatus.h"
#include "httpversion.h"

#include <ctype.h>
#include <poser/core.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAXBODY (1024*1024)

typedef enum ReqRecvState {
    RRS_METHOD,
    RRS_HEADERS,
    RRS_BODY
} ReqRecvState;

typedef enum HdrRecvState {
    HRS_NONE,
    HRS_NONELF,
    HRS_NAME,
    HRS_SPACE,
    HRS_VALUE,
    HRS_EOL
} HdrRecvState;

struct HttpRequest {
    size_t bodySize;
    size_t bodypos;
    PSC_Event *received;
    HeaderSet *headers;
    uint8_t *body;
    HttpMethod method;
    HttpStatus status;
    HttpVersion version;
    ReqRecvState recvState;
    HdrRecvState hdrState;
    uint16_t hdrvalpos;
    uint8_t deleteScheduled;
    char path[8192];
    char hdrval[8192];
    char hdrnm[256];
    char meth[16];
};

static void connectionLost(void *receiver, void *sender, void *args);
static void dataReceived(void *receiver, void *sender, void *args);
static void deleteRequest(void *receiver, void *sender, void *args);

static void connectionLost(void *receiver, void *sender, void *args)
{
    (void)args;

    HttpRequest *self = receiver;
    PSC_Connection *conn = sender;

    PSC_Log_fmt(PSC_L_DEBUG, "httprequest: connection from %s lost",
	    PSC_Connection_remoteAddr(conn));
    PSC_Event_unregister(PSC_Connection_dataReceived(conn), self,
	    dataReceived, 0);
    PSC_Event_unregister(PSC_Connection_closed(conn), self,
	    connectionLost, 0);
    HttpRequest_deleteLater(self);
}

static void dataReceived(void *receiver, void *sender, void *args)
{
    HttpRequest *self = receiver;
    PSC_Connection *conn = sender;
    PSC_EADataReceived *dra = args;

    size_t bodychunk;
    const char *line;
    const char *linep;

    switch (self->recvState)
    {
	case RRS_METHOD:
	    line = PSC_EADataReceived_text(dra);
	    for (linep = line; *linep && *linep != ' '; ++linep)
	    {
		if (!isupper((unsigned char)*linep)) goto error;
	    }
	    if (!*linep || linep == line
		    || (size_t)(linep - line) > sizeof self->meth - 1)
		goto error;
	    memcpy(self->meth, line, linep - line);
	    self->meth[linep - line] = 0;
	    while (*linep == ' ') ++linep;
	    line = linep;
	    for (linep = line; *linep > 0x20 && *linep < 0x7f; ++linep);
	    if (*linep != ' '
		    || (size_t)(linep - line) > sizeof self->path - 1)
		goto error;
	    memcpy(self->path, line, linep - line);
	    self->path[linep - line] = 0;
	    while (*linep == ' ') ++linep;
	    line = linep;
	    if (memcmp("HTTP/1.", line, 7)) goto error;
	    line += 7;
	    if (*line == '1') self->version = HTTP_1_1;
	    else if (*line == '0') self->version = HTTP_1_0;
	    else goto error;
	    ++line;
	    while (*line == ' ') ++line;
	    if (*line != '\r' && *line != '\n') goto error;
	    self->recvState = RRS_HEADERS;
	    return;

	case RRS_HEADERS:
	    line = PSC_EADataReceived_text(dra);
	    if (*line == ' ' || *line == '\t')
	    {
		if (!*self->hdrnm) goto error;
		while (*line == ' ' || *line == '\t') ++line;
		linep = strchr(line, '\r');
		if (!linep) linep = strchr(line, '\n');
		if (!linep) goto error;
		if (self->hdrvalpos + (self->hdrvalpos > 0)
			+ (size_t)(linep - line) > sizeof self->hdrval - 1)
		    goto error;
		if (self->hdrvalpos > 0) self->hdrval[self->hdrvalpos++] = ' ';
		memcpy(self->hdrval + self->hdrvalpos, line, linep - line);
		self->hdrvalpos += linep - line;
		self->hdrval[self->hdrvalpos] = 0;
	    }
	    else
	    {
		if (*self->hdrnm)
		{
		    HeaderSet_add(self->headers,
			    Header_create(self->hdrnm, self->hdrval));
		    *self->hdrnm = 0;
		    self->hdrvalpos = 0;
		}
		if (*line == '\r' || *line == '\n')
		{
		     const Header *contentLength = HeaderSet_first(
			     self->headers, "Content-Length");
		     if (!contentLength)
		     {
			 if (!strcmp(self->meth, "POST")
				 || !strcmp(self->meth, "PUT"))
			 {
			     self->status = HTTP_LENGTHREQUIRED;
			 }
			 goto received;
		     }
		     const char *lengthStr = Header_value(contentLength);
		     char *endp;
		     long long length = strtoll(lengthStr, &endp, 10);
		     if (*endp || length <=0 || length > MAXBODY)
		     {
			 if (length > MAXBODY)
			 {
			     self->status = HTTP_REQUESTENTITYTOOLARGE;
			 }
			 else
			 {
			    self->status = HTTP_BADREQUEST;
			 }
			 goto received;
		     }
		     self->bodySize = length;
		     self->body = PSC_malloc(length);
		     self->recvState = RRS_BODY;
		     PSC_Connection_receiveBinary(conn, 0);
		}
		else
		{
		    linep = strchr(line, ':');
		    if (!linep || linep == line
			    || (size_t)(linep - line) > sizeof self->hdrnm - 1)
			goto error;
		    memcpy(self->hdrnm, line, linep - line);
		    self->hdrnm[linep - line] = 0;
		    line = linep + 1;
		    while (*line == ' ') ++line;
		    linep = strchr(line, '\r');
		    if (!linep) linep = strchr(line, '\n');
		    if (!linep
			    || (size_t)(linep - line) > sizeof self->hdrval - 1)
			goto error;
		    memcpy(self->hdrval, line, linep - line);
		    self->hdrval[linep - line] = 0;
		    self->hdrvalpos = linep - line;
		}
	    }
	    return;

	case RRS_BODY:
	    bodychunk = PSC_EADataReceived_size(dra);
	    if (bodychunk > self->bodySize - self->bodypos)
		bodychunk = self->bodySize - self->bodypos;
	    memcpy(self->body, PSC_EADataReceived_buf(dra), bodychunk);
	    self->bodypos += bodychunk;
	    if (self->bodypos < self->bodySize) return;
	    break;
    }

received:
    if (!strcmp("OPTIONS", self->meth)) self->method = HTTP_OPTIONS;
    else if (!strcmp("GET", self->meth)) self->method = HTTP_GET;
    else if (!strcmp("HEAD", self->meth)) self->method = HTTP_HEAD;
    else if (!strcmp("POST", self->meth)) self->method = HTTP_POST;
    else if (!strcmp("PUT", self->meth)) self->method = HTTP_PUT;
    else if (!strcmp("DELETE", self->meth)) self->method = HTTP_DELETE;
    else if (!strcmp("TRACE", self->meth)) self->method = HTTP_TRACE;
    else if (!strcmp("CONNECT", self->meth)) self->method = HTTP_CONNECT;
    if (self->status == HTTP_OK) switch (self->method)
    {
	case HTTP_GET:
	case HTTP_HEAD:
	case HTTP_DELETE:
	case HTTP_CONNECT:
	    if (self->bodySize) self->status = HTTP_BADREQUEST;
	    break;

	case HTTP_POST:
	case HTTP_PUT:
	    if (!self->bodySize) self->status = HTTP_BADREQUEST;
	    break;

	default:
	    break;
    }
    PSC_Event_unregister(PSC_Connection_dataReceived(conn),
	    self, dataReceived, 0);
    PSC_Event_unregister(PSC_Connection_closed(conn),
	    self, connectionLost, 0);
    PSC_Event_raise(self->received, 0, conn);
    return;

error:
    PSC_Log_fmt(PSC_L_INFO, "httprequest: protocol error from %s",
	    PSC_Connection_remoteAddr(conn));
    PSC_Connection_close(conn, 0);
}

HttpRequest *HttpRequest_create(PSC_Connection *conn)
{
    HttpRequest *self = PSC_malloc(sizeof *self);
    memset(self, 0, sizeof *self);
    self->received = PSC_Event_create(self);
    self->headers = HeaderSet_create();
    self->status = HTTP_OK;
    PSC_Event_register(PSC_Connection_dataReceived(conn), self,
	    dataReceived, 0);
    PSC_Event_register(PSC_Connection_closed(conn), self,
	    connectionLost, 0);
    PSC_Connection_receiveLine(conn);
    return self;
}

HeaderSet *HttpRequest_headers(HttpRequest *self)
{
    return self->headers;
}

const char *HttpRequest_path(const HttpRequest *self)
{
    return self->path;
}

HttpMethod HttpRequest_method(const HttpRequest *self)
{
    return self->method;
}

HttpStatus HttpRequest_status(const HttpRequest *self)
{
    return self->status;
}

HttpVersion HttpRequest_version(const HttpRequest *self)
{
    return self->version;
}

const char *HttpRequest_rawMethod(const HttpRequest *self)
{
    return self->meth;
}

const uint8_t *HttpRequest_body(const HttpRequest *self)
{
    return self->body;
}

size_t HttpRequest_bodySize(const HttpRequest *self)
{
    return self->bodySize;
}

PSC_Event *HttpRequest_received(HttpRequest *self)
{
    return self->received;
}

static void deleteRequest(void *receiver, void *sender, void *args)
{
    (void)sender;
    (void)args;

    HttpRequest *self = receiver;
    self->deleteScheduled = 2;
    HttpRequest_destroy(self);
}

void HttpRequest_deleteLater(HttpRequest *self)
{
    if (!self) return;
    if (!self->deleteScheduled)
    {
	self->deleteScheduled = 1;
	PSC_Event_register(PSC_Service_eventsDone(), self, deleteRequest, 0);
    }
}

void HttpRequest_destroy(HttpRequest *self)
{
    if (!self) return;
    if (self->deleteScheduled == 1) return;
    HeaderSet_destroy(self->headers);
    if (self->deleteScheduled)
    {
	PSC_Event_unregister(PSC_Service_eventsDone(), self, deleteRequest, 0);
    }
    PSC_Event_destroy(self->received);
    free(self->body);
    free(self);
}

