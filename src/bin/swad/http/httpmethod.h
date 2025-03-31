#ifndef SWAD_HTTPMETHOD_H
#define SWAD_HTTPMETHOD_H

typedef enum HttpMethod {
    HTTP_INVALM	 = 0,
    HTTP_OPTIONS = 1 << 0,
    HTTP_GET	 = 1 << 1,
    HTTP_HEAD	 = 1 << 2,
    HTTP_POST	 = 1 << 3,
    HTTP_PUT	 = 1 << 4,
    HTTP_DELETE	 = 1 << 5,
    HTTP_TRACE	 = 1 << 6,
    HTTP_CONNECT = 1 << 7,
    HTTP_ANYM	 = (1 << 8) - 1
} HttpMethod;

#endif
