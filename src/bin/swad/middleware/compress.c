#include "compress.h"

#include "../http/header.h"
#include "../http/headerset.h"
#include "../http/httpcontext.h"
#include "../http/httprequest.h"
#include "../http/httpresponse.h"

#include <poser/core/util.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static size_t comp_deflate(uint8_t *out, const uint8_t *in, size_t size)
    ATTR_NONNULL((1)) ATTR_NONNULL((2))
    ATTR_ACCESS((write_only, 1, 3)) ATTR_ACCESS((read_only, 2, 3));
static size_t comp_gzip(uint8_t *out, const uint8_t *in, size_t size)
    ATTR_NONNULL((1)) ATTR_NONNULL((2))
    ATTR_ACCESS((write_only, 1, 3)) ATTR_ACCESS((read_only, 2, 3));

static size_t comp_deflate(uint8_t *out, const uint8_t *in, size_t size)
{
    z_stream zs = {0};
    zs.next_in = (Bytef *)in;
    zs.next_out = (Bytef *)out;
    zs.avail_out = zs.avail_in = (uInt)size;
    deflateInit(&zs, Z_DEFAULT_COMPRESSION);
    deflate(&zs, Z_FINISH);
    deflateEnd(&zs);
    return zs.total_out;
}

static size_t comp_gzip(uint8_t *out, const uint8_t *in, size_t size)
{
    z_stream zs = {0};
    zs.next_in = (Bytef *)in;
    zs.next_out = (Bytef *)out;
    zs.avail_out = zs.avail_in = (uInt)size;
    deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
	    31, 8, Z_DEFAULT_STRATEGY);
    deflate(&zs, Z_FINISH);
    deflateEnd(&zs);
    return zs.total_out;
}

void MW_Compress(HttpContext *context)
{
    HttpContext_callNext(context);
    HttpResponse *response = HttpContext_response(context);
    if (!response) return;
    size_t bodySize = HttpResponse_bodySize(response);
    if (!bodySize) return;
    const Header *accept = HeaderSet_first(HttpRequest_headers(
		HttpContext_request(context)), "Accept-Encoding");
    if (!accept) return;
    const char *acceptVal = Header_value(accept);
    int haveDeflate = 0;
    int haveGzip = 0;
    size_t dpos = strcspn(acceptVal, " ,");
    do
    {
	if (dpos == 7 && !memcmp(acceptVal, "deflate", dpos)) haveDeflate = 1;
	if (dpos == 4 && !memcmp(acceptVal, "gzip", dpos)) haveGzip = 1;
	acceptVal += dpos;
	while (*acceptVal == ' ' || *acceptVal == ',') ++acceptVal;
	dpos = strcspn(acceptVal, " ,");
    } while (*acceptVal);
    if (!haveDeflate && !haveGzip) return;
    uint8_t *compressed = PSC_malloc(bodySize);
    size_t compSize;
    if (haveGzip)
    {
	compSize = comp_gzip(compressed,
		HttpResponse_body(response), bodySize);
    }
    else
    {
	compSize = comp_deflate(compressed,
		HttpResponse_body(response), bodySize);
    }
    if (compSize < bodySize)
    {
	HttpResponse_passBody(response, compressed, compSize);
	HeaderSet_set(HttpResponse_headers(response),
		Header_create("Content-Encoding",
		    haveGzip ? "gzip" : "deflate"));
    }
    else free(compressed);
}

