#include "mediatype.h"

const char *MediaType_str(MediaType self)
{
    switch (self)
    {
	case MT_TEXT: return "text/plain; charset=utf-8";
	case MT_HTML: return "text/html; charset=utf-8";
	case MT_CSS: return "text/css; charset=utf-8";
	case MT_PNG: return "image/png";
	case MT_GIF: return "image/gif";
	default: return "application/octet-stream";
    }
}

