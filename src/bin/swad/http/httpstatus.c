#include "httpstatus.h"

HttpStatus HttpStatus_downgrade(HttpStatus status, HttpVersion version)
{
    switch (version)
    {
	case HTTP_1_1:
	    return status;

	case HTTP_1_0:
	    switch (status)
	    {
		case HTTP_SEEOTHER: return HTTP_FOUND;
		default:	    return status;
	    }

	default:
	    return status;
    }
}
