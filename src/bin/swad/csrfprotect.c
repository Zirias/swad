#include "csrfprotect.h"

#include "http/httpcontext.h"
#include "http/httprequest.h"
#include "http/httpresponse.h"
#include "http/httpstatus.h"
#include "middleware/formdata.h"
#include "middleware/session.h"

#include <poser/core.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define PROPNAME "_CSRFPROTECT"

typedef struct CSRFTokens
{
    PSC_HashTable *tokens;
    pthread_mutex_t lock;
} CSRFTokens;

const char *CSRFProtect_name(void)
{
    return PROPNAME;
}

static CSRFTokens *createTokens(void)
{
    CSRFTokens *tokens = PSC_malloc(sizeof *tokens);
    tokens->tokens = PSC_HashTable_create(5);
    pthread_mutex_init(&tokens->lock, 0);
    return tokens;
}

static void deleteTokens(void *obj)
{
    if (!obj) return;
    CSRFTokens *tokens = obj;
    pthread_mutex_destroy(&tokens->lock);
    PSC_HashTable_destroy(tokens->tokens);
    free(tokens);
}

const char *CSRFProtect_token(HttpContext *context, const char *path)
{
    Session *session = Session_start(context);
    if (!session) return 0;
    CSRFTokens *tokens = Session_getProp(session, PROPNAME);
    if (!tokens)
    {
	tokens = createTokens();
	Session_setProp(session, PROPNAME, tokens, deleteTokens);
    }
    pthread_mutex_lock(&tokens->lock);
    char *token = PSC_HashTable_get(tokens->tokens, path);
    if (!token)
    {
	token = PSC_Random_createStr(32, PSC_RF_SECURE, PSC_B64_URLSAFE);
	if (token) PSC_HashTable_set(tokens->tokens, path, token, free);
    }
    pthread_mutex_unlock(&tokens->lock);
    return token;
}

int CSRFProtect_verify(HttpContext *context)
{
    const FormData *form = FormData_get(context);
    if (!form) goto fail;
    const char *tokenVal = FormData_single(form, PROPNAME, 0);
    if (!tokenVal) goto fail;
    Session *session = Session_get(context);
    if (!session) goto fail;
    CSRFTokens *tokens = Session_getProp(session, PROPNAME);
    if (!tokens) goto fail;
    const char *path = HttpRequest_path(HttpContext_request(context));
    pthread_mutex_lock(&tokens->lock);
    const char *token = PSC_HashTable_get(tokens->tokens, path);
    if (!token || strcmp(token, tokenVal))
    {
	pthread_mutex_unlock(&tokens->lock);
	goto fail;
    }
    PSC_HashTable_delete(tokens->tokens, path);
    pthread_mutex_unlock(&tokens->lock);
    return 1;

fail:
    HttpContext_setResponse(context, HttpResponse_createError(
		HTTP_FORBIDDEN, "Possible request tampering detected. "
		"Authorization for submitting this form refused. "
		"Check whether your browser allows session cookies."));
    return 0;
}

