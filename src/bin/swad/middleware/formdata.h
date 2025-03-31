#ifndef SWAD_MIDDLEWARE_FORMDATA_H
#define SWAD_MIDDLEWARE_FORMDATA_H

#include <poser/decl.h>
#include <stddef.h>

C_CLASS_DECL(FormParam);
C_CLASS_DECL(FormData);

typedef enum FormDataValidate
{
    FDV_NONE,
    FDV_UTF8,
    FDV_UTF8_SANITIZE
} FormDataValidate;

C_CLASS_DECL(HttpContext);

const FormData *FormData_get(const HttpContext *context)
    ATTR_NONNULL((1)) ATTR_PURE;
int FormData_valid(const FormData *self) CMETHOD ATTR_PURE;
const FormParam *FormData_param(const FormData *self,
	const char *name, const FormParam *curr)
    CMETHOD ATTR_NONNULL((2)) ATTR_PURE;
const char *FormData_first(const FormData *self,
	const char *name, size_t *len)
    CMETHOD ATTR_NONNULL((2)) ATTR_ACCESS((write_only, 3));
const char *FormData_single(const FormData *self,
	const char *name, size_t *len)
    CMETHOD ATTR_NONNULL((2)) ATTR_ACCESS((write_only, 3));
const char *FormParam_name(const FormParam *param)
    CMETHOD ATTR_RETNONNULL ATTR_PURE;
size_t FormParam_nameLen(const FormParam *param) CMETHOD ATTR_PURE;
int FormParam_nameValid(const FormParam *param) CMETHOD ATTR_PURE;
const char *FormParam_value(const FormParam *param) CMETHOD ATTR_PURE;
size_t FormParam_valueLen(const FormParam *param) CMETHOD ATTR_PURE;
int FormParam_valueValid(const FormParam *param) CMETHOD ATTR_PURE;

void MW_FormData_setValidation(FormDataValidate validation);
void MW_FormData(HttpContext *context) ATTR_NONNULL((1));

#endif
