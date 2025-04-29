#ifndef SWAD_STATICFILES_H
#define SWAD_STATICFILES_H

#include <stddef.h>

#ifdef CRED_POW
extern const unsigned char *static_pow_mjs;
extern const size_t static_pow_mjs_sz;
extern const unsigned static_pow_mjs_vers;
#endif
extern const unsigned char *static_style_css;
extern const size_t static_style_css_sz;
extern const unsigned static_style_css_vers;

#endif
