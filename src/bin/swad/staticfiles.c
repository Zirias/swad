#include "staticfiles.h"

#include "suppress.h"

SUPPRESS(overlength-strings)

#ifdef CRED_POW
static const unsigned char static_pow_mjs_a[sizeof
#include "static/pow.mjs.h"
- 1] =
#include "static/pow.mjs.h"
;
const unsigned char *static_pow_mjs = static_pow_mjs_a;
const size_t static_pow_mjs_sz = sizeof
#include "static/pow.mjs.h"
- 1;
const unsigned static_pow_mjs_vers = 0;
#endif

static const unsigned char static_style_css_a[sizeof
#include "static/style.css.h"
- 1] =
#include "static/style.css.h"
;
const unsigned char *static_style_css = static_style_css_a;
const size_t static_style_css_sz = sizeof
#include "static/style.css.h"
- 1;
const unsigned static_style_css_vers = 0;

ENDSUPPRESS
