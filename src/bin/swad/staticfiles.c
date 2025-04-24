#include "staticfiles.h"

#include "suppress.h"

SUPPRESS(overlength-strings)

static const unsigned char static_pow_mjs_a[sizeof
#include "static/pow.mjs.h"
- 1] =
#include "static/pow.mjs.h"
;
const unsigned char *static_pow_mjs = static_pow_mjs_a;
const size_t static_pow_mjs_sz = sizeof
#include "static/pow.mjs.h"
- 1;

ENDSUPPRESS
