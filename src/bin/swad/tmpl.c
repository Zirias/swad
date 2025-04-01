#include "tmpl.h"

#include "suppress.h"

SUPPRESS(overlength-strings)

static const unsigned char tmpl_login_html_a[sizeof
#include "tmpl/login.html.h"
- 1] =
#include "tmpl/login.html.h"
;
const unsigned char *tmpl_login_html = tmpl_login_html_a;
const size_t tmpl_login_html_sz = sizeof
#include "tmpl/login.html.h"
- 1;

static const unsigned char tmpl_logout_html_a[sizeof
#include "tmpl/logout.html.h"
- 1] =
#include "tmpl/logout.html.h"
;
const unsigned char *tmpl_logout_html = tmpl_logout_html_a;
const size_t tmpl_logout_html_sz = sizeof
#include "tmpl/logout.html.h"
- 1;

ENDSUPPRESS
