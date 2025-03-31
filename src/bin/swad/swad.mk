GEN_BIN2CSTR_tool=	$(BIN2CSTR_TARGET)
GEN_BIN2CSTR_args=	$1 $2

swad_VERSION=		0.1
swad_MODULES=		base64 \
			handler/login \
			handler/root \
			htmlescape \
			http/header \
			http/headerset \
			http/httpcontext \
			http/httprequest \
			http/httpresponse \
			httpserver \
			main \
			mediatype \
			middleware/compress \
			middleware/cookies \
			middleware/formdata \
			middleware/pathparser \
			middleware/session \
			random \
			template \
			tmpl \
			urlencode \
			utf8 \
			util
swad_PKGDEPS=		posercore \
			zlib
swad_TMPL=		login
swad_GEN=		BIN2CSTR
swad_BIN2CSTR_FILES=	$(foreach l,$(swad_TMPL),tmpl/$l.html.h:tmpl/$l.html)

$(call binrules,swad)
