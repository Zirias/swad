GEN_BIN2CSTR_tool=	$(BIN2CSTR_TARGET)
GEN_BIN2CSTR_args=	$1 $2
GEN_CHELP_tool=		$(MKCLIDOC_TARGET)
GEN_CHELP_args=		-fcpp -o$1 $2

swad_VERSION=		0.1
swad_MODULES=		authenticator \
			config \
			base64 \
			cred/pamchecker \
			handler/login \
			handler/root \
			htmlescape \
			http/header \
			http/headerset \
			http/httpcontext \
			http/httprequest \
			http/httpresponse \
			http/httpstatus \
			httpserver \
			ipaddr \
			main \
			mediatype \
			middleware/compress \
			middleware/cookies \
			middleware/csrfprotect \
			middleware/formdata \
			middleware/pathparser \
			middleware/session \
			proxylist \
			random \
			template \
			tmpl \
			urlencode \
			utf8 \
			util
swad_DEFINES=		-DLIBEXECDIR=\"$(libexecdir)\" \
			-DRUNSTATEDIR=\"$(runstatedir)\" \
			-DSYSCONFDIR=\"$(sysconfdir)\" \
			-DVERSION=\"$(swad_VERSION)\"
swad_LDFLAGS=		-pthread
swad_PKGDEPS=		zlib
swad_TMPL=		login \
			logout
swad_GEN=		BIN2CSTR CHELP
swad_BIN2CSTR_FILES=	$(foreach l,$(swad_TMPL),tmpl/$l.html.h:tmpl/$l.html)
swad_CHELP_FILES=	help.h:swad.cdoc
swad_SUB_FILES=		swad.cdoc \
			swad.conf.sample
swad_SUB_LIST=		"RUNSTATEDIR=$(runstatedir)" \
			"SYSCONFDIR=$(sysconfdir)"
swad_DOCS=		README.md \
			LICENSE.txt
swad_EXTRADIRS=		sysconf
swad_sysconf_FILES=	swad.conf.sample

ifeq ($(BUNDLED_POSER),1)
swad_STATICDEPS+=	posercore
swad_PRECFLAGS+=	-I./poser/include
swad_LIBS+=		posercore $(posercore_LIBS)
swad_LDFLAGS+=		$(posercore_LDFLAGS)
swad_PKGDEPS+=		$(posercore_PKGDEPS)
swad_DEFINES+=		-DBUNDLED_POSER
else
swad_PKGDEPS+=		posercore >= 1.2.3
endif

ifeq ($(WITH_MAN),1)
MANFMT:=		$(or $(MANFMT),$(if \
			$(findstring BSD,$(SYSNAME)),mdoc,man))
GEN_MAN_tool=		$(MKCLIDOC_TARGET)
GEN_MAN_args=		-f$(MANFMT),sect=$(swad_MANSECT) -o$1 $2
swad_MANSECT=		8
swad_MAN8=		swad
swad_GEN+=		MAN
swad_MAN_FILES=		swad.8:swad.cdoc
endif

$(call binrules,swad)
