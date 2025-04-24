swad_PRECHECK=		MEMSET_EXP MEMSET_S EXP_BZERO EXP_BZERO_G EXP_BZERO_S
MEMSET_EXP_FUNC=	memset_explicit
MEMSET_EXP_HEADERS=	string.h
MEMSET_EXP_CFLAGS=	-std=c23
MEMSET_EXP_ARGS=	void *, int, size_t
MEMSET_EXP_RETURN=	void *
MEMSET_S_FUNC=		memset_s
MEMSET_S_HEADERS=	string.h
MEMSET_S_CFLAGS=	-D__STC_WANT_LIB_EXT1__=1
MEMSET_S_ARGS=		void *, rsize_t, int, rsize_t
MEMSET_S_RETURN=	errno_t
EXP_BZERO_FUNC=		explicit_bzero
EXP_BZERO_HEADERS=	string.h
EXP_BZERO_ARGS=		void *, size_t
EXP_BZERO_RETURN=	void
EXP_BZERO_G_FUNC=	explicit_bzero
EXP_BZERO_G_HEADERS=	string.h
EXP_BZERO_G_CFLAGS=	-D_DEFAULT_SOURCE
EXP_BZERO_G_ARGS=	void *, size_t
EXP_BZERO_G_RETURN=	void
EXP_BZERO_S_FUNC=	explicit_bzero
EXP_BZERO_S_HEADERS=	strings.h
EXP_BZERO_S_ARGS=	void *, size_t
EXP_BZERO_S_RETURN=	void

swad_VERSION=		0.4
swad_MODULES=		authenticator \
			config \
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
			main \
			mediatype \
			middleware/compress \
			middleware/cookies \
			middleware/csrfprotect \
			middleware/formdata \
			middleware/pathparser \
			middleware/session \
			proxylist \
			ratelimit \
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
swad_SFILES=		#
swad_TMPL=		login \
			logout
swad_GEN=		BIN2CSTR CHELP
swad_BIN2CSTR_FILES=	$(foreach s,$(swad_SFILES),static/$s.h:static/$s) \
			$(foreach l,$(swad_TMPL),tmpl/$l.html.h:tmpl/$l.html)
swad_CHELP_FILES=	help.h:swad.cdoc
swad_SUB_FILES=		swad.cdoc \
			swad.conf.sample
swad_SUB_LIST=		"RUNSTATEDIR=$(runstatedir)" \
			"SYSCONFDIR=$(sysconfdir)"
swad_DOCS=		README.md \
			LICENSE.txt
swad_EXTRADIRS=		sysconf
swad_sysconf_FILES=	swad.conf.sample

ifeq ($(CRED_EXEC),1)
swad_MODULES+=		cred/execchecker
swad_DEFINES+=		-DCRED_EXEC
endif

ifeq ($(CRED_FILE),1)
swad_MODULES+=		cred/filechecker
swad_DEFINES+=		-DCRED_FILE
swad_INCLUDES+=		-I./include/swadbcrypt
swad_STATICDEPS+=	swadbcrypt
swad_LIBS+=		swadbcrypt
endif

ifeq ($(CRED_PAM),1)
swad_MODULES+=		cred/pamchecker
swad_DEFINES+=		-DCRED_PAM
endif

ifeq ($(CRED_POW),1)
swad_MODULES+=		cred/powchecker \
			handler/static \
			staticfiles
swad_DEFINES+=		-DCRED_POW
swad_SFILES+=		pow.mjs
swad_TMPL+=		pow
  ifneq ($(OPENSSLINC)$(OPENSSLLIB),)
    ifeq ($(OPENSSLINC),)
$(error OPENSSLLIB specified without OPENSSLINC)
    endif
    ifeq ($(OPENSSLLIB),)
$(error OPENSSLINC specified without OPENSSLLIB)
    endif
swad_INCLUDES+=		-I$(OPENSSLINC)
swad_LDFLAGS+=		-L$(OPENSSLLIB)
swad_LIBS+=		crypto
  else
swad_PKGDEPS+=		libcrypto
  endif
endif

ifeq ($(BUNDLED_POSER),1)
swad_STATICDEPS+=	posercore
swad_PRECFLAGS+=	-I./poser/include
swad_LIBS+=		posercore $(posercore_LIBS)
swad_LDFLAGS+=		$(posercore_LDFLAGS)
swad_PKGDEPS+=		$(posercore_PKGDEPS)
else
swad_PKGDEPS+=		posercore >= 1.2.3
endif

ifeq ($(WITH_MAN),1)
swad_MANSECT=		8
swad_MAN8=		swad
swad_GEN+=		MAN8
swad_MAN8_FILES=	swad.8:swad.cdoc
endif

$(call binrules,swad)

ifeq ($(swad_HAVE_MEMSET_EXP),1)
swad_CSTD=		c23
endif
