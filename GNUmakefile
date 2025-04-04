BOOLCONFVARS_ON=	BUNDLED_POSER WITH_POSER_TLS
SINGLECONFVARS=		OPENSSLINC OPENSSLLIB
USES=			gen pkgconfig sub

SUBBUILD=		BIN2CSTR
BIN2CSTR_TARGET=	tools/bin/bin2cstr
BIN2CSTR_SRCDIR=	tools/bin2cstr
BIN2CSTR_MAKEARGS=	DESTDIR=../bin prefix= bindir= \
			HOSTBUILD=1 PORTABLE=1 STATIC=0
BIN2CSTR_MAKEGOAL=	install
BIN2CSTR_CLEANGOAL=	distclean

DISTCLEANDIRS=		tools/bin

include zimk/zimk.mk

ifeq ($(BUNDLED_POSER),1)
WITH_TLS:=		$(WITH_POSER_TLS)
posercore_BUILDWITH:=	#
posercore_STRIPWITH:=	#
posercore_INSTALLWITH:=	#
posercore_PRECFLAGS:=	-I./poser/include
$(call zinc, poser/src/lib/core/core.mk)
endif

$(call zinc, src/bin/swad/swad.mk)
$(call zinc, src/libexec/swad_pam/swad_pam.mk)
