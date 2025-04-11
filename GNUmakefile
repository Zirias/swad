BOOLCONFVARS_ON=	BUNDLED_POSER WITH_MAN WITH_POSER_TLS
SINGLECONFVARS=		MANFMT OPENSSLINC OPENSSLLIB POSER_FD_SETSIZE

DEFAULT_POSER_FD_SETSIZE=	4096

USES=			gen man pkgconfig sub

SUBBUILD=		BIN2CSTR MKCLIDOC

BIN2CSTR_TARGET=	tools/bin/bin2cstr
BIN2CSTR_SRCDIR=	tools/bin2cstr
BIN2CSTR_MAKEARGS=	DESTDIR=../bin prefix= bindir= \
			HOSTBUILD=1 PORTABLE=1 STATIC=0
BIN2CSTR_MAKEGOAL=	install
BIN2CSTR_CLEANGOAL=	distclean

MKCLIDOC_TARGET=	tools/bin/mkclidoc
MKCLIDOC_SRCDIR=	tools/mkclidoc
MKCLIDOC_MAKEARGS=	DESTDIR=../bin prefix= bindir= zimkdir=../../zimk \
			HOSTBUILD=1 PORTABLE=1 STATIC=0
MKCLIDOC_MAKEGOAL=	install
MKCLIDOC_CLEANGOAL=	distclean

DISTCLEANDIRS=		tools/bin
NODIST=			poser/zimk \
			tools/mkclidoc/zimk

include zimk/zimk.mk

ifeq ($(BUNDLED_POSER),1)
WITH_TLS:=		$(WITH_POSER_TLS)
FD_SETSIZE:=		$(POSER_FD_SETSIZE)
posercore_BUILDWITH:=	#
posercore_STRIPWITH:=	#
posercore_INSTALLWITH:=	#
posercore_PRECFLAGS:=	-I./poser/include
$(call zinc, poser/src/lib/core/core.mk)
endif

$(call zinc, src/bin/swad/swad.mk)
$(call zinc, src/libexec/swad_pam/swad_pam.mk)
