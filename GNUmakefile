BOOLCONFVARS_ON=	BUNDLED_POSER WITH_MAN WITH_POSER_TLS \
			CRED_EXEC CRED_FILE CRED_PAM
BOOLCONFVARS_OFF=	WITH_POSER_POLL WITH_POSER_EPOLL WITH_POSER_KQUEUE \
			WITHOUT_POSER_EPOLL WITHOUT_POSER_KQUEUE
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
WITH_POLL:=		$(WITH_POSER_POLL)
WITH_EPOLL:=		$(WITH_POSER_EPOLL)
WITH_KQUEUE:=		$(WITH_POSER_KQUEUE)
WITH_TLS:=		$(WITH_POSER_TLS)
WITHOUT_EPOLL:=		$(WITHOUT_POSER_EPOLL)
WITHOUT_KQUEUE:=	$(WITHOUT_POSER_KQUEUE)
FD_SETSIZE:=		$(POSER_FD_SETSIZE)
posercore_BUILDWITH:=	#
posercore_STRIPWITH:=	#
posercore_INSTALLWITH:=	#
posercore_PRECFLAGS:=	-I./poser/include
$(call zinc, poser/src/lib/core/core.mk)
endif

GEN_BIN2CSTR_tool=	$(BIN2CSTR_TARGET)
GEN_BIN2CSTR_args=	$1 $2
GEN_CHELP_tool=		$(MKCLIDOC_TARGET)
GEN_CHELP_args=		-fcpp -o$1 $2
GEN_MAN_tool=		$(MKCLIDOC_TARGET)
GEN_MAN_args=		-f$(MANFMT) -o$1 $2
GEN_MAN8_tool=		$(MKCLIDOC_TARGET)
GEN_MAN8_args=		-f$(MANFMT),sect=8 -o$1 $2
MANFMT:=		$(or $(MANFMT),$(if \
			$(findstring BSD,$(SYSNAME)),mdoc,man))

ifeq ($(CRED_FILE),1)
$(call zinc, src/lib/swadbcrypt/swadbcrypt.mk)
endif

$(call zinc, src/bin/swad/swad.mk)

ifeq ($(CRED_FILE),1)
$(call zinc, src/bin/swadpw/swadpw.mk)
endif

ifeq ($(CRED_PAM),1)
$(call zinc, src/libexec/swad_pam/swad_pam.mk)
endif
