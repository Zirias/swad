swadpw_VERSION=		$(swad_VERSION)
swadpw_MODULES=		config \
			main \
			password \
			pwfile \
			util
swadpw_PRECFLAGS=	$(swad_PRECFLAGS)
swadpw_DEFINES=		$(swad_DEFINES)
swadpw_INCLUDES=	-I./include/swadbcrypt
swadpw_STATICDEPS=	swadbcrypt
swadpw_LIBS=		swadbcrypt
swadpw_GEN=		CHELP
swadpw_CHELP_FILES=	help.h:swadpw.cdoc
swadpw_SUB_FILES=	swadpw.cdoc

ifeq ($(WITH_MAN),1)
swadpw_MAN1=		swadpw
swadpw_GEN+=		MAN
swadpw_MAN_FILES=	swadpw.1:swadpw.cdoc
endif

$(call binrules,swadpw)
