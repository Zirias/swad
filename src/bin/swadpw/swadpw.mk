swadpw_VERSION=		$(swad_VERSION)
swadpw_MODULES=		config \
			main \
			util
swadpw_DEFINES=		-DVERSION=\"$(swadpw_VERSION)\"
swadpw_INCLUDES=	-I./include/swadbcrypt
swadpw_STATICDEPS=	swadbcrypt
swadpw_LIBS=		swadbcrypt
swadpw_GEN=		CHELP
swadpw_CHELP_FILES=	help.h:swadpw.cdoc
swadpw_SUB_FILES=	swadpw.cdoc

$(call binrules,swadpw)
