swadbcrypt_PRECHECK=	ARC4R GETRANDOM TS_BCMP TS_MEMCMP
ARC4R_FUNC=		arc4random_buf
ARC4R_CFLAGS=		-D_DEFAULT_SOURCE
ARC4R_HEADERS=		stdlib.h
ARC4R_ARGS=		void *, size_t
ARC4R_RETURN=		void
GETRANDOM_FUNC=		getrandom
GETRANDOM_HEADERS=	sys/random.h
GETRANDOM_RETURN=	ssize_t
GETRANDOM_ARGS=		void *, size_t, unsigned
TS_BCMP_FUNC=		timingsafe_bcmp
TS_BCMP_HEADERS=	string.h
TS_BCMP_CFLAGS=		-D_DEFAULT_SOURCE
TS_BCMP_ARGS=		const void *, const void *, size_t
TS_MEMCMP_FUNC=		timingsafe_memcmp
TS_MEMCMP_HEADERS=	string.h
TS_MEMCMP_CFLAGS=	-D_DEFAULT_SOURCE
TS_MEMCMP_ARGS=		const void *, const void *, size_t

swadbcrypt_MODULES=	bcrypt \
			blowfish \
			$(if $(filter 1,$(swadbcrypt_HAVE_ARC4R)),,random)
swadbcrypt_INCLUDES=	-I./contrib/openbsd/include -I./poser/include \
			-I./include/swadbcrypt
swadbcrypt_CFLAGS=	-Wno-pointer-sign
swadbcrypt_CSTD=	$(if $(filter 1,$(swad_HAVE_MEMSET_EXP)),c23,c11)
swadbcrypt_DEFINES=	$(swad_DEFINES)
swadbcrypt_BUILDWITH=	#
swadbcrypt_INSTALLWITH=	#
swadbcrypt_STRIPWITH=	#

ifneq ($(findstring -solaris,$(TARGETARCH)),)
swadbcrypt_PRECFLAGS+=	-D__EXTENSIONS__
endif

$(call librules,swadbcrypt)
