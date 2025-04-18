swadbcrypt_PRECHECK=	TS_BCMP TS_MEMCMP
TS_BCMP_FUNC=		timingsafe_bcmp
TS_BCMP_HEADERS=	string.h
TS_BCMP_CFLAGS=		-D_DEFAULT_SOURCE
TS_BCMP_ARGS=		const void *, const void *, size_t
TS_MEMCMP_FUNC=		timingsafe_memcmp
TS_MEMCMP_HEADERS=	string.h
TS_MEMCMP_CFLAGS=	-D_DEFAULT_SOURCE
TS_MEMCMP_ARGS=		const void *, const void *, size_t

swadbcrypt_MODULES=	bcrypt \
			blowfish
swadbcrypt_INCLUDES=	-I./contrib/openbsd/include -I./poser/include \
			-I./include/swadbcrypt
swadbcrypt_CFLAGS=	-Wno-pointer-sign
swadbcrypt_CSTD=	$(if $(filter 1,$(swad_HAVE_MEMSET_EXP)),c23,c11)
swadbcrypt_DEFINES=	$(swad_DEFINES)
swadbcrypt_BUILDWITH=	#
swadbcrypt_INSTALLWITH=	#
swadbcrypt_STRIPWITH=	#

$(call librules,swadbcrypt)
