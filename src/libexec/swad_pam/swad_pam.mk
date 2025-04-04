swad_pam_VERSION=		$(swad_VERSION)
swad_pam_MODULES=		main
swad_pam_INSTALLDIRNAME=	libexec

ifeq ($(HAVE_SYSPAM),1)
swad_pam_LIBS=			pam
else
swad_pam_PKGDEPS=		pam
endif

$(call binrules,swad_pam)
