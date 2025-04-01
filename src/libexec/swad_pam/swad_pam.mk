swad_pam_VERSION=		$(swad_VERSION)
swad_pam_MODULES=		main
swad_pam_LIBS=			pam
swad_pam_INSTALLDIRNAME=	libexec

$(call binrules,swad_pam)
