swad_pam_PRECHECK=		SYSPAM
SYSPAM_TYPE=			pam_handle_t
SYSPAM_HEADERS=			security/pam_appl.h

swad_pam_VERSION=		$(swad_VERSION)
swad_pam_MODULES=		main
swad_pam_INSTALLDIRNAME=	libexec
swad_pam_LIBS=			$(if $(filter 1,$(swad_pam_HAVE_SYSPAM)),pam)
swad_pam_PKGDEPS=		$(if $(filter 0,$(swad_pam_HAVE_SYSPAM)),pam)

$(call binrules,swad_pam)
