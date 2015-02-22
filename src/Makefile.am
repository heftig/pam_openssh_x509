lib_LTLIBRARIES = pam_openssh_x509_base.la \
                  pam_openssh_x509_audit.la \
                  pam_openssh_x509_validate.la
include_HEADERS = pam_openssh_x509.h

pam_openssh_x509_base_la_SOURCES = pam_openssh_x509_base.c \
                                   pam_openssh_x509_config.c \
                                   pam_openssh_x509_util.c \
                                   pam_openssh_x509_config.h \
                                   pam_openssh_x509_util.h
pam_openssh_x509_base_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pam_openssh_x509_base_la_LIBADD = ${LIBADD_BASE}

pam_openssh_x509_audit_la_SOURCES = pam_openssh_x509_audit.c \
                                    pam_openssh_x509_util.c \
                                    pam_openssh_x509.h
pam_openssh_x509_audit_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pam_openssh_x509_audit_la_LIBADD = ${LIBADD_AUDIT}

pam_openssh_x509_validate_la_SOURCES = pam_openssh_x509_validate.c\
                                       pam_openssh_x509_util.c \
                                       pam_openssh_x509.h
pam_openssh_x509_validate_la_LDFLAGS = -avoid-version -module -export-dynamic -shared
pam_openssh_x509_validate_la_LIBADD = ${LIBADD_VALIDATE}

