TESTS = pam_openssh_x509_check
check_PROGRAMS = pam_openssh_x509_check
pam_openssh_x509_check_SOURCES = pam_openssh_x509_check_main.c \
                                 pam_openssh_x509_check_base.c \
                                 pam_openssh_x509_check_config.c \
                                 pam_openssh_x509_check_util.c \
                                 pam_openssh_x509_check.h \
                                 ../src/pam_openssh_x509_util.c
pam_openssh_x509_check_LDADD = ${LDADD_CHECK}
pam_openssh_x509_check_CPPFLAGS = -DKEYSDIR="\"${srcdir}/openssh_keys\"" \
                                  -DX509CERTSDIR="\"${srcdir}/x509_certificates\"" \
                                  -DCACERTSDIR="\"${srcdir}/ca_certificates\"" \
                                  -DCONFIGSDIR="\"${srcdir}/configs\""

