CC=gcc
CFLAGS=-Wall -fPIC -Wno-unused-but-set-variable
LDFLAGS=-lldap -lpam -lconfuse -shared

BUILDDIR=build

all: $(BUILDDIR)/pam_openssh_x509_base.so \
     $(BUILDDIR)/pam_openssh_x509_audit.so \
     $(BUILDDIR)/pam_openssh_x509_validate.so

$(BUILDDIR)/pam_openssh_x509_base.so: pam_openssh_x509_base.c pam_openssh_x509_util.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ pam_openssh_x509_util.c $<

$(BUILDDIR)/pam_openssh_x509_audit.so: pam_openssh_x509_audit.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ pam_openssh_x509_util.c $<

$(BUILDDIR)/pam_openssh_x509_validate.so: pam_openssh_x509_validate.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ pam_openssh_x509_util.c $<

