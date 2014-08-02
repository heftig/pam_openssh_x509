CC=gcc
CFLAGS=-Wall -Wno-unused-but-set-variable
LDFLAGS=-lldap -lpam -shared

BUILDDIR=build

all: $(BUILDDIR)/pam_openssh_x509_base.so \
	 $(BUILDDIR)/pam_openssh_x509_validate.so \
	 $(BUILDDIR)/pam_openssh_x509_audit.so

$(BUILDDIR)/pam_openssh_x509_base.so: pam_openssh_x509_base.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILDDIR)/pam_openssh_x509_validate.so: pam_openssh_x509_validate.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILDDIR)/pam_openssh_x509_audit.so: pam_openssh_x509_audit.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

