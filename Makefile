CC=gcc
CFLAGS=-Wall -fPIC -Wno-unused-but-set-variable
CFLAGS_TEST=-Wall -Wno-unused-variable
LDFLAGS=-lssl -lcrypto -lldap -lpam -lconfuse -shared
LDFLAGS_TEST=-lcheck -lconfuse -lssl -lcrypto

SRCDIR=src
TESTDIR=$(SRCDIR)/tests
BUILDDIR=build

TEST_SUITE_UTIL=pam_openssh_x509_check_util.c

all: $(BUILDDIR)/pam_openssh_x509_base.so \
     $(BUILDDIR)/pam_openssh_x509_audit.so \
     $(BUILDDIR)/pam_openssh_x509_validate.so \
     $(BUILDDIR)/pam_openssh_x509_check

$(BUILDDIR)/pam_openssh_x509_base.so: $(SRCDIR)/pam_openssh_x509_base.c $(SRCDIR)/pam_openssh_x509_util.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCDIR)/pam_openssh_x509_util.c $<

$(BUILDDIR)/pam_openssh_x509_audit.so: $(SRCDIR)/pam_openssh_x509_audit.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCDIR)/pam_openssh_x509_util.c $<

$(BUILDDIR)/pam_openssh_x509_validate.so: $(SRCDIR)/pam_openssh_x509_validate.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCDIR)/pam_openssh_x509_util.c $<

$(BUILDDIR)/pam_openssh_x509_check: $(BUILDDIR)/pam_openssh_x509_base.so
	$(CC) $(CFLAGS_TEST) $(LDFLAGS_TEST) -o $@ $(TESTDIR)/pam_openssh_x509_check_main.c $(TESTDIR)/$(TEST_SUITE_UTIL) $(SRCDIR)/pam_openssh_x509_util.c

