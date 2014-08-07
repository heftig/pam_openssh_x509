#ifndef _PAM_OPENSSH_X509
#define _PAM_OPENSSH_X509

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <confuse.h>

#define PUT_32BIT(cp, value) ( \
    (cp)[0] = (unsigned char)((value) >> 24), \
    (cp)[1] = (unsigned char)((value) >> 16), \
    (cp)[2] = (unsigned char)((value) >> 8), \
    (cp)[3] = (unsigned char)(value) )

/* type declarations */
struct __config_lookup_table {
    char *name;
    int value;
};

struct pam_openssh_x509_info {
    /* certificate information */
    char has_cert;
    char *subject;
    char *serial;
    char *issuer;
    char is_expired;
    char has_valid_signature;
    char is_revoked;

    /* openssh related */
    char *ssh_rsa;
    char *authorized_keys_file;

    /* additional */
    char directory_online;
    char has_access;
};

/* function declarations */
long int config_lookup(const char *key);
void init_data_transfer_object(struct pam_openssh_x509_info **x509_info);
void check_access(char *group_dn, char *has_access);
void check_signature(char *exchange_with_cert, char *has_valid_signature);
void check_expiration(char *exchange_with_cert, char *is_expired);
void check_revocation(char *exchange_with_cert, char *is_revoked);
void extract_ssh_key(EVP_PKEY *pkey, char **ssh_rsa, cfg_t *cfg);

#endif
