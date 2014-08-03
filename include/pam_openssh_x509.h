#ifndef _PAM_OPENSSH_X509
#define _PAM_OPENSSH_X509

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
    char has_local_account;
    char directory_online;
    char has_access;
};

long int config_lookup(const char *);

#endif
