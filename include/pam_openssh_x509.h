#ifndef _PAM_OPENSSH_X509_INFO
#define _PAM_OPENSSH_X509_INFO

struct pam_ssh_x509_info {
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

#endif
