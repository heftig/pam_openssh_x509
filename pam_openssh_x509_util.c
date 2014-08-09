#include "include/pam_openssh_x509.h"

static const char *own_fqdn = "test.ssh.hq";

static struct __config_lookup_table _config_lookup[] =
    {
        // syslog facilities
        { "LOG_KERN", (0<<3) },
        { "LOG_USER", (1<<3) },
        { "LOG_MAIL", (2<<3) },
        { "LOG_DAEMON", (3<<3) },
        { "LOG_AUTH", (4<<3) },
        { "LOG_SYSLOG", (5<<3) },
        { "LOG_LPR", (6<<3) },
        { "LOG_NEWS", (7<<3) },
        { "LOG_UUCP", (8<<3) },
        { "LOG_CRON", (9<<3) },
        { "LOG_AUTHPRIV", (10<<3) },
        { "LOG_FTP", (11<<3) },
        { "LOG_LOCAL0", (16<<3) },
        { "LOG_LOCAL1", (17<<3) },
        { "LOG_LOCAL2", (18<<3) },
        { "LOG_LOCAL3", (19<<3) },
        { "LOG_LOCAL4", (20<<3) },
        { "LOG_LOCAL5", (21<<3) },
        { "LOG_LOCAL6", (22<<3) },
        { "LOG_LOCAL7", (23<<3) },

        // libldap
        { "LDAP_VERSION1", 1 },
        { "LDAP_VERSION2", 2 },
        { "LDAP_VERSION3", 3 },
        { "LDAP_SCOPE_BASE", 0 },
        { "LDAP_SCOPE_BASEOBJECT", 0 },
        { "LDAP_SCOPE_ONELEVEL", 1 },
        { "LDAP_SCOPE_ONE", 1 },
        { "LDAP_SCOPE_SUBTREE", 2 },
        { "LDAP_SCOPE_SUB", 2 },
        { "LDAP_SCOPE_SUBORDINATE", 3 },
        { "LDAP_SCOPE_CHILDREN", 3 },

        // mark end
        { NULL, 0 }
    };

static int
is_msb_set(unsigned char byte)
{
    if (byte & 0x80) {
        return 1;
    } else {
        return 0;
    }
}

long int
config_lookup(const char *key)
{
    struct __config_lookup_table *lookup_ptr;
    for (lookup_ptr = _config_lookup; lookup_ptr->name != NULL; lookup_ptr++) {
        if (strcasecmp(lookup_ptr->name, key) == 0) {
            return lookup_ptr->value;
        }
    }

    return -EINVAL;
}

void
init_data_transfer_object(struct pam_openssh_x509_info *x509_info)
{
    if (x509_info != NULL) {
        /* set standard values */
        memset(x509_info, 0, sizeof(*x509_info));

        x509_info->has_cert = -1;
        x509_info->subject = NULL;
        x509_info->serial = NULL;
        x509_info->issuer = NULL;
        x509_info->is_expired = -1;
        x509_info->has_valid_signature = -1;
        x509_info->is_revoked = -1;
        x509_info->uid = NULL;
        x509_info->authorized_keys_file = NULL;
        x509_info->ssh_rsa = NULL;
        x509_info->directory_online = -1;
        x509_info->has_access = -1;
    }
}

void percent_expand
(char token, char *subst, char *src, char *dst, int dst_length)
{
    if (src != NULL && dst != NULL) {
        bool cdt = 0;
        int j = 0;
        size_t strlen_subst = strlen(subst);
        int i;
        for (i = 0; (src[i] != '\0') && (j < dst_length - 1); i++) {
            if (cdt) {
                cdt = 0;
                if (src[i] == token) {
                    j--;
                    /* substitute token in dst buffer */
                    int k;
                    for (k = 0; (j < dst_length - 1) && (k < strlen_subst); k++) {
                        dst[j++] = subst[k];
                    }
                    continue;
                }
            }
            if (src[i] == '%') {
                cdt = 1;
            }
            /* copy char to dst buffer */
            dst[j++] = src[i];
        }
        dst[j] = '\0';
    }
}

void
check_access(char *group_dn, char *has_access)
{
    char *stored_fqdn = strtok(group_dn, "=");
    stored_fqdn = strtok(NULL, "_");
    stored_fqdn = strtok(NULL, ",");

    if (stored_fqdn && own_fqdn) {
        if (strcmp(stored_fqdn, own_fqdn) == 0) {
        /* attribute set for server */
            *has_access = 1;
            return;
        }
    }
    *has_access = 0;
}

void
check_signature(char *exchange_with_cert, char *has_valid_signature)
{
    /* implement check of signature here */
    //*has_valid_signature = poc_val_sig;
}

void
check_expiration(char *exchange_with_cert, char *is_expired)
{
    /* implement check for expiration here */
    //*is_expired = poc_expired;
}

void
check_revocation(char *exchange_with_cert, char *is_revoked)
{
    /* implement check for revocation here */
    //*is_revoked = poc_revoked;
}

void
extract_ssh_key(cfg_t *cfg, EVP_PKEY *pkey, char **ssh_rsa)
{
    if (pkey == NULL) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "[-] extract_ssh_key(): pkey == NULL");
        return;
    }

    switch (EVP_PKEY_type(pkey->type)) {
        case EVP_PKEY_RSA:
            {
                syslog(cfg_getint(cfg, "pam_log_facility"), "[#] keytype: rsa");
                char *keyname = "ssh-rsa";
                RSA *rsa = EVP_PKEY_get1_RSA(pkey);
                if (rsa == NULL) {
                /* unlikely */
                    syslog(cfg_getint(cfg, "pam_log_facility"), "[-] EVP_PKEY_get1_RSA(): rsa == NULL");
                    break;
                }

                /* create authorized_keys entry */
                int length_keyname, length_exponent, length_modulus, pre_length_blob, post_length_blob;
                length_keyname = strlen(keyname);
                length_exponent = BN_num_bytes(rsa->e);
                length_modulus = BN_num_bytes(rsa->n);

                /* the 4 bytes hold the length of the following value and the 2 extra bytes before
                 * the exponent and modulus are possibly needed to prefix the values with leading zeroes if the
                 * most significant bit of them is set. this is to avoid misinterpreting the value as a
                 * negative number later.
                 */
                pre_length_blob = 4 + length_keyname + 4 + 1 + length_exponent + 4 + 1 + length_modulus;

                /* TODO: SET LIMIT FOR LENGTH OF BLOB TO AVOID STACK OVERFLOW */
                unsigned char blob[pre_length_blob], *blob_p, blob_buffer[pre_length_blob];
                blob_p = blob;
                PUT_32BIT(blob_p, length_keyname);
                blob_p += 4;
                memcpy(blob_p, keyname, length_keyname);
                blob_p += length_keyname;
                BN_bn2bin(rsa->e, blob_buffer);

                /* put length of exponent */
                if (is_msb_set(blob_buffer[0])) {
                    PUT_32BIT(blob_p, length_exponent + 1);
                    blob_p += 4;
                    *(blob_p++) = 0;
                } else {
                    PUT_32BIT(blob_p, length_exponent);
                    blob_p += 4;
                }
                /* put exponent */
                memcpy(blob_p, blob_buffer, length_exponent);
                blob_p += length_exponent;
                BN_bn2bin(rsa->n, blob_buffer);

                /* put length of modulus */
                if (is_msb_set(blob_buffer[0])) {
                    PUT_32BIT(blob_p, length_modulus + 1);
                    blob_p += 4;
                    *(blob_p++) = 0;
                } else {
                    PUT_32BIT(blob_p, length_modulus);
                    blob_p += 4;
                }
                /* put modulus */
                memcpy(blob_p, blob_buffer, length_modulus);
                blob_p += length_modulus;
                post_length_blob = blob_p - blob;

                /* encode base64 */
                int data_in;
                long data_out;
                unsigned char *tmp_result;
                BIO *bio, *b64;

                bio = BIO_new(BIO_s_mem());
                b64 = BIO_new(BIO_f_base64());
                BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
                b64 = BIO_push(b64, bio);
                data_in = BIO_write(b64, blob, post_length_blob);
                BIO_flush(b64);
                data_out = BIO_get_mem_data(b64, &tmp_result);

                /* store key */
                char *ssh_pkey = malloc(data_out + 1);
                if (ssh_pkey != NULL) {
                    memcpy(ssh_pkey, tmp_result, data_out);
                    ssh_pkey[data_out] = '\0';
                }

                /* probably there is already a pointer to allocated mem => free first */
                free(*ssh_rsa);
                *ssh_rsa = ssh_pkey;

                /* clear structures */
                BIO_free_all(b64);
                RSA_free(rsa);
                EVP_PKEY_free(pkey);

                break;
            }
        case EVP_PKEY_DSA:
            {
                syslog(cfg_getint(cfg, "pam_log_facility"), "[#] dsa...");
                break;
            }
        case EVP_PKEY_DH:
            {
                syslog(cfg_getint(cfg, "pam_log_facility"), "[#] dh...");
                break;
            }
        case EVP_PKEY_EC:
            {
                syslog(cfg_getint(cfg, "pam_log_facility"), "[#] ec...");
                break;
            }
        default:
            {
                syslog(cfg_getint(cfg, "pam_log_facility"), "[-] unsupported public key type (%i)", pkey->type);
            }
    }
}

