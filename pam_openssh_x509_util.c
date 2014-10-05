/*
 * Copyright (C) 2014 Sebastian Roland <seroland86@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <syslog.h>
#include <ldap.h>

#include "include/pam_openssh_x509.h"

#define DEFAULT_LOG_FACILITY LOG_LOCAL1
#define LOG_BUFFER_SIZE 2048

static long int log_facility = DEFAULT_LOG_FACILITY;
static const char *own_fqdn = "test.ssh.hq";

/* define config lookup table */
static struct __config_lookup_table syslog_facilities[] =
    {
        { "LOG_KERN", LOG_KERN },
        { "LOG_USER", LOG_USER },
        { "LOG_MAIL", LOG_MAIL },
        { "LOG_DAEMON", LOG_DAEMON },
        { "LOG_AUTH", LOG_AUTH },
        { "LOG_SYSLOG", LOG_SYSLOG },
        { "LOG_LPR", LOG_LPR },
        { "LOG_NEWS", LOG_NEWS },
        { "LOG_UUCP", LOG_UUCP },
        { "LOG_CRON", LOG_CRON },
        { "LOG_AUTHPRIV", LOG_AUTHPRIV },
        { "LOG_FTP", LOG_FTP },
        { "LOG_LOCAL0", LOG_LOCAL0 },
        { "LOG_LOCAL1", LOG_LOCAL1 },
        { "LOG_LOCAL2", LOG_LOCAL2 },
        { "LOG_LOCAL3", LOG_LOCAL3 },
        { "LOG_LOCAL4", LOG_LOCAL4 },
        { "LOG_LOCAL5", LOG_LOCAL5 },
        { "LOG_LOCAL6", LOG_LOCAL6 },
        { "LOG_LOCAL7", LOG_LOCAL6 },
        /* mark end */
        { NULL, 0 }
    };

static struct __config_lookup_table libldap[] =
    {
        { "LDAP_VERSION1", LDAP_VERSION1 },
        { "LDAP_VERSION2", LDAP_VERSION2 },
        { "LDAP_VERSION3", LDAP_VERSION3 },
        { "LDAP_SCOPE_BASE", LDAP_SCOPE_BASE },
        { "LDAP_SCOPE_BASEOBJECT", LDAP_SCOPE_BASEOBJECT },
        { "LDAP_SCOPE_ONELEVEL", LDAP_SCOPE_ONELEVEL },
        { "LDAP_SCOPE_ONE", LDAP_SCOPE_ONE },
        { "LDAP_SCOPE_SUBTREE", LDAP_SCOPE_SUBTREE },
        { "LDAP_SCOPE_SUB", LDAP_SCOPE_SUB },
        { "LDAP_SCOPE_SUBORDINATE", LDAP_SCOPE_SUBORDINATE },
        { "LDAP_SCOPE_CHILDREN", LDAP_SCOPE_CHILDREN },
        /* mark end */
        { NULL, 0 }
    };

static struct __config_lookup_table *_config_lookup[] = { syslog_facilities, libldap };

long int
config_lookup(const enum __sections sec, const char *key)
{
    if (key == NULL) {
        return -EINVAL;
    }
    struct __config_lookup_table *lookup_ptr;
    for (lookup_ptr = _config_lookup[sec]; lookup_ptr->name != NULL; lookup_ptr++) {
        if (strcasecmp(lookup_ptr->name, key) == 0) {
            return lookup_ptr->value;
        }
    }
    return -EINVAL;
}

static void
__LOG(char *prefix, const char *fmt, va_list ap)
{
    char buffer[LOG_BUFFER_SIZE];
    vsnprintf(buffer, LOG_BUFFER_SIZE, fmt, ap);
    syslog(log_facility, "%s %s\n", prefix, buffer);
}

void
LOG_SUCCESS(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    __LOG("[+]", fmt, ap);
    va_end(ap);
}

void
LOG_FAIL(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    __LOG("[-]", fmt, ap);
    va_end(ap);
}

void
LOG_MSG(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    __LOG("[#]", fmt, ap);
    va_end(ap);
}

int
set_log_facility(const char *lf_in)
{
    long int value = config_lookup(SYSLOG, lf_in);
    if (value != -EINVAL) {
        log_facility = value;
        return 0;
    }
    return -EINVAL;
}

static int
is_msb_set(unsigned char byte)
{
    if (byte & 0x80) {
        return 1;
    } else {
        return 0;
    }
}

void
init_data_transfer_object(struct pam_openssh_x509_info *x509_info)
{
    if (x509_info != NULL) {
        memset(x509_info, 0, sizeof(*x509_info));

        x509_info->uid = NULL;
        x509_info->authorized_keys_file = NULL;
        x509_info->ssh_rsa = NULL;

        x509_info->has_cert = 0x86;
        x509_info->serial = NULL;
        x509_info->issuer = NULL;
        x509_info->subject = NULL;
        x509_info->has_valid_signature = 0x86;
        x509_info->is_expired = 0x86;
        x509_info->is_revoked = 0x86;

        x509_info->directory_online = 0x86;
        x509_info->has_access = 0x86;

        x509_info->log_facility = NULL;
    }
}

/*
 * CAUTION!
 *
 * before calling percent_expand() make sure that you filter values
 * that can lead to unwanted behavior.
 *
 * for example if the substitution value for the token can be chosen
 * by an attacker and the function is used for replacing tokens in a
 * path.
 *
 * consider the following example:
 * path: /etc/ssh/keystore/%u/authorized_keys
 *
 * an attacker could change the path easily if he provides the following:
 * substitution value: ../../../root/.ssh 
 *
 * that would lead to the following path:
 * /etc/ssh/keystore/../../../root/.ssh/authorized_keys
 *
 */
void percent_expand
(char token, char *subst, char *src, char *dst, int dst_length)
{
    if (subst != NULL && src != NULL && dst != NULL) {
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

void release_config
(cfg_t *cfg)
{
    /* free values of each option */
    cfg_opt_t *opt_ptr;
    for (opt_ptr = cfg->opts; opt_ptr->name != NULL; opt_ptr++) {
        cfg_free_value(opt_ptr);
    }
    /* free cfg structure */
    cfg_free(cfg);
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
extract_ssh_key(EVP_PKEY *pkey, char **ssh_rsa)
{
    if (pkey == NULL) {
        LOG_FAIL("extract_ssh_key(): pkey == NULL");
        return;
    }

    switch (EVP_PKEY_type(pkey->type)) {
        case EVP_PKEY_RSA:
            {
                LOG_MSG("keytype: rsa");
                char *keyname = "ssh-rsa";
                RSA *rsa = EVP_PKEY_get1_RSA(pkey);
                if (rsa == NULL) {
                /* unlikely */
                    LOG_FAIL("EVP_PKEY_get1_RSA(): rsa == NULL");
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
                LOG_MSG("dsa...");
                break;
            }
        case EVP_PKEY_DH:
            {
                LOG_MSG("dh...");
                break;
            }
        case EVP_PKEY_EC:
            {
                LOG_MSG("ec...");
                break;
            }
        default:
            {
                LOG_FAIL("unsupported public key type (%i)", pkey->type);
            }
    }
}

