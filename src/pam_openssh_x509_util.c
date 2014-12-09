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

#include "pam_openssh_x509.h"

#define DEFAULT_LOG_FACILITY LOG_LOCAL1
#define LOG_BUFFER_SIZE 2048
#define GROUP_DN_BUFFER_SIZE 1024

#define PUT_32BIT(cp, value)( \
    (cp)[0] = (unsigned char)((value) >> 24), \
    (cp)[1] = (unsigned char)((value) >> 16), \
    (cp)[2] = (unsigned char)((value) >> 8), \
    (cp)[3] = (unsigned char)(value) )

static long int log_facility = DEFAULT_LOG_FACILITY;

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
        x509_info->ssh_keytype = NULL;
        x509_info->ssh_key = NULL;

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
void
percent_expand (char token, char *subst, char *src, char *dst, int dst_length)
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

void
release_config (cfg_t *cfg)
{
    /* free values of each option */
    cfg_opt_t *opt_ptr;
    for (opt_ptr = cfg->opts; opt_ptr->name != NULL; opt_ptr++) {
        cfg_free_value(opt_ptr);
    }
    /* free cfg structure */
    cfg_free(cfg);
}

/*
void
get_fqdn(char *buffer, int buffer_length)
{
    char hostname[HOSTNAME_BUFFER_SIZE];
    int rc = gethostname(hostname, sizeof(hostname));
    if (rc == 0) {
        struct addrinfo *addrinfo = NULL;
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_CANONNAME;
        hints.ai_family = AF_UNSPEC;

        rc = getaddrinfo(hostname, NULL, &hints, &addrinfo);
        if (rc == 0) {
            if (addrinfo->ai_canonname != NULL) {
                buffer[buffer_length - 1] = '\0';
                strncpy(buffer, addrinfo->ai_canonname, buffer_length - 1);
            }
            freeaddrinfo(addrinfo);
        }
    }
}
*/

void
check_access(char *group_dn, char *identifier, char *has_access)
{
    /*
     * copy group_dn to char array in order to make sure that
     * string is mutable as strtok will try to change it
     */
    char group_dn_mutable[GROUP_DN_BUFFER_SIZE];
    strncpy(group_dn_mutable, group_dn, GROUP_DN_BUFFER_SIZE);

    char *token = strtok(group_dn_mutable, "=");
    token = strtok(NULL, ",");
    /* token now contains rdn value of group only */
    if (strcmp(token, identifier) == 0) {
        *has_access = 1;
        return;
    }
    *has_access = 0;
}

void
check_signature(char *exchange_with_cert, char *has_valid_signature)
{
    /* TODO: implement check of signature here */
    *has_valid_signature = 1;
}

void
check_expiration(char *exchange_with_cert, char *is_expired)
{
    /* TODO: implement check for expiration here */
    *is_expired = 0;
}

void
check_revocation(char *exchange_with_cert, char *is_revoked)
{
    /* TODO: implement check for revocation here */
    *is_revoked = 0;
}

void
extract_ssh_key(EVP_PKEY *pkey, struct pam_openssh_x509_info *x509_info)
{
    /* should never happen */
    if (pkey == NULL) {
        LOG_FAIL("extract_ssh_key(): pkey == NULL");
        return;
    }

    switch (EVP_PKEY_type(pkey->type)) {
        case EVP_PKEY_RSA:
            {
                x509_info->ssh_keytype = strdup("ssh-rsa");
                RSA *rsa = EVP_PKEY_get1_RSA(pkey);
                if (rsa == NULL) {
                    LOG_FAIL("EVP_PKEY_get1_RSA()");
                    break;
                }

                /* create authorized_keys entry */
                int length_keytype = strlen(x509_info->ssh_keytype);
                int length_exponent = BN_num_bytes(rsa->e);
                int length_modulus = BN_num_bytes(rsa->n);

                /*
                 * the 4 bytes hold the length of the following value and the 2 extra bytes before
                 * the exponent and modulus are possibly needed to prefix the values with leading zeroes if the
                 * most significant bit of them is set. this is to avoid misinterpreting the value as a
                 * negative number later.
                 */
                int pre_length_blob = 4 + length_keytype + 4 + 1 + length_exponent + 4 + 1 + length_modulus;

                /* TODO: SET LIMIT FOR LENGTH OF BLOB TO AVOID STACK OVERFLOW */
                unsigned char blob[pre_length_blob];
                unsigned char blob_buffer[pre_length_blob];
                unsigned char *blob_p;

                blob_p = blob;
                PUT_32BIT(blob_p, length_keytype);
                blob_p += 4;
                memcpy(blob_p, x509_info->ssh_keytype, length_keytype);
                blob_p += length_keytype;
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
                int post_length_blob = blob_p - blob;

                /* encode base64 */

                /* create base64 bio */
                BIO *bio_base64 = BIO_new(BIO_f_base64());
                if (bio_base64 == NULL) {
                    LOG_FAIL("BIO_new()");
                    goto free_rsa;
                }
                BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);

                /* create memory bio */
                BIO *bio_mem = BIO_new(BIO_s_mem());
                if (bio_mem == NULL) {
                    LOG_FAIL("BIO_new()");
                    goto free_bio_rsa;
                }
                /* create bio chain base64->mem */
                bio_base64 = BIO_push(bio_base64, bio_mem);
                BIO_write(bio_base64, blob, post_length_blob);
                BIO_flush(bio_base64);
                unsigned char *tmp_result = NULL;
                long data_out = BIO_get_mem_data(bio_base64, &tmp_result);

                /* store key */
                x509_info->ssh_key = malloc(data_out + 1);
                if (x509_info->ssh_key != NULL) {
                    memcpy(x509_info->ssh_key, tmp_result, data_out);
                    x509_info->ssh_key[data_out] = '\0';
                }

                /* clear structures */
                free_bio_rsa:
                    BIO_free_all(bio_base64);
                free_rsa:
                    RSA_free(rsa);

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

