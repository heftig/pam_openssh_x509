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

#ifndef _PAM_OPENSSH_X509
#define _PAM_OPENSSH_X509

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <syslog.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <confuse.h>

/* macros */
#define PUT_32BIT(cp, value)( \
    (cp)[0] = (unsigned char)((value) >> 24), \
    (cp)[1] = (unsigned char)((value) >> 16), \
    (cp)[2] = (unsigned char)((value) >> 8), \
    (cp)[3] = (unsigned char)(value) )

/* type declarations */
enum __sections { SYSLOG, LIBLDAP };

struct __config_lookup_table {
    char *name;
    int value;
};

struct pam_openssh_x509_info {
    char *uid;
    char *authorized_keys_file;
    char *ssh_rsa;

    char has_cert;
    char *serial;
    char *issuer;
    char *subject;
    char has_valid_signature;
    char is_expired;
    char is_revoked;

    char directory_online;
    char has_access;

    char *log_facility;
};

/* function declarations */
void LOG_SUCCESS(const char *fmt, ...);
void LOG_FAIL(const char *fmt, ...);
void LOG_MSG(const char *fmt, ...);
int set_log_facility(const char *log_facility);
long int config_lookup(const enum __sections sec, const char *key);
void release_config(cfg_t *cfg);
void init_data_transfer_object(struct pam_openssh_x509_info *x509_info);
void percent_expand(char token, char *repl, char *src, char *dst, int dst_length);
void check_access(char *group_dn, char *has_access);
void check_signature(char *exchange_with_cert, char *has_valid_signature);
void check_expiration(char *exchange_with_cert, char *is_expired);
void check_revocation(char *exchange_with_cert, char *is_revoked);
void extract_ssh_key(EVP_PKEY *pkey, char **ssh_rsa);
#endif
