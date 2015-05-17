/*
 * Copyright (C) 2014-2015 Sebastian Roland <seroland86@gmail.com>
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

#ifndef PAM_OPENSSH_X509_UTIL_H
#define PAM_OPENSSH_X509_UTIL_H

#include <stddef.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

#include "pam_openssh_x509.h"

/* type declarations */
enum pox509_sections { SYSLOG, LIBLDAP };

/* function declarations */
int is_readable_file(const char *file);
int is_valid_uid(const char *uid);
long int config_lookup(const enum pox509_sections sec, const char *key);
void init_data_transfer_object(struct pam_openssh_x509_info *x509_info);
void substitute_token(char token, char *subst, char *src, char *dst, size_t dst_length);
void create_ldap_search_filter(char *rdn, char *uid, char *dst, size_t dst_length);
void check_access_permission(char *group_dn, char *identifier, struct pam_openssh_x509_info *x509_info);
void validate_x509(X509 *x509, char *cacerts_dir, struct pam_openssh_x509_info *x509_info);
void pkey_to_authorized_keys(EVP_PKEY *pkey, struct pam_openssh_x509_info *x509_info);
#endif

