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

#include <unistd.h>
#include <sys/stat.h>
#include <openssl/x509.h>

#include "pam_openssh_x509.h"

#define DEFAULT_LOG_FACILITY LOG_LOCAL1
#define LOG_BUFFER_SIZE 2048
#define GROUP_DN_BUFFER_SIZE 1024

#define PUT_32BIT(cp, value)( \
    (cp)[0] = (unsigned char)((value) >> 24), \
    (cp)[1] = (unsigned char)((value) >> 16), \
    (cp)[2] = (unsigned char)((value) >> 8), \
    (cp)[3] = (unsigned char)(value) )

/* type declarations */
enum __sections { SYSLOG, LIBLDAP };

/* function declarations */
int is_file_readable(const char *file);
long int config_lookup(const enum __sections sec, const char *key);
void init_data_transfer_object(struct pam_openssh_x509_info *x509_info);
void substitute_token(char token, char *subst, char *src, char *dst, int dst_length);
void check_access_permission(char *group_dn, char *identifier, struct pam_openssh_x509_info *x509_info);
void validate_x509(X509 *x509, char *cacerts_dir, struct pam_openssh_x509_info *x509_info);
void pkey_to_authorized_keys(EVP_PKEY *pkey, struct pam_openssh_x509_info *x509_info);
#endif

