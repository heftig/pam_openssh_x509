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

#ifndef PAM_OPENSSH_X509_CHECK_H
#define PAM_OPENSSH_X509_CHECK_H

#include <check.h>

/* type declarations */
struct pox509_test_substitute_token_item {
    char token;
    char *subst;
    char *src;
    size_t dst_length;
    char *exp_result;
};

struct pox509_test_create_ldap_search_filter_item {
    char *rdn;
    char *uid;
    size_t dst_length;
    char *exp_result;
};

struct pox509_test_check_access_permission_item {
    char *group_dn;
    char *identifier;
    char exp_result;
};

struct pox509_test_validate_x509_item {
    char *file;
    char exp_result;
};

struct pox509_is_valid_uid_item {
    char *uid;
    char exp_result;
};

/* function declarations */
Suite *make_config_suite(void);
Suite *make_util_suite(void);
#endif

