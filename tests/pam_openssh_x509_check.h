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

#ifndef _PAM_OPENSSH_X509_CHECK
#define _PAM_OPENSSH_X509_CHECK

/* type declarations */
struct test_percent_expand {
    char token;
    char *subst;
    char *src;
    unsigned int dst_length;
    char *exp_result;
};

struct test_check_access {
    char *group_dn;
    char *identifier;
    char exp_result;
};

struct test_validate_x509 {
    char *file;
    char exp_result;
};

struct test_init_and_parse_config {
    char *file;
    char exp_result;
};

/* function declarations */
Suite *make_base_suite(void);
Suite *make_util_suite(void);
#endif
