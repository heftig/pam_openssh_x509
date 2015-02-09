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

#include <check.h>
#include <stdio.h>
#include <string.h>

#include "pam_openssh_x509_check.h"
#include "../src/pam_openssh_x509_base.c"

static struct test_init_and_parse_config _test_init_and_parse_config_lt[] =
{
    { "valid.conf", 0 },
    { "cfg_str_to_int_parser_libldap_ldap_scope_negative_0.conf", -1 },
    { "cfg_str_to_int_parser_libldap_ldap_scope_negative_1.conf", -1 },
    { "cfg_str_to_int_parser_libldap_ldap_scope_negative_2.conf", -1 },
    { "cfg_str_to_int_parser_libldap_ldap_version_negative.conf", -1 },
    { "cfg_validate_log_facility_negative.conf", -1 },
    { "cfg_validate_ldap_uri_negative.conf", -1 },
    { "cfg_validate_ldap_search_timeout_negative.conf", -1 },
    { "cfg_validate_cacerts_dir_negative_0.conf", -1 },
    { "cfg_validate_cacerts_dir_negative_1.conf", -1 },
    { "cfg_validate_cacerts_dir_negative_2.conf", -1 },
};

START_TEST
(test_init_and_parse_config)
{
    char *config_file = _test_init_and_parse_config_lt[_i].file;
    int exp_result = _test_init_and_parse_config_lt[_i].exp_result;

    char *configs_dir = CONFIGSDIR;

    int rc = chdir(configs_dir);
    if (rc == 0) {
        cfg_t *cfg = NULL;
        rc = init_and_parse_config(config_file, &cfg);
        ck_assert_int_eq(rc, exp_result);
    } else {
        ck_abort_msg("chdir() failed ('%s')", strerror(errno));
    }
}
END_TEST

START_TEST
(test_init_and_parse_config_params)
{
    char *config_file = _test_init_and_parse_config_lt[0].file;
    char *configs_dir = CONFIGSDIR;
    cfg_t *cfg = NULL;

    int rc = init_and_parse_config(NULL, &cfg);
    ck_assert_int_eq(rc, -1);
    rc = init_and_parse_config(NULL, NULL);
    ck_assert_int_eq(rc, -1);

    rc = chdir(configs_dir);
    if (rc == 0) {
        rc = init_and_parse_config(config_file, NULL);
        ck_assert_int_eq(rc, -1);
    } else {
        ck_abort_msg("chdir() failed ('%s')", strerror(errno));
    }
}
END_TEST

Suite *
make_base_suite(void)
{
    Suite *s = suite_create("base");
    TCase *tc_config = tcase_create("config");

    /* add test cases to suite */
    suite_add_tcase(s, tc_config);

    /* config test cases */
    int length_iapc_lt = sizeof(_test_init_and_parse_config_lt) / sizeof(struct test_init_and_parse_config);
    tcase_add_loop_test(tc_config, test_init_and_parse_config, 0, length_iapc_lt);
    tcase_add_test(tc_config, test_init_and_parse_config_params);

    return s;
}

