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
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

#include "pam_openssh_x509_check.h"

#include "../src/pam_openssh_x509_config.c"

static char *_test_init_and_parse_config_exit_lt[] =
{
    CONFIGSDIR "/cfg_str_to_int_parser_libldap_ldap_scope_negative_0.conf",
    CONFIGSDIR "/cfg_str_to_int_parser_libldap_ldap_scope_negative_1.conf",
    CONFIGSDIR "/cfg_str_to_int_parser_libldap_ldap_scope_negative_2.conf",
    CONFIGSDIR "/cfg_str_to_int_parser_libldap_ldap_version_negative.conf",
    CONFIGSDIR "/cfg_validate_log_facility_negative.conf",
    CONFIGSDIR "/cfg_validate_ldap_uri_negative.conf",
    CONFIGSDIR "/cfg_validate_ldap_search_timeout_negative.conf",
    CONFIGSDIR "/cfg_validate_cacerts_dir_negative_0.conf",
    CONFIGSDIR "/cfg_validate_cacerts_dir_negative_1.conf",
    CONFIGSDIR "/cfg_validate_cacerts_dir_negative_2.conf",
};

static char *_test_init_and_parse_config_lt[] =
{
    CONFIGSDIR "/valid.conf",
};

START_TEST
(test_init_and_parse_config_exit)
{
    char *config_file = _test_init_and_parse_config_exit_lt[_i];

    int rc = is_file_readable(config_file);
    if (rc == 0) {
        cfg_t *cfg = NULL;
        init_and_parse_config(&cfg, config_file);
    } else {
        ck_abort_msg("is_file_readable() failed (%s)", config_file);
    }
}
END_TEST

START_TEST
(test_init_and_parse_config)
{
    char *config_file = _test_init_and_parse_config_lt[_i];

    int rc = is_file_readable(config_file);
    if (rc == 0) {
        cfg_t *cfg = NULL;
        init_and_parse_config(&cfg, config_file);
    } else {
        ck_abort_msg("is_file_readable() failed (%s)", config_file);
    }
}
END_TEST

START_TEST
(release_config_exit_cfg_NULL)
{
    release_config(NULL);
}
END_TEST

START_TEST
(cfg_error_handler_exit_cfg_NULL)
{
    va_list ap;
    cfg_error_handler(NULL, "foo", ap);
}
END_TEST

START_TEST
(cfg_error_handler_exit_fmt_NULL)
{
    va_list ap;
    cfg_t cfg;

    cfg_error_handler(&cfg, NULL, ap);
}
END_TEST

START_TEST
(cfg_error_handler_exit_cfg_fmt_NULL)
{
    va_list ap;

    cfg_error_handler(NULL, NULL, ap);
}
END_TEST

START_TEST
(cfg_str_to_int_parser_libldap_exit_cfg_NULL)
{
    cfg_opt_t opt;
    const char *value = "LDAP_VERSION3";
    long int result;

    cfg_str_to_int_parser_libldap(NULL, &opt, value, &result);
}
END_TEST

START_TEST
(cfg_str_to_int_parser_libldap_exit_opt_NULL)
{
    cfg_t cfg;
    const char *value = "LDAP_VERSION3";
    long int result;

    cfg_str_to_int_parser_libldap(&cfg, NULL, value, &result);
}
END_TEST

START_TEST
(cfg_str_to_int_parser_libldap_exit_value_NULL)
{
    cfg_t cfg;
    cfg_opt_t opt;
    long int result;

    cfg_str_to_int_parser_libldap(&cfg, &opt, NULL, &result);
}
END_TEST

START_TEST
(cfg_str_to_int_parser_libldap_exit_result_NULL)
{
    cfg_t cfg;
    cfg_opt_t opt;
    const char *value = "LDAP_VERSION3";

    cfg_str_to_int_parser_libldap(&cfg, &opt, value, NULL);
}
END_TEST

START_TEST
(cfg_str_to_int_parser_libldap_exit_cfg_opt_value_result_NULL)
{
    cfg_str_to_int_parser_libldap(NULL, NULL, NULL, NULL);
}
END_TEST

START_TEST
(cfg_validate_log_facility_exit_cfg_NULL)
{
    cfg_opt_t opt;

    cfg_validate_log_facility(NULL, &opt);
}
END_TEST

START_TEST
(cfg_validate_log_facility_exit_opt_NULL)
{
    cfg_t cfg;

    cfg_validate_log_facility(&cfg, NULL);
}
END_TEST

START_TEST
(cfg_validate_log_facility_exit_cfg_opt_NULL)
{
    cfg_validate_log_facility(NULL, NULL);
}
END_TEST

START_TEST
(cfg_validate_ldap_uri_exit_cfg_NULL)
{
    cfg_opt_t opt;

    cfg_validate_ldap_uri(NULL, &opt);
}
END_TEST

START_TEST
(cfg_validate_ldap_uri_exit_opt_NULL)
{
    cfg_t cfg;

    cfg_validate_ldap_uri(&cfg, NULL);
}
END_TEST

START_TEST
(cfg_validate_ldap_uri_exit_cfg_opt_NULL)
{
    cfg_validate_ldap_uri(NULL, NULL);
}
END_TEST

START_TEST
(cfg_validate_ldap_search_timeout_exit_cfg_NULL)
{
    cfg_opt_t opt;

    cfg_validate_ldap_search_timeout(NULL, &opt);
}
END_TEST

START_TEST
(cfg_validate_ldap_search_timeout_exit_opt_NULL)
{
    cfg_t cfg;

    cfg_validate_ldap_search_timeout(&cfg, NULL);
}
END_TEST

START_TEST
(cfg_validate_ldap_search_timeout_exit_cfg_opt_NULL)
{
    cfg_validate_ldap_search_timeout(NULL, NULL);
}
END_TEST

START_TEST
(cfg_validate_cacerts_dir_exit_cfg_NULL)
{
    cfg_opt_t opt;

    cfg_validate_cacerts_dir(NULL, &opt);
}
END_TEST

START_TEST
(cfg_validate_cacerts_dir_exit_opt_NULL)
{
    cfg_t cfg;

    cfg_validate_cacerts_dir(&cfg, NULL);
}
END_TEST

START_TEST
(cfg_validate_cacerts_dir_exit_cfg_opt_NULL)
{
    cfg_validate_cacerts_dir(NULL, NULL);
}
END_TEST

Suite *
make_config_suite(void)
{
    Suite *s = suite_create("config");
    TCase *tc_main = tcase_create("main");
    TCase *tc_callbacks = tcase_create("callbacks");

    /* add test cases to suite */
    suite_add_tcase(s, tc_main);
    suite_add_tcase(s, tc_callbacks);

    /* main test cases */
    int length_iapce_lt = sizeof(_test_init_and_parse_config_exit_lt) / sizeof(char *);
    tcase_add_loop_exit_test(tc_main, test_init_and_parse_config_exit, EXIT_FAILURE, 0, length_iapce_lt);
    int length_iapc_lt = sizeof(_test_init_and_parse_config_lt) / sizeof(char *);
    tcase_add_loop_test(tc_main, test_init_and_parse_config, 0, length_iapc_lt);

    tcase_add_exit_test(tc_main, release_config_exit_cfg_NULL, EXIT_FAILURE);

    /* callbacks test cases */
    tcase_add_exit_test(tc_callbacks, cfg_error_handler_exit_cfg_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_error_handler_exit_fmt_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_error_handler_exit_cfg_fmt_NULL, EXIT_FAILURE);

    tcase_add_exit_test(tc_callbacks, cfg_str_to_int_parser_libldap_exit_cfg_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_str_to_int_parser_libldap_exit_opt_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_str_to_int_parser_libldap_exit_value_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_str_to_int_parser_libldap_exit_result_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_str_to_int_parser_libldap_exit_cfg_opt_value_result_NULL, EXIT_FAILURE);

    tcase_add_exit_test(tc_callbacks, cfg_validate_log_facility_exit_cfg_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_validate_log_facility_exit_opt_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_validate_log_facility_exit_cfg_opt_NULL, EXIT_FAILURE);

    tcase_add_exit_test(tc_callbacks, cfg_validate_ldap_uri_exit_cfg_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_validate_ldap_uri_exit_opt_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_validate_ldap_uri_exit_cfg_opt_NULL, EXIT_FAILURE);

    tcase_add_exit_test(tc_callbacks, cfg_validate_ldap_search_timeout_exit_cfg_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_validate_ldap_search_timeout_exit_opt_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_validate_ldap_search_timeout_exit_cfg_opt_NULL, EXIT_FAILURE);

    tcase_add_exit_test(tc_callbacks, cfg_validate_cacerts_dir_exit_cfg_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_validate_cacerts_dir_exit_opt_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, cfg_validate_cacerts_dir_exit_cfg_opt_NULL, EXIT_FAILURE);

    return s;
}

