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

#include "pam_openssh_x509_config.h"

#include <errno.h>
#include <ldap.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>

#include "pam_openssh_x509_util.h"

static void
cfg_error_handler(cfg_t *cfg, const char *fmt, va_list ap)
{
    if (cfg == NULL || fmt == NULL) {
        FATAL("cfg_error_handler(): cfg or fmt == NULL");
    }

    char error_msg[ERROR_MSG_BUFFER_SIZE];
    vsnprintf(error_msg, sizeof(error_msg), fmt, ap);
    FATAL("%s", error_msg);
}

/*
 * note that value parsing and validation callback functions will only be called
 * during parsing. altering the value later wont incorporate them
 */
static int
cfg_str_to_int_parser_libldap(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result)
{
    if (cfg == NULL || opt == NULL || value == NULL || result == NULL) {
        FATAL("cfg_str_to_int_parser_libldap(): cfg, opt, value or result == NULL");
    }

    long int result_value = config_lookup(LIBLDAP, value);
    if (result_value == -EINVAL) {
        cfg_error(cfg, "cfg_value_parser_int(): option: '%s', value: '%s'", cfg_opt_name(opt), value);
        return -1; 
    }
    long int *ptr_result = result;
    *ptr_result = result_value;
    return 0;
}

static int
cfg_validate_log_facility(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        FATAL("cfg_validate_log_facility(): cfg or opt == NULL");
    }

    const char *log_facility = cfg_opt_getnstr(opt, 0);
    int rc = set_log_facility(log_facility);
    if (rc == -EINVAL) {
        cfg_error(cfg, "cfg_validate_log_facility(): option: '%s', value: '%s' (value is not a valid syslog facility)", cfg_opt_name(opt), log_facility);
        return -1;
    }
    return 0;
}

static int
cfg_validate_ldap_uri(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        FATAL("cfg_validate_ldap_uri(): cfg or opt == NULL");
    }

    const char *ldap_uri = cfg_opt_getnstr(opt, 0);
    int rc = ldap_is_ldap_url(ldap_uri);
    if (rc == 0) {
        cfg_error(cfg, "cfg_validate_ldap_uri(): option: '%s', value: '%s' (value is not an ldap uri)", cfg_opt_name(opt), ldap_uri);
        return -1;
    }
    return 0;
}

static int
cfg_validate_ldap_starttls(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        FATAL("cfg_validate_ldap_starttls(): cfg or opt == NULL");
    }

    long int starttls = cfg_opt_getnint(opt, 0);
    if (starttls != 0 && starttls != 1) {
        cfg_error(cfg, "cfg_validate_ldap_starttls(): option: '%s', value: '%li' (value must be either 0 or 1)", cfg_opt_name(opt), starttls);
        return -1;
    }
    return 0;
}

static int
cfg_validate_ldap_search_timeout(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        FATAL("cfg_validate_ldap_search_timeout(): cfg or opt == NULL");
    }

    long int timeout = cfg_opt_getnint(opt, 0);
    if (timeout <= 0) {
        cfg_error(cfg, "cfg_validate_ldap_search_timeout(): option: '%s', value: '%li' (value must be > 0)", cfg_opt_name(opt), timeout);
        return -1;
    }
    return 0;
}

static int
cfg_validate_cacerts_dir(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        FATAL("cfg_validate_cacerts_dir(): cfg or opt == NULL");
    }

    const char *cacerts_dir = cfg_opt_getnstr(opt, 0);
    /* check if directory exists */
    DIR *cacerts_dir_stream = opendir(cacerts_dir);
    if (cacerts_dir_stream == NULL) {
        cfg_error(cfg, "cfg_validate_cacerts_dir(): option: '%s', value: '%s' (%s)", cfg_opt_name(opt), cacerts_dir, strerror(errno));
        return -1;
    }
    closedir(cacerts_dir_stream);

    return 0;
}

void
init_and_parse_config(cfg_t **cfg, const char *cfg_file)
{
    if (cfg == NULL || cfg_file == NULL) {
        FATAL("init_and_parse_config(): cfg or cfg_file == NULL");
    }

    /* setup config options */
    cfg_opt_t opts[] = { 
        CFG_STR("log_facility", "LOG_LOCAL1", CFGF_NONE),
        CFG_STR("ldap_uri", "ldap://localhost:389", CFGF_NONE),
        CFG_INT("ldap_starttls", 0, CFGF_NONE),
        CFG_STR("ldap_bind_dn", "cn=directory_manager,dc=ssh,dc=hq", CFGF_NONE),
        CFG_STR("ldap_pwd", "test123", CFGF_NONE),
        CFG_STR("ldap_base", "ou=people,dc=ssh,dc=hq", CFGF_NONE),
        CFG_INT_CB("ldap_scope", config_lookup(LIBLDAP, "LDAP_SCOPE_ONE"), CFGF_NONE, &cfg_str_to_int_parser_libldap),
        CFG_INT("ldap_search_timeout", 5, CFGF_NONE),
        CFG_INT_CB("ldap_version", config_lookup(LIBLDAP, "LDAP_VERSION3"), CFGF_NONE, &cfg_str_to_int_parser_libldap),
        CFG_STR("ldap_attr_rdn_person", "uid", CFGF_NONE),
        CFG_STR("ldap_attr_access", "memberOf", CFGF_NONE),
        CFG_STR("ldap_attr_cert", "userCertificate;binary", CFGF_NONE),
        CFG_STR("ldap_group_identifier", "pam_openssh_x509_test_server", CFGF_NONE),
        CFG_STR("authorized_keys_file", "/usr/local/etc/ssh/keystore/%u/authorized_keys", CFGF_NONE),
        CFG_STR("cacerts_dir", "/usr/local/etc/ssh/cacerts", CFGF_NONE),
        CFG_END()
    };

    /* initialize config */
    *cfg = cfg_init(opts, CFGF_NOCASE);
    /* register callbacks */
    cfg_set_error_function(*cfg, &cfg_error_handler);
    cfg_set_validate_func(*cfg, "log_facility", &cfg_validate_log_facility);
    cfg_set_validate_func(*cfg, "ldap_uri", &cfg_validate_ldap_uri);
    cfg_set_validate_func(*cfg, "ldap_starttls", &cfg_validate_ldap_starttls);
    cfg_set_validate_func(*cfg, "ldap_search_timeout", &cfg_validate_ldap_search_timeout);
    cfg_set_validate_func(*cfg, "cacerts_dir", &cfg_validate_cacerts_dir);

    /* parse config */
    int rc = cfg_parse(*cfg, cfg_file);
    if (rc == CFG_FILE_ERROR) {
        cfg_error(*cfg, "cfg_parse(): file: '%s', '%s'", cfg_file, strerror(errno));
    }
}

void
release_config(cfg_t *cfg)
{
    if (cfg == NULL) {
        FATAL("release_config(): cfg == NULL");
    }

    /* free values of each option */
    cfg_opt_t *opt_ptr = NULL;
    for (opt_ptr = cfg->opts; opt_ptr->name != NULL; opt_ptr++) {
        cfg_free_value(opt_ptr);
    }
    /* free cfg structure */
    cfg_free(cfg);
}

