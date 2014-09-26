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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#include <confuse.h>
#include <ldap.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "include/pam_openssh_x509.h"

#define MAX_SEARCH_FILTER_BUFFER_SIZE       512
#define CERT_INFO_STRING_BUFFER_SIZE        1024
#define UID_BUFFER_SIZE                     33
#define AUTHORIZED_KEYS_FILE_BUFFER_SIZE    1024

static struct pam_openssh_x509_info *x509_info = NULL;

static void
cleanup_x509_info(pam_handle_t *pamh, void *data, int error_status)
{
    // THIS FUNCTION SHOULD BE CALLED THROUGH PAM_END() WHICH UNFORTUNATELY IS NOT HAPPENING FOR OPENSSH
    // TODO: USE IF SUPPORTED
}

static void
query_ldap(cfg_t *cfg)
{
    LDAP *ldap_handle = NULL;
    LDAPMessage *ldap_result = NULL;
    struct berelement *ber = NULL;
    struct berval **bvals = NULL;
    char *attr = NULL;
    int rc, msgtype;

    struct timeval search_timeout = { cfg_getint(cfg, "ldap_search_timeout"), 0 };
    int sizelimit = 1;
    int ldap_version = cfg_getint(cfg, "ldap_version");
    
    char *attrs[] = { cfg_getstr(cfg, "ldap_attr_cert"), cfg_getstr(cfg, "ldap_attr_access"), '\0' };
    struct berval cred = { strlen(cfg_getstr(cfg, "ldap_pwd")), cfg_getstr(cfg, "ldap_pwd") };

    /* check length of search filter buffer */
    unsigned int search_filter_buffer = strlen(cfg_getstr(cfg, "ldap_attr_rdn_person")) + strlen("=") + strlen(x509_info->uid) + 1;
    if (search_filter_buffer > MAX_SEARCH_FILTER_BUFFER_SIZE) {
        LOG_FAIL("size of ldap search filter buffer exceeds maximum allowed size");
        return;
    }
    /* construct filter */
    char filter[search_filter_buffer];
    strcpy(filter, cfg_getstr(cfg, "ldap_attr_rdn_person"));
    strcat(filter, "=");
    strcat(filter, x509_info->uid);

    /* init handle */
    rc = ldap_initialize(&ldap_handle, cfg_getstr(cfg, "ldap_uri"));
    if (rc == LDAP_SUCCESS) {
        LOG_SUCCESS("ldap_initialize()");
    } else {
        LOG_FAIL("ldap_initialize(): '%s' (%d)", ldap_err2string(rc), rc);
        goto unbind_and_free_handle;
    }

    /* set version */
    rc = ldap_set_option(ldap_handle, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
    if (rc != LDAP_OPT_SUCCESS) {
        LOG_FAIL("ldap_set_option(): key: LDAP_OPT_PROTOCOL_VERSION, value: %i", ldap_version);
        goto unbind_and_free_handle;
    }

    /* bind to server */
    rc = ldap_sasl_bind_s(ldap_handle, cfg_getstr(cfg, "ldap_bind_dn"), LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
    memset(cfg_getstr(cfg, "ldap_pwd"), 0, strlen(cfg_getstr(cfg, "ldap_pwd")));

    if (rc == LDAP_SUCCESS) {
        /* connection established */
        LOG_SUCCESS("ldap_sasl_bind_s()");
        x509_info->directory_online = 1;

        /*
         * search people tree for given uid and retrieve group memberships / x.509 certificates
         */
        rc = ldap_search_ext_s(ldap_handle, cfg_getstr(cfg, "ldap_base"), cfg_getint(cfg, "ldap_scope"), filter, attrs, 0, NULL, NULL, &search_timeout, sizelimit, &ldap_result);
        if (rc == LDAP_SUCCESS) {
            LOG_SUCCESS("ldap_search_ext_s()");
            /*
             * iterate over matching entries
             *
             * even though sizelimit is 1 at least 2 messages will be returned (1x LDAP_RES_SEARCH_ENTRY + 1x LDAP_RES_SEARCH_ENTRY)
             * so that we need to iterate over the result set instead of just retrieve and process the first message
             */
            for (ldap_result = ldap_first_message(ldap_handle, ldap_result); ldap_result != NULL; ldap_result = ldap_next_message(ldap_handle, ldap_result)) {
                switch (msgtype = ldap_msgtype(ldap_result)) {
                    case LDAP_RES_SEARCH_ENTRY:
                        {
                            char *entry_dn = ldap_get_dn(ldap_handle, ldap_result); 
                            LOG_MSG("dn: %s\n", entry_dn);
                            /*
                             * iterate over all requested attributes
                             */
                            for (attr = ldap_first_attribute(ldap_handle, ldap_result, &ber); attr != NULL; attr = ldap_next_attribute(ldap_handle, ldap_result, ber)) {
                                bool is_attr_access = strcmp(attr, cfg_getstr(cfg, "ldap_attr_access")) == 0 ? 1 : 0;
                                bool is_attr_cert = strcmp(attr, cfg_getstr(cfg, "ldap_attr_cert")) == 0 ? 1 : 0;
                                /*
                                 * iterate over all values for attribute
                                 *
                                 * result of ldap_get_values_len() is an array in order to handle
                                 * mutivalued attributes
                                 */
                                if ((bvals = ldap_get_values_len(ldap_handle, ldap_result, attr)) != NULL) {
                                    int i;
                                    for (i = 0; bvals[i] != '\0'; i++) {
                                        char *value = bvals[i]->bv_val;
                                        ber_len_t len = bvals[i]->bv_len;

                                        /*
                                         * process group memberships
                                         */
                                        if (is_attr_access) {
                                            /* stop looping over group memberships when access is already granted */
                                            if (x509_info->has_access == 1) {
                                                break;
                                            }
                                            /* check access permission based on group membership and store result */
                                            check_access(value, &(x509_info->has_access));

                                        /*
                                         * process x.509 certificates
                                         */ 
                                        } else if (is_attr_cert) {
                                            /* stop looping over x.509 certificates when a valid one has already been found */
                                            if (x509_info->has_cert == 1) {
                                                break;
                                            }
                                            /* get public key */
                                            X509 *x509;
                                            x509 = d2i_X509(NULL, (const unsigned char **) &value, len);

                                            if (x509 == NULL) {
                                                LOG_FAIL("d2i_X509(): cannot decode certificate");
                                                /* try next certificate if existing */
                                                continue;
                                            }
                                            x509_info->has_cert = 1;

                                            EVP_PKEY *pkey; 
                                            /* TODO: free everything that has been gathered through openssl and malloc own space */
                                            pkey = X509_get_pubkey(x509);
                                            /* obtain information */
                                            extract_ssh_key(pkey, &(x509_info->ssh_rsa));
                                            check_signature(NULL, &(x509_info->has_valid_signature));
                                            check_expiration(NULL, &(x509_info->is_expired));
                                            check_revocation(NULL, &(x509_info->is_revoked));
                                            x509_info->subject = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
                                            x509_info->serial = BN_bn2hex(ASN1_INTEGER_to_BN(X509_get_serialNumber(x509), 0));
                                            x509_info->issuer = X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0);

                                        } else {
                                            /* should be impossible */
                                            LOG_FAIL("unhandled (not requested) attribute: '%s'", attr);
                                        }
                                    }

                                } else {
                                    /* unlikely */
                                    LOG_FAIL("ldap_get_values_len()");
                                }
                                /* free values structure after each iteration */
                                ldap_value_free_len(bvals);
                            }
                            /* free attributes structure */
                            ber_free(ber, 0);
                            break;
                        }

                    case LDAP_RES_SEARCH_REFERENCE:
                        {
                            /* TODO: handle references here */
                            LOG_FAIL("unhandled msgtype '(0x%x)'\n", msgtype);
                            break;
                        }

                    case LDAP_RES_SEARCH_RESULT:
                        {
                            /* handle result here */
                            int error_code;
                            char *error_msg = NULL;
                            rc = ldap_parse_result(ldap_handle, ldap_result, &error_code, NULL, &error_msg, NULL, NULL, 0);
                            if (rc == LDAP_SUCCESS) {
                                if (error_code != LDAP_SUCCESS) {
                                    LOG_FAIL("ldap_parse_result(): '%s' (%i)", ldap_err2string(error_code), error_code);
                                }
                                if (error_msg != NULL) {
                                    LOG_FAIL("ldap_parse_result(): '%s'", error_msg);
                                    ldap_memfree(error_msg);
                                }
                            }
                            break;
                        }

                    default:
                        {
                            /* unlikely */
                            LOG_FAIL("undefined msgtype '(0x%x)'\n", msgtype);
                        }
                }
            }

        } else {
            /* ldap_search_ext_s() error */
            LOG_FAIL("ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
        }
        /* clear result structure - even if no result has been found (see man page) */
        ldap_msgfree(ldap_result);

    } else {
        /* bind not successful */
        x509_info->directory_online = 0;
        LOG_FAIL("ldap_sasl_bind_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }

    unbind_and_free_handle:
        /*
         * unbind and free ldap_handle
         *
         * it is important to unbind also when the bind has actually failed because
         * else the ldap_handle structure that has been initialized before would
         * never be freed leading to a memory leak
         */
        if (ldap_handle != NULL) {
            rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
            if (rc == LDAP_SUCCESS) {
                LOG_SUCCESS("ldap_unbind_ext_s()");
            } else {
                LOG_FAIL("ldap_unbind_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
            }
        }
}

static void cfg_error_handler
(cfg_t *cfg, const char *fmt, va_list ap) 
{
    char error_msg[1024];
    vsnprintf(error_msg, sizeof(error_msg), fmt, ap);
    LOG_FAIL("%s", error_msg);
}

/*
 * note that value parsing and validation callback functions will only be called
 * during parsing. altering the value later wont incorporate them
 */
static int cfg_value_parser_lookup
(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) 
{
    long int result_value = config_lookup(value);
    if (result_value == -EINVAL) {
        cfg_error(cfg, "cfg_value_parser_int(): option: '%s', value: '%s'", cfg_opt_name(opt), value);
        return -1; 
    }
    /* reset log_facility var */
    if (strcmp("pam_log_facility", cfg_opt_name(opt)) == 0) {
        set_log_facility(result_value);
    }

    long int *ptr_result = result;
    *ptr_result = result_value;
    return 0;
}

static int cfg_validate_ldap_uri
(cfg_t *cfg, cfg_opt_t *opt)
{
    const char *ldap_uri = cfg_opt_getnstr(opt, 0);
    if (ldap_is_ldap_url(ldap_uri) == 0) {
        cfg_error(cfg, "cfg_validate_ldap_uri(): option: '%s', value: '%s' (value is not an ldap uri)", cfg_opt_name(opt), ldap_uri);
        return -1;
    }
    return 0;
}

static int cfg_validate_ldap_search_timeout
(cfg_t *cfg, cfg_opt_t *opt)
{
    long int timeout = cfg_opt_getnint(opt, 0);
    if (timeout <= 0) {
        cfg_error(cfg, "cfg_validate_ldap_search_timeout():  '%s', value: '%li' (value must be > 0)", cfg_opt_name(opt), timeout);
        return -1;
    }
    return 0;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    /* first argument must be path to config file */
    if (argc != 1) {
        LOG_FAIL("arg count != 1");
        goto auth_err;
    }

    /* setup config options */
    cfg_opt_t opts[] = { 
        CFG_INT_CB("pam_log_facility", 0, CFGF_NODEFAULT, &cfg_value_parser_lookup),
        CFG_STR("ldap_uri", "ldap://localhost:389", CFGF_NONE),
        CFG_STR("ldap_bind_dn", "cn=directory_manager,dc=ssh,dc=hq", CFGF_NONE),
        CFG_STR("ldap_pwd", "test123", CFGF_NONE),
        CFG_STR("ldap_base", "ou=person,dc=ssh,dc=hq", CFGF_NONE),
        CFG_INT_CB("ldap_scope", config_lookup("LDAP_SCOPE_ONE"), CFGF_NONE, &cfg_value_parser_lookup),
        CFG_INT("ldap_search_timeout", 5, CFGF_NONE),
        CFG_INT_CB("ldap_version", config_lookup("LDAP_VERSION3"), CFGF_NONE, &cfg_value_parser_lookup),
        CFG_STR("ldap_attr_rdn_person", "uid", CFGF_NONE),
        CFG_STR("ldap_attr_access", "memberOf", CFGF_NONE),
        CFG_STR("ldap_attr_cert", "userCertificate;binary", CFGF_NONE),
        CFG_STR("authorized_keys_file", "/usr/local/etc/ssh/keystore/%u/authorized_keys", CFGF_NONE),
        CFG_END()
    }; 

    /* initialize config */
    cfg_t *cfg = cfg_init(opts, CFGF_NOCASE);
    /* register callbacks */
    cfg_set_error_function(cfg, &cfg_error_handler);
    cfg_set_validate_func(cfg, "ldap_uri", &cfg_validate_ldap_uri);
    cfg_set_validate_func(cfg, "ldap_search_timeout", &cfg_validate_ldap_search_timeout);

    /* parse config */
    switch (cfg_parse(cfg, argv[0])) {
        case CFG_SUCCESS:
            break;
        case CFG_FILE_ERROR:
            cfg_error(cfg, "cfg_parse(): file: '%s', '%s'", argv[0], strerror(errno));
        case CFG_PARSE_ERROR:
            goto auth_err;
    }

    /* initialize data transfer object */
    x509_info = malloc(sizeof(*x509_info));
    if (x509_info != NULL) {
        init_data_transfer_object(x509_info);
    } else {
        LOG_FAIL("init of data transfer object failed");
        goto auth_err;
    }

    /* make data transfer object available to module stack */
    int rc = pam_set_data(pamh, "x509_info", x509_info, &cleanup_x509_info);
    if (rc != PAM_SUCCESS) {
        LOG_FAIL("pam_set_data()");
        goto auth_err;
    }

    /* make log facility available in data transfer object */
    x509_info->log_facility = cfg_getint(cfg, "pam_log_facility");

    /* retrieve uid and check for local account */
    const char *uid = NULL;
    rc = pam_get_user(pamh, &uid, NULL);
    if (rc == PAM_SUCCESS) {
        /*
         * make uid available in data transfer object. do not point to value in
         * pam space because if we free our data structure we would free it from
         * global pam space as well. other modules could rely on it
         */
        x509_info->uid = strndup(uid, UID_BUFFER_SIZE);
        if (x509_info->uid == NULL) {
            LOG_FAIL("strndup()");
            goto auth_err;
        }
        /*
         * check for local account
         *
         * this is needed because openssh validates local account after running
         * the pam modules so that the whole pam module chain would run all the
         * time an invalid user would try to connect
         */
        struct passwd *pwd = NULL;
        pwd = getpwnam(x509_info->uid);

        if (pwd == NULL) {
            LOG_FAIL("user '%s' has no local account", x509_info->uid);
            goto auth_err;
        }

    } else if (rc == PAM_SYSTEM_ERR) {
        LOG_FAIL("pam_get_user(): (%i)", rc);
        goto auth_err;

    } else if (rc == PAM_CONV_ERR) {
        LOG_FAIL("pam_get_user(): (%i)", rc);
        goto auth_err;
    }

    /* expand authorized_keys_file option and add to data transfer object */
    char *expanded_path = malloc(AUTHORIZED_KEYS_FILE_BUFFER_SIZE);
    if (expanded_path != NULL) {
        percent_expand('u', x509_info->uid, cfg_getstr(cfg, "authorized_keys_file"), expanded_path, AUTHORIZED_KEYS_FILE_BUFFER_SIZE);
        x509_info->authorized_keys_file = expanded_path;
    } else {
        LOG_FAIL("malloc() failed");
        goto auth_err;
    }

    /* make sure file is readable / writable */
    FILE *access_test = fopen(x509_info->authorized_keys_file, "a+");
    if (access_test != NULL) {
        fclose(access_test);
    } else {
        LOG_FAIL("'%s' is not readable / writable", x509_info->authorized_keys_file);
        goto auth_err;
    }

    /*
     * query ldap server and retrieve access permission and certificate of user
     */
    query_ldap(cfg);

    /* free config */
    release_config(cfg);

    return PAM_SUCCESS;

    auth_err:
        /* free config */
        release_config(cfg);
        return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

