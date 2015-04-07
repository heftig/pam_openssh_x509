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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/time.h>
#include <dirent.h>
#include <pwd.h>
#include <errno.h>

#include <confuse.h>
#include <ldap.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pam_openssh_x509_config.h"
#include "pam_openssh_x509_util.h"

#define LDAP_SEARCH_FILTER_BUFFER_SIZE      512
#define UID_BUFFER_SIZE                     33
#define AUTHORIZED_KEYS_FILE_BUFFER_SIZE    1024

static void
cleanup_x509_info(pam_handle_t *pamh, void *data, int error_status)
{
    /*
     * this cleanup function should normally be called by pam_end().
     * unfortunately this is not happening for OpenSSH under "normal"
     * circumstances. the reasons is as follows:
     *
     * unless UNSUPPORTED_POSIX_THREADS_HACK has been defined during
     * compilation (which in most cases is not) OpenSSH creates a new
     * process(!) for pam authentication and account handling. the pam
     * handle is duplicated into the new process and every information
     * added through pam modules to the handle is only visible in the
     * new process. as the process terminates after the account handling
     * the original pam handle does not know anything about the previously
     * registered data structure and cleanup function so that it cannot
     * be taken into account during pam_end().
     *
     * not freeing the data structure results in a memory leak.
     * as the process terminates immediately and all memory is given
     * back to the operating system no further workarounds have been
     * setup.
     *
     * still an implementation follows for the brave people who enabled
     * posix threads in OpenSSH and to be prepared for possible changes
     * in OpenSSH.
     */
    struct pam_openssh_x509_info *x509_info = data;
    LOG_MSG("freeing x509_info");
    free(x509_info->log_facility);
    free(x509_info->subject);
    free(x509_info->issuer);
    free(x509_info->serial);
    free(x509_info->ssh_key);
    free(x509_info->ssh_keytype);
    free(x509_info->authorized_keys_file);
    free(x509_info->uid);
    free(x509_info);
    LOG_MSG("x509_info freed");
}

static void
retrieve_access_permission_and_x509_from_ldap(cfg_t *cfg, struct pam_openssh_x509_info *x509_info, X509 **x509)
{
    /* init handle */
    LDAP *ldap_handle = NULL;
    int rc = ldap_initialize(&ldap_handle, cfg_getstr(cfg, "ldap_uri"));
    if (rc == LDAP_SUCCESS) {
        LOG_SUCCESS("ldap_initialize()");
    } else {
        FATAL("ldap_initialize(): '%s' (%d)", ldap_err2string(rc), rc);
    }

    /* set version */
    int ldap_version = cfg_getint(cfg, "ldap_version");
    rc = ldap_set_option(ldap_handle, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
    if (rc != LDAP_OPT_SUCCESS) {
        FATAL("ldap_set_option(): key: LDAP_OPT_PROTOCOL_VERSION, value: %i", ldap_version);
    }

    /* bind to server */
    char *ldap_pwd = cfg_getstr(cfg, "ldap_pwd");
    size_t ldap_pwd_length = strlen(ldap_pwd);
    struct berval cred = { ldap_pwd_length, ldap_pwd };
    rc = ldap_sasl_bind_s(ldap_handle, cfg_getstr(cfg, "ldap_bind_dn"), LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
    memset(ldap_pwd, 0, ldap_pwd_length);

    if (rc == LDAP_SUCCESS) {
        /* connection established */
        LOG_SUCCESS("ldap_sasl_bind_s()");
        x509_info->directory_online = 1;

        /* search people tree for given uid and retrieve group memberships / x509 certificates */

        /* construct search filter */
        char filter[LDAP_SEARCH_FILTER_BUFFER_SIZE];
        strncpy(filter, cfg_getstr(cfg, "ldap_attr_rdn_person"), sizeof(filter));
        strncat(filter, "=", sizeof(filter) - strlen(filter) - 1);
        strncat(filter, x509_info->uid, sizeof(filter) - strlen(filter) - 1);

        char *attrs[] = { cfg_getstr(cfg, "ldap_attr_cert"), cfg_getstr(cfg, "ldap_attr_access"), '\0' };
        struct timeval search_timeout = { cfg_getint(cfg, "ldap_search_timeout"), 0 };
        int sizelimit = 1;
        LDAPMessage *ldap_result = NULL;

        rc = ldap_search_ext_s(ldap_handle, cfg_getstr(cfg, "ldap_base"), cfg_getint(cfg, "ldap_scope"), filter, attrs, 0, NULL, NULL, &search_timeout, sizelimit, &ldap_result);
        if (rc == LDAP_SUCCESS) {
            LOG_SUCCESS("ldap_search_ext_s()");
            /*
             * iterate over matching entries
             *
             * even though sizelimit is 1 at least 2 messages will be returned (1x LDAP_RES_SEARCH_ENTRY + 1x LDAP_RES_SEARCH_RESULT)
             * so that we need to iterate over the result set instead of just retrieve and process the first message
             */
            for (ldap_result = ldap_first_message(ldap_handle, ldap_result); ldap_result != NULL; ldap_result = ldap_next_message(ldap_handle, ldap_result)) {
                int msgtype = ldap_msgtype(ldap_result);
                switch (msgtype) {
                    case LDAP_RES_SEARCH_ENTRY:
                        {
                            char *user_dn = ldap_get_dn(ldap_handle, ldap_result); 
                            if (user_dn == NULL) {
                                /* cannot access ldap_handle->ld_errno as structure is opaque */
                                LOG_FAIL("ldap_get_dn(): '%s'", "user_dn == NULL");
                            } else {
                                LOG_MSG("user_dn: %s", user_dn);
                            }

                            /* iterate over all requested attributes */
                            char *attr = NULL;
                            struct berelement *attributes = NULL;
                            for (attr = ldap_first_attribute(ldap_handle, ldap_result, &attributes); attr != NULL; attr = ldap_next_attribute(ldap_handle, ldap_result, attributes)) {
                                bool is_attr_access = strcmp(attr, cfg_getstr(cfg, "ldap_attr_access")) == 0 ? 1 : 0;
                                bool is_attr_cert = strcmp(attr, cfg_getstr(cfg, "ldap_attr_cert")) == 0 ? 1 : 0;

                                struct berval **attr_values = ldap_get_values_len(ldap_handle, ldap_result, attr);
                                if (attr_values != NULL) {
                                    /*
                                     * iterate over all values for attribute
                                     *
                                     * result of ldap_get_values_len() is an array in order to handle
                                     * mutivalued attributes
                                     */
                                    int i;
                                    for (i = 0; attr_values[i] != '\0'; i++) {
                                        char *value = attr_values[i]->bv_val;
                                        ber_len_t len = attr_values[i]->bv_len;

                                        /* process group memberships */
                                        if (is_attr_access) {
                                            /* check access permission based on group membership and store result */
                                            LOG_MSG("group_dn: %s", value);
                                            check_access_permission(value, cfg_getstr(cfg, "ldap_group_identifier"), x509_info);
                                            /* stop looping over group memberships when access has been granted */
                                            if (x509_info->has_access == 1) {
                                                break;
                                            }

                                        /* process x509 certificates */
                                        } else if (is_attr_cert) {
                                            /* decode certificate */
                                            *x509 = d2i_X509(NULL, (const unsigned char **) &value, len);
                                            if (*x509 == NULL) {
                                                LOG_FAIL("d2i_X509(): cannot decode certificate");
                                                /* try next certificate if existing */
                                                continue;
                                            }
                                            x509_info->has_cert = 1;
                                            /* stop looping over x509 certificates when a valid one has been found */
                                            break;
                                        } else {
                                            /* unlikely */
                                            LOG_FAIL("unhandled (not requested) attribute: '%s'", attr);
                                        }
                                    }
                                    /* free attribute values array after each iteration */
                                    ldap_value_free_len(attr_values);
                                } else {
                                    /* unlikely */
                                    LOG_FAIL("ldap_get_values_len()");
                                }
                            }
                            /* free attributes structure */
                            ber_free(attributes, 0);
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

    /*
     * unbind and free ldap_handle
     *
     * it is important to unbind also when the bind has actually failed because
     * else the ldap_handle structure that has been initialized before would
     * never be freed leading to a memory leak
     */
    rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
    if (rc == LDAP_SUCCESS) {
        LOG_SUCCESS("ldap_unbind_ext_s()");
    } else {
        LOG_FAIL("ldap_unbind_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    /* check if argument is path to config file */
    if (argc != 1) {
        FATAL("arg count != 1");
    }
    const char *cfg_file = argv[0];
    int rc = is_file_readable(cfg_file);
    if (rc != 0) {
        FATAL("cannot open config file (%s) for reading", cfg_file);
    }

    /* initialize and parse config */
    cfg_t *cfg = NULL;
    init_and_parse_config(&cfg, cfg_file);

    /* initialize data transfer object */
    struct pam_openssh_x509_info *x509_info = malloc(sizeof(struct pam_openssh_x509_info));
    if (x509_info != NULL) {
        init_data_transfer_object(x509_info);
    } else {
        FATAL("malloc()");
    }

    /* make data transfer object available to module stack */
    rc = pam_set_data(pamh, "x509_info", x509_info, &cleanup_x509_info);
    if (rc != PAM_SUCCESS) {
        FATAL("pam_set_data()");
    }

    /* make log facility available in data transfer object */
    x509_info->log_facility = strdup(cfg_getstr(cfg, "log_facility"));
    if (x509_info->log_facility == NULL) {
        FATAL("strdup()");
    }

    /* retrieve uid */
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
            FATAL("strndup()");
        }
    } else {
        FATAL("pam_get_user(): (%i)", rc);
    }

    /* expand authorized_keys_file option and add to data transfer object */
    char *expanded_path = malloc(AUTHORIZED_KEYS_FILE_BUFFER_SIZE);
    if (expanded_path != NULL) {
        substitute_token('u', x509_info->uid, cfg_getstr(cfg, "authorized_keys_file"), expanded_path, AUTHORIZED_KEYS_FILE_BUFFER_SIZE);
        x509_info->authorized_keys_file = expanded_path;
    } else {
        FATAL("malloc()");
    }

    /* query ldap server and retrieve access permission and certificate of user */
    X509 *x509 = NULL;
    retrieve_access_permission_and_x509_from_ldap(cfg, x509_info, &x509);

    /* process certificate if one has been found*/
    if (x509 != NULL) {
        /* validate certificate */
        validate_x509(x509, cfg_getstr(cfg, "cacerts_dir"), x509_info);

        x509_info->subject = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
        x509_info->serial = BN_bn2hex(ASN1_INTEGER_to_BN(X509_get_serialNumber(x509), 0));
        x509_info->issuer = X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0);

        /* extract public key and convert to OpenSSH format */
        EVP_PKEY *pkey = X509_get_pubkey(x509);
        if (pkey != NULL) {
            pkey_to_authorized_keys(pkey, x509_info);
            EVP_PKEY_free(pkey);
        } else {
            FATAL("X509_get_pubkey(): unable to load public key");
        }
        /* free x509 structure */
        X509_free(x509);
    }

    /* free config */
    release_config(cfg);

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

