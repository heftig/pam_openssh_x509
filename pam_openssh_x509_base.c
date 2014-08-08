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

#define SEARCH_FILTER_BUFFER_SIZE       1024
#define CERT_INFO_STRING_BUFFER_SIZE    1024
// TODO: outsource to config
#define AUTH_KEYS_FILE                  ".ssh/authorized_keys"                  /* relative to home directory */

static struct pam_openssh_x509_info *x509_info;

static void
cleanup_x509_info(pam_handle_t *pamh, void *data, int error_status)
{
    // THIS FUNCTION SHOULD BE CALLED THROUGH PAM_END() WHICH UNFORTUNATELY IS NOT HAPPENING FOR OPENSSH
    // TODO: USE IF SUPPORTED
    //syslog(log_prio, "callback touched");
}

static void
gather_information(const char *uid, cfg_t *cfg)
{
    LDAP *ldap_handle;
    LDAPMessage *ldap_result;
    struct berelement *ber;
    struct berval **bvals;
    char *attr;
    int rc, msgtype;

    struct timeval search_timeout = { cfg_getint(cfg, "ldap_search_timeout"), 0 };
    int sizelimit = 1;
    int ldap_version = cfg_getint(cfg, "ldap_version");
    
    char *attrs[] = { cfg_getstr(cfg, "ldap_attr_cert"), cfg_getstr(cfg, "ldap_attr_access"), '\0' };
    struct berval cred = { strlen(cfg_getstr(cfg, "ldap_pwd")), cfg_getstr(cfg, "ldap_pwd") };

    /* construct filter */
    bool overflow = (strlen(cfg_getstr(cfg, "ldap_attr_rdn_person")) + strlen("=") + strlen(uid) + 1 <= SEARCH_FILTER_BUFFER_SIZE) ? 0 : 1;
    if (overflow) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "internal error: there is not enough space to hold filter in buffer");
        return;
    }
    char filter[SEARCH_FILTER_BUFFER_SIZE];
    strcpy(filter, cfg_getstr(cfg, "ldap_attr_rdn_person"));
    strcat(filter, "=");
    strcat(filter, uid);

    /* init handle */
    rc = ldap_initialize(&ldap_handle, cfg_getstr(cfg, "ldap_uri"));
    if (rc == LDAP_SUCCESS) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "ldap_initialize() successful");
    } else {
        syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: '%s' (%d)", ldap_err2string(rc), rc);

        return;
    }

    /* set version */
    rc = ldap_set_option(ldap_handle, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
    if (rc != LDAP_OPT_SUCCESS) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: ldap_set_option()");

        return;
    }

    /* bind to server */
    rc = ldap_sasl_bind_s(ldap_handle, cfg_getstr(cfg, "ldap_bind_dn"), LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
    memset(cfg_getstr(cfg, "ldap_pwd"), 0, strlen(cfg_getstr(cfg, "ldap_pwd")));

    if (rc == LDAP_SUCCESS) {
        /* connection established */
        syslog(cfg_getint(cfg, "pam_log_facility"), "ldap_sasl_bind_s() successful");
        x509_info->directory_online = 1;

        /*
         * search people tree for given uid and retrieve group memberships/x.509 certificates
         */
        rc = ldap_search_ext_s(ldap_handle, cfg_getstr(cfg, "ldap_base"), cfg_getint(cfg, "ldap_scope"), filter, attrs, 0, NULL, NULL, &search_timeout, sizelimit, &ldap_result);
        if (rc == LDAP_SUCCESS) {
            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap_search_ext_s() successful");
            
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
                            syslog(cfg_getint(cfg, "pam_log_facility"), "dn: %s\n", entry_dn);

                            /*
                             * iterate over all requested attributes
                             */
                            for (attr = ldap_first_attribute(ldap_handle, ldap_result, &ber); attr != NULL; attr = ldap_next_attribute(ldap_handle, ldap_result, ber)) {
                                bool is_attr_access = (strcmp(attr, cfg_getstr(cfg, "ldap_attr_access")) == 0) ? 1 : 0;
                                bool is_attr_cert = (strcmp(attr, cfg_getstr(cfg, "ldap_attr_cert")) == 0) ? 1 : 0;
                                /*
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
                                                syslog(cfg_getint(cfg, "pam_log_facility"), "error: cannot decode certificate");
                                                /* try next certificate if existing */
                                                continue;
                                            }
                                            x509_info->has_cert = 1;

                                            EVP_PKEY *pkey; 
                                            pkey = X509_get_pubkey(x509);
                                            /* obtain information */
                                            extract_ssh_key(pkey, &(x509_info->ssh_rsa), cfg);
                                            check_signature(NULL, &(x509_info->has_valid_signature));
                                            check_expiration(NULL, &(x509_info->is_expired));
                                            check_revocation(NULL, &(x509_info->is_revoked));
                                            x509_info->subject = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
                                            x509_info->serial = BN_bn2hex(ASN1_INTEGER_to_BN(X509_get_serialNumber(x509), 0));
                                            x509_info->issuer = X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0);

                                        } else {
                                            /* should be impossible */
                                            syslog(cfg_getint(cfg, "pam_log_facility"), "unhandled (not requested) attribute: %s", attr);
                                        }
                                    }

                                } else {
                                    /* unlikely */
                                    syslog(cfg_getint(cfg, "pam_log_facility"), "error: ldap_get_values_len()"); 
                                }
                                /* free values structure after each iteration */
                                /* TODO: if nothing was allocated this will fail... problem is what happens if ldap_get_values_len() fails. do we have allocated memory or not */
                                ldap_value_free_len(bvals);
                            }
                            /* free attributes structure */
                            ber_free(ber, 0);
                            break;
                        }

                    case LDAP_RES_SEARCH_REFERENCE:
                        {
                            /* handle references here */
                            /* TODO: entry could be a reference. should be able to handle that */
                            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: unhandled msgtype (0x%x)\n", msgtype);
                            break;
                        }

                    case LDAP_RES_SEARCH_RESULT:
                        {
                            /* handle results here */
                            /* TODO: last message is always of type LDAP_RES_SEARCH_RESULT. Analyse what can be done with it */
                            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: unhandled msgtype (0x%x)\n", msgtype);
                            break;
                        }

                    default:
                        {
                            /* unlikely */
                            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: undefined msgtype (0x%x)\n", msgtype);
                        }
                }
            }
        } else {
            /* ldap_search_ext_s() error */
            syslog(cfg_getint(cfg, "pam_log_facility"), "[-] {libldap}(ldap_search_ext_s()): '%s' (%d)", ldap_err2string(rc), rc);
        }

        /* clear result structure - even if no result has been found (see man page) */
        ldap_msgfree(ldap_result);

        /* unbind */
        rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
        if (rc == LDAP_SUCCESS) {
            syslog(cfg_getint(cfg, "pam_log_facility"), "[+] {libldap}(ldap_unbind_ext_s())"); 
        } else {
            syslog(cfg_getint(cfg, "pam_log_facility"), "[-] {libldap}(ldap_unbind_ext_s()): '%s' (%d)", ldap_err2string(rc), rc);
        }

    } else {
        /* bind not successful */
        x509_info->directory_online = 0;
        syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: '%s' (%d)", ldap_err2string(rc), rc);
    }
}

static void cfg_error_handler
(cfg_t *cfg, const char *fmt, va_list ap) 
{
    char error_msg[1024];
    vsnprintf(error_msg, sizeof(error_msg), fmt, ap);
    syslog(cfg_getint(cfg, "pam_log_facility"), "%s\n", error_msg);
}

static int cfg_value_parser_int
(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) 
{
    long int result_value = config_lookup(value);
    if (result_value == -EINVAL) {
        cfg_error(cfg, "[libconfuse]-parse_error: option: %s, value: %s", cfg_opt_name(opt), value);
        return -1; 
    }   

    long int *ptr_result = result;
    *ptr_result = result_value;

    return 0;
}

static int cfg_validate_ldap_uri
(cfg_t *cfg, cfg_opt_t *opt)
{
    const char *value = cfg_opt_getnstr(opt, 0);
    if (ldap_is_ldap_url(value) == 0) {
        cfg_error(cfg, "[libconfuse]-validation_error: option: %s, value: %s (value is not an ldap uri)", cfg_opt_name(opt), value);
        return -1;
    }

    return 0;
}

static int cfg_validate_ldap_search_timeout
(cfg_t *cfg, cfg_opt_t *opt)
{
    long int value = cfg_opt_getnint(opt, 0);
    if (value <= 0) {
        cfg_error(cfg, "[libconfuse]-validation_error: option: %s, value: %li (value must be > 0)", cfg_opt_name(opt), value);
        return -1;
    }

    return 0;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int rc;

    // BEGIN: parse config
    cfg_opt_t opts[] = { 
        CFG_INT_CB("pam_log_facility", config_lookup("LOG_LOCAL1"), CFGF_NONE, &cfg_value_parser_int),
        CFG_STR("ldap_uri", "ldap://localhost:389", CFGF_NONE),
        CFG_STR("ldap_bind_dn", NULL, CFGF_NODEFAULT),
        CFG_STR("ldap_pwd", NULL, CFGF_NODEFAULT),
        CFG_STR("ldap_base", NULL, CFGF_NODEFAULT),
        CFG_INT_CB("ldap_scope", config_lookup("LDAP_SCOPE_ONE"), CFGF_NONE, &cfg_value_parser_int),
        CFG_INT("ldap_search_timeout", 5, CFGF_NONE),
        CFG_INT_CB("ldap_version", config_lookup("LDAP_VERSION3"), CFGF_NONE, &cfg_value_parser_int),
        CFG_STR("ldap_attr_rdn_person", "uid", CFGF_NONE),
        CFG_STR("ldap_attr_access", "memberOf", CFGF_NONE),
        CFG_STR("ldap_attr_cert", "userCertificate;binary", CFGF_NONE),
        CFG_END()
    }; 

    cfg_t *cfg = cfg_init(opts, CFGF_NOCASE);
    // register callback for error handling
    cfg_set_error_function(cfg, &cfg_error_handler);
    // register callback for validating ldap_uri
    cfg_set_validate_func(cfg, "ldap_uri", &cfg_validate_ldap_uri);
    // register callback for validating ldap_search_timeout
    cfg_set_validate_func(cfg, "ldap_search_timeout", &cfg_validate_ldap_search_timeout);

    if (argc != 1) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "arg count != 1");
        goto auth_err;
    }

    switch (cfg_parse(cfg, argv[0]))
    {
        case CFG_SUCCESS:
            break;

        case CFG_FILE_ERROR:
            cfg_error(cfg, "[libconfuse]-file_error: (%s) %s", argv[0], strerror(errno));

        case CFG_PARSE_ERROR:
            goto auth_err;
    } 
    // END: parse config

    init_data_transfer_object(&x509_info); 
    if (x509_info == NULL) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "init of data transfer object failed");
        goto auth_err;
    }

    /* make data transfer object available for module stack */
    rc = pam_set_data(pamh, "x509_info", x509_info, &cleanup_x509_info);
    if (rc != PAM_SUCCESS) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "error: pam_set_data()");
        goto auth_err;
    }

    const char *uid;
    rc = pam_get_user(pamh, &uid, NULL);
    if (rc == PAM_SUCCESS) {
        /*
         * check for local account
         *
         * this is needed because openssh validates local account after running
         * the pam modules so that the whole pam module chain would run all the
         * time an invalid user would try to connect
         */
        struct passwd *pwd;
        pwd = getpwnam(uid);

        if (pwd == NULL) {
            syslog(cfg_getint(cfg, "pam_log_facility"), "error: user '%s' has no local account", uid);
            goto auth_err;

        } else {
            /* get information from ldap server */
            gather_information(uid, cfg);

            /* construct authorized_keys path */
            int length_auth_keys_path = strlen(pwd->pw_dir) + 1 + strlen(AUTH_KEYS_FILE) + 1;
            char path[length_auth_keys_path];
            memcpy(path, pwd->pw_dir, strlen(pwd->pw_dir) + 1);
            strcat(path, "/");
            strcat(path, AUTH_KEYS_FILE);

            FILE *access_test = fopen(path, "a+");
            if (access_test != NULL) {
                x509_info->authorized_keys_file = malloc(strlen(path) + 1);
                    if (x509_info->authorized_keys_file != NULL)
                        memcpy(x509_info->authorized_keys_file, path, strlen(path) + 1);

                fclose(access_test);
            }
        }
    } else if (rc == PAM_SYSTEM_ERR) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "error: pam_get_user()");
        goto auth_err;

    } else if (rc == PAM_CONV_ERR) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "error: pam_get_user() => NULL POINTER");
        goto auth_err;
    }

    return PAM_SUCCESS;

    auth_err:
        // free config
        cfg_free_value(opts);
        cfg_free(cfg);

        return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

