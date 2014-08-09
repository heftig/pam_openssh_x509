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

#define SEARCH_FILTER_BUFFER_SIZE           1024
#define CERT_INFO_STRING_BUFFER_SIZE        1024
#define UID_BUFFER_SIZE                     33
#define AUTHORIZED_KEYS_FILE_BUFFER_SIZE    1024

static struct pam_openssh_x509_info *x509_info;

static void
cleanup_x509_info(pam_handle_t *pamh, void *data, int error_status)
{
    // THIS FUNCTION SHOULD BE CALLED THROUGH PAM_END() WHICH UNFORTUNATELY IS NOT HAPPENING FOR OPENSSH
    // TODO: USE IF SUPPORTED
    //syslog(log_prio, "callback touched");
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

    /* construct filter */
    bool overflow = strlen(cfg_getstr(cfg, "ldap_attr_rdn_person")) + strlen("=") + strlen(x509_info->uid) + 1 <= SEARCH_FILTER_BUFFER_SIZE ? 0 : 1;
    if (overflow) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "[-] there is not enough space to hold filter in buffer");

        return;
    }
    char filter[SEARCH_FILTER_BUFFER_SIZE];
    strcpy(filter, cfg_getstr(cfg, "ldap_attr_rdn_person"));
    strcat(filter, "=");
    strcat(filter, x509_info->uid);

    /* init handle */
    rc = ldap_initialize(&ldap_handle, cfg_getstr(cfg, "ldap_uri"));
    if (rc == LDAP_SUCCESS) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "[+] ldap_initialize()");
    } else {
        syslog(cfg_getint(cfg, "pam_log_facility"), "[-] ldap_initialize(): '%s' (%d)", ldap_err2string(rc), rc);

        goto unbind_and_free_handle;
    }

    /* set version */
    rc = ldap_set_option(ldap_handle, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
    if (rc != LDAP_OPT_SUCCESS) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "[-] ldap_set_option(): key: LDAP_OPT_PROTOCOL_VERSION, value: %i", ldap_version);

        goto unbind_and_free_handle;
    }

    /* bind to server */
    rc = ldap_sasl_bind_s(ldap_handle, cfg_getstr(cfg, "ldap_bind_dn"), LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
    memset(cfg_getstr(cfg, "ldap_pwd"), 0, strlen(cfg_getstr(cfg, "ldap_pwd")));

    if (rc == LDAP_SUCCESS) {
        /* connection established */
        syslog(cfg_getint(cfg, "pam_log_facility"), "[+] ldap_sasl_bind_s()");
        x509_info->directory_online = 1;

        /*
         * search people tree for given uid and retrieve group memberships / x.509 certificates
         */
        rc = ldap_search_ext_s(ldap_handle, cfg_getstr(cfg, "ldap_base"), cfg_getint(cfg, "ldap_scope"), filter, attrs, 0, NULL, NULL, &search_timeout, sizelimit, &ldap_result);
        if (rc == LDAP_SUCCESS) {
            syslog(cfg_getint(cfg, "pam_log_facility"), "[+] ldap_search_ext_s()");
            
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
                            syslog(cfg_getint(cfg, "pam_log_facility"), "[#] dn: %s\n", entry_dn);

                            /*
                             * iterate over all requested attributes
                             */
                            for (attr = ldap_first_attribute(ldap_handle, ldap_result, &ber); attr != NULL; attr = ldap_next_attribute(ldap_handle, ldap_result, ber)) {
                                bool is_attr_access = strcmp(attr, cfg_getstr(cfg, "ldap_attr_access")) == 0 ? 1 : 0;
                                bool is_attr_cert = strcmp(attr, cfg_getstr(cfg, "ldap_attr_cert")) == 0 ? 1 : 0;
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
                                                syslog(cfg_getint(cfg, "pam_log_facility"), "[-] d2i_X509(): cannot decode certificate");
                                                /* try next certificate if existing */
                                                continue;
                                            }
                                            x509_info->has_cert = 1;

                                            EVP_PKEY *pkey; 
                                            /* TODO: free everything that has been gathered through openssl and malloc own space */
                                            pkey = X509_get_pubkey(x509);
                                            /* obtain information */
                                            extract_ssh_key(cfg, pkey, &(x509_info->ssh_rsa));
                                            check_signature(NULL, &(x509_info->has_valid_signature));
                                            check_expiration(NULL, &(x509_info->is_expired));
                                            check_revocation(NULL, &(x509_info->is_revoked));
                                            x509_info->subject = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
                                            x509_info->serial = BN_bn2hex(ASN1_INTEGER_to_BN(X509_get_serialNumber(x509), 0));
                                            x509_info->issuer = X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0);

                                        } else {
                                            /* should be impossible */
                                            syslog(cfg_getint(cfg, "pam_log_facility"), "[-] unhandled (not requested) attribute: '%s'", attr);
                                        }
                                    }

                                } else {
                                    /* unlikely */
                                    syslog(cfg_getint(cfg, "pam_log_facility"), "[-] ldap_get_values_len()");
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
                            /* handle references here */
                            /* TODO: entry could be a reference. should be able to handle that */
                            syslog(cfg_getint(cfg, "pam_log_facility"), "[-] unhandled msgtype '(0x%x)'\n", msgtype);
                            break;
                        }

                    case LDAP_RES_SEARCH_RESULT:
                        {
                            /* handle results here */
                            /* TODO: last message is always of type LDAP_RES_SEARCH_RESULT. Analyse what can be done with it */
                            syslog(cfg_getint(cfg, "pam_log_facility"), "[-] unhandled msgtype '(0x%x)'\n", msgtype);
                            break;
                        }

                    default:
                        {
                            /* unlikely */
                            syslog(cfg_getint(cfg, "pam_log_facility"), "[-] undefined msgtype '(0x%x)'\n", msgtype);
                        }
                }
            }
        } else {
            /* ldap_search_ext_s() error */
            syslog(cfg_getint(cfg, "pam_log_facility"), "[-] ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
        }
        /* clear result structure - even if no result has been found (see man page) */
        ldap_msgfree(ldap_result);

    } else {
        /* bind not successful */
        x509_info->directory_online = 0;
        syslog(cfg_getint(cfg, "pam_log_facility"), "[-] ldap_sasl_bind_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }

    unbind_and_free_handle:
        /*
         * unbind and free ldap_handle
         *
         * it is important to unbind also when the bind has actually failed because
         * else the ldap_handle structure that has been initialized before would
         * never be freed leading to a memory leak
         *
         */
        if (ldap_handle != NULL) {
            rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
            if (rc == LDAP_SUCCESS) {
                syslog(cfg_getint(cfg, "pam_log_facility"), "[+] ldap_unbind_ext_s()");
            } else {
                syslog(cfg_getint(cfg, "pam_log_facility"), "[-] ldap_unbind_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
            }
        }
}

static void cfg_error_handler
(cfg_t *cfg, const char *fmt, va_list ap) 
{
    char error_msg[1024];
    vsnprintf(error_msg, sizeof(error_msg), fmt, ap);
    syslog(cfg_getint(cfg, "pam_log_facility"), "[-] %s\n", error_msg);
}

static int cfg_value_parser_lookup
(cfg_t *cfg, cfg_opt_t *opt, const char *value, void *result) 
{
    long int result_value = config_lookup(value);
    if (result_value == -EINVAL) {
        cfg_error(cfg, "cfg_value_parser_int(): option: '%s', value: '%s'", cfg_opt_name(opt), value);
        return -1; 
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

static int cfg_validate_authorized_keys_file
(cfg_t *cfg, cfg_opt_t *opt)
{
    char *path = cfg_opt_getnstr(opt, 0);
    char *expanded_path = malloc(AUTHORIZED_KEYS_FILE_BUFFER_SIZE);
    if (expanded_path != NULL) {
        percent_expand('u', x509_info->uid, path, expanded_path, AUTHORIZED_KEYS_FILE_BUFFER_SIZE);
        x509_info->authorized_keys_file = expanded_path;

        /* check if file is read and writable */
        FILE *access_test = fopen(x509_info->authorized_keys_file, "a+");
        if (access_test != NULL) {
                fclose(access_test);
                return 0;
        } else {
            cfg_error(cfg, "cfg_validate_authorized_keys_file(): '%s' is not readable / writable", x509_info->authorized_keys_file);
        }

    } else {
        cfg_error(cfg, "cfg_validate_authorized_keys_file(): malloc() failed");
    }

    return -1;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    /* setup config options */
    cfg_opt_t opts[] = { 
        CFG_INT_CB("pam_log_facility", config_lookup("LOG_LOCAL1"), CFGF_NONE, &cfg_value_parser_lookup),
        CFG_STR("ldap_uri", "ldap://localhost:389", CFGF_NONE),
        CFG_STR("ldap_bind_dn", NULL, CFGF_NODEFAULT),
        CFG_STR("ldap_pwd", NULL, CFGF_NODEFAULT),
        CFG_STR("ldap_base", NULL, CFGF_NODEFAULT),
        CFG_INT_CB("ldap_scope", config_lookup("LDAP_SCOPE_ONE"), CFGF_NONE, &cfg_value_parser_lookup),
        CFG_INT("ldap_search_timeout", 5, CFGF_NONE),
        CFG_INT_CB("ldap_version", config_lookup("LDAP_VERSION3"), CFGF_NONE, &cfg_value_parser_lookup),
        CFG_STR("ldap_attr_rdn_person", "uid", CFGF_NONE),
        CFG_STR("ldap_attr_access", "memberOf", CFGF_NONE),
        CFG_STR("ldap_attr_cert", "userCertificate;binary", CFGF_NONE),
        CFG_STR("authorized_keys_file", "/usr/local/etc/ssh/keystore/%u/authorized_keys", CFGF_NONE),
        CFG_END()
    }; 

    /*
     * initalizing config
     *
     * default values will be initialized. after it we can log. syslog facility will be the
     * default value specified above
     *
     */
    cfg_t *cfg = cfg_init(opts, CFGF_NOCASE);
    /* register callbacks */
    cfg_set_error_function(cfg, &cfg_error_handler);
    cfg_set_validate_func(cfg, "ldap_uri", &cfg_validate_ldap_uri);
    cfg_set_validate_func(cfg, "ldap_search_timeout", &cfg_validate_ldap_search_timeout);
    cfg_set_validate_func(cfg, "authorized_keys_file", &cfg_validate_authorized_keys_file);

    /* first argument must be path to config file */
    if (argc != 1) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "[-] arg count != 1");
        goto auth_err;
    }

    /*
     * initialize data transfer object
     *
     * the validation of the authorized_keys_file config option needs the uid of the
     * connecting user. in order to not call pam_get_user() more than once the data
     * transfer object will be initialized before parsing the config file.
     * the uid will be put there so that the validation callback can access it then
     *
     */
    x509_info = malloc(sizeof(*x509_info));
    if (x509_info != NULL) {
        init_data_transfer_object(x509_info);
    } else {
        syslog(cfg_getint(cfg, "pam_log_facility"), "[-] init of data transfer object failed");
        goto auth_err;
    }

    /* make data transfer object available for module stack */
    int rc = pam_set_data(pamh, "x509_info", x509_info, &cleanup_x509_info);
    if (rc != PAM_SUCCESS) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "[-] pam_set_data()");
        goto auth_err;
    }

    /* retrieve uid and check for local account */
    const char *uid = NULL;
    rc = pam_get_user(pamh, &uid, NULL);
    if (rc == PAM_SUCCESS) {
        /*
         * make uid available in data transfer object. do not point to value in
         * pam space because if we free our data structure we would free it from
         * global pam space as well. other modules could rely on it
         *
         */
        x509_info->uid = strndup(uid, UID_BUFFER_SIZE);
        if (x509_info->uid == NULL) {
            syslog(cfg_getint(cfg, "pam_log_facility"), "[-] strndup()");
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
            syslog(cfg_getint(cfg, "pam_log_facility"), "[-] user '%s' has no local account", x509_info->uid);
            goto auth_err;
        }

    } else if (rc == PAM_SYSTEM_ERR) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "[-] pam_get_user(): (%i)", rc);
        goto auth_err;

    } else if (rc == PAM_CONV_ERR) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "[-] pam_get_user(): (%i)", rc);
        goto auth_err;
    }

    /* parse config */
    switch (cfg_parse(cfg, argv[0]))
    {
        case CFG_SUCCESS:
            break;

        case CFG_FILE_ERROR:
            cfg_error(cfg, "cfg_parse(): file: '%s', '%s'", argv[0], strerror(errno));

        case CFG_PARSE_ERROR:
            goto auth_err;
    }

    /*
     * query ldap server and retrieve access permission and certificate of user
     *
     */
    query_ldap(cfg);

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

