/*
author: sebastian roland
date: 2013-06-10
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#include <confuse.h>
#include <ldap.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "include/pam_openssh_x509.h"

#define PUT_32BIT(cp, value) ( \
    (cp)[0] = (unsigned char)((value) >> 24), \
    (cp)[1] = (unsigned char)((value) >> 16), \
    (cp)[2] = (unsigned char)((value) >> 8), \
    (cp)[3] = (unsigned char)(value) )

#define SEARCH_FILTER_BUFFER_SIZE       1024
#define CERT_INFO_STRING_BUFFER_SIZE    1024
#define AUTH_KEYS_FILE                  ".ssh/authorized_keys"                  /* relative to home directory */

static struct pam_openssh_x509_info *x509_info;
static const char *own_fqdn = "test.ssh.hq";			                       /* TODO: CHANGE TO OBTAIN FQDN FROM SYSTEM */

static int
is_msb_set(unsigned char byte)
{
    if (byte & 0x80) {
        return 1;
    } else {
        return 0;
    }
}

static void
cleanup_x509_info(pam_handle_t *pamh, void *data, int error_status)
{
	// THIS FUNCTION SHOULD BE CALLED THROUGH PAM_END() WHICH UNFORTUNATELY IS NOT HAPPENING FOR OPENSSH
	// TODO: USE IF SUPPORTED
    //syslog(log_prio, "callback touched");
}

static void
init_data_transfer_object(struct pam_openssh_x509_info **x509_info)
{
    *x509_info = malloc(sizeof(**x509_info));
    if (*x509_info != NULL) {
        /* set standard values */
        memset(*x509_info, 0, sizeof(**x509_info));

        (*x509_info)->has_cert = -1;
        (*x509_info)->subject = NULL;
        (*x509_info)->serial = NULL;
        (*x509_info)->issuer = NULL;
        (*x509_info)->is_expired = -1;
        (*x509_info)->has_valid_signature = -1;
        (*x509_info)->is_revoked = -1;
        (*x509_info)->ssh_rsa = NULL;
        (*x509_info)->authorized_keys_file = NULL;
        (*x509_info)->has_local_account = -1;
        (*x509_info)->directory_online = -1;
        (*x509_info)->has_access = -1;
    }
}

static void
check_access(char *group_dn, char *has_access)
{
    char *stored_fqdn = strtok(group_dn, "=");
    stored_fqdn = strtok(NULL, "_");
    stored_fqdn = strtok(NULL, ",");

    if (stored_fqdn && own_fqdn) {
        if (strcmp(stored_fqdn, own_fqdn) == 0) {
        /* attribute set for server */
            *has_access = 1;
            return;
        }
    }
    *has_access = 0;
}

static void
check_signature(char *exchange_with_cert, char *has_valid_signature)
{
    /* implement check of signature here */
    //*has_valid_signature = poc_val_sig;
}

static void
check_expiration(char *exchange_with_cert, char *is_expired)
{
    /* implement check for expiration here */
    //*is_expired = poc_expired;
}

static void
check_revocation(char *exchange_with_cert, char *is_revoked)
{
    /* implement check for revocation here */
    //*is_revoked = poc_revoked;
}

static void
extract_ssh_key(EVP_PKEY *pkey, char **ssh_rsa, cfg_t *cfg)
{
    if (pkey == NULL) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "error: cannot get public key from certificate");
        return;
    }

    switch (EVP_PKEY_type(pkey->type)) {
        case EVP_PKEY_RSA:
            {
                syslog(cfg_getint(cfg, "pam_log_facility"), "Keytype: RSA");
                char *keyname = "ssh-rsa";
                RSA *rsa = EVP_PKEY_get1_RSA(pkey);
                if (rsa == NULL) {
                /* unlikely */
                    syslog(cfg_getint(cfg, "pam_log_facility"), "error: EVP_PKEY_get1_RSA()");
                    break;
                }

                /* create authorized_keys entry */
                int length_keyname, length_exponent, length_modulus, pre_length_blob, post_length_blob;
                length_keyname = strlen(keyname);
                length_exponent = BN_num_bytes(rsa->e);
                length_modulus = BN_num_bytes(rsa->n);

                /* the 4 bytes hold the length of the following value and the 2 extra bytes before
                 * the exponent and modulus are possibly needed to prefix the values with leading zeroes if the
                 * most significant bit of them is set. this is to avoid misinterpreting the value as a
                 * negative number later.
                 */
                pre_length_blob = 4 + length_keyname + 4 + 1 + length_exponent + 4 + 1 + length_modulus;

                /* TODO: SET LIMIT FOR LENGTH OF BLOB TO AVOID STACK OVERFLOW */
                unsigned char blob[pre_length_blob], *blob_p, blob_buffer[pre_length_blob];
                blob_p = blob;
                PUT_32BIT(blob_p, length_keyname);
                blob_p += 4;
                memcpy(blob_p, keyname, length_keyname);
                blob_p += length_keyname;
                BN_bn2bin(rsa->e, blob_buffer);

                /* put length of exponent */
                if (is_msb_set(blob_buffer[0])) {
                    PUT_32BIT(blob_p, length_exponent + 1);
                    blob_p += 4;
                    *(blob_p++) = 0;
                } else {
                    PUT_32BIT(blob_p, length_exponent);
                    blob_p += 4;
                }
                /* put exponent */
                memcpy(blob_p, blob_buffer, length_exponent);
                blob_p += length_exponent;
                BN_bn2bin(rsa->n, blob_buffer);

                /* put length of modulus */
                if (is_msb_set(blob_buffer[0])) {
                    PUT_32BIT(blob_p, length_modulus + 1);
                    blob_p += 4;
                    *(blob_p++) = 0;
                } else {
                    PUT_32BIT(blob_p, length_modulus);
                    blob_p += 4;
                }  
                /* put modulus */
                memcpy(blob_p, blob_buffer, length_modulus);
                blob_p += length_modulus;
                post_length_blob = blob_p - blob;

                /* encode base64 */
                int data_in;
                long data_out;
                unsigned char *tmp_result;
                BIO *bio, *b64;

                bio = BIO_new(BIO_s_mem()); 
                b64 = BIO_new(BIO_f_base64());
                BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
                b64 = BIO_push(b64, bio);
                data_in = BIO_write(b64, blob, post_length_blob);
                BIO_flush(b64);
                data_out = BIO_get_mem_data(b64, &tmp_result); 

                /* store key */
                char *ssh_pkey = malloc(data_out + 1);
                if (ssh_pkey != NULL) {
                    memcpy(ssh_pkey, tmp_result, data_out);
                    ssh_pkey[data_out] = '\0';
                }
                
                /* probably there is already a pointer to allocated mem => free first */
                free(*ssh_rsa);
                *ssh_rsa = ssh_pkey;

                /* clear structures */
                BIO_free_all(b64);
                RSA_free(rsa);
                EVP_PKEY_free(pkey);
                                                    
                break;
            }
        case EVP_PKEY_DSA:
            {
                syslog(cfg_getint(cfg, "pam_log_facility"), "dsa...");
                break;
            }
        case EVP_PKEY_DH:
            {
                syslog(cfg_getint(cfg, "pam_log_facility"), "dh...");
                break;
            }
        case EVP_PKEY_EC:
            {
                syslog(cfg_getint(cfg, "pam_log_facility"), "ec...");
                break;
            }
        default:
            {
                syslog(cfg_getint(cfg, "pam_log_facility"), "error: unsupported public key type (pkey->type)");
            }
    }
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

    struct timeval timeout = { cfg_getint(cfg, "ldap_timeout"), 0 };
    int sizelimit = 1;
	int ldap_version = cfg_getint(cfg, "ldap_version");
    
    char *attrs[] = { cfg_getstr(cfg, "ldap_attr_cert"), cfg_getstr(cfg, "ldap_attr_access"), '\0' };
    struct berval cred = { strlen(cfg_getstr(cfg, "ldap_pwd")), cfg_getstr(cfg, "ldap_pwd") };

    /* construct filter */
    unsigned int overflow = strlen(cfg_getstr(cfg, "ldap_attr_rdn_person")) + strlen("=") + strlen(uid) + 1 <= SEARCH_FILTER_BUFFER_SIZE ? 0 : 1;
    if (overflow) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "internal error: there is not enough space to hold filter in buffer. increase SEARCH_FILTER_BUFFER_SIZE!");

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
	// TODO: remove password from config file in memory here
    //memset(pwd, 0, strlen(pwd));
    if (rc == LDAP_SUCCESS) {
        syslog(cfg_getint(cfg, "pam_log_facility"), "ldap_sasl_bind_s() successful");
        x509_info->directory_online = 1;

        /* connection established */
        rc = ldap_search_ext_s(ldap_handle, cfg_getstr(cfg, "ldap_base"), cfg_getint(cfg, "ldap_scope"), filter, attrs, 0, NULL, NULL, &timeout, sizelimit, &ldap_result);
        if (rc == LDAP_SUCCESS) {
            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap_search_ext_s() successful");
            
            /* loop over matching entries */
            for (ldap_result = ldap_first_message(ldap_handle, ldap_result); ldap_result != NULL; ldap_result = ldap_next_message(ldap_handle, ldap_result)) {
                
                switch (msgtype = ldap_msgtype(ldap_result)) {
                    case LDAP_RES_SEARCH_ENTRY:
                        {
                            char *entry_dn = ldap_get_dn(ldap_handle, ldap_result); 
                            syslog(cfg_getint(cfg, "pam_log_facility"), "DN: %s\n", entry_dn);

                            /* go through attributes */
                            for (attr = ldap_first_attribute(ldap_handle, ldap_result, &ber); attr != NULL; attr = ldap_next_attribute(ldap_handle, ldap_result, ber)) {
                                /* get corresponding values */
                                if ((bvals = ldap_get_values_len(ldap_handle, ldap_result, attr)) != NULL) {
                                    int i;
                                    for (i = 0; bvals[i] != '\0'; i++) {
                                        char *value = bvals[i]->bv_val;
                                        ber_len_t len = bvals[i]->bv_len;

                                        /* case: attr == ldap_attr_access */
                                        if (strcmp(attr, cfg_getstr(cfg, "ldap_attr_access")) == 0) {
                                            /* check access permission based on group membership and store result */
                                            check_access(value, &(x509_info->has_access));

                                        /* case: attr = ldap_attr_cert */
                                        } else if (strcmp(attr, cfg_getstr(cfg, "ldap_attr_cert")) == 0) {
                                            x509_info->has_cert = 1;

                                            /* get public key */
                                            X509 *x509;
                                            x509 = d2i_X509(NULL, (const unsigned char **) &value, len);

                                            if (x509 == NULL) {
                                                syslog(cfg_getint(cfg, "pam_log_facility"), "error: cannot decode certificate");
                                                continue;
                                            }

                                            EVP_PKEY *pkey; 
                                            pkey = X509_get_pubkey(x509);

                                            /* extract and store ssh-key from cert */
                                            extract_ssh_key(pkey, &(x509_info->ssh_rsa), cfg);
                                            
                                            /* check validation of cert and store result */
                                            check_signature(NULL, &(x509_info->has_valid_signature));

                                            /* check if cert is expired and store result */
                                            check_expiration(NULL, &(x509_info->is_expired));

                                            /* check if cert is revoked and store result */
                                            check_revocation(NULL, &(x509_info->is_revoked));
                                            
                                            /* extract some other data from cert */
                                            x509_info->subject = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
                                            x509_info->serial = "1100101";
                                            x509_info->issuer = X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0);
                                        }
                                    }
                                } 
                                /* free values structure */
                                ldap_value_free_len(bvals);
                            }
                            /* free attributes structure */
                            ber_free(ber, 0);
                            break;
                        }

                    case LDAP_RES_SEARCH_REFERENCE:
                        {
                            /* handle references here */
                            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: unhandled msgtype (0x%x)\n", msgtype);
                            break;
                        }

                    case LDAP_RES_SEARCH_RESULT:
                        {
                            /* handle results here */
                            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: unhandled msgtype (0x%x)\n", msgtype);
                            break;
                        }

                    default:
                        {
                            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: undefined msgtype (0x%x)\n", msgtype);
                        }
                }
            }
        } else {
            /* dn not found */
            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: '%s' (%d)", ldap_err2string(rc), rc);
        }

        /* clear result structure - even if no result has been found (see man page) */
        ldap_msgfree(ldap_result);

        /* unbind */
        rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
        if (rc == LDAP_SUCCESS) {
            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap_unbind_ext_s() successful"); 
        } else {
            syslog(cfg_getint(cfg, "pam_log_facility"), "ldap error: '%s' (%d)", ldap_err2string(rc), rc);
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
		CFG_INT("ldap_timeout", 5, CFGF_NONE),
		CFG_INT_CB("ldap_version", config_lookup("LDAP_VERSION3"), CFGF_NONE, &cfg_value_parser_int),
		CFG_STR("ldap_attr_rdn_person", "uid", CFGF_NONE),
		CFG_STR("ldap_attr_access", "memberOf", CFGF_NONE),
		CFG_STR("ldap_attr_cert", "userCertificate;binary", CFGF_NONE),
		CFG_END()
	}; 

	cfg_t *cfg = cfg_init(opts, CFGF_NOCASE);
	// register callback for error handling
	cfg_set_error_function(cfg, &cfg_error_handler);

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
        /* check for local account */
        struct passwd *pwd;

        pwd = getpwnam(uid);
        if (pwd == NULL) {
            x509_info->has_local_account = 0;
        } else {
            x509_info->has_local_account = 1;
           
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

