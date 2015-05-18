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
#include <string.h>

#include <confuse.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pam_openssh_x509_config.h"
#include "pam_openssh_x509_ldap.h"
#include "pam_openssh_x509_util.h"

#define MAX_UID_LENGTH 32
#define AUTHORIZED_KEYS_FILE_BUFFER_SIZE 1024

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

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    /* check if argument is path to config file */
    if (argc != 1) {
        FATAL("arg count != 1");
    }
    const char *cfg_file = argv[0];
    if(!is_readable_file(cfg_file)) {
        FATAL("cannot open config file (%s) for reading", cfg_file);
    }

    /* initialize and parse config */
    cfg_t *cfg = NULL;
    init_and_parse_config(&cfg, cfg_file);

    /* initialize data transfer object */
    struct pam_openssh_x509_info *x509_info = malloc(sizeof *x509_info);
    if (x509_info == NULL) {
        FATAL("malloc()");
    }
    init_data_transfer_object(x509_info);

    /* make data transfer object available to module stack */
    int rc = pam_set_data(pamh, "x509_info", x509_info, &cleanup_x509_info);
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
    if (rc != PAM_SUCCESS) {
        FATAL("pam_get_user(): (%i)", rc);
    }
    /*
     * an attacker could provide a malicious uid (e.g. '../keystore/foo') that
     * can cause problems with the resulting authorized_keys path after token
     * substitution. to minimize this attack vector the given uid will be tested
     * against a restrictive regular expression
     */
    if (!is_valid_uid(uid)) {
        FATAL("is_valid_uid(): uid: '%s'", uid);
    }

    /*
     * make uid available in data transfer object. do not point to value in
     * pam space because if we free our data structure we would free it from
     * global pam space as well. other modules could rely on it
     */
    x509_info->uid = strndup(uid, MAX_UID_LENGTH);
    if (x509_info->uid == NULL) {
        FATAL("strndup()");
    }

    /* expand authorized_keys_file option and add to data transfer object */
    char *expanded_path = malloc(AUTHORIZED_KEYS_FILE_BUFFER_SIZE);
    if (expanded_path == NULL) {
        FATAL("malloc()");
    }
    substitute_token('u', x509_info->uid, cfg_getstr(cfg, "authorized_keys_file"), expanded_path, AUTHORIZED_KEYS_FILE_BUFFER_SIZE);
    x509_info->authorized_keys_file = expanded_path;

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
        if (pkey == NULL) {
            FATAL("X509_get_pubkey(): unable to load public key");
        }
        pkey_to_authorized_keys(pkey, x509_info);
        EVP_PKEY_free(pkey);

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

