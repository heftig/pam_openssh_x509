#include <stdlib.h>
#include <syslog.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "include/pam_openssh_x509.h"

static char *unset = "unset";

static void
log_string(char *attr, char *value)
{
    if (attr == NULL) {
        return;
    }
    if (value == NULL) {
        value = unset;
    }
    LOG_MSG("%s: %s", attr, value);
}

static void
log_char(char *attr, char value)
{
    if (attr == NULL) {
        return;
    }
    char *value_string = NULL;
    if (value == 0x86) {
        value_string = unset;
    } else {
        if (value == 1) {
            value_string = "true";
        } else {
            value_string = "false";
        }
    }
    LOG_MSG("%s: %s", attr, value_string);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct pam_openssh_x509_info *x509_info = NULL;
    int rc = pam_get_data(pamh, "x509_info", (const void **) &x509_info);
    if (rc == PAM_SUCCESS) {
        /* set log facility */
        rc = set_log_facility(x509_info->log_facility);

        LOG_MSG("===================================================");
        log_string("uid", x509_info->uid);
        log_string("auth_keys_file", x509_info->authorized_keys_file);
        log_string("ssh_rsa", x509_info->ssh_rsa);
        LOG_MSG("");
        log_char("has_cert", x509_info->has_cert);
        log_string("serial", x509_info->serial);
        log_string("issuer", x509_info->issuer);
        log_string("subject", x509_info->subject);
        log_char("has_valid_sig", x509_info->has_valid_signature);
        log_char("is_expired", x509_info->is_expired);
        log_char("is_revoked", x509_info->is_revoked);
        LOG_MSG("");
        log_char("is_directory_online", x509_info->directory_online);
        log_char("has_access", x509_info->has_access);
        LOG_MSG("===================================================");
        
    } else if (rc == PAM_SYSTEM_ERR) {
        LOG_FAIL("pam_get_data(): pamh == NULL");
        goto auth_err;

    } else if (rc == PAM_NO_MODULE_DATA) {
        LOG_FAIL("pam_get_data(): module data not found or entry is NULL");
        goto auth_err;
    }

    return PAM_SUCCESS;

    auth_err:
        return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

