#include <stdlib.h>
#include <syslog.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "include/pam_openssh_x509.h"

static int log_prio = LOG_DEBUG | LOG_LOCAL1;

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int rc;
    struct pam_openssh_x509_info *x509_info = NULL;

    rc = pam_get_data(pamh, "x509_info", (const void **) &x509_info);
    if (rc == PAM_SUCCESS) {
        /* log information */
        syslog(log_prio, "===================================================");
        syslog(log_prio, "has_cert: %d", x509_info->has_cert);
        
        if (x509_info->subject != NULL)
            syslog(log_prio, "subject: %s", x509_info->subject);

        if (x509_info->serial != NULL)
            syslog(log_prio, "serial: %s", x509_info->serial);

        if (x509_info->issuer != NULL)
            syslog(log_prio, "issuer: %s", x509_info->issuer);

        syslog(log_prio, "is_expired: %d", x509_info->is_expired);
        syslog(log_prio, "has_valid_sig: %d", x509_info->has_valid_signature);
        syslog(log_prio, "is_revoked: %d", x509_info->is_revoked);

        if (x509_info->ssh_rsa != NULL)
            syslog(log_prio, "ssh-rsa: %s", x509_info->ssh_rsa);

        if (x509_info->authorized_keys_file != NULL) 
            syslog(log_prio, "auth_keys_file: %s", x509_info->authorized_keys_file);

        syslog(log_prio, "directory_online: %d", x509_info->directory_online);
        syslog(log_prio, "has_access: %d", x509_info->has_access);
        syslog(log_prio, "===================================================");
        
    } else {
        syslog(log_prio, "error: pam_get_data()");
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

