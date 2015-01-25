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
#include <syslog.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pam_openssh_x509.h"

static int 
authorized(struct pam_openssh_x509_info *x509_info)
{
    return (x509_info->has_access == 1 &&
            x509_info->has_valid_signature == 1 &&
            x509_info->is_expired == 0 &&
            x509_info->is_revoked == 0);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct pam_openssh_x509_info *x509_info = NULL;
    int rc = pam_get_data(pamh, "x509_info", (const void **) &x509_info);
    if (rc == PAM_SUCCESS) {
        /* set log facility */
        rc = set_log_facility(x509_info->log_facility);
        if (rc == -EINVAL) {
            LOG_FAIL("set_log_facility(%s)", x509_info->log_facility);
        }
        
        /* only modify authorized_keys file if LDAP server could be queried */
        if (x509_info->directory_online == 1) {
            if (authorized(x509_info)) {
                LOG_MSG("Access granted!");
                LOG_MSG("Synchronizing keys");
                if (x509_info->ssh_keytype != NULL && x509_info->ssh_key != NULL) {
                    /* write key to authorized_keys file */
                    FILE *fd_auth_keys = fopen(x509_info->authorized_keys_file, "w");
                    if (fd_auth_keys != NULL) {
                        fwrite(x509_info->ssh_keytype, strlen(x509_info->ssh_keytype), 1, fd_auth_keys);
                        fwrite(" ", 1, 1, fd_auth_keys);
                        fwrite(x509_info->ssh_key, strlen(x509_info->ssh_key), 1, fd_auth_keys);
                        fwrite("\n", 1, 1, fd_auth_keys);
                        fclose(fd_auth_keys);
                    } else {
                        /* unlikely */
                        LOG_FATAL("Cannot open '%s' for writing", x509_info->authorized_keys_file);
                        goto auth_err;
                    }
                } else {
                    LOG_FATAL("Cannot synchronize keys. Either key or keytype not known");
                    goto auth_err;
                }
            } else {
                LOG_MSG("Access denied!");
                LOG_MSG("Truncating authorized_keys file");
                FILE *fd_auth_keys = fopen(x509_info->authorized_keys_file, "w");
                if (fd_auth_keys != NULL) {
                    LOG_SUCCESS("'%s' truncated", x509_info->authorized_keys_file);
                    fclose(fd_auth_keys);
                } else {
                    /* unlikely */
                    LOG_FATAL("Truncation of '%s' failed", x509_info->authorized_keys_file);
                    goto auth_err;
                }
            }
        } else {
            LOG_MSG("LDAP server not accessible. Not changing anything");
        }
    } else {
        LOG_FATAL("pam_get_data()");
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

