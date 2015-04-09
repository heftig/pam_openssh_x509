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
#include <errno.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pam_openssh_x509.h"

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
    if (value == 0x56) {
        value_string = unset;
    } else if (value == 1) {
        value_string = "true";
    } else {
        value_string = "false";
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
        if (rc == -EINVAL) {
            LOG_FAIL("set_log_facility(%s)", x509_info->log_facility);
        }
        LOG_MSG("===================================================");
        log_string("uid", x509_info->uid);
        log_string("auth_keys_file", x509_info->authorized_keys_file);
        log_string("ssh_keytype", x509_info->ssh_keytype);
        log_string("ssh_key", x509_info->ssh_key);
        LOG_MSG("");
        log_char("has_cert", x509_info->has_cert);
        log_char("has_valid_cert", x509_info->has_valid_cert);
        log_string("serial", x509_info->serial);
        log_string("issuer", x509_info->issuer);
        log_string("subject", x509_info->subject);
        LOG_MSG("");
        log_char("is_directory_online", x509_info->directory_online);
        log_char("has_access", x509_info->has_access);
        LOG_MSG("===================================================");
    } else {
        FATAL("pam_get_data()");
    }

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

