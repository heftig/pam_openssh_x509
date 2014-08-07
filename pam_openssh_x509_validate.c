/*
author: sebastian roland
date: 2013-06-10
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "include/pam_openssh_x509.h"

static int log_prio = LOG_DEBUG | LOG_LOCAL1;

static void
truncate_file(char *path)
{
    FILE *fd_auth_keys = fopen(path, "w");
    if (fd_auth_keys != NULL) {
        fclose(fd_auth_keys);
    } else {
        syslog(log_prio, "cant truncate file! this should never happen!");
    }
}

static int
access_granted(struct pam_openssh_x509_info *x509_info)
{
    return (x509_info->is_revoked == 0 && x509_info->is_expired == 0 && x509_info->has_valid_signature == 1 && x509_info->has_access == 1);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int rc;
    struct pam_openssh_x509_info *x509_info;
    rc = pam_get_data(pamh, "x509_info", (const void **) &x509_info);
    if (rc == PAM_SUCCESS) {
        
        if (x509_info->has_cert == 1) {
            if (access_granted(x509_info)) {
                syslog(log_prio, "ACCESS GRANTED :)");

                /* check authorized_keys file */
                if (x509_info->ssh_rsa != NULL && x509_info->authorized_keys_file != NULL) {
                    FILE *fd_auth_keys = fopen(x509_info->authorized_keys_file, "r");
                    if (fd_auth_keys != NULL) {
                        /* read only first line */
                        char prefix[] = "ssh-rsa ";
                        int prefix_length = strlen(prefix);       /* 'ssh-rsa ' */
                        int length = strlen(x509_info->ssh_rsa);
                        char buffer[prefix_length + length + 1];
                        fgets(buffer, sizeof(buffer), fd_auth_keys);
                        fclose(fd_auth_keys);
                        if (buffer != NULL) {
                            char pkey_ak[length + 1];
                            memcpy(pkey_ak, &buffer[prefix_length], sizeof(pkey_ak));
                            if (strcmp(x509_info->ssh_rsa, pkey_ak) == 0) {
                                /* everything is fine */
                                syslog(log_prio, "authorized_keys file is up to date");
                            } else {
                                /*
                                 * we have an outdated key in authorized_key file
                                 * delete old file and update with key from cert 
                                 */
                                syslog(log_prio, "authorized_keys needs an update");
                                fd_auth_keys = fopen(x509_info->authorized_keys_file, "w");
                                if (fd_auth_keys != NULL) {
                                    /* write update */
                                    fwrite(prefix, strlen(prefix), 1, fd_auth_keys);
                                    fwrite(x509_info->ssh_rsa, strlen(x509_info->ssh_rsa), 1, fd_auth_keys);
                                    fwrite("\n", 1, 1, fd_auth_keys);
                                    fclose(fd_auth_keys);
                                    syslog(log_prio, "authorized_keys file updated");
                                } else {
                                    syslog(log_prio, "opening (w) authorized keys file failed!");
                                }
                            }
                        }
                    } else {
                        syslog(log_prio, "opening (r) authorized keys file failed!");
                    }
                } else {
                    syslog(log_prio, "couldnt update authorized_keys because either key or path is not konwn");
                }
                return PAM_SUCCESS;
            } else {
                /*
                 * cert is either expired / revoked, signature is invalid or group membership is missing
                 * truncate authorized_keys file
                 */
                syslog(log_prio, "access_granted() not true");
                truncate_file(x509_info->authorized_keys_file);

                goto auth_err;
            }
        } else {
            /* no certificate information available, determine if directory service was available or not */
            if (x509_info->directory_online == 1) {
                syslog(log_prio, "cant find certificate in directory");
                truncate_file(x509_info->authorized_keys_file);

                goto auth_err;
            } else {
                syslog(log_prio, "directory not accessible");
            }
        }
    } else {
        syslog(log_prio, "pam_get_data() FAILED");
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

