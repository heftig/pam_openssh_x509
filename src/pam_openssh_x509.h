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

#ifndef PAM_OPENSSH_X509_H
#define PAM_OPENSSH_X509_H

/* type declarations */
struct pam_openssh_x509_info {
    char *uid;
    char *authorized_keys_file;
    char *ssh_keytype;
    char *ssh_key;

    char has_cert;
    char has_valid_cert;
    char *serial;
    char *issuer;
    char *subject;

    char directory_online;
    char has_access;

    char *log_facility;
};

/* function declarations */
void LOG_SUCCESS(const char *fmt, ...);
void LOG_FATAL(const char *fmt, ...);
void LOG_CRITICAL(const char *fmt, ...);
void LOG_FAIL(const char *fmt, ...);
void LOG_MSG(const char *fmt, ...);
int set_log_facility(const char *log_facility);
#endif

