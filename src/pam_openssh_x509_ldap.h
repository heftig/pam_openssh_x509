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

#ifndef PAM_OPENSSH_X509_LDAP_H
#define PAM_OPENSSH_X509_LDAP_H

#include <confuse.h>
#include <openssl/x509.h>

#include "pam_openssh_x509_util.h"

/* type declarations */

/* function declarations */
void retrieve_access_permission_and_x509_from_ldap(cfg_t *cfg, struct pam_openssh_x509_info *x509_info, X509 **x509);
#endif

