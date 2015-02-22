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

#include <check.h>

#include "pam_openssh_x509_check.h"
#include "../src/pam_openssh_x509_base.c"

Suite *
make_base_suite(void)
{
    Suite *s = suite_create("base");
    TCase *tc_all = tcase_create("all");

    /* add test cases to suite */
    suite_add_tcase(s, tc_all);

    /* config test cases */

    return s;
}

