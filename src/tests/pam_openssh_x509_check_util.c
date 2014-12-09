#include <check.h>
#include "pam_openssh_x509_check.h"
#include "../pam_openssh_x509.h"

static struct test_percent_expand _test_percent_expand_lt[] =
    {
        { 'u', "foo", "/home/%u/", 1024, "/home/foo/" },
        { 'u', "foo", "/home/%u/", 3, "/h" },
        { 'u', "foo", "/home/%u%u%u/", 512, "/home/foofoofoo/" },
        { 'u', "foo", "/home/%u%u%/", 512, "/home/foofoo%/" },
        { 'u', "foo", "%u%u", 512, "foofoo" },
        { 'u', "foo", "/home/%a/%u", 512, "/home/%a/foo" },
        { '%', "%", "/home/%%%", 512, "/home/%%" },
        { 'u', "../../root", "/home/%u", 512, "/home/../../root" },
        { 'u', "$blub", "/home/%u", 512, "/home/$blub" },
        { 'u', "\\", "/home/%u", 512, "/home/\\" },
        { '$', "\\", "/home/%u", 512, "/home/%u" },
        { 'u', "bar", "%/u%uhome/%u", 512, "%/ubarhome/bar" },
        { 'u', "foo", "/home/%u/", 8, "/home/%" },
        { 'u', "foo", "/home/%u/", 9, "/home/fo" },
        { 'u', "foo", "/home/%u/", 10, "/home/foo" },
        { 'u', "foo", "/home/%u/", 0, ""},
        { 'u', "foo", "/home/%u/", 1, ""},
        { 'u', "foo", "/home/%u/", 2, "/"},
    };

START_TEST(test_percent_expand)
{
    char token = _test_percent_expand_lt[_i].token;
    char *subst = _test_percent_expand_lt[_i].subst;
    char *src = _test_percent_expand_lt[_i].src;
    unsigned int dst_length = _test_percent_expand_lt[_i].dst_length;
    char *exp_result = _test_percent_expand_lt[_i].exp_result;

    char dst[dst_length];
    percent_expand(token, subst, src, dst, dst_length); 
    ck_assert_str_eq(dst, exp_result);
}
END_TEST

Suite *
make_util_suite(void)
{
    Suite *s = suite_create("util");
    TCase *tc_helper = tcase_create("helper");
    TCase *tc_ssh = tcase_create("ssh");
    TCase *tc_x509 = tcase_create("x509");

    /* add test cases to suite */
    suite_add_tcase(s, tc_helper);
    suite_add_tcase(s, tc_ssh);
    suite_add_tcase(s, tc_x509);

    /* helper test cases */
    int length_pe_lt = sizeof(_test_percent_expand_lt) / sizeof(struct test_percent_expand);
    tcase_add_loop_test(tc_helper, test_percent_expand, 0, length_pe_lt);

    /* ssh test cases */

    /* x509 test cases */

    return s;
}

