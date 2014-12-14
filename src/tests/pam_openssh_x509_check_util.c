#include <check.h>
#include <stdio.h>
#include <string.h>

#include "pam_openssh_x509_check.h"
#include "../pam_openssh_x509.h"

#define BUFFER_SIZE 2048

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
        { 'u', "foo", "/home/%u/", -1, "1.FC KOELN" },
        { 'u', "foo", "/home/%u/", 0, "1.FC KOELN" },
        { 'u', "foo", "/home/%u/", 1, "" },
        { 'u', "foo", "/home/%u/", 2, "/" },
        { 'u', NULL, NULL, -1, "1.FC KOELN" },
        { 'u', NULL, NULL, 1024, "1.FC KOELN" },
        { 'u', "foo", NULL, 1024, "1.FC KOELN" },
    };

static struct test_check_access _test_check_access_lt[] =
    {
        { "cn=blub,dc=abc,dc=afg", "blub", 1 },
        { "cn==blub,dc=abc,dc=afg", "=blub", 1 },
        { "cn=cn=blub,dc=abc,dc=afg", "cn=blub", 1 },
        { "cn=blub", "blub", 1 },
        { "blub", "blub", 0 },
        { "", "blub", 0 },
        { "", "", 0 },
        { " ", "", 0 },
        { " ", " ", 0 },
        { "=a,", "a", 0 },
        { NULL, NULL, 0 },
        { NULL, "a", 0 },
        { "cn=blub,dc=abc", NULL, 0 },
    };

START_TEST
(test_percent_expand)
{
    char token = _test_percent_expand_lt[_i].token;
    char *subst = _test_percent_expand_lt[_i].subst;
    char *src = _test_percent_expand_lt[_i].src;
    unsigned int dst_length = _test_percent_expand_lt[_i].dst_length;
    char *exp_result = _test_percent_expand_lt[_i].exp_result;

    char dst[dst_length];
    strcpy(dst, "1.FC KOELN");
    percent_expand(token, subst, src, dst, dst_length); 
    ck_assert_str_eq(dst, exp_result);
}
END_TEST

START_TEST
(test_extract_ssh_key)
{
    char *directory = "openssh_keys";
    char *oneliner = "openssh_keys/ssh_rsa.txt";

    FILE *fh_oneliner = fopen(oneliner, "r");
    if (fh_oneliner != NULL) {
        char line_buffer[BUFFER_SIZE];
        while (fgets(line_buffer, sizeof(line_buffer), fh_oneliner) != NULL) {
            char *pem_file_rel = strtok(line_buffer, ":");
            char *ssh_rsa = strtok(NULL, "\n");
            if (pem_file_rel != NULL && ssh_rsa != NULL) {
                char pem_file_abs[BUFFER_SIZE];
                strncpy(pem_file_abs, directory, sizeof(pem_file_abs));
                strncat(pem_file_abs, "/", sizeof(pem_file_abs) - strlen(pem_file_abs) - 1);
                strncat(pem_file_abs, pem_file_rel, sizeof(pem_file_abs) - strlen(pem_file_abs) - 1);
                FILE *f_pem_file = fopen(pem_file_abs, "r");
                if (f_pem_file != NULL) {
                    EVP_PKEY *pkey = PEM_read_PUBKEY(f_pem_file, NULL, NULL, NULL);
                    if (pkey != NULL) {
                        struct pam_openssh_x509_info x509_info;
                        extract_ssh_key(pkey, &x509_info);
                        char exp_ssh_rsa[BUFFER_SIZE];
                        strncpy(exp_ssh_rsa, x509_info.ssh_keytype, sizeof(exp_ssh_rsa));
                        strncat(exp_ssh_rsa, " ", sizeof(exp_ssh_rsa) - strlen(exp_ssh_rsa) - 1);
                        strncat(exp_ssh_rsa, x509_info.ssh_key, sizeof(exp_ssh_rsa) - strlen(exp_ssh_rsa) - 1);
                        ck_assert_str_eq(ssh_rsa, exp_ssh_rsa);
                    } else {
                        printf("PEM_read_PUBKEY() failed ('%s')\n", pem_file_abs);
                    }
                    fclose(f_pem_file);
                } else {
                    printf("fopen() failed ('%s')\n", pem_file_abs);
                }
            } else {
                printf("parsing failure\n");
            }
        }
        fclose(fh_oneliner);
    } else {
        printf("fopen() failed ('%s')\n", oneliner);
        exit(-1);
    }
}
END_TEST

START_TEST
(test_extract_ssh_key_params)
{
    struct pam_openssh_x509_info x509_info;
    init_data_transfer_object(&x509_info);
    extract_ssh_key(NULL, NULL);
    extract_ssh_key(NULL, &x509_info);
    ck_assert_ptr_eq(NULL, x509_info.ssh_keytype);
    ck_assert_ptr_eq(NULL, x509_info.ssh_key);
    EVP_PKEY pkey;
    extract_ssh_key(&pkey, NULL);

    char *pkey_string = "-----BEGIN PUBLIC KEY-----\n"
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Wv1aHB/coSsamD9Acd7\n"
                        "EIiLmYQPW9Tbw6XOcfIKfQy7OaFlevYPXE5y9Zh8w/mqsQKjRYhnZn9DCkfJZyhl\n"
                        "CbXXqmfE3hMUGg90ENWE68SEXcCb3hA/e/Bn01lSBWjcSBhhSXUOvhuLYRFYGAL1\n"
                        "a3ru1NpWO+XSouaso0XZkCwJzigRA/g0ML7dHya9rR+TA95yU7PrEvtib9GppMeG\n"
                        "vcDd/JQFkPQkEaGIKsxYkcVGu804ZEMlXKY4QBXFCsTXrJ+aQuzba0WXTd3527uw\n"
                        "DTGgjYsuw32P//ENlWItuTdxSLqqogxuWYHZ6V7Z+9l3BdNhIzSeyXgPpefECtII\n"
                        "WwIDAQAB\n"
                        "-----END PUBLIC KEY-----";
    BIO *pkey_mem_bio = BIO_new_mem_buf(pkey_string, -1);
    EVP_PKEY *pkey_static = PEM_read_bio_PUBKEY(pkey_mem_bio, NULL, NULL, NULL);
    if (pkey_static != NULL) {
        extract_ssh_key(pkey_static, NULL);
    } else {
        printf("PEM_read_bio_PUBKEY() failed\n");
    }
    BIO_free(pkey_mem_bio);
}
END_TEST

START_TEST
(test_config_lookup)
{
    int exp_result = config_lookup(10, "foo");
    ck_assert_int_eq(-EINVAL, exp_result);
    exp_result = config_lookup(SYSLOG, "foo");
    ck_assert_int_eq(-EINVAL, exp_result);
    exp_result = config_lookup(SYSLOG, NULL);
    ck_assert_int_eq(-EINVAL, exp_result);
    exp_result = config_lookup(LIBLDAP, NULL);
    ck_assert_int_eq(-EINVAL, exp_result);
}
END_TEST

START_TEST
(test_set_log_facility)
{
    int exp_result = set_log_facility("LOG_KERN");
    ck_assert_int_eq(0, exp_result);
    exp_result = set_log_facility("LOG_KERNEL");
    ck_assert_int_eq(-EINVAL, exp_result);
    exp_result = set_log_facility(NULL);
    ck_assert_int_eq(-EINVAL, exp_result);
}
END_TEST

START_TEST
(test_release_config)
{
    release_config(NULL);
}
END_TEST

START_TEST
(test_check_access)
{
    char *group_dn = _test_check_access_lt[_i].group_dn;
    char *identifier = _test_check_access_lt[_i].identifier;
    char exp_result = _test_check_access_lt[_i].exp_result;

    char has_access = -1;
    check_access(group_dn, identifier, &has_access);
    ck_assert_int_eq(has_access, exp_result);
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
    tcase_add_test(tc_helper, test_extract_ssh_key);
    tcase_add_test(tc_helper, test_extract_ssh_key_params);
    tcase_add_test(tc_helper, test_config_lookup);
    tcase_add_test(tc_helper, test_set_log_facility);
    tcase_add_test(tc_helper, test_release_config);
    int length_ca_lt = sizeof(_test_check_access_lt) / sizeof(struct test_check_access);
    tcase_add_loop_test(tc_helper, test_check_access, 0, length_ca_lt);

    /* ssh test cases */

    /* x509 test cases */

    return s;
}

