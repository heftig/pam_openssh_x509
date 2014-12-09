#include <check.h>

#include "pam_openssh_x509_check.h"

int
main(int argc, char **argv)
{
    SRunner *sr = srunner_create(NULL);
    srunner_add_suite(sr, make_util_suite());

    srunner_run_all(sr, CK_VERBOSE);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);

    return 0;
}

