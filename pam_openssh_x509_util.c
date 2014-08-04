#include <strings.h>
#include <errno.h>
#include <stdlib.h>

#include "include/pam_openssh_x509.h"

struct __config_lookup_table {
    char *name;
    int value;
};

static struct __config_lookup_table _config_lookup[] =
    {
        // syslog facilities
        { "LOG_KERN", (0<<3) },
        { "LOG_USER", (1<<3) },
        { "LOG_MAIL", (2<<3) },
        { "LOG_DAEMON", (3<<3) },
        { "LOG_AUTH", (4<<3) },
        { "LOG_SYSLOG", (5<<3) },
        { "LOG_LPR", (6<<3) },
        { "LOG_NEWS", (7<<3) },
        { "LOG_UUCP", (8<<3) },
        { "LOG_CRON", (9<<3) },
        { "LOG_AUTHPRIV", (10<<3) },
        { "LOG_FTP", (11<<3) },
        { "LOG_LOCAL0", (16<<3) },
        { "LOG_LOCAL1", (17<<3) },
        { "LOG_LOCAL2", (18<<3) },
        { "LOG_LOCAL3", (19<<3) },
        { "LOG_LOCAL4", (20<<3) },
        { "LOG_LOCAL5", (21<<3) },
        { "LOG_LOCAL6", (22<<3) },
        { "LOG_LOCAL7", (23<<3) },

        // libldap
        { "LDAP_VERSION1", 1 },
        { "LDAP_VERSION2", 2 },
        { "LDAP_VERSION3", 3 },
        { "LDAP_SCOPE_BASE", 0 },
        { "LDAP_SCOPE_BASEOBJECT", 0 },
        { "LDAP_SCOPE_ONELEVEL", 1 },
        { "LDAP_SCOPE_ONE", 1 },
        { "LDAP_SCOPE_SUBTREE", 2 },
        { "LDAP_SCOPE_SUB", 2 },
        { "LDAP_SCOPE_SUBORDINATE", 3 },
        { "LDAP_SCOPE_CHILDREN", 3 },

        // mark end
        { NULL, 0 }
    };

long int
config_lookup(const char *key)
{
    struct __config_lookup_table *lookup_ptr;
    for (lookup_ptr = _config_lookup; lookup_ptr->name != NULL; lookup_ptr++) {
        if (strcasecmp(lookup_ptr->name, key) == 0) {
            return lookup_ptr->value;
        }
    }

    return -EINVAL;
}

