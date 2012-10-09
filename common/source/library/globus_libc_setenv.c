#include "globus_common.h"

/* These are included for backward compatibility. No need to use these
 */
int
globus_libc_setenv(
    register const char *name,
    register const char *value,
    int rewrite)
{
    return setenv(name, value, rewrite);
}

void
globus_libc_unsetenv(
    const char *name)
{
    unsetenv(name);
}

char *
globus_libc_getenv(const char *name)
{
    return getenv(name);
}
