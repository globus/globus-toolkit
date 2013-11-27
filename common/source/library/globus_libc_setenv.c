#include "globus_config.h"
#include <stdio.h>
#include <stdlib.h>

int
globus_libc_setenv(
    register const char *name,
    register const char *value,
    int rewrite)
{
#ifdef _WIN32
    size_t len = snprintf(NULL, 0, "%s=%s", name, value);
    char *tmp;
    if (rewrite || !getenv(name))
    {
        tmp = malloc(len);
        sprintf(tmp, "%s=%s", name, value);
        putenv(tmp);
    }
#else
    return setenv(name, value, rewrite);
#endif
}

void
globus_libc_unsetenv(
    const char *name)
{
#ifdef _WIN32
    size_t len = snprintf(NULL, 0, "%s=", name);
    char *tmp = malloc(len);
    sprintf(tmp, "%s=", name);
    putenv(name);
#else
    unsetenv(name);
#endif
}

char *
globus_libc_getenv(const char *name)
{
    return getenv(name);
}
