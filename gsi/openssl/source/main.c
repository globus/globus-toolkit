#include <stdio.h>
#include <string.h>

#include "openssl/opensslv.h"

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "-H") == 0)
    {
        printf("#define GLOBUS_OPENSSL_VERSION_NUMBER 0x%08lxL\n",
               OPENSSL_VERSION_NUMBER);
        printf("#define GLOBUS_OPENSS_VERSION_TEXT \"%s\"\n",
               OPENSSL_VERSION_TEXT);
    }
    else
    {
        printf("%s\n", OPENSSL_VERSION_TEXT);
    }

    return 0;
}
