/*
 * gssapi-om-uint-size-test-2.c
 *
 * Print the sizeof(OM_uint32) if "gssapi_config.h" is included before
 * "gssapi.h"
 */

#include "gssapi_config.h"
#include "gssapi.h"

int
main()
{
    printf("%d\n", sizeof(OM_uint32));
    return(0);
}



