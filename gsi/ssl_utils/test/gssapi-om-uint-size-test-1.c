/*
 * gssapi-om-uint-size-test-1.c
 *
 * Print the sizeof(OM_uint32) if "gssapi.h" is included before
 * "gssapi_config.h"
 */

#include "gssapi.h"
#include "globus_gssapi_config.h"

int
main()
{
    printf("%d\n", sizeof(OM_uint32));
    return(0);
}



