/*
 * gssapi-om-uint-size-test-2.c
 *
 * Return the sizeof(OM_uint32) if "gssapi_config.h" is included before
 * "gssapi.h"
 */

#include "gssapi_config.h"
#include "gssapi.h"

int
size_of_OM_uint32_2()
{
    return sizeof(OM_uint32);
}



