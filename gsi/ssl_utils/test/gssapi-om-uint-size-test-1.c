/*
 * gssapi-om-uint-size-test-1.c
 *
 * Return the sizeof(OM_uint32) if "gssapi.h" is included before
 * "gssapi_config.h"
 */

#include "gssapi.h"
#include "gssapi_config.h"

int
size_of_OM_uint32_1()
{
    return sizeof(OM_uint32);
}



