/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

/*
 * gssapi-om-uint-size-test-2.c
 *
 * Print the sizeof(OM_uint32) if "gssapi_config.h" is included before
 * "gssapi.h"
 */

#include "globus_gssapi_config.h"
#include "gssapi.h"

int
main()
{
    printf("%d\n", sizeof(OM_uint32));
    return(0);
}



