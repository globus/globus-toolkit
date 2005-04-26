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

#include <stdlib.h>
#include <stdio.h>
#include "globus_common.h"

#ifndef WIN32
globus_result_t
chainc_test_callout(va_list ap)
#else
globus_result_t
__declspec(dllexport) chainc_test_callout(va_list ap)
#endif
{
    vprintf("Callout C Got arguments 1) %s 2) %s\n", ap);
    return GLOBUS_SUCCESS;
}


