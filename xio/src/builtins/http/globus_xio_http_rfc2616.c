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

#include "globus_i_xio_http.h"
#include "globus_i_xio_http_responses.h"

extern
const char *
globus_i_xio_http_lookup_reason(
    int                                 code)
{
    char                                code_str[4];
    int                                 i;

    if (code < 100 || code > 599)
    {
        return "Unknown status";
    }
    sprintf(&code_str[0], "%d", code);

    for (i = 0; i < GLOBUS_XIO_ARRAY_LENGTH(globus_l_http_descriptions); i+=2)
    {
        if (strcmp(code_str, globus_l_http_descriptions[i]) == 0)
        {
            return globus_l_http_descriptions[i+1];
        }
    }
    return "Unknown status";
}
/* globus_i_xio_http_lookup_reason() */
