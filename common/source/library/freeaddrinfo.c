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

#include "globus_common.h"

#ifdef GLOBUS_IMPLEMENT_FREEADDRINFO
void
freeaddrinfo(
    globus_addrinfo_t *                 res)
{
    globus_addrinfo_t *                 tmp;
    globus_addrinfo_t *                 tmp2;

    tmp = res->ai_next;

    while (tmp != NULL)
    {
        if (tmp->ai_addr != NULL)
        {
            free(tmp->ai_addr);
        }
        tmp2 = tmp;
        tmp = tmp->ai_next;

        free(tmp2);

    }
    if (res->ai_addr != NULL)
    {
        free(res->ai_addr);
    }
    if (res->ai_canonname)
    {
        free(res->ai_canonname);
    }
    free(res);
}
#endif /* GLOBUS_IMPLEMENT_FREEADDRINFO */
