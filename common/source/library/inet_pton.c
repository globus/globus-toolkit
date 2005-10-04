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

#ifdef GLOBUS_IMPLEMENT_INET_PTON
int
inet_pton(
    int                                 af,
    const char *                        src,
    void *                              dst)
{
    uint32_t                            addr;
    
    if (af != AF_INET || src == NULL || dst == NULL)
    {
        errno = EAFNOSUPPORT;
        return -1;
    }
    
    addr = inet_addr(src);

    if (addr != 0xffffffff)
    {
        struct in_addr * dstaddr = dst;

        dstaddr->s_addr = addr;

        return 1;
    }
    else
    {
        return 0;
    }
}
#endif /* GLOBUS_IMPLMENENT_INET_PTON */
