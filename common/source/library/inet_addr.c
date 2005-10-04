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

#ifdef GLOBUS_IMPLEMENT_INET_ADDR
uint32_t
inet_addr(const char * cp)
{
    uint32_t output;
    int rc;
    unsigned int octets[4];

    rc = sscanf(
        cp,
        "%d.%d.%d.%d",
        &octets[0], &octets[1], &octets[2], &octets[3]);

    if (rc < 4)
    {
        return -1;
    }
    else
    {
        output = 0;
        output |= octets[3];
        output |= octets[2] << 8;
        output |= octets[1] << 16;
        output |= octets[0] << 24;

        return output;
    }
}
#endif /* GLOBUS_IMPLEMENT_INET_ADDR */
