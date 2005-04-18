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
#if defined(HAVE_NETDB_H)
#    include <netdb.h>
#endif

#if !defined(MAXHOSTNAMELEN)
#    define MAXHOSTNAMELEN 1024
#endif

int main()
{
    int rc;
    char host[MAXHOSTNAMELEN];

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    rc = globus_libc_gethostname(host, MAXHOSTNAMELEN);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    globus_libc_printf("%s\n", host);

    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    return 0;
}
