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
 * Append fail test: verify fix to bug #3472 (segmentation fault in
 * deactivate if globus_gass_open with append fails).
 */
#include "globus_gass_file.h"

#include <fcntl.h>

int main()
{
    int fd;

    globus_module_activate(GLOBUS_GASS_FILE_MODULE);
    fd = globus_gass_open(
	    "http://no_such_machine.globus.org/no/such/file",
	    O_WRONLY|O_APPEND,
	    0755);
    if(fd >= 0)
    {
	globus_gass_close(fd);
    }
    globus_module_deactivate_all();
    printf("ok\n");
    return 0;
}
