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
#include "globus_error_string.h"

int main()
{
    globus_object_t * err;
    char * s;
    static char * myname = "main";

    globus_module_activate(GLOBUS_COMMON_MODULE);

    err = globus_error_construct_string(GLOBUS_COMMON_MODULE,
	    GLOBUS_ERROR_NO_INFO,
	    "[%s]: Error doing something hard at %s:%d\n",
	    GLOBUS_COMMON_MODULE->module_name,
	    myname,
	    __LINE__);
    s = globus_object_printable_to_string(err);

    globus_libc_printf(s);
    return globus_module_deactivate_all();
}
