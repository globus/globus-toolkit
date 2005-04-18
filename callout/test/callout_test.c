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



#include "globus_callout.h"
#include "globus_common.h"
#include <stdlib.h>
#include <stdio.h>


int main()
{
    globus_callout_handle_t     authz_handle;
    char *                      filename = "test.conf";
    globus_result_t             result;

    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_CALLOUT_MODULE);
    
    result = globus_callout_handle_init(&authz_handle);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    
    result = globus_callout_read_config(authz_handle, filename);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    
    result = globus_callout_call_type(authz_handle,
                                      "TEST",
                                      "foo",
                                      "bar");

    if(result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    
    result = globus_callout_handle_destroy(authz_handle);


    if(result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    globus_module_deactivate_all();
    
    return 0;

 error_exit:

    fprintf(stderr,"ERROR: %s",
            globus_error_print_chain(globus_error_get(result)));
    
    globus_module_deactivate_all();

    return 1;
}
