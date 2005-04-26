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

#include "flavor.h"

#define FLAVOR_LIB(_LIB_PREFIX_) \
    _LIB_PREFIX_ "_" GLOBUS_FLAVOR_NAME

int main()
{
    globus_callout_handle_t     callout_handle;
    globus_result_t             result;

    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_CALLOUT_MODULE);
    
    result = globus_callout_handle_init(&callout_handle);

    if(result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    result = globus_callout_register(callout_handle, 
                                     "TEST_CHAIN",
                                     FLAVOR_LIB("libchaina_test"),
                                     "chaina_test_callout");
    if(result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    result = globus_callout_register(callout_handle, 
                                     "TEST_CHAIN",
                                     FLAVOR_LIB("libchainb_test"),
                                     "chainb_test_callout");
    if(result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    result = globus_callout_register(callout_handle, 
                                     "TEST_CHAIN",
                                     FLAVOR_LIB("libchainc_test"),
                                     "chainc_test_callout");
    if(result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    
    result = globus_callout_call_type(callout_handle,
                                      "TEST_CHAIN",
                                      "foo",
                                      "bar");

    if(result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    
    result = globus_callout_handle_destroy(callout_handle);


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
