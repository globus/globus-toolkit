/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
