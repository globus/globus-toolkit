

#include "globus_callout.h"
#include <stdlib.h>
#include <stdio.h>


int main()
{
    globus_callout_handle_t     authz_handle;
    char *                      filename = "test.conf";
    globus_result_t             result;
            
    globus_callout_handle_init(&authz_handle);
    
    globus_callout_read_config(authz_handle, filename);
    
    result = globus_callout_call_type(handle,
                                      "TEST",
                                      NULL);
    
    globus_callout_handle_destroy(authz_handle);
    
    return 0;
}
