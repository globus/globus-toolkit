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

#include "globus_xio.h"

int
main(
    int                             argc,
    char *                          argv[])
{
    globus_result_t                 res;
    char *                          driver_name;
    globus_xio_driver_t             driver;
    globus_xio_stack_t              stack;
    globus_xio_handle_t             handle;
    globus_size_t                   nbytes;
    char *                          contact_string = NULL;
    char                            buf[256];

    contact_string = argv[1];
    driver_name = argv[2];

    globus_module_activate(GLOBUS_XIO_MODULE);
    res = globus_xio_driver_load(
            driver_name,
            &driver);
    assert(res == GLOBUS_SUCCESS);
    
    res = globus_xio_stack_init(&stack, NULL);
    assert(res == GLOBUS_SUCCESS);
    res = globus_xio_stack_push_driver(stack, driver);
    assert(res == GLOBUS_SUCCESS);

    res = globus_xio_handle_create(&handle, stack);
    assert(res == GLOBUS_SUCCESS);

    res = globus_xio_open(handle, contact_string, NULL);
    assert(res == GLOBUS_SUCCESS);

    do
    {
        res = globus_xio_read(handle, buf, sizeof(buf) - 1, 1, &nbytes, NULL);
        if(nbytes > 0)
        {
            buf[nbytes] = '\0';
            fprintf(stderr, "%s", buf);
        }
    } while(res == GLOBUS_SUCCESS);
    
    globus_xio_close(handle, NULL);

    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}
