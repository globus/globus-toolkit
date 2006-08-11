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
#include "globus_xio_tcp_driver.h"

#define LINE_LEN 1024

void
test_res(
    globus_result_t                         res)
{
    if(res == GLOBUS_SUCCESS)
    {
        return;
    }

    fprintf(stderr, "ERROR: %s\n", globus_error_print_friendly(
        globus_error_peek(res)));

    globus_assert(0);
}

void
help()
{
    fprintf(stdout, "globus-xio-simple-server [options]\n");
    fprintf(stdout, "----------------------------------\n");
    fprintf(stdout, "options:\n");
    fprintf(stdout, "-D <drivers> : add this driver to the stack\n");
    exit(0);
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    globus_xio_driver_t                     driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    char *                                  cs;
    globus_result_t                         res;
    char                                    line[LINE_LEN];
    int                                     ctr;
    globus_bool_t                           done = GLOBUS_FALSE;
    globus_size_t                           nbytes;
    globus_xio_server_t                     server_handle;

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_xio_stack_init(&stack, NULL);
    for(ctr = 1; ctr < argc; ctr++)
    {
        if(strcmp(argv[ctr], "-h") == 0)
        {
            help();
        }
        else if(strcmp(argv[ctr], "-D") == 0 && ctr + 1 < argc)
        {
            ctr++;
            res = globus_xio_driver_load(argv[ctr], &driver);
            test_res(res);
            res = globus_xio_stack_push_driver(stack, driver);
            test_res(res);
        }
    }

    res = globus_xio_server_create(&server_handle, NULL, stack);
    test_res(res);

    globus_xio_server_get_contact_string(server_handle, &cs);
    fprintf(stdout, "Contact: %s\n", cs);

    res = globus_xio_server_accept(&xio_handle, server_handle);
    test_res(res);

    res = globus_xio_open(xio_handle, NULL, NULL);
    test_res(res);

    while(!done)
    {
        res = globus_xio_read(
            xio_handle, (globus_byte_t *)line, LINE_LEN, 1, &nbytes, NULL);
        line[nbytes] = '\0';
        if(res != GLOBUS_SUCCESS)
        {
            done = 1;
        }

        fprintf(stdout, "%s", line);
    }
    fprintf(stdout, "\n");

    res = globus_xio_close(xio_handle, NULL);
    test_res(res);

    globus_module_activate(GLOBUS_XIO_MODULE);

    return 0;
}
