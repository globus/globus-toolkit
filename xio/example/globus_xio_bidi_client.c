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

    fprintf(stderr, "ERROR: %s\n", globus_object_printable_to_string(
        globus_error_get(res)));

    globus_assert(0);
}

void
help()
{
    fprintf(stdout, "globus_xio_client [options] <contact string>\n");
    fprintf(stdout, "-----------------\n");
    fprintf(stdout, "options:\n");
    fprintf(stdout, "-D <drivers> : add this driver to the stack\n");
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
    char				    readline[LINE_LEN];
    int                                     ctr;
    globus_bool_t                           done = GLOBUS_FALSE;
    globus_size_t                           nbytes;
    globus_size_t			    pbytes;

    if(argc < 2)
    {
        help();
        return 1;
    }

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_xio_stack_init(&stack, NULL);
     globus_xio_driver_load("bidi", &driver);
     globus_xio_stack_push_driver(stack, driver);

    cs = argv[argc - 1];
    res = globus_xio_handle_create(&xio_handle, stack);
    test_res(res);

    globus_xio_open(xio_handle, cs, NULL);

    while(!done)
    {
        if(fgets(line, LINE_LEN, stdin) == NULL)
        {
            done = GLOBUS_TRUE;
        }
        else
        {
            int                         len;
            
            len = strlen(line);
            res = globus_xio_write(
                xio_handle, line, len, len, &nbytes, NULL);
            test_res(res);
	    res = globus_xio_read(
			xio_handle, readline, len, 1, &pbytes, NULL);
            readline[pbytes] = '\0';
	    fprintf(stdout, "%s", readline);
	    test_res(res);
        }
    }

    globus_xio_close(xio_handle, NULL);

    globus_module_activate(GLOBUS_XIO_MODULE);

    return 0;
}
