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

int
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_driver_t                     tcp_driver;
    globus_xio_driver_t                     smtp_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     smtp_handle;
    globus_xio_attr_t                       smtp_attr;
    char *                                  to_addr;
    char *                                  cs;
    globus_result_t                         res;
    char                                    line[LINE_LEN];

    if(argc < 3)
    {
        fprintf(stdout, "%s <contact string> <to address>.\n", argv[0]);
        return 1;
    }

    cs = argv[1];
    to_addr = argv[2];

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res);
    res = globus_xio_driver_load("smtp", &smtp_driver);
    test_res(res);

    globus_xio_stack_init(&stack, NULL);
    globus_xio_stack_push_driver(stack, tcp_driver);
    globus_xio_stack_push_driver(stack, smtp_driver);

    res = globus_xio_attr_init(&smtp_attr);
    test_res(res);
    res = globus_xio_attr_cntl(smtp_attr, smtp_driver,
            1, to_addr);
    test_res(res);

    res = globus_xio_handle_create(&smtp_handle, stack);
    test_res(res);
    res = globus_xio_open(smtp_handle, cs, smtp_attr);
    test_res(res);

    while(fgets(line, LINE_LEN, stdin) != NULL)
    {
        res = globus_xio_write(smtp_handle, line, 
                strlen(line), strlen(line), NULL, NULL);
        test_res(res);
    }

    res = globus_xio_close(smtp_handle, NULL);
    test_res(res);
    res = globus_xio_attr_destroy(smtp_attr);
    test_res(res);

    res = globus_xio_driver_unload(tcp_driver);
    test_res(res);
    res = globus_xio_driver_unload(smtp_driver);
    test_res(res);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    return 0;
}
