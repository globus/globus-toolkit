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
#include "globus_xio_gssapi_ftp.h"

#define LINE_LEN 1024

void
test_res(
    globus_result_t                         res,
    int                                     line)
{
    if(res == GLOBUS_SUCCESS)
    {
        return;
    }

    fprintf(stderr, "ERROR @ %d: %s\n", line, globus_error_print_chain(
        globus_error_get(res)));

    globus_assert(0);
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    globus_xio_driver_t                     tcp_driver;
    globus_xio_driver_t                     ftp_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    char *                                  cs;
    char *                                  subject;
    globus_result_t                         res;
    char                                    line[LINE_LEN];
    globus_bool_t                           done = GLOBUS_FALSE;
    globus_size_t                           nbytes;
    globus_xio_attr_t                       attr;
    int                                     len;

    if(argc < 2)
    {
        fprintf(stderr, "arg error: <contact string> <subject>\n");
        return 1;
    }

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_xio_stack_init(&stack, NULL);

    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res, __LINE__);
    res = globus_xio_stack_push_driver(stack, tcp_driver);
    test_res(res, __LINE__);
    res = globus_xio_driver_load("gssapi_ftp", &ftp_driver);
    test_res(res, __LINE__);
    res = globus_xio_stack_push_driver(stack, ftp_driver);
    test_res(res, __LINE__);

    cs = argv[argc - 1];
    subject = argv[argc - 2];
    res = globus_xio_handle_create(&xio_handle, stack);
    test_res(res, __LINE__);
    res = globus_xio_attr_init(&attr);
    test_res(res, __LINE__);
    res = globus_xio_attr_cntl(attr, ftp_driver, 
        GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUBJECT, 
        subject);
    test_res(res, __LINE__);

    res = globus_xio_open(xio_handle, cs, attr);
    test_res(res, __LINE__);

    while(!done)
    {
        if(fgets(line, LINE_LEN, stdin) == NULL)
        {
            done = GLOBUS_TRUE;
        }
        else
        {
            len = strlen(line);
            line[len] = '\r';
            len++;
            line[len] = '\n';
            len++;
            res = globus_xio_write(
                xio_handle, line, len, len, &nbytes, NULL);
            test_res(res, __LINE__);
        }
    }

    globus_xio_close(xio_handle, NULL);

    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}
