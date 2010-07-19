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

globus_bool_t
is_full_reply(
    const char *                        msg,
    int                                 length)
{
    char *                              tmp_ptr;

    if(msg[length-1] != '\n' || msg[length-2] != '\r')
    {
        return GLOBUS_FALSE;
    }

    tmp_ptr =(char *) msg;

    while(1)
    {
        if(tmp_ptr[3] == ' ')
        {
            return GLOBUS_TRUE;
        }
        tmp_ptr = strstr(tmp_ptr, "\r\n");
        if(tmp_ptr == NULL)
        {
            return GLOBUS_FALSE;
        }
        *tmp_ptr = '^';
        tmp_ptr++;
        *tmp_ptr = '^';
        tmp_ptr++;
        if(tmp_ptr - msg >= length || *tmp_ptr == '\0')
        {
            return GLOBUS_FALSE;
        }
    }
}


int
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_driver_t                     tcp_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    globus_xio_attr_t                       attr;
    char *                                  cs;
    globus_result_t                         res;
    char                                    line[LINE_LEN];
    globus_bool_t                           done = GLOBUS_FALSE;
    int                                     ndx;
    int                                     length;
    globus_size_t                           nbytes;
    globus_size_t                           size;

    globus_module_activate(GLOBUS_XIO_MODULE);

    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res, __LINE__);
    res = globus_xio_stack_init(&stack, NULL);
    test_res(res, __LINE__);
    res = globus_xio_stack_push_driver(stack, tcp_driver);
    test_res(res, __LINE__);

    res = globus_xio_attr_init(&attr);
    test_res(res, __LINE__);

    cs = argv[argc - 1];
    res = globus_xio_handle_create(&xio_handle, stack);
    test_res(res, __LINE__);

    res = globus_xio_open(xio_handle, cs, attr);
    test_res(res, __LINE__);

    length = 0;
    while(!is_full_reply(line, length))
    { 
        res = globus_xio_read(
            xio_handle, &line[length], LINE_LEN-length, 1, &nbytes, NULL);
        length+=nbytes;
    } 
    line[length] = '\0';
    printf(line);

    while(!done)
    {
        if(fgets(line, LINE_LEN, stdin) == NULL)
        {
            done = GLOBUS_TRUE;
        }
        else
        {
            if(strncasecmp(line, "QUIT", 4) == 0)
            {
                done = GLOBUS_TRUE;
            }
            ndx = strlen(line);
            line[ndx-1] = '\r';
            line[ndx] = '\n';
            size = ndx+1;
            res = globus_xio_write(
                xio_handle, line, size, size, &nbytes, NULL);
            test_res(res, __LINE__);

            length = 0;
            while(!is_full_reply(line, length))
            {
                res = globus_xio_read(
                    xio_handle,
                    &line[length], LINE_LEN-length, 1, &nbytes, NULL);
                length+=nbytes;
            }
            line[length] = '\0';
            printf(line);
        }
    }

    res = globus_xio_close(xio_handle, NULL);
    test_res(res, __LINE__);

    res = globus_xio_driver_unload(tcp_driver);
    test_res(res, __LINE__);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    return 0;
}
