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

void 
globus_l_xio_read_cb(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    int                                     ctr;
    globus_result_t                         res;

    for(ctr = 0; ctr < nbytes; ctr++)
    {
        if(isprint(buffer[ctr]) || buffer[ctr] == '\n')
        {
            fprintf(stdout, "%c", buffer[ctr]);
        }
    }
    fflush(stdout);

    res = globus_xio_register_read(handle, buffer, 
            LINE_LEN, 1, NULL, 
            globus_l_xio_read_cb, NULL);
    test_res(res, __LINE__);
}

void
help()
{
    fprintf(stdout, "globus_xio_telnet [options] <host> <port>\n");
    fprintf(stdout, "-----------------\n");
    fprintf(stdout, "Opens up a tcp connection to host:port.  All data read\n");
    fprintf(stdout, "from stdin is sent down the connection, and all data\n");
    fprintf(stdout, "read from the connection is sent to stdout.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "options:\n");
    fprintf(stdout, "-D <driver> : add this driver to the stack\n");
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_driver_t                     tcp_driver;
    globus_xio_driver_t                     driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    globus_xio_attr_t                       attr;
    char *                                  cs;
    globus_result_t                         res;
    char                                    line[LINE_LEN];
    char                                    read_buffer[LINE_LEN];
    int                                     ctr;
    globus_bool_t                           done = GLOBUS_FALSE;
    globus_bool_t                           reading;
    int                                     ndx;
    globus_size_t                           nbytes;

    globus_module_activate(GLOBUS_XIO_MODULE);

    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res, __LINE__);
    res = globus_xio_stack_init(&stack, NULL);
    test_res(res, __LINE__);
    res = globus_xio_stack_push_driver(stack, tcp_driver);
    test_res(res, __LINE__);

    res = globus_xio_attr_init(&attr);
    test_res(res, __LINE__);

    if(argc < 2)
    {
        help();
        return 1;
    }

    for(ctr = 1; ctr < argc - 1; ctr++)
    {
        if(strcmp(argv[ctr], "-h") == 0)
        {
            help();
            return 0;
        }
        else if(strcmp(argv[ctr], "-D") == 0)
        {
            res = globus_xio_driver_load(argv[ctr + 1], &driver);
            globus_xio_stack_push_driver(stack, driver);
        }
        else if(strcmp(argv[ctr], "-S") == 0 && ctr + 1 < argc - 1)
        {
            ctr++;
            res = globus_xio_attr_cntl(
                attr, driver, GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUBJECT, argv[ctr]);
        }
    }

    cs = argv[argc - 1];
    res = globus_xio_handle_create(&xio_handle, stack);
    test_res(res, __LINE__);

    res = globus_xio_attr_cntl(
        attr,
        driver,
        GLOBUS_XIO_GSSAPI_ATTR_TYPE_SUBJECT,
        "/O=Grid/O=Globus/OU=mcs.anl.gov/CN=John Bresnahan");
    test_res(res, __LINE__);


    res = globus_xio_open(xio_handle, cs, attr);
    test_res(res, __LINE__);

    fprintf(stderr, "open\n");
    while(!done)
    {
        globus_poll();
        ndx = 0;
        reading = GLOBUS_TRUE;
        while(reading)
        {
            res = globus_xio_read(
                xio_handle, &read_buffer[ndx], LINE_LEN-ndx, 1, &nbytes, NULL);
            test_res(res, __LINE__);
            ndx += nbytes;
            read_buffer[ndx] = '\0';
            if(strstr(read_buffer, "\r\n") != NULL)
            {
                reading = GLOBUS_FALSE;
            }
        }
        for(ctr = 0; ctr < ndx; ctr++)
        {
            if(isprint(read_buffer[ctr]) || read_buffer[ctr] == '\n')
            {
                fprintf(stdout, "%c", read_buffer[ctr]);
            }
        }
        if(strcasecmp(line, "QUIT\r\n") == 0 || 
            fgets(line, LINE_LEN, stdin) == NULL)
        {
            done = GLOBUS_TRUE;
        }
        else
        {
            if(line[0] == 29)
            {
                fprintf(stdout, "xio telnet>");
                fflush(stdout);
                scanf("%s", line);
                if(strcmp(line, "quit") == 0)
                {
                    done = GLOBUS_TRUE;
                }
            }
            else
            {
                ndx = strlen(line);
                line[ndx-1] = '\r'; /* overwrite '\n' */
                line[ndx] = '\n';
                line[ndx+1] = '\0';
                res = globus_xio_write(xio_handle, line, 
                        strlen(line), strlen(line), NULL, NULL);
                test_res(res, __LINE__);
            }
        }

        fflush(stdout);
    }

    res = globus_xio_close(xio_handle, NULL);
    test_res(res, __LINE__);

    res = globus_xio_driver_unload(tcp_driver);
    test_res(res, __LINE__);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    return 0;
}
