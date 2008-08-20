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
#include "globus_xio_udp_driver.h"

#define LINE_LEN 1024

void
test_res(
    globus_result_t                         res)
{
    if(res == GLOBUS_SUCCESS)
    {
        return;
    }

    fprintf(stderr, "ERROR: %s\n", globus_error_print_chain(
        globus_error_peek(res)));

    globus_assert(0);
}

void
help()
{
    fprintf(stdout, 
        "globus-xio-udp-echo [options]\n"
        "-----------------\n"
        "using the -s switch sets up an 'echo' server.  if -c is specified\n"
        "with this option, the server will only be able to receive requests\n"
        "from that client\n"
        "\n"
        "specify -c <contact string> to communicated with an 'echo' server\n"
        "lines will be read from stdin until eof.  each line will be sent to\n"
        "the specified 'echo' server and the server's response echoed.\n"
        "Sending 'EXIT' will terminate a server\n"
        "\n"
        "options:\n"
        "-c <contact_string> : use this contact string (required for client)\n"
        "-s : be a server\n"
        "-l : print read data to stdout as server, do not listen for echo\n"
        "     as client \n"
        "-p : server port\n"
        "-D <driver> : add this driver to the stack\n");
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    globus_xio_driver_t                     udp_driver;
    globus_xio_driver_t                     driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    globus_xio_attr_t                       attr = NULL;
    char *                                  cs = NULL;
    globus_result_t                         res;
    int                                     ctr;
    globus_bool_t                           be_server = GLOBUS_FALSE;
    globus_bool_t                           print_reads = GLOBUS_FALSE;
    int                                     rc;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    res = globus_xio_driver_load("udp", &udp_driver);
    test_res(res);
    res = globus_xio_stack_init(&stack, NULL);
    test_res(res);
    res = globus_xio_stack_push_driver(stack, udp_driver);
    test_res(res);

    for(ctr = 1; ctr < argc; ctr++)
    {
        if(strcmp(argv[ctr], "-h") == 0)
        {
            help();
            return 0;
        }
        else if(strcmp(argv[ctr], "-D") == 0 && ctr + 1 < argc)
        {
            res = globus_xio_driver_load(argv[ctr + 1], &driver);
            test_res(res);
            res = globus_xio_stack_push_driver(stack, driver);
            test_res(res);
            ctr++;
        }
        else if(strcmp(argv[ctr], "-c") == 0 && ctr + 1 < argc)
        {
            cs = argv[ctr + 1];
            ctr++;
        }
        else if(strcmp(argv[ctr], "-s") == 0)
        {
            be_server = GLOBUS_TRUE;
        }
        else if(strcmp(argv[ctr], "-l") == 0)
        {
            print_reads = GLOBUS_TRUE;
        }
        else if(strcmp(argv[ctr], "-p") == 0 && ctr + 1 < argc)
        {
            test_res(globus_xio_attr_init(&attr));
            test_res(globus_xio_attr_cntl(
                attr,
                udp_driver,
                GLOBUS_XIO_UDP_SET_PORT,
                atoi(argv[ctr + 1])));
        }
    }
    
    if(!be_server && !*cs)
    {
        help();
        exit(1);
    }
    
    res = globus_xio_handle_create(&xio_handle, stack);
    test_res(res);
    res = globus_xio_stack_destroy(stack);
    test_res(res);
    res = globus_xio_open(xio_handle, cs, attr);
    test_res(res);
    
    res = globus_xio_handle_cntl(
            xio_handle,
            udp_driver,
            GLOBUS_XIO_UDP_GET_CONTACT,
            &cs);
    test_res(res);
    fprintf(stdout, "contact: %s\n", cs);
    globus_free(cs);
        
    if(be_server)
    {
        globus_xio_data_descriptor_t        dd;
        
        test_res(globus_xio_data_descriptor_init(&dd, xio_handle));

        /* be server */
        while(1)
        {
            char                            buffer[LINE_LEN + 1];
            int                             nbytes;
            
            res = globus_xio_read(
                xio_handle,
                buffer,
                sizeof(buffer) - 1,
                1,
                &nbytes,
                dd);
            test_res(res);
            
            if(print_reads)
            {
                buffer[nbytes++] = '\n';
                write(STDOUT_FILENO, buffer, nbytes);
            }
            else
            {
                res = globus_xio_write(
                    xio_handle,
                    buffer,
                    nbytes,
                    nbytes,
                    &nbytes,
                    dd);
                test_res(res);
            }
            
            if(nbytes == 5 && strncmp(buffer, "EXIT\n", 5) == 0)
            {
                break;
            }
        }
        
        test_res(globus_xio_data_descriptor_destroy(dd));
    }
    else
    {
        /* be client */
        char                            buffer[LINE_LEN];
        
        while(fgets(buffer, sizeof(buffer), stdin))
        {
            int                         nbytes;
            
            nbytes = strlen(buffer);
            res = globus_xio_write(
                xio_handle,
                buffer,
                nbytes,
                nbytes,
                &nbytes,
                NULL);
            test_res(res);
            
            if(!print_reads)
            {
                res = globus_xio_read(
                    xio_handle,
                    buffer,
                    sizeof(buffer),
                    nbytes,
                    &nbytes,
                    NULL);
                test_res(res);
            
                fputs(buffer, stdout);
            }
        }
    }
    
    res = globus_xio_close(xio_handle, NULL);
    test_res(res);

    res = globus_xio_driver_unload(udp_driver);
    test_res(res);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    return 0;
}
