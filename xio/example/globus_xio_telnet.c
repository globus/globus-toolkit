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
    test_res(res);
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
    globus_xio_target_t                     target;
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
    test_res(res);
    globus_xio_stack_init(&stack, NULL);
    globus_xio_stack_push_driver(stack, tcp_driver);

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
    }

    cs = argv[argc - 1];

    res = globus_xio_target_init(&target, NULL, cs, stack);
    test_res(res);
    res = globus_xio_open(&xio_handle, NULL, target);
    test_res(res);
    fprintf(stdout, "Successfully opened.\n");
/*
    res = globus_xio_register_read(xio_handle, read_buffer, 
            LINE_LEN, 1, NULL, 
            globus_l_xio_read_cb, NULL);
    test_res(res);
*/
    while(!done)
    {
        globus_poll();
        if(fgets(line, LINE_LEN, stdin) == NULL)
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
                fprintf(stdout, "Sending:%s:\n", line);
                res = globus_xio_write(xio_handle, line, 
                        strlen(line), strlen(line), NULL, NULL);
                test_res(res);
            }
        }

        ndx = 0;
        reading = GLOBUS_TRUE;
        while(reading)
        {
                fprintf(stdout, "globus_xio_read\n");
            res = globus_xio_read(
                xio_handle, &read_buffer[ndx], LINE_LEN-ndx, 1, &nbytes, NULL);
                fprintf(stdout, "done globus_xio_read\n");
            test_res(res);
            ndx += nbytes;
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
        fflush(stdout);
    }

    res = globus_xio_close(xio_handle, NULL);
    test_res(res);

    res = globus_xio_driver_unload(tcp_driver);
    test_res(res);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    return 0;
}
