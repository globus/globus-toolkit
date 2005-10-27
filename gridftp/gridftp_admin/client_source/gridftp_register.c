/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
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
    fprintf(stdout, "globus-gridftp-register <registry contact> <contact string> <max conneciton count> [<repo name>]\n");
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     c_count;
    globus_xio_driver_t                     tcp_driver;
    globus_xio_driver_t                     gsi_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    char *                                  cs;
    char *                                  repo;
    char *                                  registry_cs;
    globus_result_t                         res;
    char                                    msg[256];
    globus_size_t                           nbytes;
    int                                     len;

    if(argc < 3)
    {
        help();
        return 1;
    }

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_xio_stack_init(&stack, NULL);

    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res);
    res = globus_xio_stack_push_driver(stack, tcp_driver);
    test_res(res);
/*
    res = globus_xio_driver_load("gsi", &gsi_driver);
    test_res(res);
  */  
/*
    res = globus_xio_stack_push_driver(stack, gsi_driver);
    test_res(res);
*/
    registry_cs = argv[1];
    cs = argv[2];

    if(argc < 5)
    {
        repo = "";
    }
    else if(argc < 4)
    {
        help();
        exit(1);
    }
    else
    {
        repo = argv[4];
    }
    c_count = atoi(argv[3]);
    res = globus_xio_handle_create(&xio_handle, stack);
    test_res(res);

    res = globus_xio_open(xio_handle, registry_cs, NULL);
    test_res(res);

    memset(msg, '\0', 256);
    len = strlen(repo);
    *msg = (char)c_count;
    memcpy(&msg[1], repo, len);
    msg[len+1] = '\0';
    memcpy(&msg[len+2], cs, strlen(cs));
    res = globus_xio_write(xio_handle, msg, 256, 256, &nbytes, NULL);
    test_res(res);

    globus_xio_close(xio_handle, NULL);

    globus_module_activate(GLOBUS_XIO_MODULE);

    return 0;
}
