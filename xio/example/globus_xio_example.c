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
