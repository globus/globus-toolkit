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
#include "globus_xio_bidi_driver.h"

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
    globus_xio_driver_t                     transport_driver = NULL;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    char *                                  cs;
    globus_result_t                         res;
    char                                    line[LINE_LEN];
    char				    writeline[LINE_LEN];
    int					    len;
    int                                     ctr;
    globus_bool_t                           done = GLOBUS_FALSE;
    globus_size_t                           nbytes;
    globus_size_t			    pbytes;
    globus_xio_server_t                     server_handle;
    globus_xio_attr_t			    attr=NULL;
    globus_size_t			    port;

    /*if(argc < 2)
    {
        help();
        return 1;
    }*/

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_xio_stack_init(&stack, NULL);
    for(ctr = 1; ctr < argc; ctr++)
    {
        if(strcmp(argv[ctr], "-h") == 0)
        {
            help();
            return 0;
        }
	else if(strcmp(argv[ctr], "-p") == 0 && ctr + 1 < argc)
	{
            port = atoi(argv[ctr+1]);       
	    globus_xio_driver_load("bidi", &driver);
	    globus_xio_attr_init(&attr);
            res = globus_xio_attr_cntl( 
		       		    attr, 
				    driver, 
				    GLOBUS_XIO_BIDI_SET_PORT, 
				    port);
	}
    }
    
    globus_xio_stack_push_driver(stack, driver);

    globus_xio_server_create(&server_handle, attr, stack);

    globus_xio_server_get_contact_string(server_handle, &cs);
    fprintf(stdout, "\n\n %s\n\n", cs);

    globus_xio_server_accept(&xio_handle, server_handle);

    globus_xio_open(xio_handle, NULL, NULL);

    while(!done)
    {
        res = globus_xio_read(
            xio_handle, line, LINE_LEN, 1, &nbytes, NULL);

        if(res != GLOBUS_SUCCESS)
        {
            done = 1;
        }

        line[nbytes] = '\0';
        fprintf(stdout, "%s", line);
        sprintf(writeline, "%s", line);
	len=strlen(line);
	res = globus_xio_write(
		xio_handle, writeline, len, len, &pbytes, NULL);

	if(res != GLOBUS_SUCCESS)
	{
	    done = 1;
	}

    }

    globus_xio_close(xio_handle, NULL);

    globus_module_activate(GLOBUS_XIO_MODULE);

    return 0;
}
