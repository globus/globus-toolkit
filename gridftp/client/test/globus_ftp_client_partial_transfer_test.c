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

/*
 * partial transfer.
 *
 * makes sure that the ftp client and control libraries will handle the
 * partial fila attribute for a 3rd party transfer.
 */
#include "globus_ftp_client.h"
#include "globus_ftp_client_test_common.h"

#include <stdlib.h>

static globus_mutex_t lock;
static globus_cond_t cond;
static globus_bool_t done;
static globus_bool_t error = GLOBUS_FALSE;

static
void
done_cb(
	void *					user_arg,
	globus_ftp_client_handle_t *		handle,
	globus_object_t *			err)
{
    char * tmpstr;

    if(err) tmpstr = " an";
    else    tmpstr = "out";

    if(err) { printf("done with%s error\n", tmpstr); 
              error = GLOBUS_TRUE; }
    globus_mutex_lock(&lock);
    done = GLOBUS_TRUE;
    globus_cond_signal(&cond);
    globus_mutex_unlock(&lock);
       
}

int main(int argc,
	 char *argv[])
{
    globus_ftp_client_handle_t			handle;
    globus_ftp_client_operationattr_t		attr;
    globus_result_t				result;
    char *					src;
    char *					dst;
    globus_ftp_client_handleattr_t		handle_attr;
    globus_off_t				start_offset=5;
    globus_off_t				end_offset=10;
    int						i;

    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    globus_ftp_client_handleattr_init(&handle_attr);
    globus_ftp_client_operationattr_init(&attr);

    /* Parse local arguments */
    for(i = 1; i < argc; i++)
    {
	if(strcmp(argv[i], "-R") == 0 && i + 2 < argc)
	{
	    sscanf(argv[i+1], "%"GLOBUS_OFF_T_FORMAT, &start_offset);
	    sscanf(argv[i+2], "%"GLOBUS_OFF_T_FORMAT, &end_offset);

	    test_remove_arg(&argc, argv, &i, 2);
	}
    }

    test_parse_args(argc, 
		    argv,
		    &handle_attr,
		    &attr,
		    &src,
		    &dst);

    if(start_offset < 0) start_offset = 0;
    if(end_offset < 0) end_offset = 0;

    globus_mutex_init(&lock, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);

    globus_ftp_client_handle_init(&handle,  &handle_attr);

    done = GLOBUS_FALSE;
    result =
	globus_ftp_client_partial_third_party_transfer(&handle,
						       src,
						       &attr,
						       dst,
						       &attr,
						       GLOBUS_NULL,
						       start_offset,
						       end_offset,
						       done_cb,
						       0);
    if(result != GLOBUS_SUCCESS)
    {
	error = GLOBUS_TRUE;
	done = GLOBUS_TRUE;
    }

    globus_mutex_lock(&lock);
    while(!done)
    {
	globus_cond_wait(&cond, &lock);
    }
    globus_mutex_unlock(&lock);

    globus_ftp_client_handle_destroy(&handle);

    globus_module_deactivate_all();

    if(test_abort_count && error)
    {
	return 0;
    }
    return error;
}
