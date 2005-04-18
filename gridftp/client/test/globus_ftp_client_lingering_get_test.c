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
 * simple authenticated get which is not completed before
 * deactivation.
 *
 * makes sure that the ftp client and control libraries will 
 * correctly deal with a handle in a unfinished state before
 * deactivation.
 */
#include "globus_ftp_client.h"

static globus_mutex_t lock;
static globus_cond_t cond;
static int done = 0;

static
void
done_cb(
	void *					user_arg,
	globus_ftp_client_handle_t *		handle,
	globus_object_t *			err)
{
    char * tmpstr;

    if(err) {tmpstr = " an";done=1;}
    else    {tmpstr = "out";done=2;}

    printf("done with%s error\n", tmpstr);
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
    globus_byte_t				buffer[1024];
    globus_size_t				buffer_length = sizeof(buffer);
    globus_result_t				result;
    char *					src;
    char *					dst;
    globus_ftp_client_handleattr_t		handle_attr;

    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);

    globus_ftp_client_handleattr_init(&handle_attr);
    globus_ftp_client_operationattr_init(&attr);

    test_parse_args(argc, 
		    argv,
		    &handle_attr,
		    &attr,
		    &src,
		    &dst);

    globus_mutex_init(&lock, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);

    globus_ftp_client_handle_init(&handle,  &handle_attr);

    done = GLOBUS_FALSE;
    result = globus_ftp_client_get(&handle,
				   src,
				   &attr,
				   GLOBUS_NULL,
				   done_cb,
				   0);
    globus_module_deactivate_all();

    return done;
}
