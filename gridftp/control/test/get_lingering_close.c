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

#include "globus_ftp_control.h"

globus_mutex_t the_lock;
globus_cond_t the_cond;
globus_bool_t done = GLOBUS_FALSE;

void
response_cb(
    void *					closure,
    globus_ftp_control_handle_t *		handle,
    globus_object_t *				err,
    globus_ftp_control_response_t *		response)
{
    globus_ftp_control_auth_info_t	auth_info;

    globus_ftp_control_auth_info_init(&auth_info,
	    "anonymous",
	    "globus@",
	    0,
	    0);

	if(response->code == 220)
	{
	    globus_ftp_control_authenticate(handle,
		    &auth_info,
		    0,
		    response_cb,
		    0);
	}
	else
	{
	    globus_ftp_control_quit(
		    handle,
		    response_cb,
		    0);
	    globus_mutex_lock(&the_lock);
	    done = 1;
	    globus_cond_signal(&the_cond);
	    globus_mutex_unlock(&the_lock);
	}
}

int main(int					argc,
	char **					argv)
{
    globus_ftp_control_handle_t		handle;

    globus_module_activate(GLOBUS_FTP_CONTROL_MODULE);

    globus_mutex_init(&the_lock, 0);
    globus_cond_init(&the_cond, 0);

    globus_ftp_control_handle_init(&handle);

    globus_ftp_control_connect(&handle,
	    "ftp.globus.org",
	    21,
	    response_cb,
	    0);
    globus_mutex_lock(&the_lock);
    while(!done)
    {
	globus_cond_wait(&the_cond, &the_lock);
    }
    globus_mutex_unlock(&the_lock);

    return globus_module_deactivate_all();
}
