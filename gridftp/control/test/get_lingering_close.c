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
