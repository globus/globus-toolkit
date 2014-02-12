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

#include "globus_ftp_control_test.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>

void 
connect_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response);

void
authenticate_callback(
    void *callback_arg,
    globus_ftp_control_handle_t *handle,
    globus_object_t *error,
    globus_ftp_control_response_t *ftp_response);

void
send_command_callback(
    void *callback_arg,
    globus_ftp_control_handle_t *handle,
    globus_object_t *error,
    globus_ftp_control_response_t *ftp_response);

void
quit_callback(
    void *callback_arg,
    globus_ftp_control_handle_t *handle,
    globus_object_t *error,
    globus_ftp_control_response_t *ftp_response);


globus_mutex_t                                  end_mutex;
globus_cond_t                                   end_cond;
globus_bool_t                                   end_done;

globus_mutex_t                                  data_mutex;
globus_cond_t                                   data_cond;
globus_bool_t                                   data_done;

globus_ftp_control_auth_info_t              auth;


globus_bool_t
async_control_test(
    globus_ftp_control_handle_t *               handle) 
{
    globus_ftp_control_handle_t control_handle;
    globus_result_t result;


    globus_mutex_init(&end_mutex, GLOBUS_NULL);
    globus_cond_init(&end_cond, GLOBUS_NULL);
    end_done = GLOBUS_FALSE;
  
    result = globus_ftp_control_handle_init(&control_handle);
    if (result != GLOBUS_SUCCESS)
    {
        printf("error: could not initialize\n");
        exit(1);
    }
  
    result = globus_ftp_control_connect(
        &control_handle, 
        login_info.hostname, 
        login_info.port, 
        connect_callback,
        GLOBUS_NULL);

    if (result != GLOBUS_SUCCESS)
    {
        printf("error: could not connect\n");
        return GLOBUS_FALSE;
    }
  
    globus_mutex_lock(&end_mutex);
    {
        while(!end_done)
        {
	    globus_cond_wait(&end_cond, &end_mutex);
        }
    }
    globus_mutex_unlock(&end_mutex);

    globus_ftp_control_handle_destroy(&control_handle);
    return GLOBUS_TRUE;
}

void
connect_callback(
    void * callback_arg,
    globus_ftp_control_handle_t * handle, 
    globus_object_t * error, 
    globus_ftp_control_response_t * ftp_response)
{
    globus_result_t result;

    if (ftp_response->code == 220 || ftp_response->code == 530) {
        verbose_printf(2, "%s\n", ftp_response->response_buffer);
    
    	auth.auth_gssapi_subject = GLOBUS_NULL;
    	auth.auth_gssapi_context = GLOBUS_NULL;
    
    	auth.user = login_info.login;
    	auth.password = login_info.password;
    
    	result= globus_ftp_control_authenticate(
	    handle, 
	    &auth,
	    GLOBUS_TRUE,
	    authenticate_callback, 
	    GLOBUS_NULL);

    	if (result != GLOBUS_SUCCESS) {
     	    printf("authentication failed\n");
      	    exit(1);
    	}
    } else {
    	printf("Error : %s\n", ftp_response->response_buffer);
    	exit(1);
    }
}

void
authenticate_callback(
    void * callback_arg,
    globus_ftp_control_handle_t * handle, 
    globus_object_t * error, 
    globus_ftp_control_response_t * ftp_response)
{
    globus_result_t result;

    if(error != GLOBUS_NULL)
    {
	verbose_printf(1, "Error : %s\n", 
		       globus_object_printable_to_string(error));
    	exit(1);
    }
    
    if (ftp_response->code == 230) 
    {
    	verbose_printf(2, "%s\n", ftp_response->response_buffer);
    
    	result = globus_ftp_control_send_command(
            handle, 
            "PWD\r\n",
            send_command_callback,
	    GLOBUS_NULL);

    	if (result != GLOBUS_SUCCESS)
    	{
            verbose_printf(1, "send_command PWD failed\n"); 
            exit(1);
        }
    } 
    else 
    {
    	verbose_printf(1, "Error : %s\n", ftp_response->response_buffer);
    	exit(1);
    } 
}

void
send_command_callback(
    void * callback_arg,
    globus_ftp_control_handle_t * handle, 
    globus_object_t * error, 
    globus_ftp_control_response_t * ftp_response)
{
    globus_result_t result;
  
    if (ftp_response->code == 257) 
    {
        verbose_printf(2, "%s\n", ftp_response->response_buffer);
    
        result = globus_ftp_control_quit(
            handle, 
	    quit_callback,
	    GLOBUS_NULL);

    	if (result != GLOBUS_SUCCESS)
      	{
            verbose_printf(1, "quit failed\n"); 
            exit(1);
        }
    } 
    else 
    {
        verbose_printf(1, "Error : %s\n", ftp_response->response_buffer);
        exit(1);
    }
}

void
quit_callback(
    void * callback_arg,
    globus_ftp_control_handle_t * handle, 
    globus_object_t * error, 
    globus_ftp_control_response_t * ftp_response)
{
    if (ftp_response->code == 221) 
    {
        verbose_printf(2, "%s\n", ftp_response->response_buffer);
 
        globus_mutex_lock(&end_mutex);
        {
            end_done = GLOBUS_TRUE;
            globus_cond_signal(&end_cond);
        }
        globus_mutex_unlock(&end_mutex);
    } 
    else 
    {
        verbose_printf(1,"Error : %s\n", ftp_response->response_buffer);
        exit(1);
    }
}

