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
#include "globus_ftp_control.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>



#define MAX_LEN          255


static globus_ftp_control_test_monitor_t        monitor;

void 
pending_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response);


globus_bool_t
pending_response_test(
    globus_ftp_control_handle_t *               handle)
{
    globus_result_t                             result;
    char                                        command[MAX_LEN];


    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;

    printf("Enter the commands \n");
    scanf("%s",command);
    strcat(command,"\r\n");    
    monitor.done = GLOBUS_FALSE;
    result = globus_ftp_control_send_command(
                     handle,
                     command,
                     pending_response_callback,
                     GLOBUS_NULL);
    
	if(result != GLOBUS_SUCCESS)
        {   
	  printf("Command failed, waiting for data command \n");
	  return GLOBUS_FALSE;
        }
        globus_mutex_lock(&monitor.mutex);
        {
            while(!monitor.done)
            { 
                globus_cond_wait(&monitor.cond, &monitor.mutex);
            }
        }
        globus_mutex_unlock(&monitor.mutex);
	return GLOBUS_TRUE;
}

void
pending_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
 
     printf("ftp response code %d\n",ftp_response->code);
    if( ftp_response->code == 150 || ftp_response->code == 227 || ftp_response->code == 225  )
    {
      printf(" data command pending\n");
    }
    else if(ftp_response->code == 257)
    {
        globus_mutex_lock(&monitor.mutex);
        {
            monitor.done = GLOBUS_TRUE;
            globus_cond_signal(&monitor.cond);
        }
        globus_mutex_unlock(&monitor.mutex);
    }
}






