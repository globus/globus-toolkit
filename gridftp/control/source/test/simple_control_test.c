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

#define TEST_ITERATIONS  8

void
simple_control_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response);

void
block_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response);

static globus_ftp_control_test_monitor_t        monitor;

globus_bool_t
simple_control_test(
    globus_ftp_control_handle_t *               handle)
{
    int                                         ctr;
    globus_result_t                             result;

    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.rc = GLOBUS_FALSE;

    for(ctr = 0; ctr < TEST_ITERATIONS; ctr++)
    {
        /* try to send a command  and wait for a response */
        monitor.done = GLOBUS_FALSE;
        result = globus_ftp_control_send_command(
                     handle,
                     "PWD\r\n",
                     simple_control_response_callback,
                     GLOBUS_NULL);
        if(result != GLOBUS_SUCCESS)
        {   
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
    }

    return monitor.rc;
}

void
simple_control_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    if(ftp_response->code == 257)
    {
        globus_mutex_lock(&monitor.mutex);
        {
            monitor.done = GLOBUS_TRUE;
            monitor.rc = GLOBUS_TRUE;
            globus_cond_signal(&monitor.cond);
        }
        globus_mutex_unlock(&monitor.mutex);
    }
}
