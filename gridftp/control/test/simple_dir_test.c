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
#include "globus_libc.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TEST_ITERATIONS  8
#define BUFFER_SIZE      2048 

void
simple_dir_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response);

void
simple_dir_command_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response);

void
list_read_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof);

void 
signal_exit();

static globus_ftp_control_test_monitor_t        monitor;
static globus_ftp_control_test_monitor_t        data_monitor;

typedef struct get_put_info_s
{
    int                                         buffer_size;
    globus_byte_t *                             buffer;
} get_put_info_t;

globus_bool_t
simple_dir_test(
    globus_ftp_control_handle_t *               handle)
{
    int                                         ctr;
    int                                         hi;
    int                                         low;
    globus_result_t                             result;
    globus_ftp_control_host_port_t              addr;
    char                                        portmsg[256];

    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;

    globus_mutex_init(&data_monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&data_monitor.cond, GLOBUS_NULL);
    data_monitor.done = GLOBUS_FALSE;

    for(ctr = 0; ctr < TEST_ITERATIONS; ctr++)
    {
        monitor.done = GLOBUS_FALSE;
        monitor.rc = GLOBUS_TRUE;
        data_monitor.done = GLOBUS_FALSE;
        monitor.count = 0;

	globus_ftp_control_host_port_init(&addr, "localhost", 0);
	
	result = globus_ftp_control_local_pasv(handle, &addr);
	if (result != GLOBUS_SUCCESS)
	{
	    verbose_printf(1, "globus_ftp_control_host_port_init failed\n");
	    return GLOBUS_FALSE;
        }

	hi = addr.port / 256;
	low = addr.port - (hi * 256);

        sprintf(portmsg, "PORT %d,%d,%d,%d,%d,%d\r\n", 
                addr.host[0],
                addr.host[1],
                addr.host[2],
                addr.host[3],
                hi, 
                low);
        verbose_printf(2, "@@@%s\n", portmsg);
	result = globus_ftp_control_send_command(
	    handle,
	    portmsg,
	    simple_dir_response_callback,
	    GLOBUS_NULL);
	if(result != GLOBUS_SUCCESS)
	{
	    verbose_printf(1, "send_command PORT failed\n"); 
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

	if (!monitor.rc) 
        {
	    return GLOBUS_FALSE;
        }
    }
    return GLOBUS_TRUE;
}

void 
signal_exit()
{
    verbose_printf(2, "signal_exit() : start\n");
    globus_mutex_lock(&monitor.mutex);
    {
        monitor.done = GLOBUS_TRUE;
	monitor.count++;
	globus_cond_signal(&monitor.cond);
    }
    globus_mutex_unlock(&monitor.mutex);
}

void
simple_dir_response_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_ftp_control_response_t *             ftp_response)
{
    get_put_info_t *                            get_put_info;
    globus_result_t                             result; 

    if (ftp_response->code == 200) 
    {
       verbose_printf(2, "%s\n", ftp_response->response_buffer);

       get_put_info = (get_put_info_t *) globus_malloc(sizeof(get_put_info_t));
       get_put_info->buffer_size = BUFFER_SIZE;
       get_put_info->buffer = globus_malloc(BUFFER_SIZE);

       result = globus_ftp_control_send_command(
           handle,
           "LIST\r\n",
           simple_dir_response_callback,
           (void *)get_put_info);
       if (result != GLOBUS_SUCCESS)
       {
           verbose_printf(1, "LIST failed\n");
	   monitor.rc = GLOBUS_FALSE;
           signal_exit();
       }

       result = globus_ftp_control_data_connect_read(
           handle, GLOBUS_NULL, GLOBUS_NULL);
       if (result != GLOBUS_SUCCESS)
       {
          verbose_printf(1, "ls failed\n");
	  monitor.rc = GLOBUS_FALSE;
	  signal_exit();
       }
    } 
    else if (ftp_response->code == 150) 
    {
        verbose_printf(2, "%s\n", ftp_response->response_buffer);

        get_put_info = (get_put_info_t *)callback_arg;

        data_monitor.done = GLOBUS_FALSE;
        globus_ftp_control_data_read(
            handle,
	    get_put_info->buffer,
	    get_put_info->buffer_size,
	    list_read_data_callback, 
	    (void *) get_put_info);
    } 
    else if (ftp_response->code == 226)
    { 
        globus_mutex_lock(&data_monitor.mutex);
	{
	    while(!data_monitor.done)
	    {
	        globus_cond_wait(&data_monitor.cond, &data_monitor.mutex);
            }
        }
	globus_mutex_unlock(&data_monitor.mutex);

        verbose_printf(2, "%s\n", ftp_response->response_buffer);

        monitor.rc = GLOBUS_TRUE;
        signal_exit();
    } 
    else 
    {
        verbose_printf(1, "Error: %s\n", ftp_response->response_buffer);
	monitor.rc = GLOBUS_FALSE;
	signal_exit();
    }
}

void 
list_read_data_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof)
{
    get_put_info_t *                            get_put_info;

    get_put_info = (get_put_info_t *) callback_arg;
    if(error != GLOBUS_NULL)
    {
        verbose_printf(1, "unable to list files\n");
	monitor.rc = GLOBUS_FALSE;
	signal_exit();
    }
							 
    buffer[length] = '\0';
    verbose_printf(3, "%s", buffer);

    if (!eof) 
    {
        globus_ftp_control_data_read(
            handle,
            get_put_info->buffer,
            get_put_info->buffer_size,
            list_read_data_callback,
            (void *) get_put_info);
    } 
    else 
    {
        verbose_printf(2, "we have eof\n");
        globus_mutex_lock(&data_monitor.mutex);
	{
	    data_monitor.done = GLOBUS_TRUE;
	    globus_cond_signal(&data_monitor.mutex);
        }
	globus_mutex_unlock(&data_monitor.mutex);
    }
}
