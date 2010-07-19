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

/*
 * Globus I/O Authorization test.
 *
 * Create a TCP socket pair, using with one the various Globus I/O
 * authorization modes.
 */
#include "globus_common.h"
#include "globus_io.h"
#include <stdlib.h>

typedef struct
{
    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_bool_t			connected;
}
globus_l_io_authorization_test_monitor_t;

static
globus_bool_t
globus_l_io_authorization_test_callback(
	void *				arg,
	globus_io_handle_t *		handle,
	globus_result_t			result,
	char *				identity,
	gss_ctx_id_t 			context_handle);

static
void
globus_l_io_authorization_test_connect_callback(
	void *				arg,
	globus_io_handle_t *		handle,
	globus_result_t			result);

int
main(
    int					argc,
    char *				argv[])
{
    globus_io_handle_t			listener;
    globus_io_handle_t			server_handle;
    globus_io_handle_t			client_handle;
    globus_io_attr_t			attr;
    unsigned short			port = 0;
    globus_result_t			result;
    globus_io_secure_authorization_data_t
					auth_data;
    globus_l_io_authorization_test_monitor_t
					monitor;
    char				greeting[] = "Hello, my friend.";
    char 				reply_buffer[256];
    globus_size_t			written;
    globus_size_t			read_amt;

    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_IO_MODULE);

    /* Initialize monitor */
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.connected = GLOBUS_FALSE;

    /* Prepare attributes */
    globus_io_secure_authorization_data_initialize(&auth_data);
    globus_io_tcpattr_init(&attr);
    globus_io_attr_set_secure_authentication_mode(
	    &attr,
	    GLOBUS_IO_SECURE_AUTHENTICATION_MODE_GSSAPI,
	    GSS_C_NO_CREDENTIAL);


    if(argc >= 2)
    {
	if(! strcasecmp(argv[1], "self"))
	{
	    globus_io_attr_set_secure_authorization_mode(
		    &attr,
		    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF,
		    &auth_data);
	}
	else if(argc > 2 && ! strcasecmp(argv[1], "identity") )
	{
	    globus_io_secure_authorization_data_set_identity(&auth_data,
		                                             argv[2]);
	    globus_io_attr_set_secure_authorization_mode(
		    &attr,
		    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY,
		    &auth_data);
	}
	else if(! strcasecmp(argv[1], "callback"))
	{
	    globus_io_secure_authorization_data_set_callback(
		    &auth_data,
		    globus_l_io_authorization_test_callback,
		    GLOBUS_NULL);

	    globus_io_attr_set_secure_authorization_mode(
		    &attr,
		    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK,
		    &auth_data);
	}
	else if(! strcasecmp(argv[1], "-callback"))
	{
	    globus_io_secure_authorization_data_set_callback(
		    &auth_data,
		    globus_l_io_authorization_test_callback,
		    (void *) 0x1);

	    globus_io_attr_set_secure_authorization_mode(
		    &attr,
		    GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK,
		    &auth_data);
	}
	else
	{
	    goto no_authorization_mode;
	}
    }
    else
    {
	goto no_authorization_mode;
    }

    result = globus_io_tcp_create_listener(
	    &port,
	    -1,
	    &attr,
	    &listener);

    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("Could not create listener\n");

	goto error_exit;
    }

    result = globus_io_tcp_register_connect(
	    "localhost",
	    port,
	    &attr,
	    globus_l_io_authorization_test_connect_callback,
	    &monitor,
	    &client_handle);

    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("Could not register connect\n");
	goto error_exit;
    }

    result = globus_io_tcp_listen(&listener);
    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("Could not listen for connections\n");
	goto error_exit;
    }
    result = globus_io_tcp_accept(&listener,
	                          &attr,
			          &server_handle);
    if(result != GLOBUS_SUCCESS)
    {
	if(strcasecmp(argv[1], "-callback") == 0)
	{
	    globus_libc_printf("ok\n");
	    globus_module_deactivate_all();
	    exit(0);
	}
	else
	{
	    globus_libc_printf("Could not accept connection\n");
	    goto error_exit;
	}
    }

    globus_mutex_lock(&monitor.mutex);
    while(! monitor.connected)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }

    result = globus_io_close(&listener);
    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("Could not close listener\n");
	goto error_exit;
    }

    result = globus_io_write(&server_handle,
			     greeting,
		             sizeof(greeting),
		             &written);
    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("Could not write greeting\n");
	goto error_exit;
    }
    result = globus_io_close(&server_handle);
    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("Could not close server\n");
	goto error_exit;
    }
    result = globus_io_read(&client_handle,
	                    reply_buffer,
		            sizeof(reply_buffer),
		            sizeof(reply_buffer),
		            &read_amt);
    if(result != GLOBUS_SUCCESS)
    {
	globus_object_t * err;

	err = globus_error_get(result);

	if(! globus_io_eof(err))
	{
	    globus_libc_printf("Could not read greeting\n");
	    goto error_exit;
	}
    }
    result = globus_io_close(&client_handle);
    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("Could not close client\n");
	goto error_exit;
    }

    if(memcmp(greeting, reply_buffer, sizeof(greeting)) == 0)
    {
	globus_libc_printf("ok\n");
    }
    else
    {
	globus_libc_printf("not ok");
    }

    globus_module_deactivate_all();
    exit(0);


no_authorization_mode:
    globus_libc_printf(
    "Usage: %s AUTHORIZATION\n"
    "      AUTHORIZATION is one of\n"
    "      self                 use Globus I/O's self-authorization mode\n"
    "      identity \"subject\"   use Globus I/O's subject-based authorization\n"
    "      callback             use Globus I/O's callback authorization\n"
    "      -callback            use Globus I/O's callback authorization with\n"
    "                           a failure callback\n",
    argv[0]);

error_exit:
    globus_module_deactivate_all();
    exit(1);
}
/* main() */

static
globus_bool_t
globus_l_io_authorization_test_callback(
	void *				arg,
	globus_io_handle_t *		handle,
	globus_result_t			result,
	char *				identity,
	gss_ctx_id_t  			context_handle)
{
    if(arg) return GLOBUS_FALSE;
    else    return GLOBUS_TRUE;
}
/* globus_l_io_authorization_test_callback() */

static
void
globus_l_io_authorization_test_connect_callback(
	void *				arg,
	globus_io_handle_t *		handle,
	globus_result_t			result)
{
    globus_l_io_authorization_test_monitor_t *
					monitor;

    monitor = (globus_l_io_authorization_test_monitor_t *) arg;
    if(result != GLOBUS_SUCCESS)
    { 
        printf("%s\n", globus_object_printable_to_string(
                   globus_error_get(result)));
        exit(1);
    }
    globus_mutex_lock(&monitor->mutex);
    monitor->connected = GLOBUS_TRUE;
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
}
/* globus_l_io_authorization_test_connect_callback() */
