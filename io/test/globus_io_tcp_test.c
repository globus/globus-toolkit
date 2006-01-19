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

#include "globus_io.h"
#include "gssapi.h"
#ifndef WIN32
#include <arpa/inet.h>
#endif

void test1(void);
void test2(void);
void test3(void);
void test4(int port);

typedef struct
{
    globus_mutex_t			mutex;
    globus_cond_t			cond;
    globus_object_t *			err;
    globus_bool_t			use_err;
    volatile globus_bool_t		done;
    volatile globus_bool_t		ready;
    globus_size_t			nbytes;
    void *				user_data;
} test_monitor_t;


#define test_buffer_size 1024
globus_byte_t test_buffer[test_buffer_size];

void
test_monitor_initialize(
    test_monitor_t *			monitor,
    void *				user_data)
{
    globus_mutex_init(&monitor->mutex, GLOBUS_NULL);
    globus_cond_init(&monitor->cond, GLOBUS_NULL);
    monitor->err = GLOBUS_NULL;
    monitor->use_err = GLOBUS_FALSE;
    monitor->done = GLOBUS_FALSE;
    monitor->ready = GLOBUS_FALSE;
    monitor->nbytes = 0;
    monitor->user_data = user_data;
}

void
test_monitor_reset(
    test_monitor_t *			monitor)
{
    globus_mutex_lock(&monitor->mutex);

    if(monitor->err)
    {
	globus_object_free(monitor->err);
	monitor->err = GLOBUS_NULL;
    }
    monitor->use_err = GLOBUS_FALSE;
    monitor->done = GLOBUS_FALSE;
    
    globus_mutex_unlock(&monitor->mutex);
}

void
test_monitor_destroy(
    test_monitor_t *			monitor)
{
    globus_cond_destroy(&monitor->cond);
    globus_mutex_destroy(&monitor->mutex);
}

/*
 * Function:	main
 *
 * Description:	
 *		
 * Parameters:	
 *
 * Returns:	
 */
int
main(int argc, char **argv)
{
    int					rc;
    
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_IO_MODULE);
    

#if 1
    test1();				/* connect, read, write, read */
    test2();				/* connect, read, writev, read */
    test3();				/* failed connect */
#endif
    test4(atoi(argv[1]));		/* connect to secure server*/
    globus_module_deactivate(GLOBUS_IO_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
}
/* main() */

void
test1_connect_callback(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_object_t *			err;
    test_monitor_t *			monitor;
    
    monitor = (test_monitor_t *) callback_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
    }

    globus_mutex_lock(&monitor->mutex);

    if(result != GLOBUS_SUCCESS)
    {
	monitor->use_err = GLOBUS_TRUE;
	monitor->err = err;
    }
    
    monitor->done = GLOBUS_TRUE;

    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);    
    
    return;
}

void
test1_read_callback(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes)
{
    globus_object_t *			err;
    test_monitor_t *			monitor;
    
    monitor = (test_monitor_t *) callback_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
    }

    globus_mutex_lock(&monitor->mutex);

    if(result != GLOBUS_SUCCESS &&
       !globus_io_eof(err))
    {
	monitor->use_err = GLOBUS_TRUE;
	monitor->err = err;
    }
    buf[nbytes >= test_buffer_size ? test_buffer_size-1 : nbytes] = '\0';
    
    monitor->done = GLOBUS_TRUE;

    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);    
    
    return;
}
/* test1_read_callback() */


void
test1_write_callback(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    globus_byte_t *			buf,
    globus_size_t			nbytes)
{
    globus_object_t *			err;
    test_monitor_t *			monitor;
    
    monitor = (test_monitor_t *) callback_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
    }

    globus_mutex_lock(&monitor->mutex);

    if(result != GLOBUS_SUCCESS &&
       !globus_io_eof(err))
    {
	monitor->use_err = GLOBUS_TRUE;
	monitor->err = err;
    }
    
    monitor->done = GLOBUS_TRUE;

    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);    
    
    return;
}
/* test1_write_callback() */

void
test1(void)
{
    globus_result_t			result;
    globus_object_t *			err;
    test_monitor_t 			monitor;
    globus_io_handle_t			handle;

    test_monitor_initialize(&monitor, GLOBUS_NULL);
    
    /* simple connection to known services with read and write */
    result = globus_io_tcp_register_connect(
	"localhost",
	25,
	GLOBUS_NULL,
	test1_connect_callback,
	(void *) &monitor,
	&handle);

    if(result != GLOBUS_SUCCESS)
    {
	globus_mutex_lock(&monitor.mutex);
	
	monitor.err = globus_error_get(result);
	monitor.use_err = GLOBUS_TRUE;
	monitor.done = GLOBUS_TRUE;

	globus_mutex_unlock(&monitor.mutex);
    }

    globus_mutex_lock(&monitor.mutex);
    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond,
			 &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);

    if(monitor.use_err)
    {
	globus_libc_printf("test 1 failed connecting\n");
	globus_object_free(monitor.err);
	
	goto finish;
    }

    test_monitor_reset(&monitor);
    
    result = globus_io_register_read(&handle,
				     test_buffer,
				     test_buffer_size,
				     1,
				     test1_read_callback,
				     &monitor);
    if(result != GLOBUS_SUCCESS)
    {
	globus_mutex_lock(&monitor.mutex);
	
	monitor.err = globus_error_get(result);
	monitor.use_err = GLOBUS_TRUE;
	monitor.done = GLOBUS_TRUE;

	globus_mutex_unlock(&monitor.mutex);
    }

    globus_mutex_lock(&monitor.mutex);
    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond,
			 &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);

    if(monitor.use_err)
    {
	globus_libc_printf("test 1 failed reading\n");
	globus_object_free(monitor.err);
	
	goto finish;
    }
    else
    {
	globus_libc_printf("test 1 read message:\n%s\n",
			   test_buffer);
    }
    
    test_monitor_reset(&monitor);

    globus_libc_sprintf((char *) test_buffer, "quit\n");
    
    result = globus_io_register_write(&handle,
				     test_buffer,
				     strlen((char *) test_buffer),
				     test1_write_callback,
				     &monitor);
    if(result != GLOBUS_SUCCESS)
    {
	globus_mutex_lock(&monitor.mutex);
	
	monitor.err = globus_error_get(result);
	monitor.use_err = GLOBUS_TRUE;
	monitor.done = GLOBUS_TRUE;

	globus_mutex_unlock(&monitor.mutex);
    }

    globus_mutex_lock(&monitor.mutex);
    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond,
			 &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);

    if(monitor.use_err)
    {
	globus_libc_printf("test 1 failed writing\n");
	globus_object_free(monitor.err);
	
	goto finish;
    }
    else
    {
	globus_libc_printf("test 1 write message:\n%s\n",
			   test_buffer);
    }
    test_monitor_reset(&monitor);
    
    result = globus_io_register_read(&handle,
				     test_buffer,
				     test_buffer_size,
				     1,
				     test1_read_callback,
				     &monitor);
    if(result != GLOBUS_SUCCESS)
    {
	globus_mutex_lock(&monitor.mutex);
	
	monitor.err = globus_error_get(result);
	monitor.use_err = GLOBUS_TRUE;
	monitor.done = GLOBUS_TRUE;

	globus_mutex_unlock(&monitor.mutex);
    }

    globus_mutex_lock(&monitor.mutex);
    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond,
			 &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);

    if(monitor.use_err)
    {
	globus_libc_printf("test 1 failed reading\n");
	globus_object_free(monitor.err);
	
	goto finish;
    }
    else
    {
	globus_libc_printf("test 1 read message:\n%s\n",
			   test_buffer);
    }

    test_monitor_reset(&monitor);

    result = globus_io_close(&handle);
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
	
	globus_libc_printf("test 1 failed closing\n");
    }

    globus_libc_printf("test 1 successful\n");
    
  finish:
    test_monitor_destroy(&monitor);
}

void
test2_writev_callback(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    struct iovec *			iov,
    globus_size_t			iovcnt,
    globus_size_t			nbytes)
{
    globus_object_t *			err = GLOBUS_NULL;
    test_monitor_t *			monitor;
    
    monitor = (test_monitor_t *) callback_arg;
    
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
    }

    globus_mutex_lock(&monitor->mutex);

    if(result != GLOBUS_SUCCESS &&
       !globus_io_eof(err))
    {
	monitor->use_err = GLOBUS_TRUE;
	monitor->err = err;
    }
    
    monitor->done = GLOBUS_TRUE;

    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);    
    
    return;
}
/* test2_writev_callback() */

void
test2(void)
{
    globus_result_t			result;
    globus_object_t *			err;
    test_monitor_t 			monitor;
    globus_io_handle_t			handle;
    globus_size_t			bytes_read;
    char				buf[6];
    struct iovec			iov[6];

    test_monitor_initialize(&monitor, GLOBUS_NULL);
    
    /* simple connection to known services with read and write */
    result = globus_io_tcp_connect(
	"antares.mcs.anl.gov",
	25,
	GLOBUS_NULL,
	&handle);

    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("test 1 failed connecting\n");
	
	goto finish;
    }

    result = globus_io_read(&handle,
			    test_buffer,
			    test_buffer_size,
			    1,
			    &bytes_read);
    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("test 1 failed reading\n");
	
	goto finish;
    }
    else
    {
	globus_libc_printf("test 1 read message:\n%s\n",
			   test_buffer);
    }
    
    buf[0]='q';
    buf[1]='u';
    buf[2]='i';
    buf[3]='t';
    buf[4]='\r';
    buf[5]='\n';
    iov[0].iov_base=buf;
    iov[0].iov_len=1;
    iov[1].iov_base=buf+1;
    iov[1].iov_len=1;
    iov[2].iov_base=buf+2;
    iov[2].iov_len=1;
    iov[3].iov_base=buf+3;
    iov[3].iov_len=1;
    iov[4].iov_base=buf+4;
    iov[4].iov_len=1;
    iov[5].iov_base=buf+5;
    iov[5].iov_len=1;
    
    result = globus_io_register_writev(&handle,
				       iov,
				       6,
				       test2_writev_callback,
				       &monitor);
    if(result != GLOBUS_SUCCESS)
    {
	globus_mutex_lock(&monitor.mutex);
	
	monitor.err = globus_error_get(result);
	monitor.use_err = GLOBUS_TRUE;
	monitor.done = GLOBUS_TRUE;

	globus_mutex_unlock(&monitor.mutex);
    }

    globus_mutex_lock(&monitor.mutex);
    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond,
			 &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);

    if(monitor.use_err)
    {
	globus_libc_printf("test 1 failed writing\n");
	globus_object_free(monitor.err);
	
	goto finish;
    }
    else
    {
	globus_libc_printf("test 1 wrote message:\n%s\n",
			   test_buffer);
    }
    test_monitor_reset(&monitor);
    
    result = globus_io_register_read(&handle,
				     test_buffer,
				     test_buffer_size,
				     1,
				     test1_read_callback,
				     &monitor);
    if(result != GLOBUS_SUCCESS)
    {
	globus_mutex_lock(&monitor.mutex);
	
	monitor.err = globus_error_get(result);
	monitor.use_err = GLOBUS_TRUE;
	monitor.done = GLOBUS_TRUE;

	globus_mutex_unlock(&monitor.mutex);
    }

    globus_mutex_lock(&monitor.mutex);
    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond,
			 &monitor.mutex);
    }
    globus_mutex_unlock(&monitor.mutex);

    if(monitor.use_err)
    {
	globus_libc_printf("test 1 failed reading\n");
	globus_object_free(monitor.err);
	
	goto finish;
    }
    else
    {
	globus_libc_printf("test 1 read message:\n%s\n",
			   test_buffer);
    }

    test_monitor_reset(&monitor);

    result = globus_io_close(&handle);
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
	
	globus_libc_printf("test 1 failed closing\n");
    }

    globus_libc_printf("test 1 successful\n");
    
  finish:
    test_monitor_destroy(&monitor);
}

void
test3(void)
{
    globus_result_t			result;
    globus_object_t *			err;
    test_monitor_t 			monitor;
    globus_io_handle_t			handle;
    globus_size_t			bytes_read;
    char				buf[6];
    struct iovec			iov[6];

    /* simple failed connection */
    result = globus_io_tcp_connect(
	"antares.mcs.mcs.mcs",
	25,
	GLOBUS_NULL,
	&handle);

    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("test 3 connect aborted (success)\n");
	
    }
    
}

void
test4(int port)
{
    globus_result_t			result;
    globus_object_t *			err;
    test_monitor_t 			monitor;
    globus_io_handle_t			handle;
    globus_size_t			bytes_read;
    char				buf[6];
    struct iovec			iov[6];
    globus_io_attr_t			attr;
    globus_io_secure_authorization_data_t
					auth_data;

    globus_io_tcpattr_init(&attr);

    globus_io_attr_set_secure_authentication_mode(
	&attr,
	GLOBUS_IO_SECURE_AUTHENTICATION_MODE_MUTUAL,
	GSS_C_NO_CREDENTIAL);

    globus_io_attr_set_secure_authorization_mode(
	&attr,
	GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF,
	&auth_data);

    globus_io_attr_set_secure_channel_mode(
	&attr,
	GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR);

    /* simple failed connection */
    result = globus_io_tcp_connect(
	"localhost",
	(unsigned short) port,
	&attr,
	&handle);

    if(result != GLOBUS_SUCCESS)
    {
	globus_libc_printf("test 4 connect failed\n");
	
    }
    else
    {
	globus_libc_printf("test 4 connect succeeded\n");
	globus_io_close(&handle);
    }
}
