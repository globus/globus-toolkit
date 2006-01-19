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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int test1(int argc, char **argv);

#ifdef TARGET_ARCH_WIN32
#include "getoptWin.h"
#endif

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

    rc = test1(argc, argv); /* secure server*/
    globus_module_deactivate(GLOBUS_IO_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return rc;
}
/* main() */

globus_bool_t
auth_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result,
    char *				identity,
    gss_ctx_id_t 			context_handle)
{
    if(strcmp((char *) arg,identity))
    {
	return GLOBUS_FALSE;
    }
    else
    {
	return GLOBUS_TRUE;
    }
}



int
test1(int argc, char **argv)
{
    globus_result_t			result;
    globus_object_t *			err = GLOBUS_NULL;
    test_monitor_t 			monitor;
    globus_io_handle_t			handle;
    globus_io_handle_t			child_handle;
    globus_size_t			nbytes;
    globus_io_attr_t			attr;
    globus_io_secure_authorization_data_t
					auth_data;
    unsigned short			port=0;
    globus_byte_t *			large_buf=GLOBUS_NULL;
    globus_size_t			large_buf_size;
    int					c;
    char *				errstring = GLOBUS_NULL;
    int                                 host[4];
    int                                 rc = 0;
    int                                 vector = 0;
    struct iovec			iov_write[16];
    int                                 i;
    int                                 io_delegation = 0;
    
    setbuf(stdout, NULL);
    
    globus_io_tcpattr_init(&attr);

    globus_io_attr_set_secure_authentication_mode(
	&attr,
	GLOBUS_IO_SECURE_AUTHENTICATION_MODE_MUTUAL,
	GSS_C_NO_CREDENTIAL);

    globus_io_secure_authorization_data_initialize(&auth_data);

    globus_io_attr_set_secure_authorization_mode(
	&attr,
	GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF,
	&auth_data);
/*
    globus_io_attr_set_tcp_restrict_port(
	&attr,
	GLOBUS_FALSE);
*/
#ifndef TARGET_ARCH_WIN32
    while (( c = getopt(argc, argv, "brgscvz:i:I:P:")) != EOF)
#else
    while (( c = getoptWin(argc, argv, "rgscz:i:I:P:")) != EOF)
#endif
    {
        switch(c)
	{
          case 'b': /* all good options were taken */
            io_delegation = 1;
            break;
	  case 'g':
            result = globus_io_attr_set_secure_channel_mode(
		&attr,
		GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP);
            if(result != GLOBUS_SUCCESS)
            {
                err = globus_error_get(result);
                errstring = globus_object_printable_to_string(err);
                globus_libc_printf("test 1 setting io attribute failed: %s\n",
                                   errstring);
                rc = -1;
                goto exit;
            }
	    break;
	  case 's':
            result = globus_io_attr_set_secure_channel_mode(
		&attr,
		GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP);
            if(result != GLOBUS_SUCCESS)
            {
                err = globus_error_get(result);
                errstring = globus_object_printable_to_string(err);
                globus_libc_printf("test 1 setting io attribute failed: %s\n",
                                   errstring);
                rc = -1;
                goto exit;
            }
	    break;
	  case 'c':
            result = globus_io_attr_set_secure_channel_mode(
		&attr,
		GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR);
            if(result != GLOBUS_SUCCESS)
            {
                err = globus_error_get(result);
                errstring = globus_object_printable_to_string(err);
                globus_libc_printf("test 1 setting io attribute failed: %s\n",
                                   errstring);
                rc = -1;
                goto exit;
            }
	    break;
          case 'P':
            if(!strcmp(optarg, "none"))
            {
                result = globus_io_attr_set_secure_protection_mode(
                    &attr,
                    GLOBUS_IO_SECURE_PROTECTION_MODE_NONE);
                if(result != GLOBUS_SUCCESS)
                {
                    err = globus_error_get(result);
                    errstring = globus_object_printable_to_string(err);
                    globus_libc_printf("test 1 setting io attribute failed: %s\n",
                                       errstring);
                    rc = -1;
                    goto exit;
                }
            }
            else if(!strcmp(optarg, "integrity"))
            {
                result = globus_io_attr_set_secure_protection_mode(
                    &attr,
                    GLOBUS_IO_SECURE_PROTECTION_MODE_SAFE);
                if(result != GLOBUS_SUCCESS)
                {
                    err = globus_error_get(result);
                    errstring = globus_object_printable_to_string(err);
                    globus_libc_printf("test 1 setting io attribute failed: %s\n",
                                       errstring);
                    rc = -1;
                    goto exit;
                }
            }
            else if(!strcmp(optarg, "privacy"))
            {
                result = globus_io_attr_set_secure_protection_mode(
                    &attr,
                    GLOBUS_IO_SECURE_PROTECTION_MODE_PRIVATE);
                if(result != GLOBUS_SUCCESS)
                {
                    err = globus_error_get(result);
                    errstring = globus_object_printable_to_string(err);
                    globus_libc_printf("test 1 setting io attribute failed: %s\n",
                                       errstring);
                    rc = -1;
                    goto exit;
                }
            }
            break;
	  case 'z':
            result = globus_io_secure_authorization_data_set_callback(
                &auth_data,
                auth_callback,
                optarg);
            result = globus_io_attr_set_secure_authorization_mode(
		&attr,
		GLOBUS_IO_SECURE_AUTHORIZATION_MODE_CALLBACK,
                &auth_data);
            if(result != GLOBUS_SUCCESS)
            {
                err = globus_error_get(result);
                errstring = globus_object_printable_to_string(err);
                globus_libc_printf("test 1 setting io attribute failed: %s\n",
                                   errstring);
                rc = -1;
                goto exit;
            }
	    break;
	  case 'i':
            result = globus_io_secure_authorization_data_set_identity(
                &auth_data,
                optarg);
            result = globus_io_attr_set_secure_authorization_mode(
		&attr,
		GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY,
                &auth_data);
            if(result != GLOBUS_SUCCESS)
            {
                err = globus_error_get(result);
                errstring = globus_object_printable_to_string(err);
                globus_libc_printf("test 1 setting io attribute failed: %s\n",
                                   errstring);
                rc = -1;
                goto exit;
            }
	    break;
	  case 'r':
            result = globus_io_attr_set_tcp_restrict_port(
		&attr,
                GLOBUS_TRUE);
            if(result != GLOBUS_SUCCESS)
            {
                err = globus_error_get(result);
                errstring = globus_object_printable_to_string(err);
                globus_libc_printf("test 1 setting io attribute failed: %s\n",
                                   errstring);
                rc = -1;
                goto exit;
            }
	    break;
          case 'I':
            result = globus_io_attr_set_tcp_interface(
		&attr,
                optarg);
            if(result != GLOBUS_SUCCESS)
            {
                err = globus_error_get(result);
                errstring = globus_object_printable_to_string(err);
                globus_libc_printf("test 1 setting io attribute failed: %s\n",
                                   errstring);
                rc = -1;
                goto exit;
            }
	    break;
          case 'v':
            vector = 1;
            break;
	  default:
	    printf("unknown flag -%c\n", (char ) c);
	    globus_io_tcpattr_destroy(&attr);
	    return -1;
	}
    }

    result = globus_io_tcp_create_listener(
        &port,
        -1,
        &attr,
        &handle);

    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);
        errstring = globus_object_printable_to_string(err);

	globus_libc_printf("test 1 create listener failed: %s\n",
                           errstring);
        rc = -1;
	goto exit;
    }
    else
    {
        globus_libc_printf("listening on port %d\n", (int) port);
    }

    result = globus_io_tcp_listen(&handle);
	if ( result != GLOBUS_SUCCESS )
	{
        err = globus_error_get(result);
        errstring = globus_object_printable_to_string(err);
		globus_libc_printf("test 1 listen failed: %s\n", errstring);
		goto exit;
	}
    result = globus_io_tcp_accept(&handle,
				  &attr,
				  &child_handle);

    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);
        errstring = globus_object_printable_to_string(err);
	globus_libc_printf("test 1 accept failed: %s\n", errstring);
        rc = -1;
	goto exit;
    }
    else
    {
        gss_cred_id_t cred;
	globus_libc_printf("test 1 accept succeeded\n");
	result = globus_io_tcp_get_delegated_credential(&child_handle, &cred);
	if(result == GLOBUS_SUCCESS && cred != GSS_C_NO_CREDENTIAL)
	{
	    globus_libc_printf("Delegated credential %p\n", cred);
	}
	else
	{
	    globus_libc_printf("No delegated credential\n");
	}

    }
    globus_io_tcp_get_local_address(&child_handle,
	                            host,
			            &port);
    printf("Accepted connection on my socket: %d.%d.%d.%d:%d\n",
	    host[0],
	    host[1],
	    host[2],
	    host[3],
	    (int) port);

    globus_io_tcp_get_remote_address(&child_handle,
	                            host,
			            &port);
    printf("Accepted connection on my peer: %d.%d.%d.%d:%d\n",
	    host[0],
	    host[1],
	    host[2],
	    host[3],
	    (int) port);

    if(io_delegation)
    {
        gss_cred_id_t                   delegated_cred;

        result = globus_io_accept_delegation(
            &child_handle,
            &delegated_cred,
            GSS_C_NO_OID_SET,
            GSS_C_NO_BUFFER_SET,
            0,
            NULL);

        if(result != GLOBUS_SUCCESS)
        {
            err = globus_error_get(result);
            errstring = globus_object_printable_to_string(err);
            globus_libc_printf("test1 delegation failed: %s\n", errstring);
            rc = -1;
            goto exit;
        }
        else
        {
            globus_libc_printf("delegated credential\n");
        }

    }
    
    /* attemp large read */
    large_buf_size = 1024*1024;
    large_buf = (globus_byte_t *) globus_malloc(large_buf_size);

    result = globus_io_read(&child_handle,
		            large_buf,
		            large_buf_size,
		            large_buf_size,
		            &nbytes);

    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);
        errstring = globus_object_printable_to_string(err);
	globus_libc_printf("test1 large read failed: %s\n",errstring);
        rc = -1;
	goto exit;
    }
    else
    {
	globus_libc_printf("read large_block\n");
    }

    if(vector)
    {
        for(i = 0; i < 16; i++)
        {
            iov_write[i].iov_base = large_buf + i * 65536;
            iov_write[i].iov_len = 65536;
        }

        result = globus_io_writev(&child_handle,
                                  iov_write,
                                  16,
                                  &nbytes);
    }
    else
    { 
        result = globus_io_write(&child_handle,
                                 large_buf,
                                 large_buf_size,
                                 &nbytes);
    }

    if(result != GLOBUS_SUCCESS)
    {
        err = globus_error_get(result);
        errstring = globus_object_printable_to_string(err);
	globus_libc_printf("test1 large write failed: %s\n", errstring);
        rc = -1;
	goto exit;
    }
    else
    {
	globus_libc_printf("wrote large_block\n");
    }

  exit:
    globus_io_tcpattr_destroy(&attr);
    globus_io_close(&child_handle);
    globus_io_close(&handle);
    if(large_buf) 
    {
	globus_free(large_buf);
    }
    if(err)
    {
        globus_object_free(err);
    }
    if(errstring)
    {
        globus_libc_free(errstring);
    }
    return rc;
}
