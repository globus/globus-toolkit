#include "globus_io.h"

#ifdef TARGET_ARCH_WIN32
#include "getoptWin.h"
#endif

void test1(int argc, char **argv);

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


#define test_buffer_size 1021
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
    

    test1(argc, argv); /* connect to secure server */
    globus_module_deactivate(GLOBUS_IO_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
}
/* main() */

void
test1(int argc, char **argv)
{
    globus_result_t			result;
    globus_object_t *			err = GLOBUS_NULL;
    test_monitor_t 			monitor;
    globus_io_handle_t			handle;
    globus_size_t			nbytes;
    char				buf[6];
    struct iovec			iov[6];
    globus_io_attr_t			attr;
    globus_io_secure_authorization_data_t
					auth_data;
    globus_byte_t *			large_buf=GLOBUS_NULL;
    globus_byte_t *			large_buf2=GLOBUS_NULL;
    globus_size_t			large_buf_size;
    int					i;
    int					c;
    extern char *			optarg;
    extern int				optind;
    char *				host=GLOBUS_NULL;
    unsigned short			port=0;
    char *			        errstring=GLOBUS_NULL;

    globus_io_tcpattr_init(&attr);
    globus_io_secure_authorization_data_initialize(&auth_data);
    globus_io_attr_set_secure_authentication_mode(
	&attr,
	GLOBUS_IO_SECURE_AUTHENTICATION_MODE_MUTUAL,
	GSS_C_NO_CREDENTIAL);

    globus_io_attr_set_secure_authorization_mode(
	&attr,
	GLOBUS_IO_SECURE_AUTHORIZATION_MODE_SELF,
	&auth_data);

    globus_io_attr_set_tcp_restrict_port(
	&attr,
	GLOBUS_FALSE);
#ifdef TARGET_ARCH_WIN32
    while (( c = getoptWin(argc, argv, "rHi:gsch:p:I:dD")) != EOF)
#else
    while (( c = getopt(argc, argv, "rHi:gsch:p:I:dD")) != EOF)
#endif
    {
	switch(c)
	{
	  case 'g':
	    globus_io_attr_set_secure_channel_mode(
		&attr,
		GLOBUS_IO_SECURE_CHANNEL_MODE_GSI_WRAP);
	    break;
	  case 's':
	    globus_io_attr_set_secure_channel_mode(
		&attr,
		GLOBUS_IO_SECURE_CHANNEL_MODE_SSL_WRAP);
	    break;
	  case 'c':
	    globus_io_attr_set_secure_channel_mode(
		&attr,
		GLOBUS_IO_SECURE_CHANNEL_MODE_CLEAR);
	    break;
	  case 'h':
	    host = optarg;
	    break;
	  case 'p':
	    port = atoi(optarg);
	    break;
          case 'H':
            globus_io_attr_set_secure_authorization_mode(
	        &attr,
	        GLOBUS_IO_SECURE_AUTHORIZATION_MODE_HOST,
	        &auth_data);
            break;
          case 'i':
	    globus_io_secure_authorization_data_set_identity(&auth_data,
	        optarg);
            globus_io_attr_set_secure_authorization_mode(
	        &attr,
	        GLOBUS_IO_SECURE_AUTHORIZATION_MODE_IDENTITY,
	        &auth_data);
            break;
	  case 'd':
	    globus_io_attr_set_secure_delegation_mode(
		    &attr,
		    GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY);
	    break;
	  case 'D':
	    globus_io_attr_set_secure_delegation_mode(
		    &attr,
		    GLOBUS_IO_SECURE_DELEGATION_MODE_FULL_PROXY);
	    break;
          case 'r':
            globus_io_attr_set_tcp_restrict_port(
		&attr,
                GLOBUS_TRUE);
	    break;
          case 'I':
            globus_io_attr_set_tcp_interface(
		&attr,
                optarg);
            break;
	  default:
	    printf("unknown flag -%c\n",(char) c);
	    globus_io_tcpattr_destroy(&attr);
	    return;
	}
    }
    if(host == GLOBUS_NULL || port == 0)
    {
	printf("please specify -h host and -p port\n");
	globus_io_tcpattr_destroy(&attr);
	return;
    }

    result = globus_io_tcp_connect(
	host,
	(unsigned short) port,
	&attr,
	&handle);

    err = globus_error_get(result);
    errstring = globus_object_printable_to_string(err);

    globus_io_tcpattr_destroy(&attr);

    if(result != GLOBUS_SUCCESS)
    {
	
	globus_libc_printf("test 1 connect failed: %s\n", errstring);

	goto exit;
    }
    else
    {
	globus_libc_printf("test 1 connect succeeded\n");
    }
    /* attempt large write */
    large_buf_size = 1024*1024;
    large_buf = (globus_byte_t *) globus_malloc(large_buf_size);
    large_buf2 = (globus_byte_t *) globus_malloc(large_buf_size);

    for(i = 0; i < large_buf_size; i++)
    {
	large_buf[i] = i & 0xff;
    }

    result = globus_io_write(&handle,
		             large_buf,
		             large_buf_size,
		             &nbytes);

    if(result != GLOBUS_SUCCESS)
    {
		err = globus_error_get(result);
		errstring = globus_object_printable_to_string(err);
		globus_libc_printf("test1 large write failed: %s\n", errstring);
		goto exit;
    }
    else
    {
		globus_libc_printf("wrote large_block\n");
    }

    result = globus_io_read(&handle,
			    large_buf2,
			    large_buf_size,
			    large_buf_size,
			    &nbytes);

    if(result != GLOBUS_SUCCESS)
    {
		err = globus_error_get(result);

		if(!globus_io_eof(err))
		{
			errstring = globus_object_printable_to_string(err);
			globus_libc_printf("test1 large read failed: %s\n", errstring);
		}
		goto exit;
    }
    else
    {
		globus_libc_printf("read large_block\n");
    }

    for(i = 0; i < large_buf_size; i++)
    {
		if(large_buf[i] != large_buf2[i])
		{
			globus_libc_printf("comparison failed at byte %d\n",i);

			goto exit;
		}
    }
  exit:
    if(large_buf2)
    {
        globus_free(large_buf2);
    }
    if(large_buf)
    {
        globus_free(large_buf);
    }
    if(err)
    {
		// TESTING!!!
		fprintf( stderr, "=====================================================\n" );
		fprintf( stderr, "calling globus_object_free()\n" );
		// END TESTING
		globus_object_free(err);
    }
    if(errstring)
    {
		// TESTING!!!
		//fprintf( stderr, "calling globus_free()\n" );
		// END TESTING
		globus_free(errstring);
    }
	// TESTING!!!
	//fprintf( stderr, "calling globus_io_close()\n" );
	// END TESTING
    globus_io_close(&handle);
}
