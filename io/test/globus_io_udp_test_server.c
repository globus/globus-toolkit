#include "globus_io.h"
#include <stdlib.h>
#include <assert.h>

#define BUF_SIZE   1024

static void test1(int argc, char **argv);
static void print_usage();

static void 
globus_l_udp_test_receive_callback(
    void *                            arg,
    globus_io_handle_t *              handle,
    globus_result_t                   result,
    globus_byte_t *                   buf,
    globus_size_t                     nbytes,
    char *                            host,
    unsigned short                    port);

static int                   mc_count = 1;
static int                   msgs_received;
static globus_cond_t         globus_l_io_udp_cond;
static globus_mutex_t        globus_l_io_udp_mutex;

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
    
    globus_module_activate(GLOBUS_IO_MODULE);

    test1(argc, argv);			/* secure server*/
    globus_module_deactivate(GLOBUS_IO_MODULE);

    return 0;
}
/* main() */

void
test1(int argc, char **argv)
{
    globus_result_t			result;
    globus_io_handle_t			handle;
    globus_io_attr_t			attr;
    globus_byte_t  			buf[BUF_SIZE];
    char *                              from_host;
    unsigned short                      from_port;
    globus_size_t			from_bytes;
    char *                              mc_host = GLOBUS_NULL;
    unsigned short                      mc_port = 0;
    globus_bool_t                       mc_enabled = GLOBUS_FALSE;
    char *                              mc_interface;
    static char *                       myname = "test1";
    char                                c;

    setbuf(stdout, NULL);
    
    globus_libc_printf("%s() : start\n", myname);
 
    globus_io_udpattr_init(&attr);
    globus_cond_init(&globus_l_io_udp_cond, 
		     GLOBUS_NULL);
    globus_mutex_init(&globus_l_io_udp_mutex,
		      GLOBUS_NULL);
    while (( c = getopt(argc, argv, "gsch:p:n:")) != EOF)
    {
       switch(c)
       {
	   case 'h':
               mc_host = optarg;
	       mc_interface = INADDR_ANY;
	       mc_enabled = GLOBUS_TRUE;
               break;
	      
	   case 'p':
	       mc_port = atoi(optarg);
	       mc_enabled = GLOBUS_TRUE;
	       break;

	   case 'n':
	       mc_count = atoi(optarg);
	       break;
       }
    }

    if(mc_enabled && (mc_host == GLOBUS_NULL || mc_port == 0))
    {
        printf("Must specify host, port, and count to use multicast\n");
	print_usage();

	return;
    }

    /* setup attribute for multicast */
    if(mc_enabled)
    {
        result = globus_io_attr_set_udp_multicast_membership(
						    &attr,
						    mc_host,
						    mc_interface);
        assert(result == GLOBUS_SUCCESS);

	globus_libc_printf("enabled multicast\n");
    }
    
    result = globus_io_udp_bind(
	          &mc_port,
	          &attr,
	          &handle);
    assert(result == GLOBUS_SUCCESS);
    globus_libc_printf("Binding to %d\n", mc_port);

    result = globus_io_udp_register_recvfrom(
	              &handle,
                      buf,
                      BUF_SIZE,
		      0,
		      globus_l_udp_test_receive_callback,
                      GLOBUS_NULL);
    assert(result == GLOBUS_SUCCESS);

    globus_libc_printf("%s() : waiting for signal\n", myname);
    globus_mutex_lock(&globus_l_io_udp_mutex);
    {
        while(msgs_received < mc_count)
	{
	    globus_libc_printf("a");
            globus_cond_wait(&globus_l_io_udp_cond,
			     &globus_l_io_udp_mutex);
	}
    }
    globus_mutex_unlock(&globus_l_io_udp_mutex);

    result = globus_io_close(&handle);
    assert(result == GLOBUS_SUCCESS);

    globus_cond_destroy(&globus_l_io_udp_cond);
    globus_mutex_destroy(&globus_l_io_udp_mutex);

    globus_libc_printf("%s() : end\n", myname);
}

void print_usage()
{
    globus_libc_printf("globus_io_udp_test_server\n");
    globus_libc_printf("-------------------------\n");
    globus_libc_printf("globus_io_udp_test_server [-h <multicast address> -p <multicast port> -c <count>]\n");
}

static void 
globus_l_udp_test_receive_callback(
    void *                            arg,
    globus_io_handle_t *              handle,
    globus_result_t                   result,
    globus_byte_t *                   buf,
    globus_size_t                     nbytes,
    char *                            host,
    unsigned short                    port)
{
    static int                       count = 0;
    static char *                    myname = "globus_l_udp_test_receive_callback";
    
    msgs_received++;
    globus_libc_printf("%s() : start %d\n", myname, msgs_received);

    globus_libc_printf("%s() : received %d bytes msg = %s\n", 
		       myname, 
                       nbytes,
		       (char *) buf);

    globus_mutex_lock(&globus_l_io_udp_mutex);
    {
        if(msgs_received >= mc_count)
        {
            globus_cond_signal(&globus_l_io_udp_cond);
	}
	else
	{
            result = globus_io_udp_register_recvfrom(
	                  handle,
                          buf,
                          BUF_SIZE,
		          0,
		          globus_l_udp_test_receive_callback,
                          GLOBUS_NULL);
            assert(result == GLOBUS_SUCCESS);
        }
    }
    globus_mutex_unlock(&globus_l_io_udp_mutex);


    globus_libc_printf("%s() : end\n", myname);
}


