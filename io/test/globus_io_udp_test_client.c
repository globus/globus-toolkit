#include "globus_io.h"
#include <stdlib.h>
#include <assert.h>

static globus_cond_t         globus_l_io_udp_cond;
static globus_mutex_t        globus_l_io_udp_mutex;
static globus_bool_t         globus_l_done = GLOBUS_FALSE;

void test1(int argc, char **argv);

static void
globus_l_udp_test_receivev_callback(
    void *                              arg,
    globus_io_handle_t *                handle,
    globus_result_t                     result,
    struct iovec *                      iov,
    int                                 iovc,
    globus_size_t                       nbytes_recvd,
    const char *                        host,
    unsigned short                      port)
{
    globus_mutex_lock(&globus_l_io_udp_mutex);
    {
        globus_libc_printf("Received %s:%s\n", 
            (char *)iov[0].iov_base,
            (char *)iov[1].iov_base);

        globus_l_done = GLOBUS_TRUE;
        globus_cond_signal(&globus_l_io_udp_cond);
    }
    globus_mutex_unlock(&globus_l_io_udp_mutex);
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
    globus_module_activate(GLOBUS_IO_MODULE);

    globus_cond_init(&globus_l_io_udp_cond, NULL);
    globus_mutex_init(&globus_l_io_udp_mutex, NULL);

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
    unsigned short			port=0;
    unsigned short			l_port=0;
    char *                              msg = "Testing UDP";
    char *                              host;
    globus_size_t			nbytes;
    int                                 c;
    globus_bool_t                       mc_enabled = GLOBUS_FALSE;
    char *                              mc_interface = INADDR_ANY;
    struct iovec                        iov[2];

    setbuf(stdout, NULL);
    
    globus_io_udpattr_init(&attr);

    while (( c = getopt(argc, argv, "mh:p:")) != EOF)
    {
       switch(c)
       {
	   case 'h':
               host = optarg;
	       mc_interface = INADDR_ANY;
               break;
	   case 'p':
	       port = atoi(optarg);
	       break;
	   case 'm':
	       mc_enabled = GLOBUS_TRUE;
	       break;
       }
    }

    /* set up attribute for multicast */
    if(mc_enabled)
    {
        result = globus_io_attr_set_udp_multicast_membership(
						    &attr,
						    host,
						    mc_interface);
        assert(result == GLOBUS_SUCCESS);
        globus_libc_printf("enabled multicast\n");
    }

    globus_libc_printf("Binding to %d\n", port);

    result = globus_io_udp_bind(
	            &l_port,
	            &attr,
	            &handle);
    assert(result == GLOBUS_SUCCESS);

    globus_libc_printf("Sending message \"%s\" to %s:%d\n", msg, host, port);
    result = globus_io_udp_sendto(
                   &handle,
	           (globus_byte_t *)msg,
	           0,
	           strlen(msg) + 1,
                   host,
	           port,
                   &nbytes);
    assert(result == GLOBUS_SUCCESS);

    iov[0].iov_len = 4;
    iov[0].iov_base = globus_malloc(iov[0].iov_len);
    iov[1].iov_len = 5;;
    iov[1].iov_base = globus_malloc(iov[1].iov_len);
    result = globus_io_udp_register_recvfromv(
                &handle,
                iov,
                2,    
                0,
                globus_l_udp_test_receivev_callback,
                GLOBUS_NULL);

    globus_mutex_lock(&globus_l_io_udp_mutex);
    {
        while(!globus_l_done)
        {
            globus_cond_wait(&globus_l_io_udp_cond, &globus_l_io_udp_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_io_udp_mutex);

    thread_print("-->%d bytes sent\n", nbytes);
    thread_print("test1 end()\n");
}
