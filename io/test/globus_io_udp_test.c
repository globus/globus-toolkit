#include "globus_io.h"
#include <stdlib.h>
#include <assert.h>

#define BUF_SIZE   1024

enum globus_io_udp_test_error_codes
{
    GLOBUS_IO_UDP_NO_ERROR,
    GLOBUS_IO_UDP_BIND_FAILED,
    GLOBUS_IO_UDP_REGISTER_RECV_FAILED,
    GLOBUS_IO_UDP_UNICAST_DEAD_LOCK,
    GLOBUS_IO_UDP_UNICAST_RECIEVE_FAILED,
    GLOBUS_IO_UDP_SENDTO_FAILED,
    GLOBUS_IO_UDP_USAGE_ERROR,
    GLOBUS_IO_UDP_CLOSE_FAILED,
    GLOBUS_IO_UDP_MULTICAST_JOIN_FAILED,
    GLOBUS_IO_UDP_IO_ATTR_ERROR
};

static int
globus_l_io_udp_mc_listen(
    globus_io_handle_t *     mc_handle,
    globus_io_attr_t *       mc_attr,
    char *                   mc_host,
    unsigned short           mc_port);	

static int 
unicast_receive_multicast_send(
    unsigned short                   port,
    char *                           mc_host,
    unsigned short                   mc_port,
    char *                           msg);

static int 
unicast_send_multicast_receive(
    char *                           host,
    unsigned short                   port,
    char *                           mc_host,
    unsigned short                   mc_port,
    char *                           msg);

static int
globus_l_udp_test_recv(
    globus_io_handle_t *             handle,
    unsigned short                   port,
    globus_io_attr_t *               attr);

int
globus_l_udp_test_send_msg(
    char *                      host,
    unsigned short              port,
    globus_io_attr_t *          attr,
    char *                      msg);

static int globus_io_udp_receive_wait();
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

static int                   msg_count = 1;
static int                   msgs_received = 0;
static globus_cond_t         globus_l_io_udp_cond;
static globus_mutex_t        globus_l_io_udp_mutex;

/*
 * Function:	main
 *
 * Description:	
 *		
 * Parameters:	
 *
 *   s  -   server
 *   c  -   client
 *   l  -   listener
 *   m  -   message
 *   n  -   number of messages to send or receive
 *   h  -   unicast host
 *   p  -   unicast port
 *   i  -   multicast host
 *   d  -   multicast port
 *
 * Returns:	
 */
int
main(int argc, char **argv)
{
    int					rc;
    char                                c;
    globus_bool_t                       listener = GLOBUS_FALSE;
    globus_bool_t                       server   = GLOBUS_FALSE;
    char *                              host = GLOBUS_NULL;
    unsigned short                      port = 0;
    char *                              mc_host = GLOBUS_NULL;
    unsigned short                      mc_port = 0;
    globus_io_handle_t                  mc_handle;
    globus_io_attr_t                    mc_attr;
    char **                             save_argv;
    int                                 save_argc;
    char *                              msg = "Testing UDP";

    save_argv = argv;
    save_argc = argc;


    globus_module_activate(GLOBUS_IO_MODULE);


    /* get parameters */
    while (( c = getopt(argc, argv, "lscm:n:h:p:i:d:")) != EOF)
    {
       switch(c)
       {
	   case 'l':
	       listener = GLOBUS_TRUE;
	       break;
	   
	   case 's':
	       server = GLOBUS_TRUE;
	       break;
	   
	   case 'm':
	       msg = optarg;
               break;

	   case 'n':
	       msg_count = atoi(optarg);
	       break;

	   case 'h':
	       host = optarg;
               break;

	   case 'p':
	       port = atoi(optarg);
	       break;

	   case 'i':
	       mc_host = optarg;
               break;

	   case 'd':
	       mc_port = atoi(optarg);
               break;
       }
    }

    if(listener)
    {
	thread_print("Running as a multicast listener\n");
        rc = globus_l_io_udp_mc_listen(&mc_handle, &mc_attr, mc_host, mc_port);
	globus_io_udp_receive_wait();
    }
    else if(server)
    {
	thread_print("Running as a unicast_send_multicast_receive server\n");
        rc = unicast_send_multicast_receive(
		host,
		port,
                mc_host,
		mc_port,
		msg);
    }
    else
    {
	thread_print("Running as a unicast_receive_multicast_send client\n");
        rc = unicast_receive_multicast_send(
		port,
                mc_host,
		mc_port,
		msg);
    }

    globus_module_deactivate(GLOBUS_IO_MODULE);

    return rc;
}
/* main() */

static int
unicast_receive_multicast_send(
    unsigned short                   port,
    char *                           mc_host,
    unsigned short                   mc_port,
    char *                           msg)
{
    globus_result_t			result;
    globus_io_handle_t                  handle;
    globus_io_attr_t			attr;
    char                                c;
    char *                              myname = "unicast_receive_multicast_send";
    int                                 rc;


    if(mc_port == 0 ||
       mc_host == GLOBUS_NULL)
    {
        thread_print("%s() : ERROR : failed give multicast address and port\n", myname);
	print_usage();
	return(GLOBUS_IO_UDP_USAGE_ERROR);
    }


    /* set up to receive unicast */
    result = globus_io_udpattr_init(&attr);
    if(result != GLOBUS_SUCCESS)
    {
        thread_print("%s() : ERROR : globus_io_udpattr_init() failed\n", myname);
	return(GLOBUS_IO_UDP_IO_ATTR_ERROR);
    }
    /* register receive */
    rc = globus_l_udp_test_recv(&handle, port, &attr);
    if(rc != 0)
    {
        return rc;
    }
    /* wait for messages */
    globus_io_udp_receive_wait();
    /* close the handle */
    result = globus_io_close(&handle);
    if(result != GLOBUS_SUCCESS)
    {
        thread_print("%s(): error closing unicast handle\n", myname);  
	return(GLOBUS_IO_UDP_UNICAST_DEAD_LOCK);
    }
    
    /* set up to send multicast */
    result = globus_io_udpattr_init(&attr);
    if(result != GLOBUS_SUCCESS)
    {
        thread_print("%s() : ERROR : globus_io_udpattr_init() failed\n", myname);
	return(GLOBUS_IO_UDP_IO_ATTR_ERROR);
    }

    
    result = globus_io_attr_set_udp_multicast_membership(
		    &attr,
                    mc_host,
		    INADDR_ANY);
    if(result != GLOBUS_SUCCESS)
    {
        thread_print("%s(): globus_io_attr_set_udp_multicast_membership() failed\n",
		     myname);
        return(GLOBUS_IO_UDP_MULTICAST_JOIN_FAILED);
    }
    rc = globus_l_udp_test_send_msg(
	     mc_host,
             mc_port,
	     &attr,
	     msg);
    if(rc != 0)
    {
        return rc;
    }
    globus_io_udp_receive_wait();

    return GLOBUS_TRUE;    
}

static int
unicast_send_multicast_receive(
    char *                           host,
    unsigned short                   port,
    char *                           mc_host,
    unsigned short                   mc_port,
    char *                           msg)
{
    globus_result_t			result;
    globus_io_handle_t                  handle;
    globus_io_attr_t			attr;
    globus_io_handle_t                  mc_handle;
    globus_io_attr_t			mc_attr;
    static char *                       myname = "unicast_send_multicast_receive";
    int                                 rc;

    thread_print("%s() : start\n", myname);
    if(mc_port == 0 ||
       mc_host == GLOBUS_NULL ||
       host == GLOBUS_NULL ||
       port == 0)
    {
        thread_print("%s() : ERROR : failed give multicast address and port\n", myname);
	print_usage();
	return(GLOBUS_IO_UDP_USAGE_ERROR);
    }


    result = globus_io_udpattr_init(&attr);
    if(result != GLOBUS_SUCCESS)
    {
        thread_print("%s() : ERROR : globus_io_udpattr_init() failed\n", myname);
	return(GLOBUS_IO_UDP_IO_ATTR_ERROR);
    }
    /* init multicast */

    msgs_received = 0;
    globus_l_io_udp_mc_listen(&mc_handle, &mc_attr, mc_host, mc_port);

    thread_print("sending %s to %s:%d\n", msg, host, port);
    rc = globus_l_udp_test_send_msg(
	     host,
             port,
	     &attr,
	     msg);
    if(rc != 0)
    {
        return rc;
    }

    globus_io_udp_receive_wait();

    return GLOBUS_TRUE;
}

static int
globus_l_io_udp_mc_listen(
globus_io_handle_t *     mc_handle,
globus_io_attr_t *       mc_attr,
char *                   mc_host,
unsigned short           mc_port)
{
    globus_result_t      result;
    char *               myname = "globus_l_io_udp_mc_listen";
    int                  rc;

    result = globus_io_udpattr_init(mc_attr);
    if(result != GLOBUS_SUCCESS)
    {
        thread_print("%s() : ERROR : globus_io_udpattr_init() failed\n", myname);
	return(GLOBUS_IO_UDP_IO_ATTR_ERROR);
    }

    result = globus_io_attr_set_udp_multicast_membership(
		    mc_attr,
                    mc_host,
		    INADDR_ANY);
    if(result != GLOBUS_SUCCESS)
    {
        thread_print("%s(): globus_io_attr_set_udp_multicast_membership() failed\n",
		     myname);
        return(GLOBUS_IO_UDP_MULTICAST_JOIN_FAILED);
    }
    /* register receive */
    rc = globus_l_udp_test_recv(mc_handle, mc_port, mc_attr);
    /* send unicast */

    return GLOBUS_TRUE;
}

static int
globus_l_udp_test_recv(
    globus_io_handle_t *             handle,
    unsigned short                   port,
    globus_io_attr_t *               attr)
{
    globus_result_t			result;
    globus_byte_t  			buf[BUF_SIZE];
    char *                              from_host;
    unsigned short                      from_port;
    globus_size_t			from_bytes;
    static char *                       myname = "globus_l_udp_test_recv";

    globus_cond_init(&globus_l_io_udp_cond, 
		     GLOBUS_NULL);
    globus_mutex_init(&globus_l_io_udp_mutex,
		      GLOBUS_NULL);
    result = globus_io_udp_bind(
	          &port,
	          attr,
	          handle);
    if(result != GLOBUS_SUCCESS)
    {
	thread_print("%s(): ERROR: globus_io_udp_bind failed: port=%d\n", myname, port);

	return(GLOBUS_IO_UDP_BIND_FAILED);
    }

    globus_libc_printf("%s(): Binding to %d\n", myname, port);

    result = globus_io_udp_register_recvfrom(
	              handle,
                      buf,
                      BUF_SIZE,
		      0,
		      globus_l_udp_test_receive_callback,
                      GLOBUS_NULL);
    if(result != GLOBUS_SUCCESS)
    {
	thread_print("ERROR: globus_io_udp_bind failed: port=%d\n", port);

	return(GLOBUS_IO_UDP_REGISTER_RECV_FAILED);
    }

    return GLOBUS_TRUE;
}

globus_io_udp_receive_wait()
{
    static char *                       myname = "globus_io_udp_receive_wait";
    globus_result_t			result;

    globus_libc_printf("%s() : waiting for signal\n", myname);
    globus_mutex_lock(&globus_l_io_udp_mutex);
    {
	int test_ctr = 0;

        while(msgs_received < msg_count)
	{
            globus_cond_wait(&globus_l_io_udp_cond,
			     &globus_l_io_udp_mutex);

            test_ctr++;
	    if(test_ctr > 1024)
	    {
                thread_print("%s(): ERROR: waiting for %d msgs, received %d.  Probable deadlock\n", 
			     myname, 
			     msg_count, 
			     msgs_received);

		return(GLOBUS_IO_UDP_UNICAST_DEAD_LOCK);
	    }
	}
    }
    globus_mutex_unlock(&globus_l_io_udp_mutex);


    globus_cond_destroy(&globus_l_io_udp_cond);
    globus_mutex_destroy(&globus_l_io_udp_mutex);

    globus_libc_printf("%s() : end\n", myname);
  
    return GLOBUS_TRUE;
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
        if(msgs_received >= msg_count)
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
            if(result != GLOBUS_SUCCESS)
            {
                thread_print("%s(): ERRROR: globus_io_udp_register_recvfrom() failed\n",
			     myname);
                exit(GLOBUS_IO_UDP_UNICAST_RECIEVE_FAILED);
	    }
        }
    }
    globus_mutex_unlock(&globus_l_io_udp_mutex);


    globus_libc_printf("%s() : end\n", myname);
}


int
globus_l_udp_test_send_msg(
    char *                      host,
    unsigned short              port,
    globus_io_attr_t *          attr,
    char *                      msg)
{
    unsigned short			l_port=0;
    globus_result_t			result;
    globus_io_handle_t			handle;
    globus_size_t			nbytes;
    static char *                       myname = "globus_l_udp_test_send_msg";

    globus_libc_printf("Binding to %d\n", port);

    result = globus_io_udp_bind(
	            &l_port,
	            attr,
	            &handle);
    if(result != GLOBUS_SUCCESS)
    {
        thread_print("%s(): ERROR: globus_io_udp_sendto() failed\n", myname);
	return(GLOBUS_IO_UDP_BIND_FAILED);
    }

    globus_libc_printf("Sending message \"%s\" to %s:%d\n", msg, host, port);
    result = globus_io_udp_sendto(
                   &handle,
	           (globus_byte_t *)msg,
	           0,
	           strlen(msg) + 1,
                   host,
	           port,
                   &nbytes);
    if(result != GLOBUS_SUCCESS)
    {
        thread_print("%s(): ERROR: globus_io_udp_sendto() failed\n", myname);
	return(GLOBUS_IO_UDP_SENDTO_FAILED);
    }

    result = globus_io_close(&handle);
    if(result != GLOBUS_SUCCESS)
    {
        thread_print("%s(): ERROR: globus_io_udp_close() failed\n", myname);
	return(GLOBUS_IO_UDP_CLOSE_FAILED);
    }

    thread_print("-->%d bytes sent\n", nbytes);
    thread_print("test1 end()\n");
    
    return(GLOBUS_IO_UDP_NO_ERROR);
}


void print_usage()
{
    globus_libc_printf("globus_io_udp_test_server\n");
    globus_libc_printf("-------------------------\n");
    globus_libc_printf("options:\n");
    globus_libc_printf("-[l/s/c] [l:multicast listener s: c: ]\n");
    globus_libc_printf("-i <multicast host>\n");
    globus_libc_printf("-d <multicast port>\n");
    globus_libc_printf("-h <uniicast host>\n");
    globus_libc_printf("-p <uniicast port>\n");
    globus_libc_printf("-m <message>\n");
    globus_libc_printf("-n <number of messages>\n");
}

