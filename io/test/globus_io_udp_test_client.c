#include "globus_io.h"
#include <stdlib.h>
#include <assert.h>

void test1(int argc, char **argv);

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
    unsigned short			port=0;
    unsigned short			l_port=0;
    char *                              msg = "Testing UDP";
    int                                 buf_size = 1024;
    char *                              host;
    globus_size_t			nbytes;
    char                                c;
    globus_bool_t                       mc_enabled = GLOBUS_FALSE;
    char *                              mc_interface = INADDR_ANY;

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

    thread_print("-->%d bytes sent\n", nbytes);
    thread_print("test1 end()\n");
}
