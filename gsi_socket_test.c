/*
 * gsi_socket_test
 *
 * Code to test the gsi_socket.c code.
 */

#include "gsi_socket.h"
#include "string_funcs.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

int port = 7563;		/* Default port, arbitrary */
char *host = "localhost";

int do_receive();
int do_transmit();

int
main(int argc,
     char *argv[])
{
    char *myname;
    
    extern char *optarg;
    extern int optind;
    int arg;
    
    int receive_mode = 0;
    int transmit_mode = 0;
    int arg_err = 0;

    int exit_status = 0;
    
    myname = argv[0];
    
    while((arg = getopt(argc, argv, "rt")) != EOF)
    {
	switch(arg) 
	{
	  case 'r':
	    receive_mode = 1;
	    break;
	    
	  case 't':
	    transmit_mode = 1;
	    break;
	}
    }

    if (optind < argc)
    {
	host = argv[optind++];
    }
    
    if (!receive_mode && !transmit_mode)
    {
	fprintf(stderr,
		"%s: Must specify one of -r or -t\n",
		myname);
	arg_err = 1;
    }
    
    if (receive_mode && transmit_mode)
    {
	fprintf(stderr,
		"%s: May specify only one of -r or -t\n",
		myname);
	arg_err = 1;
    }
    
    if (arg_err)
    {
	return 1;
    }
    

    if (receive_mode)
    {
	exit_status = do_receive();
    }
    if (transmit_mode)
    {
	exit_status = do_transmit();
    }

    return exit_status;
}


int
do_receive()
{
    int listen_sock;
    int sock;
    int on = 1;
    struct sockaddr_in sin;
    GSI_SOCKET *gsi_socket;
    char data[2048];
    int len;
    char client_name[256];
    char error_string[1024];
    
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if (listen_sock == -1)
    {
	perror("socket");
	return -1;
    }

    /* Allow reuse of socket */
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port);
    
    if (bind(listen_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
    {
	perror("bind");
	return -1;
    }

    if (listen(listen_sock, 5) < 0)
    {
	perror("listen");
	return -1;
    }
	
    sock = accept(listen_sock, NULL, NULL);
    
    if (sock < 0)
    {
	perror("accept");
	return -1;
    }
    
    close(listen_sock);

    gsi_socket = GSI_SOCKET_new(sock);
    
    if (gsi_socket == NULL)
    {
	perror("GSI_SOCKET_new()");
	return -1;
    }

    if (GSI_SOCKET_authentication_accept(gsi_socket) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error authenticating client: %s\n", error_string);
	return -1;
    }

    if (GSI_SOCKET_get_client_name(gsi_socket,
				   client_name,
				   sizeof(client_name)) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error getting client name: %s\n", error_string);
	return -1;
    }

    printf("Client is : %s\n", client_name);


    if (GSI_SOCKET_read_buffer(gsi_socket, data,
			       sizeof(data)) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error reading: %s\n", error_string);
	return -1;
    }

    printf("Client message: %s\n", data);

    len = my_strncpy(data, "Hello from the server",sizeof(data)) + 1 /* NUL */;
    
    if (GSI_SOCKET_write_buffer(gsi_socket, data, len) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error writing: %s\n", error_string);
	return -1;
    }

    if (GSI_SOCKET_delegation_accept_ext(gsi_socket, data, sizeof(data), NULL) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error accepting delegated credentials: %s\n",
		error_string);
	return -1;
    }

    printf("Accepted delegation: %s\n", data);
    
    GSI_SOCKET_destroy(gsi_socket);
    
    close(sock);

    return 0;
}


int
do_transmit()
{
    int sock;
    struct sockaddr_in sin;
    GSI_SOCKET *gsi_socket;
    struct hostent *host_info;
    char data[2048];
    int len;
    char error_string[1024];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sock == -1)
    {
	perror("socket");
	return -1;
    }
    
    host_info = gethostbyname(host);
    
    if (host_info == NULL)
    {
	fprintf(stderr, "Unknown host \"%s\"\n", host);
	return -1;
    }
    	
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    memcpy(&(sin.sin_addr), host_info->h_addr, sizeof(sin.sin_addr));
    sin.sin_port = htons(port);
    
    if (connect(sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
    {
	perror("connect");
	return -1;
    }	
    
    gsi_socket = GSI_SOCKET_new(sock);
    
    if (gsi_socket == NULL)
    {
	perror("GSI_SOCKET_new()");
	return -1;
    }
    
    if (GSI_SOCKET_authentication_init(gsi_socket) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error authenticating: %s\n", error_string);
	return -1;
    }

    len = my_strncpy(data, "Hello server!", sizeof(data)) + 1 /* NUL */;
    
    if (GSI_SOCKET_write_buffer(gsi_socket, data, len) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error writing: %s\n", error_string);
	return -1;
    }

    if (GSI_SOCKET_read_buffer(gsi_socket, data,
			       sizeof(data)) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error reading: %s\n", error_string);
	return -1;
    }

    printf("Server message: %s\n", data);

    if (GSI_SOCKET_delegation_init_ext(gsi_socket, NULL,
				       3600 /* lifetime */,
				       NULL /* passphrase */) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error delegating credentials: %s\n", error_string);
	return -1;
    }

    printf("Delegated credentials\n");
    
    GSI_SOCKET_destroy(gsi_socket);
    
    close(sock);
    
    return 0;
}

