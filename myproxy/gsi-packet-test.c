/*
 * gsi-packet-test
 *
 * Code to test the gsi-packet.c code.
 */

#include "gsi-packet.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

int port = 7563;		/* Default port, arbitrary */
char *host = "localhost";

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
	exit(1);
    }
    

    if (receive_mode)
    {
	exit_status = do_receive();
    }
    if (transmit_mode)
    {
	exit_status = do_transmit();
    }

    exit(exit_status);
}


int
do_receive()
{
    int listen_sock;
    int sock;
    int on = 1;
    struct sockaddr_in sin;
    GSIPACKET *packet;
    char **strings;
    int strings_index = 0;
    
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
    
    /* XXX Put gss init sec context code here */

    packet = GSIPACKET_read(NULL, sock);
    
    if (packet == NULL)
    {
	perror("read");
	return -1;
    }
    
    strings = GSIPACKET_get_strings(packet);
    
    if (strings == NULL)
    {
	fprintf(stderr, "No data received from transmitter\n");
	return -1;
    }

    while (strings[strings_index] != NULL)
    {
	printf("%s\n", strings[strings_index]);
	strings_index++;
    }

    GSIPACKET_destroy(packet);
    
    packet = GSIPACKET_new(NULL);
    
    if (packet == NULL)
    {
	perror("Creating GSIPACKET");
	return -1;
    }
    
    GSIPACKET_add_string(packet, "Test successful");
    GSIPACKET_add_string(packet, "Bye");
    GSIPACKET_write(packet, sock);
    GSIPACKET_destroy(packet);
    
    close(sock);

    return 0;
}


int
do_transmit()
{
    int sock;
    struct sockaddr_in sin;
    GSIPACKET *packet;
    char **strings;
    int strings_index = 0;
    struct hostent *host_info;
    
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
    
    /* XXX Do GSI auth here */

    packet = GSIPACKET_new(NULL);
    GSIPACKET_add_string(packet, "Hello");
    GSIPACKET_add_string(packet, "This is a test");
    GSIPACKET_write(packet, sock);
    GSIPACKET_destroy(packet);
    
    packet = GSIPACKET_read(NULL, sock);
    
    if (packet == NULL)
    {
	perror("Reading packet");
	return -1;
    }
    
    strings = GSIPACKET_get_strings(packet);
    
    if (strings == NULL)
    {
	fprintf(stderr, "No data received from receiver\n");
	return -1;
    }

    while (strings[strings_index] != NULL)
    {
	printf("%s\n", strings[strings_index]);
	strings_index++;
    }

    GSIPACKET_destroy(packet);
    
    close(sock);
    
    return 0;
}

