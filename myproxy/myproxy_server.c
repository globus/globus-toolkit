/*
 * myproxy-server
 *
 * program to store user's delegated credentials for use in a portal
 */

#include "myproxy.h"
#include "gnu_getopt.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>


static char usage[] = \
"\n"\
"Syntax: myproxy-server [-p port#] [-c config-file] ...\n"\
"        myproxy-server [--usage|--help] [-v|--version]\n"\
"\n"\
"    Options\n"\
"    --help | --usage        Displays usage\n"\
"    -v | -version           Displays version\n"\
"    -c | -config            Specifies configuration file to use\n"\
"    -p | -port   #          Specifies the port to run on\n"\
"\n";

struct option long_options[] =
{
  {"help",             no_argument, NULL, 'u'},
  {"port",       required_argument, NULL, 'p'},
  {"config",           no_argument, NULL, 'c'},       
  {"usage",            no_argument, NULL, 'u'},
  {"version",          no_argument, NULL, 'v'},
  {0, 0, 0, 0}
};

static char short_options[] = "uc:p:v";

static char version[] =
"myproxy-server version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";


/* Function declarations */
int  init_arguments(int argc, char *argv[], myproxy_socket_attrs_t *attrs);


int
main(int argc, char *argv[]) 
{    
    int rc, is_err;
    char error_string[1024];
    char client_name[1024];
    char client_buffer[1024], server_buffer[1024];
    int requestlen, responselen;
    char proxyfile[64];

    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;
    
    socket_attrs = malloc(sizeof(*socket_attrs));
    client_request = malloc(sizeof(*client_request));
    server_response = malloc(sizeof(*server_response));

    server_response->version = malloc(strlen(MYPROXY_VERSION) + 1);
    strcpy(server_response->version, MYPROXY_VERSION);   
    socket_attrs->psport = MYPROXYSERVER_PORT;

    if (init_arguments(argc, argv, socket_attrs) < 0) {
        fprintf(stderr, usage);
        exit(1);
    }

    /* Set up server socket attributes */
    if (myproxy_init_server(socket_attrs) < 0) {
        fprintf(stderr, "error in myproxy_init_server()\n");
        exit(1);
    }

    /* Authenticate server to client and get DN of client */
    if (myproxy_authenticate_accept(socket_attrs, client_name, sizeof(client_name)) < 0) {
        fprintf(stderr, "error in myproxy_authenticate_accept()\n");
        exit(1);
    } 
    
    /* Accept delegated credentials from client */
    if (myproxy_accept_delegation(socket_attrs, proxyfile, sizeof(proxyfile)) < 0) {
        fprintf(stderr, "error in myproxy_accept_delegation()\n");
        exit(1);
    }
    
    /* Receive client request */
    requestlen = myproxy_recv(socket_attrs, 
                               client_buffer, sizeof(client_buffer));
    if (requestlen < 0) {
        fprintf(stderr, "error in myproxy_recv_response()\n");
        exit(1);
    }

    /* Deserialize client request */
    if (myproxy_deserialize_request(client_buffer, requestlen, 
                                    client_request) < 0) {
        fprintf(stderr, "error in myproxy_deserialize_request()\n");
        exit(1);
    }
    

    /* Check client version */
    if (strcmp(client_request->version, MYPROXY_VERSION) != 0) {
        strcat(error_string, "Invalid version number received.\n");
        is_err = 1;
    }

    /* Handle client request */
    switch (client_request->command_type) {
    case MYPROXY_GET_PROXY:
        rc = get_proxy(client_request, server_response);
        if (rc < 0) 
          is_err = 1;
        break;
    case MYPROXY_PUT_PROXY:
        rc = put_proxy(client_request, server_response);
        if (rc < 0)
          is_err = 1;
        break;
    case MYPROXY_INFO_PROXY:
        rc = info_proxy(client_request, server_response);
        if (rc < 0)
          is_err = 1;
        break;
    case MYPROXY_DESTROY_PROXY:
        rc = destroy_proxy(client_request, server_response);
        if (rc < 0)
          is_err = 1;
        break;
    default:
        strcat(error_string, "Invalid request command received.\n");
        is_err = 1;
    }
    
    responselen = myproxy_serialize_response(server_response, 
                                         server_buffer, sizeof(server_buffer));
    
    if (responselen < 0) {
	    fprintf(stderr, "error in myproxy_serialize_response()\n");
        exit(1);
    }

    if (myproxy_send(socket_attrs, server_buffer, responselen) < 0) {
	    fprintf(stderr, "error in myproxy_send()\n");
        exit(1);
    } 
  
    myproxy_destroy(socket_attrs, client_request, server_response);

    exit(0);
}

int 
init_arguments(int argc, char *argv[], myproxy_socket_attrs_t *attrs) 
{   
    extern char *gnu_optarg;
    extern int gnu_optind;

    int arg;
    int arg_error = 0;

    while((arg = getopt_long(argc, argv, short_options, 
			     long_options, NULL)) != EOF) 
    {
	switch(arg) 
	{
	case 'p': 	/* port */
	    attrs->psport = atoi(gnu_optarg);
	    break;
	case 'u': 	/* print help and exit */
	    fprintf(stderr, usage);
	    exit(1);
	    break;
	case 'c':
	  /* XXX Need to add code */
	    break;
	case 'v': /* print version and exit */
	    fprintf(stderr, version);
	    exit(1);
	    break;
        default: /* ignore unknown */ 
	    arg_error = -1;
	    break;	
        }
    }

    return arg_error;
}

int get_proxy(const myproxy_request_t *request, myproxy_response_t *response) {
  return 0;
}

int put_proxy(const myproxy_request_t *request, myproxy_response_t *response) {
  return 0;
}

int info_proxy(const myproxy_request_t *request, myproxy_response_t *response) {
  return 0;
}

int destroy_proxy(const myproxy_request_t *request, myproxy_response_t *response) {
  return 0;
}
