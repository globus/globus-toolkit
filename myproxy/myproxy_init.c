/*
 * myproxy-init
 *
 * Client program to delegate a credential to a myproxy-server
 */

#include "myproxy.h"
#include "gnu_getopt.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>


/*
static char usage_short[] = "\
Usage: %s [-help] [-s server] [-p port] [-t lifetime] [-l username] ...\n\
Try `%s --help' for more information.\n"; 
*/


static char usage[] = \
"\n"\
"Syntax: myproxy-init [-h hours] [-l username] ...\n"\
"        myproxy-init [--usage|--help] [-v|--version]\n"\
"\n"\
"    Options\n"\
"    --help | --usage            Displays usage\n"\
"    -v | -version             Displays version\n"\
"    -l | -username <username> Specifies the username for the delegated proxy\n"\
"    -h | -hours    <hours>    Specifies the lifetime of the delegated proxy\n"\
"    -s | -pshost   <hostname> Specifies the hostname of the myproxy-server\n"\
"    -p | -psport   #          Specifies the port of the myproxy-server\n"\
"\n";

struct option long_options[] =
{
  {"help",             no_argument, NULL, 'u'},
  {"pshost",   	 required_argument, NULL, 's'},
  {"psport",     required_argument, NULL, 'p'},
  {"hours",      required_argument, NULL, 'h'},
  {"usage",            no_argument, NULL, 'u'},
  {"username",   required_argument, NULL, 'l'},
  {"version",          no_argument, NULL, 'v'},
  {0, 0, 0, 0}
};

static char short_options[] = "us:p:t:h:v";

static char version[] =
"myproxy-init version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";


/* Function declarations */
int  init_arguments(int argc, char *argv[], 
		    myproxy_socket_attrs_t *attrs, myproxy_request_t *request);
int  grid_proxy_init(int hours, const char *proxyfile);
int  grid_proxy_destroy(const char *proxyfile);
int  read_passphrase(char *passphrase, const int passlen);


int
main(int argc, char *argv[]) 
{    
    int rc;
    int is_err = 0;
    char *username; 
    char error_string[1024];
    char proxyfile[64];
    char request_buffer[1024], response_buffer[1024];
    int requestlen, responselen;

    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;
    
    socket_attrs = malloc(sizeof(*socket_attrs));
    client_request = malloc(sizeof(*client_request));
    server_response = malloc(sizeof(*server_response));

    /* setup defaults */
    client_request->version = malloc(strlen(MYPROXY_VERSION) + 1);
    strcpy(client_request->version, MYPROXY_VERSION);
    client_request->command_type = MYPROXY_PUT_PROXY;

    username = getenv("LOGNAME");
    client_request->username = malloc(strlen(username)+1);
    strcpy(client_request->username, username);

    client_request->hours    = MYPROXY_DEFAULT_HOURS;
 
    socket_attrs->psport = MYPROXYSERVER_PORT;
    socket_attrs->pshost = malloc(strlen(MYPROXYSERVER_HOST) + 1);
    sprintf(socket_attrs->pshost, "%s", MYPROXYSERVER_HOST);


    /* Initialize client arguments and create client request object */
    if (init_arguments(argc, argv, socket_attrs, client_request) < 0) {
        fprintf(stderr, usage);
        exit(1);
    }

    /* Create a proxy by running [grid-proxy-init] */
    sprintf(proxyfile, "%s.%s", MYPROXY_DEFAULT_PROXY, client_request->username);
    if (grid_proxy_init(client_request->hours, proxyfile) != 0) {
        fprintf(stderr, "Program grid_proxy_init failed\n");
        exit(1);
    }

    /* Allow user to provide a passphrase */
    if (read_passphrase(client_request->passphrase, MAX_PASS_LEN+1) < 0) {
        fprintf(stderr, "error in myproxy_read_passphrase()\n");
        exit(1);
    }
    
    /* Set up client socket attributes */
    if (myproxy_init_client(socket_attrs) < 0) {
        fprintf(stderr, "error in myproxy_init_client()\n");
        exit(1);
    }

    /* Authenticate client to server */
    if (myproxy_authenticate_init(socket_attrs, proxyfile) < 0) {
        fprintf(stderr, "error in myproxy_authenticate_init()\n");
        exit(1);
    }

    /* Delegate credentials to server  */
    if (myproxy_init_delegation(socket_attrs, proxyfile) < 0) {
        fprintf(stderr, "error in myproxy_delegate_proxy()\n");
        exit(1);
    }

    /* Delete proxy file */
    if (grid_proxy_destroy(proxyfile) != 0) {
        fprintf(stderr, "Program grid_proxy_destroy failed\n");
        exit(1);
    }

    /* Serialize client request object */
    requestlen = myproxy_serialize_request(client_request, 
                                           request_buffer, sizeof(request_buffer));
    
    if (requestlen < 0) {
        fprintf(stderr, "error in myproxy_serialize_request()\n");
        exit(1);
    }

    /* Send request to the myproxy-server */
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
        fprintf(stderr, "error in myproxy_send_request()\n");
        exit(1);
    }

    /* Receive a response from the server */
    responselen = myproxy_recv(socket_attrs, 
                               response_buffer, sizeof(response_buffer));
    if (responselen < 0) {
        fprintf(stderr, "error in myproxy_recv_response()\n");
        exit(1);
    }

    /* Make a response object from the response buffer */
    if (myproxy_deserialize_response(server_response, response_buffer, responselen) < 0) {
      fprintf(stderr, "error in myproxy_deserialize_response()\n");
      exit(1);
    }

    /* Check version */
    if (strcmp(server_response->version, MYPROXY_VERSION) != 0) {
      fprintf(stderr, "Invalid version number received from server\n");
      is_err = 1;
    } 

    /* Check response */
    switch(server_response->response_type) {
        case MYPROXY_ERROR_RESPONSE:
            strcat(error_string, server_response->error_string);
            is_err = 1;
            break;
        case MYPROXY_OK_RESPONSE:
            break;
        default:
            strcat(error_string, "Invalid response type received.\n");
            is_err = 1;
            break;
    }

    if (is_err) {
        fprintf(stderr, "%s", error_string);
    }
    
    /* free memory allocated */
    myproxy_destroy(socket_attrs, client_request, server_response);

    exit(0);
}

int 
init_arguments(int argc, 
		       char *argv[], 
		       myproxy_socket_attrs_t *attrs,
		       myproxy_request_t *request) 
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
	    
	case 'h': 	/* Specify lifetime in hours */
	    request->hours = atoi(gnu_optarg);
	    break;      
	case 's': 	/* pshost name */
	    attrs->pshost = malloc(strlen(gnu_optarg) + 1);
	    strcpy(attrs->pshost, gnu_optarg); 
	    break;
	case 'p': 	/* psport */
	    attrs->psport = atoi(gnu_optarg);
	    break;
	case 'u': 	/* print help and exit */
	    fprintf(stderr, usage);
	    exit(1);
	    break;
	case 'l':	/* username */
	    request->username = malloc(strlen(gnu_optarg) + 1);
	    strcpy(request->username, gnu_optarg); 
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

    printf("Your username to access the myproxy-server is: %s\n", request->username);

    return arg_error;
}

int
grid_proxy_init(int hours, const char *proxyfile) {

  int rc;
  char command[128];
  
  assert(proxyfile != NULL);

  sprintf(command, "grid-proxy-init -hours %d -out %s", hours, proxyfile);
  rc = system(command);

  return rc;
}

int
grid_proxy_destroy(const char *proxyfile) {
  
    int rc;
    char command[128], file[128];

    assert(proxyfile != NULL);

    sprintf(command, "grid-proxy-destroy %s", proxyfile);
    rc = system(command);

    return rc;
}

int
read_passphrase(char *passphrase, const int passlen) 
{
    int i;
    char pass[MAX_PASS_LEN+1];
    int done = 0;


    /* Get user's passphrase */    
    do {
	printf("Enter password to access myproxy-server:\n");
	if (!(fgets(pass, sizeof(pass), stdin))) {
	  fprintf(stderr,"Failed to read password from stdin\n");   
	  return -1;
	}	
	i = strlen(pass);
	if ((i < MIN_PASS_LEN) || (i > MAX_PASS_LEN)) {
	  printf("Password must be between 5 and 10 characters\n");
	} else {
	  done = 1;
	}
    } while (!done);
    
    if (pass[i-1] == '\n') {
      pass[i-1] = '\0';
    }
    strncpy(passphrase, pass, passlen);
    return 0;
}
    





