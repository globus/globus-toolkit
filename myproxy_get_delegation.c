/*
 * myproxy-get-delegation
 *
 * Webserver program to retrieve a delegated credential from a myproxy-server
 */

#include "myproxy.h"
#include "gnu_getopt.h"
#include "version.h"

#include <stdio.h>
#include <stdlib.h>


/*
static char usage_short[] = "\
Usage: %s [-help] [-s server] [-p port] [-t lifetime] [-l username] ...\n\
Try `%s --help' for more information.\n"; 
*/


static char usage[] = \
"\n"\
"Syntax: myproxy-get-delegation [-h hours] [-l username] ...\n"\
"        myproxy-get-delegation [--usage|--help] [-v|--version]\n"\
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
"myproxy-get-delegation version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";


/* Function declarations */
int  init_arguments(int argc, char *argv[], 
		    myproxy_socket_attrs_t *attrs, myproxy_request_t *request);
int  read_passphrase(char *passphrase, const int passlen);


int
main(int argc, char *argv[]) 
{    
    int rc;
    char request_buffer[1024], response_buffer[1024];
    int requestlen, responselen;
    char proxyfile[64];

    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *client_response;
    
    socket_attrs = malloc(sizeof(*socket_attrs));
    client_request = malloc(sizeof(*client_request));
    client_response = malloc(sizeof(*client_response));

    client_request->version = malloc(strlen(MYPROXY_VERSION) + 1);
    strcpy(client_request->version, MYPROXY_VERSION);
    client_request->command = (char *)malloc(strlen(MYPROXY_PUT_COMMAND) + 1);
    sprintf(client_request->command, "%s", MYPROXY_PUT_COMMAND);

    if (init_arguments(argc, argv, socket_attrs, client_request) < 0) {
        fprintf(stderr, usage);
	exit(1);
    }

    if (read_passphrase(client_request->passphrase, MAX_PASS_LEN+1) < 0) {
	fprintf(stderr, "error in myproxy_read_passphrase()\n");
	exit(1);
    }
    
    if (myproxy_init_client(socket_attrs) < 0) {
	fprintf(stderr, "error in myproxy_init_client()\n");
	exit(1);
    }
    
    requestlen = myproxy_create_request(client_request, 
					request_buffer, sizeof(request_buffer));
    
    if (requestlen < 0) {
	fprintf(stderr, "error in myproxy_create_request()\n");
	exit(1);
    }

    if (myproxy_send_request(socket_attrs, request_buffer, requestlen) < 0) {
	fprintf(stderr, "error in myproxy_send_request()\n");
	exit(1);
    }

    responselen = myproxy_recv_response(socket_attrs, 
					response_buffer, sizeof(response_buffer));
    if (responselen < 0) {
	fprintf(stderr, "error in myproxy_recv_response()\n");
	exit(1);
    }

    if (myproxy_create_response(client_response, response_buffer, responselen) < 0) {
      fprintf(stderr, "error in myproxy_create_response()\n");
      exit(1);
    }
    

    /* Check response */
    if (myproxy_check_response(client_response) != 0) {
      fprintf(stderr, "error in myproxy_check_response()\n");
      exit(1);
    }

    (void)myproxy_destroy_client(socket_attrs, client_request, client_response);

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

    request->username = getenv("LOGNAME");
    request->hours    = MYPROXY_DEFAULT_HOURS; 
    request->command  = malloc(strlen(MYPROXY_GET_COMMAND) + 1);
    sprintf(request->command, "%s", MYPROXY_GET_COMMAND); 
    attrs->psport = MYPROXYSERVER_PORT;
    attrs->pshost = MYPROXYSERVER_HOST;

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
    





