/*
 * myproxy-cp
 *
 * Webserver program to change credential password stored on myproxy server
 */

#include "myproxy_common.h"	/* all needed headers included here */

static char usage[] = \
"\n"
"Syntax: myproxy-change-pass-phrase [-l username] [-k credname] ... \n"
"        myproxy-change-pass-phrase [-usage|-help] [-version]\n"
"\n"
"   Options\n"
"       -h | --help                       Displays usage\n"
"       -u | --usage                                    \n"
"                                                      \n"
"       -v | --verbose                    Display debugging messages\n"
"       -V | --version                    Displays version\n"
"       -l | --username        <username> Username for the target proxy\n"
"       -s | --pshost          <hostname> Hostname of the myproxy-server\n"
"       -p | --psport          <port #>   Port of the myproxy-server\n"
"       -d | --dn_as_username             Use the proxy certificate subject\n"
"                                         (DN) as the default username,\n"
"                                         instead of the LOGNAME env. var.\n"
"       -k | --credname        <name>     Specify credential name\n"
"       -S | --stdin_pass                 Read pass phrase from stdin\n"
"\n";

struct option long_options[] =
{
    {"help",                   no_argument, NULL, 'h'},
    {"pshost",           required_argument, NULL, 's'},
    {"psport",           required_argument, NULL, 'p'},
    {"usage",                  no_argument, NULL, 'u'},
    {"username",         required_argument, NULL, 'l'},
    {"verbose",                no_argument, NULL, 'v'},
    {"version",                no_argument, NULL, 'V'},
    {"dn_as_username",   no_argument, NULL, 'd'},
    {"credname",	 required_argument, NULL, 'k'},
    {"stdin_pass",             no_argument, NULL, 'S'},
    {0, 0, 0, 0}
};

static char short_options[] = "hus:p:l:vVdk:S";

static char version[] =
"myproxy-change-pass-phrase version " MYPROXY_VERSION " ("
MYPROXY_VERSION_DATE ") "  "\n";

void 
init_arguments(int argc, char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request); 

/*
 * Use setvbuf() instead of setlinebuf() since cygwin doesn't support
 * setlinebuf().
 */
#define my_setlinebuf(stream)	setvbuf((stream), (char *) NULL, _IOLBF, 0)

static int dn_as_username = 0;
static int read_passwd_from_stdin = 0;

int
main(int argc, char *argv[]) 
{    
    char *pshost;
    int requestlen, rval;
    char *request_buffer = NULL;
    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;
    int return_value = 1;

    /* check library version */
    if (myproxy_check_version()) {
	fprintf(stderr, "MyProxy library version mismatch.\n"
		"Expecting %s.  Found %s.\n",
		MYPROXY_VERSION_DATE, myproxy_version(0,0,0));
	exit(1);
    }

    myproxy_log_use_stream (stderr);

    my_setlinebuf(stdout);
    my_setlinebuf(stderr);

    socket_attrs = malloc(sizeof(*socket_attrs));
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    client_request = malloc(sizeof(*client_request));
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    memset(server_response, 0, sizeof(*server_response));

    client_request->version = malloc(strlen(MYPROXY_VERSION) +1);
    strcpy (client_request->version, MYPROXY_VERSION);
    client_request->command_type = MYPROXY_CHANGE_CRED_PASSPHRASE;

    pshost = getenv ("MYPROXY_SERVER");

    if (pshost != NULL) {
	socket_attrs->pshost = strdup(pshost);
    }

    client_request->proxy_lifetime = 0;

    if (getenv("MYPROXY_SERVER_PORT")) {
	socket_attrs->psport = atoi(getenv("MYPROXY_SERVER_PORT"));
    } else {
	socket_attrs->psport = MYPROXY_SERVER_PORT;
    }

    /* Initialize client arguments and create client request object */
    init_arguments(argc, argv, socket_attrs, client_request);

    /* Set up client socket attributes */
    if (myproxy_init_client(socket_attrs) < 0) {
	verror_print_error(stderr);
        goto cleanup;
    }

    /*Accept credential passphrase*/
    if (read_passwd_from_stdin) {
	rval = myproxy_read_passphrase_stdin(client_request->passphrase,
					     sizeof(client_request->passphrase),
					     "Enter (current) MyProxy pass phrase:");
    } else {
	rval = myproxy_read_passphrase(client_request->passphrase,
				       sizeof(client_request->passphrase),
				       "Enter (current) MyProxy pass phrase:");
    }
    if (rval == -1) {
	verror_print_error(stderr);
	goto cleanup;
    }

    /* Accept new passphrase */
    if (read_passwd_from_stdin) {
	rval = myproxy_read_passphrase_stdin(client_request->new_passphrase,
					     sizeof(client_request->new_passphrase),
					     "Enter new MyProxy pass phrase:");
    } else {
	rval = myproxy_read_verified_passphrase(client_request->new_passphrase,
						sizeof(client_request->new_passphrase),
						"Enter new MyProxy pass phrase:");
    }
    if (rval == -1) {
	verror_print_error(stderr);
	goto cleanup;
    }

    /* Authenticate client to server */
    if (myproxy_authenticate_init(socket_attrs, NULL /* Default proxy */) < 0) {
	verror_print_error(stderr);
        goto cleanup;
    }

    if (client_request->username == NULL) { /* set default username */
	if (dn_as_username) {
	    if (ssl_get_base_subject_file(NULL,
					  &client_request->username)) {
		fprintf(stderr,
			"Cannot get subject name from your certificate\n");
		goto cleanup;
	    }
	} else {
	    char *username = NULL;
	    if (!(username = getenv("LOGNAME"))) {
		fprintf(stderr, "Please specify a username.\n");
		goto cleanup;
	    }
	    client_request->username = strdup(username);
	}
    }

    /*Serialize client request object */
    requestlen = myproxy_serialize_request_ex(client_request, &request_buffer);

    if (requestlen < 0) {
	    	verror_print_error(stderr);
		exit(1);
    }

    /* Send request to myproxy-server*/
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
	    verror_print_error(stderr);
	    goto cleanup;
    }
    free(request_buffer);
    request_buffer = NULL;

    /* Receive response from server */
    if (myproxy_recv_response_ex(socket_attrs, server_response,
				 client_request) != 0) {
	    verror_print_error(stderr);
	    exit (1);
    }

    /*Check response */
    switch (server_response->response_type) {
	    case MYPROXY_ERROR_RESPONSE:
		    fprintf (stderr, "Error: %s\nPass phrase unchanged.\n", 
			     server_response->error_string);
		    
		    goto cleanup;

	    case MYPROXY_OK_RESPONSE:
    		    printf("Pass phrase changed.\n");
		    break;
	
	    default:
		    fprintf (stderr, "Invalid response type received.\n");
		    goto cleanup;
	}
    verror_clear();

    return_value = 0;

 cleanup:
    /* free memory allocated */
    myproxy_free(socket_attrs, client_request, server_response);

    return return_value;
}

void 
init_arguments(int argc, 
	       char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request) 
{   
    extern char *optarg;
    int arg;

    while((arg = getopt_long(argc, argv, short_options, 
				 long_options, NULL)) != EOF) 
    {
        switch(arg) 
        {
	case 'h': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
        case 'u': 	/* print usage and exit*/
            fprintf(stderr, usage);
            exit(1);
            break;
	case 'v':
	    myproxy_debug_set_level(1);
	    break;
        case 'V':       /* print version and exit */
            fprintf(stderr, version);
            exit(1);
            break;
        case 'l':	/* username */
            request->username = strdup(optarg);
            break;
        case 's': 	/* pshost name */
	    attrs->pshost = strdup(optarg);
            break;
        case 'p': 	/* psport */
            attrs->psport = atoi(optarg);
            break;
	case 'k':   /* credential name */
	    request->credname = strdup (optarg);
	    break;
        case 'd':   /* use the certificate subject (DN) as the default
                       username instead of LOGNAME */
            dn_as_username = 1;
            break;
	case 'S':
	    read_passwd_from_stdin = 1;
	    break;
        default:        /* print usage and exit */ 
	    fprintf(stderr, usage);
	    exit(1);
	    break;	
        }
    }

    if (optind != argc) {
	fprintf(stderr, "%s: invalid option -- %s\n", argv[0],
		argv[optind]);
	fprintf(stderr, usage);
	exit(1);
    }

    /* Check to see if myproxy-server specified */
    if (attrs->pshost == NULL) {
	fprintf(stderr, "Unspecified myproxy-server. Please set the MYPROXY_SERVER environment variable\nor set the myproxy-server hostname via the -s flag.\n");
	exit(1);
    }
    return;
}
