/*
 * myproxy-info
 *
 * Client program to inqure a proxy on a myproxy-server
 */

#include "myproxy_common.h"	/* all needed headers included here */

static char usage[] = \
"\n"\
"Syntax: myproxy-info [-l username] ...\n"\
"        myproxy-info [-usage|-help] [-version]\n"\
"\n"\
"    Options\n"\
"    -h | --help                Displays usage\n"\
"    -u | --usage                             \n"\
"                                            \n"\
"    -v | --verbose             Display debugging messages\n"\
"    -V | --version             Displays version\n"\
"    -l | --username <username> Username for the delegated proxy\n"\
"    -s | --pshost   <hostname> Hostname of the myproxy-server\n"\
"    -p | --psport   #          Port of the myproxy-server\n"
"    -d | --dn_as_username      Use the proxy certificate subject\n"
"                               (DN) as the default username,\n"
"                               instead of the LOGNAME env. var.\n"
"\n";

struct option long_options[] =
{
    {"help",             no_argument, NULL, 'h'},
    {"pshost",     required_argument, NULL, 's'},
    {"psport",     required_argument, NULL, 'p'},
    {"usage",            no_argument, NULL, 'u'},
    {"username",   required_argument, NULL, 'l'},
    {"verbose",          no_argument, NULL, 'v'},
    {"version",          no_argument, NULL, 'V'},
    {"dn_as_username",   no_argument, NULL, 'd'},
    {0, 0, 0, 0}
};

static char short_options[] = "hus:p:l:vVd";

static char version[] =
"myproxy-info version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

static int dn_as_username = 0;

/* Function declarations */
void init_arguments(int argc, char *argv[],
                    myproxy_socket_attrs_t *attrs, myproxy_request_t *request);


int
main(int argc, char *argv[])
{
    char *pshost = NULL;
    char *request_buffer = NULL;
    int requestlen;
    int return_value = 1;

    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;

    /* check library version */
    if (myproxy_check_version()) {
	fprintf(stderr, "MyProxy library version mismatch.\n"
		"Expecting %s.  Found %s.\n",
		MYPROXY_VERSION_DATE, myproxy_version(0,0,0));
	exit(1);
    }

    myproxy_log_use_stream (stderr);

    socket_attrs = malloc(sizeof(*socket_attrs));
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    client_request = malloc(sizeof(*client_request));
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    memset(server_response, 0, sizeof(*server_response));

    /* setup defaults */
    client_request->version = malloc(strlen(MYPROXY_VERSION) + 1);
    strcpy(client_request->version, MYPROXY_VERSION);
    client_request->command_type = MYPROXY_INFO_PROXY;

    pshost = getenv("MYPROXY_SERVER");
    if (pshost != NULL) {
        socket_attrs->pshost = strdup(pshost);
    }

    if (getenv("MYPROXY_SERVER_PORT")) {
	socket_attrs->psport = atoi(getenv("MYPROXY_SERVER_PORT"));
    } else {
	socket_attrs->psport = MYPROXY_SERVER_PORT;
    }

    /* Initialize client arguments and create client request object */
    init_arguments(argc, argv, socket_attrs, client_request);

    /*
     * We don't need to send the real pass phrase to the server as it
     * will just use our identity to authenticate and authorize us.
     * But we need to send over a dummy pass phrase at least
     * MIN_PASS_PHASE_LEN (currently 6) characters long.
     */
    strncpy(client_request->passphrase, "DUMMY-PASSPHRASE",
            sizeof(client_request->passphrase));

    /* Set up client socket attributes */
    if (myproxy_init_client(socket_attrs) < 0) {
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
    /* Serialize client request object */
    requestlen = myproxy_serialize_request_ex(client_request,
					      &request_buffer);

    if (requestlen < 0) {
	verror_print_error(stderr);
        goto cleanup;
    }

    /* Send request to the myproxy-server */
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
	verror_print_error(stderr);
        goto cleanup;
    }
    free(request_buffer);
    request_buffer = 0;

    /* Receive a response from the server */
    if (myproxy_recv_response_ex(socket_attrs, server_response,
				 client_request) < 0) {
	verror_print_error(stderr);
        goto cleanup;
    }

    /* Check response */
    switch(server_response->response_type) {
    case MYPROXY_ERROR_RESPONSE:
        fprintf(stderr, "Received ERROR_RESPONSE: %s\n",
		server_response->error_string);
	goto cleanup;
        break;
    case MYPROXY_OK_RESPONSE:
	printf("username: %s\n", client_request->username);
	myproxy_print_cred_info(server_response->info_creds, stdout);
	break;
    default:
        fprintf(stderr, "Invalid response type received.\n");
	goto cleanup;
        break;
    }

    printf ("\n");
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
        case 's': 	/* pshost name */
	    attrs->pshost = strdup(optarg);
            break;
        case 'p': 	/* psport */
            attrs->psport = atoi(optarg);
            break;
        case 'u': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
	case 'h': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
        case 'l':	/* username */
	    request->username = strdup(optarg);
            break;
	case 'v':
	    myproxy_debug_set_level(1);
	    break;
        case 'V':       /* print version and exit */
            fprintf(stderr, version);
            exit(1);
            break;
	case 'd':   /* use the certificate subject (DN) as the default
		       username instead of LOGNAME */
	    dn_as_username = 1;
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
	fprintf(stderr, usage);
	fprintf(stderr, "Unspecified myproxy-server. Please set the MYPROXY_SERVER environment variable\nor set the myproxy-server hostname via the -s flag.\n");
	exit(1);
    }

    return;
}
