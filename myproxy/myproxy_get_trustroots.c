/*
 * myproxy-get-trustroots
 *
 * Webserver program to manage trustroots from a myproxy-server
 */

#include "myproxy_common.h"	/* all needed headers included here */

static char usage[] = \
"\n"
"Syntax: myproxy-get-trustroots [-s server] [-p port]...\n"
"        myproxy-get-trustroots [-usage|-help] [-version]\n"
"\n"
"   Options\n"
"       -h | --help                       Displays usage\n"
"       -u | --usage                                    \n"
"                                                      \n"
"       -v | --verbose                    Display debugging messages\n"
"       -V | --version                    Displays version\n"
"       -s | --pshost          <hostname> Hostname of the myproxy-server\n"
"       -p | --psport          <port #>   Port of the myproxy-server\n"
"       -q | --quiet                      Only output on error\n"
"\n";

struct option long_options[] =
{
    {"help",                   no_argument, NULL, 'h'},
    {"pshost",           required_argument, NULL, 's'},
    {"psport",           required_argument, NULL, 'p'},
    {"usage",                  no_argument, NULL, 'u'},
    {"verbose",                no_argument, NULL, 'v'},
    {"version",                no_argument, NULL, 'V'},
    {"quiet",                  no_argument, NULL, 'q'},
    {0, 0, 0, 0}
};

static char short_options[] = "hus:p:vVq";

static char version[] =
"myproxy-get-trustroots version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

void 
init_arguments(int argc, char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request); 

/*
 * Use setvbuf() instead of setlinebuf() since cygwin doesn't support
 * setlinebuf().
 */
#define my_setlinebuf(stream)	setvbuf((stream), (char *) NULL, _IOLBF, 0)

static int quiet = 0;

int myproxy_set_trustroots_defaults(
    myproxy_socket_attrs_t *socket_attrs,
    myproxy_request_t      *client_request)
{ 
    char *pshost;

    client_request->version = strdup(MYPROXY_VERSION);
    client_request->command_type = MYPROXY_GET_TRUSTROOTS;
    client_request->want_trusted_certs = 1;

    myproxy_debug("Requesting trusted certificates.\n");

    pshost = getenv("MYPROXY_SERVER");
    if (pshost != NULL) {
        socket_attrs->pshost = strdup(pshost);
    }

    if (getenv("MYPROXY_SERVER_PORT")) {
        socket_attrs->psport = atoi(getenv("MYPROXY_SERVER_PORT"));
    } else {
        socket_attrs->psport = MYPROXY_SERVER_PORT;
    }

    return 0;
}

int myproxy_get_trustroots(
    myproxy_socket_attrs_t *socket_attrs,
    myproxy_request_t      *client_request,
    myproxy_response_t     *server_response)
{
    char *request_buffer = NULL;
    int  requestlen;

    assert(socket_attrs != NULL);
    assert(client_request != NULL);
    assert(server_response != NULL);

    /* Set up client socket attributes */
    if (socket_attrs->gsi_socket == NULL) {
	if (myproxy_init_client(socket_attrs) < 0) {
	    return(1);
	}
    }
    
    /* Attempt anonymous-mode credential retrieval if we don't have a
       credential. */
    GSI_SOCKET_allow_anonymous(socket_attrs->gsi_socket, 1);

     /* Authenticate client to server */
    if (GSI_SOCKET_context_established(socket_attrs->gsi_socket) == 0) {
    if (myproxy_authenticate_init(socket_attrs, NULL) < 0) {
        return(1);
    }
    }

    /* Serialize client request object */
    requestlen = myproxy_serialize_request_ex(client_request, &request_buffer);
    if (requestlen < 0) {
        return(1);
    }

    /* Send request to the myproxy-server */
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
        return(1);
    }
    free(request_buffer);
    request_buffer = 0;

    /* Continue unless the response is not OK */
    if (myproxy_recv_response_ex(socket_attrs, server_response,
				 client_request) != 0) {
	return(1);
    }

    return(0);
}

int
main(int argc, char *argv[]) 
{    
    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;
    int return_value = 1;
    char *cert_dir = NULL;
    globus_result_t res;

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

    /* Setup defaults */
    myproxy_set_trustroots_defaults(socket_attrs,client_request);

    /* Initialize client arguments and create client request object */
    init_arguments(argc, argv, socket_attrs, client_request);

    /* Bootstrap trusted certificate directory if none exists. */
    assert(client_request->want_trusted_certs);

    globus_module_activate(GLOBUS_GSI_CERT_UTILS_MODULE);
    res = GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&cert_dir);
    if (res != GLOBUS_SUCCESS) {
        myproxy_log("Bootstrapping MyProxy server root of trust.");
        myproxy_bootstrap_trust(socket_attrs);
    }
    if (cert_dir) free(cert_dir);

    /* Connect to server. */
    if (myproxy_init_client(socket_attrs) < 0) {
        verror_print_error(stderr);
        goto cleanup;
    }
    
    /* Attempt anonymous-mode retrieval if we don't have a
       credential. */
    GSI_SOCKET_allow_anonymous(socket_attrs->gsi_socket, 1);

     /* Authenticate client to server */
    if (myproxy_authenticate_init(socket_attrs, NULL) < 0) {
        verror_print_error(stderr);
        if (client_request->want_trusted_certs &&
            strstr(verror_get_string(), "CRL") != NULL) {
            verror_clear();
            myproxy_log("CRL error detected.  Attempting to recover.");
            switch (myproxy_clean_crls()) {
            case -1:
                verror_print_error(stderr);
            case 0:
                goto cleanup;
            case 1:
                if (myproxy_init_client(socket_attrs) < 0) {
                    verror_print_error(stderr);
                    goto cleanup;
                }
                if (myproxy_authenticate_init(socket_attrs, NULL) < 0) {
                    verror_print_error(stderr);
                    goto cleanup;
                }
            }
        } else {
            goto cleanup;
        }
    }

    if (myproxy_get_trustroots(socket_attrs, client_request, server_response)!=0) {
	fprintf(stderr, "Failed to receive trustroots.\n");
	verror_print_error(stderr);
	goto cleanup;
    }

    /* Store file in trusted directory if requested and returned */
    assert(client_request->want_trusted_certs);
    if (server_response->trusted_certs != NULL) {
        if (myproxy_install_trusted_cert_files(server_response->trusted_certs) != 0) {       
            verror_print_error(stderr);
            goto cleanup;
        } else {
            char *path;
            path = get_trusted_certs_path();
            if (path) {
                if (!quiet) {
                    printf("Trust roots have been installed in %s.\n", path);
                }
                free(path);
            }
        }
    } else {
        myproxy_debug("Requested trusted certs but didn't get any.\n");
    }

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

    request->want_trusted_certs = 1;

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
	case 'h': 	/* print help and exit */
        case 'u': 	/* print help and exit */
            printf(usage);
            exit(0);
            break;
	case 'q':
	    quiet = 1;
	    break;
	case 'v':
	    myproxy_debug_set_level(1);
	    break;
        case 'V':       /* print version and exit */
            printf(version);
            exit(0);
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
