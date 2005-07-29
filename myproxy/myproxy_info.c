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
                    myproxy_socket_attrs_t *attrs, 
                    myproxy_request_t *request,
                    myproxy_other_stuff_t *other_stuff);


int
main(int argc, char *argv[])
{
    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;
    myproxy_other_stuff_t  *other_stuff;

    int retval = 0;

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

    other_stuff = malloc(sizeof(*other_stuff));
    memset(other_stuff, 0, sizeof(*other_stuff));

    if( myproxy_init( socket_attrs,
                      client_request,
                      MYPROXY_INFO_PROXY ) < 0 )
    {
      return( 1 );
    }

myproxy_init_socket_attrs( socket_attrs );

    /* Initialize client arguments and create client request object */
    init_arguments(argc, argv, socket_attrs, client_request, other_stuff);

    retval = myproxy_failover( socket_attrs,
                               client_request,
                               server_response,
                               other_stuff );

    printf ("\n");

    /* free memory allocated */
    myproxy_free(socket_attrs, client_request, server_response);

    return( retval );
}


void 
init_arguments(int argc, 
	       char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request,
               myproxy_other_stuff_t *other_stuff) 
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
	    other_stuff->dn_as_username = 1;
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
