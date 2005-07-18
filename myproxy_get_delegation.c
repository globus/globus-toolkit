/*
 * myproxy-get-delegation
 *
 * Webserver program to retrieve a delegated credential from a myproxy-server
 */

#include "myproxy_common.h"	/* all needed headers included here */

static char usage[] = \
"\n"
"Syntax: myproxy-logon [-t hours] [-l username] ...\n"
"        myproxy-logon [-usage|-help] [-version]\n"
"\n"
"   Options\n"
"       -h | --help                       Displays usage\n"
"       -u | --usage                                    \n"
"                                                      \n"
"       -v | --verbose                    Display debugging messages\n"
"       -V | --version                    Displays version\n"
"       -l | --username        <username> Username for the delegated proxy\n"
"       -t | --proxy_lifetime  <hours>    Lifetime of proxies delegated by\n" 
"                                         the server (default 12 hours)\n"
"       -o | --out             <path>     Location of delegated proxy\n"
"       -s | --pshost          <hostname> Hostname of the myproxy-server\n"
"       -p | --psport          <port #>   Port of the myproxy-server\n"
"       -a | --authorization   <path>     Use credential for authorization\n"
"                                         (instead of passphrase)\n"
"       -d | --dn_as_username             Use subject of the authorization\n"
"                                         credential (or default credential\n"
"                                         if -a not used) as the default\n"
"                                         username instead of $LOGNAME\n"
"       -k | --credname        <name>     Specify credential name\n"
"       -S | --stdin_pass                 Read passphrase from stdin\n"
"       -T | --trustroots                 Manage trust roots\n"
"       -n | --no_passphrase              Don't prompt for passphrase\n"
"\n";

struct option long_options[] =
{
    {"help",                   no_argument, NULL, 'h'},
    {"pshost",           required_argument, NULL, 's'},
    {"psport",           required_argument, NULL, 'p'},
    {"proxy_lifetime",   required_argument, NULL, 't'},
    {"out",              required_argument, NULL, 'o'},
    {"usage",                  no_argument, NULL, 'u'},
    {"username",         required_argument, NULL, 'l'},
    {"verbose",                no_argument, NULL, 'v'},
    {"version",                no_argument, NULL, 'V'},
    {"authorization",    required_argument, NULL, 'a'},
    {"dn_as_username",         no_argument, NULL, 'd'},
    {"credname",	 required_argument, NULL, 'k'},
    {"stdin_pass",             no_argument, NULL, 'S'},
    {"trustroots",             no_argument, NULL, 'T'},
    {"no_passphrase",          no_argument, NULL, 'n'},
    {0, 0, 0, 0}
};

static char short_options[] = "hus:p:l:t:o:vVa:dk:SnT";

static char version[] =
"myproxy-logon version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

void 
init_arguments(int argc, char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request); 

/*
 * Use setvbuf() instead of setlinebuf() since cygwin doesn't support
 * setlinebuf().
 */
#define my_setlinebuf(stream)	setvbuf((stream), (char *) NULL, _IOLBF, 0)

/* location of delegated proxy */
static char *outputfile = NULL;
static int dn_as_username = 0;
static int read_passwd_from_stdin = 0;
static int use_empty_passwd = 0;

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

    my_setlinebuf(stdout);
    my_setlinebuf(stderr);

    socket_attrs = malloc(sizeof(*socket_attrs));
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    client_request = malloc(sizeof(*client_request));
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    memset(server_response, 0, sizeof(*server_response));

    other_stuff = malloc(sizeof(*other_stuff));
    memset(other_stuff, 0, sizeof(*other_stuff));

    /* Setup defaults */
    myproxy_set_delegation_defaults(socket_attrs,client_request);

    /* Initialize client arguments and create client request object */
    init_arguments(argc, argv, socket_attrs, client_request);

    other_stuff->use_empty_passwd       = use_empty_passwd;
    other_stuff->read_passwd_from_stdin = read_passwd_from_stdin;
    other_stuff->dn_as_username         = dn_as_username;
    other_stuff->outputfile             = outputfile;

    retval = myproxy_failover_stuff( socket_attrs,
                                     client_request,
                                     server_response,
                                     other_stuff );

    free(outputfile);
    verror_clear();

    /* free memory allocated */
    myproxy_free(socket_attrs, client_request, server_response);
    return(retval);
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
	case 't':       /* Specify proxy lifetime in seconds */
	  request->proxy_lifetime = 60*60*atoi(optarg);
	  break;
        case 's': 	/* pshost name */
	    attrs->pshost = strdup(optarg);
            break;
        case 'p': 	/* psport */
            attrs->psport = atoi(optarg);
            break;
	case 'h': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
        case 'u': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
        case 'l':	/* username */
            request->username = strdup(optarg);
            break;
	case 'o':	/* output file */
	    outputfile = strdup(optarg);
            break;    
	case 'a':       /* special authorization */
	    request->authzcreds = strdup(optarg);
	    use_empty_passwd = 1;
	    break;
	case 'n':       /* no passphrase */
	    use_empty_passwd = 1;
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
	case 'k':   /* credential name */
	    request->credname = strdup (optarg);
	    break;
	case 'S':
	    read_passwd_from_stdin = 1;
	    break;
	case 'T':
	    request->want_trusted_certs = 1;
            myproxy_debug("Requesting trusted certificates.\n");
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
