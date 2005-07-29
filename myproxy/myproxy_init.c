/*
 * myproxy-init
 *
 * Client program to delegate a credential to a myproxy-server
 */

#include "myproxy_common.h"	/* all needed headers included here */

/* Location of default proxy */
#define MYPROXY_DEFAULT_PROXY  "/tmp/myproxy-proxy"

static char usage[] = \
"\n"\
"Syntax: myproxy-init [-c #hours] [-t #hours] [-l username] [-r retrievers] [-w renewers] ...\n"\
"        myproxy-init [-usage|-help] [-version]\n"\
"\n"\
"   Options\n"\
"       -h | --help                       Displays usage\n"
"       -u | --usage                                    \n"
"                                                      \n"
"       -v | --verbose                    Display debugging messages\n"
"       -V | --version                    Displays version\n"
"       -l | --username        <username> Username for the delegated proxy\n"
"       -c | --cred_lifetime   <hours>    Lifetime of delegated proxy on\n" 
"                                         server (default 1 week)\n"
"       -t | --proxy_lifetime  <hours>    Lifetime of proxies delegated by\n" 
"                                         server (default 12 hours)\n"
"       -s | --pshost          <hostname> Hostname of the myproxy-server\n"
"                                         Can also set MYPROXY_SERVER env. var.\n"
"       -p | --psport          <port #>   Port of the myproxy-server\n"
"       -a | --allow_anonymous_retrievers Allow credentials to be retrieved\n"
"                                         with just username/passphrase\n"
"       -A | --allow_anonymous_renewers   Allow credentials to be renewed by\n"
"                                         any client (not recommended)\n"
"       -x | --regex_dn_match             Set regular expression matching mode\n"
"                                         for following policy options\n"
"       -X | --match_cn_only              Set CN matching mode (default)\n"
"                                         for following policy options\n"
"       -r | --retrievable_by  <dn>       Allow specified entity to retrieve\n"
"                                         credential\n"
"       -R | --renewable_by    <dn>       Allow specified entity to renew\n"
"                                         credential\n"
"       -S | --stdin_pass                 Read passphrase from stdin\n"
"       -n | --no_passphrase              Don't prompt for passphrase\n"
"       -d | --dn_as_username             Use the proxy certificate subject\n"
"                                         (DN) as the default username,\n"
"                                         instead of the LOGNAME env. var.\n"
"       -k | --credname        <name>     Specifies credential name\n"
"       -K | --creddesc        <desc>     Specifies credential description\n"
"\n";

struct option long_options[] =
{
  {"help",                  no_argument, NULL, 'h'},
  {"pshost",   	      required_argument, NULL, 's'},
  {"psport",          required_argument, NULL, 'p'},
  {"cred_lifetime",   required_argument, NULL, 'c'},
  {"proxy_lifetime",  required_argument, NULL, 't'},
  {"usage",                 no_argument, NULL, 'u'},
  {"username",        required_argument, NULL, 'l'},
  {"verbose",               no_argument, NULL, 'v'},
  {"version",               no_argument, NULL, 'V'},
  {"no_passphrase",         no_argument, NULL, 'n'},
  {"dn_as_username",        no_argument, NULL, 'd'},
  {"allow_anonymous_retrievers", no_argument, NULL, 'a'},
  {"allow_anonymous_renewers", no_argument, NULL, 'A'},
  {"retrievable_by",  required_argument, NULL, 'r'},
  {"renewable_by",    required_argument, NULL, 'R'},
  {"regex_dn_match",        no_argument, NULL, 'x'},
  {"match_cn_only", 	    no_argument, NULL, 'X'},
  {"credname",	      required_argument, NULL, 'k'},
  {"creddesc",	      required_argument, NULL, 'K'},
  {"stdin_pass",            no_argument, NULL, 'S'},
  {0, 0, 0, 0}
};

/*colon following an option indicates option takes an argument */
static char short_options[] = "uhs:p:t:c:l:vVndr:R:xXaAk:K:S";

static char version[] =
"myproxy-init version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

static int use_empty_passwd = 0;
static int dn_as_username = 0;
static int read_passwd_from_stdin = 0;
static int verbose = 0;

/* Function declarations */
int init_arguments(int argc, char *argv[], 
		    myproxy_socket_attrs_t *attrs, 
                    myproxy_request_t *request, 
                    myproxy_other_stuff_t *other_stuff);

int grid_proxy_init(int hours, const char *proxyfile);

int grid_proxy_destroy(const char *proxyfile);

#define		SECONDS_PER_HOUR			(60 * 60)

int
main(int argc, char *argv[]) 
{    
    char proxyfile[MAXPATHLEN];

    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;

    myproxy_other_stuff_t  *other_stuff;

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

    /* setup defaults */
    client_request->version = malloc(strlen(MYPROXY_VERSION) + 1);
    strcpy(client_request->version, MYPROXY_VERSION);
    client_request->command_type = MYPROXY_PUT_PROXY;

    if( myproxy_init( socket_attrs,
                      client_request,
                      MYPROXY_PUT_PROXY ) < 0 )
    {
      return( 1 );
    }


    /* client_request stores the lifetime of proxies delegated by the server */
    client_request->proxy_lifetime = SECONDS_PER_HOUR * MYPROXY_DEFAULT_DELEG_HOURS;

    /* the lifetime of the proxy */
    other_stuff->cred_lifetime     = SECONDS_PER_HOUR * MYPROXY_DEFAULT_HOURS;

    /* Initialize client arguments and create client request object */
    if (init_arguments(argc, argv, socket_attrs, client_request,
		       other_stuff) != 0) 
    {
      goto cleanup;
    }

    other_stuff->use_empty_passwd = use_empty_passwd;
    other_stuff->read_passwd_from_stdin = read_passwd_from_stdin;
    other_stuff->dn_as_username = dn_as_username;
    other_stuff->proxyfile = malloc(MAXPATHLEN);

    if( myproxy_failover( socket_attrs,
                          client_request,
                          server_response,
                          other_stuff ) != 0 )
    {
      if( verror_is_error() )
      {
        printf( "VERROR: %s\n", verror_get_string() );
      }
      goto cleanup;
    }
    
    /* free memory allocated */
    myproxy_free(socket_attrs, client_request, server_response);

    return 0;

 cleanup:
    if (other_stuff->destroy_proxy) {
        grid_proxy_destroy(other_stuff->proxyfile);
    }
    return 1;
}

int
init_arguments(int argc, 
	       char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request,
	       myproxy_other_stuff_t *other_stuff) 
{   
    extern char *optarg;
    int expr_type = MATCH_CN_ONLY;  /*default */

    int arg;

    while((arg = getopt_long(argc, argv, short_options, 
				 long_options, NULL)) != EOF) 
    {
	switch(arg) 
	{
	case 'h':       /* print help and exit */
	    fprintf(stderr, usage);
	    return -1;
	    break;
	case 'c': 	/* Specify cred lifetime in hours */
	    other_stuff->cred_lifetime  = SECONDS_PER_HOUR * atoi(optarg);
	    break;    
	case 't': 	/* Specify proxy lifetime in hours */
	    request->proxy_lifetime = SECONDS_PER_HOUR * atoi(optarg);
	    break;        
	case 's': 	/* pshost name */
	    attrs->pshost = strdup(optarg);
	    break;
	case 'p': 	/* psport */
	    attrs->psport = atoi(optarg);
	    break;
	case 'u': 	/* print help and exit */
	    fprintf(stderr, usage);
	    return -1;
	    break;
	case 'l':	/* username */
	    request->username = strdup(optarg);
	    break;
	case 'v':
	    myproxy_debug_set_level(1);
	    verbose = 1;
	    break;
	case 'V': /* print version and exit */
	    fprintf(stderr, version);
	    return -1;
	    break;
	case 'n':   /* use an empty passwd == require certificate based
		       authorization while getting the creds */
#if !defined(HAVE_LIBSASL2)
	    if (request->retrievers) {
		fprintf(stderr, "-n is incompatible with -r and -a.\nA passphrase is required for credential retrieval.\n");
		return -1;
	    }
#endif
	    use_empty_passwd = 1;
	    break;
	case 'd':   /* use the certificate subject (DN) as the default
		       username instead of LOGNAME */
	    dn_as_username = 1;
	    break;
	case 'r':   /* retrievers list */
	    if (request->renewers) {
		fprintf(stderr, "-r is incompatible with -A and -R.  A credential may not be used for both\nretrieval and renewal.  If both are desired, upload multiple credentials with\ndifferent names, using the -k option.\n");
		return -1;
	    }
	    if (request->retrievers) {
		fprintf(stderr, "Only one -a or -r option may be specified.\n");
		return -1;
	    }
#if !defined(HAVE_LIBSASL2)
	    if (use_empty_passwd) {
		fprintf(stderr, "-r is incompatible with -n.  A passphrase is required for credential retrieval.\n");
		return -1;
	    }
#endif
	    if (expr_type == REGULAR_EXP)  /*copy as is */
	      request->retrievers = strdup (optarg);
	    else
	    {
		request->retrievers = (char *) malloc (strlen (optarg) + 5);
		strcpy (request->retrievers, "*/CN=");
		request->retrievers = strcat (request->retrievers,optarg);
		myproxy_debug("authorized retriever %s", request->retrievers);
	    }
	    break;
	case 'R':   /* renewers list */
	    if (request->retrievers) {
		fprintf(stderr, "-R is incompatible with -a and -r.  A credential may not be used for both\nretrieval and renewal.  If both are desired, upload multiple credentials with\ndifferent names, using the -k option.\n");
		return -1;
	    }
	    if (request->renewers) {
		fprintf(stderr, "Only one -A or -R option may be specified.\n");
		return -1;
	    }
	    if (expr_type == REGULAR_EXP)  /*copy as is */
	      request->renewers = strdup (optarg);
	    else
	    {
		request->renewers = (char *) malloc (strlen (optarg) + 6);
		strcpy (request->renewers, "*/CN=");
		request->renewers = strcat (request->renewers,optarg);
		myproxy_debug("authorized renewer %s", request->renewers);
	    }
	    use_empty_passwd = 1;
	    break;
	case 'x':   /*set expression type to regex*/
	    expr_type = REGULAR_EXP;
	    myproxy_debug("expr-type = regex");
	    break;
	case 'X':   /*set expression type to common name*/
	    expr_type = MATCH_CN_ONLY;
	    myproxy_debug("expr-type = CN");
	    break;
	case 'a':  /*allow anonymous retrievers*/
	    if (request->renewers) {
		fprintf(stderr, "-a is incompatible with -A and -R.  A credential may not be used for both\nretrieval and renewal.  If both are desired, upload multiple credentials with\ndifferent names, using the -k option.\n");
		return -1;
	    }
	    if (request->retrievers) {
		fprintf(stderr, "Only one -a or -r option may be specified.\n");
		return -1;
	    }
	    if (use_empty_passwd) {
		fprintf(stderr, "-a is incompatible with -n.  A passphrase is required for credential retrieval.\n");
		return -1;
	    }
	    request->retrievers = strdup ("*");
	    myproxy_debug("anonymous retrievers allowed");
	    break;
	case 'A':  /*allow anonymous renewers*/
	    if (request->retrievers) {
		fprintf(stderr, "-A is incompatible with -a and -r.  A credential may not be used for both\nretrieval and renewal.  If both are desired, upload multiple credentials with\ndifferent names, using the -k option.\n");
		return -1;
	    }
	    if (request->renewers) {
		fprintf(stderr, "Only one -A or -R option may be specified.\n");
		return -1;
	    }
	    request->renewers = strdup ("*");
	    myproxy_debug("anonymous renewers allowed");
	    use_empty_passwd = 1;
	    break;
	case 'k':  /*credential name*/
	    request->credname = strdup (optarg);
	    break;
	case 'K':  /*credential description*/
	    request->creddesc = strdup (optarg);
	    break;
	case 'S':
	    read_passwd_from_stdin = 1;
	    break;

        default:  
	    fprintf(stderr, usage);
	    return -1;
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
	return -1;
    }

    return 0;
}


/* grid_proxy_init()
 *
 * Uses the system() call to run grid-proxy-init to create a user proxy
 *
 * returns grid-proxy-init status 0 if OK, -1 on error
 */
int
grid_proxy_init(int seconds, const char *proxyfile) {

    int rc;
    char command[128];
    int hours;
    char *proxy_mode;
    int old=0;
      
    assert(proxyfile != NULL);

    hours = seconds / SECONDS_PER_HOUR;

    proxy_mode = getenv("GT_PROXY_MODE");
    if (proxy_mode && strcmp(proxy_mode, "old") == 0) {
	old=1;
    }
    
    sprintf(command, "grid-proxy-init -verify -valid %d:0 -out %s%s%s%s",
	    hours, proxyfile, read_passwd_from_stdin ? " -pwstdin" : "",
	    verbose ? " -debug" : "", old ? " -old" : "");
    rc = system(command);

    return rc;
}

/* grid_proxy_destroy()
 *
 * Fill the proxy file with zeros and unlink.
 *
 * returns 0 if OK, -1 on error
 */
int
grid_proxy_destroy(const char *proxyfile)
{
    if (ssl_proxy_file_destroy(proxyfile) != SSL_SUCCESS) {
	verror_print_error(stderr);
	return -1;
    }
    return 0;
}

