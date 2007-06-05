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
"       -C | --certfile        <filename> Certificate file name\n"
"       -y | --keyfile         <filename> Key file name\n"
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
"       -Z | --retrievable_by_cert <dn>   Allow specified entity to retrieve\n"
"                                         credential w/o passphrase\n"
"       -S | --stdin_pass                 Read passphrase from stdin\n"
"       -n | --no_passphrase              Don't prompt for passphrase\n"
"       -d | --dn_as_username             Use the proxy certificate subject\n"
"                                         (DN) as the default username,\n"
"                                         instead of the LOGNAME env. var.\n"
"       -k | --credname        <name>     Specifies credential name\n"
"       -K | --creddesc        <desc>     Specifies credential description\n"
"       -L | --local_proxy                Create a local proxy credential\n"
"       -m | --voms            <voms>     Include VOMS attributes\n"
"\n";

struct option long_options[] =
{
  {"help",                  no_argument, NULL, 'h'},
  {"pshost",   	      required_argument, NULL, 's'},
  {"psport",          required_argument, NULL, 'p'},
  {"certfile",        required_argument, NULL, 'C'},
  {"keyfile",         required_argument, NULL, 'y'},
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
  {"retrievable_by_cert",  required_argument, NULL, 'Z'},
  {"renewable_by",    required_argument, NULL, 'R'},
  {"regex_dn_match",        no_argument, NULL, 'x'},
  {"match_cn_only", 	    no_argument, NULL, 'X'},
  {"credname",	      required_argument, NULL, 'k'},
  {"creddesc",	      required_argument, NULL, 'K'},
  {"stdin_pass",            no_argument, NULL, 'S'},
  {"local_proxy",           no_argument, NULL, 'L'},
  {"voms",            required_argument, NULL, 'm'},
  {0, 0, 0, 0}
};

/*colon following an option indicates option takes an argument */
static char short_options[] = "uhs:p:t:c:y:C:l:vVndr:R:Z:xXaAk:K:SL";

static char version[] =
"myproxy-init version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

static char *certfile               = NULL;	/* certificate file name */
static char *keyfile                = NULL;	/* key file name */
static char *voms                   = NULL;
static int use_empty_passwd = 0;
static int dn_as_username = 0;
static int read_passwd_from_stdin = 0;
static int create_local_proxy = 0;
static int verbose = 0;

/* Function declarations */
int init_arguments(int argc, char *argv[], 
		    myproxy_socket_attrs_t *attrs, myproxy_request_t *request, int *cred_lifetime);

int grid_proxy_init(int seconds,
		    const char *cert, const char *key, const char *outfile);

int grid_proxy_destroy(const char *proxyfile);

#define		SECONDS_PER_HOUR			(60 * 60)

int
main(int argc, char *argv[]) 
{    
    int cred_lifetime, hours;
    float days;
    char *pshost = NULL;
    char proxyfile[MAXPATHLEN];
    char *request_buffer = NULL;
    int requestlen;
    int cleanup_user_proxy = 0;
    char *x509_user_proxy = NULL;
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
    client_request->command_type = MYPROXY_PUT_PROXY;

    pshost = getenv("MYPROXY_SERVER");
    if (pshost != NULL) {
      socket_attrs->pshost = strdup(pshost);
    }

    /* client_request stores the lifetime of proxies delegated by the server */
    client_request->proxy_lifetime = SECONDS_PER_HOUR * MYPROXY_DEFAULT_DELEG_HOURS;

    /* the lifetime of the proxy */
    cred_lifetime                   = SECONDS_PER_HOUR * MYPROXY_DEFAULT_HOURS;
 
    if (getenv("MYPROXY_SERVER_PORT")) {
	socket_attrs->psport = atoi(getenv("MYPROXY_SERVER_PORT"));
    } else {
	socket_attrs->psport = MYPROXY_SERVER_PORT;
    }

    x509_user_proxy = getenv("X509_USER_PROXY"); /* for create_local_proxy */

    /* Initialize client arguments and create client request object */
    if (init_arguments(argc, argv, socket_attrs, client_request,
		       &cred_lifetime) != 0) {
      goto cleanup;
    }
    
    /* Set up client socket attributes */
    if (myproxy_init_client(socket_attrs) < 0) {
	verror_print_error(stderr);
        goto cleanup;
    }

    /* Create a proxy by running [grid-proxy-init] */
    sprintf(proxyfile, "%s.%u.%u", MYPROXY_DEFAULT_PROXY,
	    (unsigned)getuid(), (unsigned)getpid());

    /* Run grid-proxy-init to create a proxy */
    if (grid_proxy_init(cred_lifetime, certfile, keyfile, proxyfile) != 0) {
        if (voms) {
            fprintf(stderr, "voms-proxy-init failed\n");
        } else {
            fprintf(stderr, "grid-proxy-init failed\n");
        }
        goto cleanup;
    }

    /* Be sure to delete the user proxy on abnormal exit */
    cleanup_user_proxy = 1;
    
    /* Authenticate client to server */
    if (myproxy_authenticate_init(socket_attrs, proxyfile) < 0) {
	verror_print_error(stderr);
        goto cleanup;
    }

    if (client_request->username == NULL) { /* set default username */
	if (dn_as_username) {
	    if (ssl_get_base_subject_file(proxyfile,
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

    /* Allow user to provide a passphrase */
    if (!use_empty_passwd) {
	int rval;
	if (read_passwd_from_stdin) {
	    rval = myproxy_read_passphrase_stdin(client_request->passphrase, sizeof(client_request->passphrase), NULL);
	} else {
	    rval = myproxy_read_verified_passphrase(client_request->passphrase, sizeof(client_request->passphrase), NULL);
	}
	if (rval == -1) {
	    verror_print_error(stderr);
	    goto cleanup;
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
    request_buffer = NULL;

    /* Continue unless the response is not OK */
    if (myproxy_recv_response_ex(socket_attrs, server_response,
				 client_request) != 0) {
	verror_print_error(stderr);
        goto cleanup;
    }
    
    /* Delegate credentials to server using the default lifetime of the cert. */
    if (myproxy_init_delegation(socket_attrs, proxyfile, cred_lifetime,
				NULL /* no passphrase */) < 0) {
	verror_print_error(stderr);
	goto cleanup;
    }

    /* Get final response from server */
    if (myproxy_recv_response(socket_attrs, server_response) != 0) {
	verror_print_error(stderr);
        goto cleanup;
    }

    /* Get actual lifetime from credential. */
    if (cred_lifetime == 0) {
	time_t cred_expiration;
	if (ssl_get_times(proxyfile, NULL, &cred_expiration) == 0) {
	    cred_lifetime = cred_expiration-time(0);
	    if (cred_lifetime <= 0) {
		fprintf(stderr, "Error: Credential expired!\n");
		goto cleanup;
	    }
	}
    }

    if (create_local_proxy) {
	unsetenv("X509_USER_PROXY"); /* GSI_SOCKET_use_creds() sets it */
	if (grid_proxy_init(client_request->proxy_lifetime,
			    proxyfile, proxyfile, x509_user_proxy) != 0) {
        if (voms) {
            fprintf(stderr, "voms-proxy-init failed\n");
        } else {
            fprintf(stderr, "grid-proxy-init failed\n");
        }
	    goto cleanup;
	}
    }

    /* Delete proxy file */
    if (grid_proxy_destroy(proxyfile) != 0) {
        fprintf(stderr, "Failed to remove temporary proxy credential.\n");
	goto cleanup;
    }
    cleanup_user_proxy = 0;
    
    hours = (int)(cred_lifetime/SECONDS_PER_HOUR);
    days = (float)(hours/24.0);
    printf("A proxy valid for %d hours (%.1f days) for user %s now exists on %s.\n", 
	   hours, days, client_request->username, socket_attrs->pshost); 
    
    return_value = 0;

 cleanup:
    /* free memory allocated */
    myproxy_free(socket_attrs, client_request, server_response);
    if (cleanup_user_proxy) {
        grid_proxy_destroy(proxyfile);
    }

    return return_value;
}

int
init_arguments(int argc, 
	       char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request,
	       int *cred_lifetime) 
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
	    printf(usage);
	    exit(0);
	    break;
	case 'c': 	/* Specify cred lifetime in hours */
	    *cred_lifetime  = SECONDS_PER_HOUR * atoi(optarg);
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
	case 'C':		/* credential file name */
	    certfile = strdup(optarg);
	    break;
	case 'y':		/* key file name */
	    keyfile = strdup(optarg);
	    break;
	case 'u': 	/* print help and exit */
	    printf(usage);
	    exit(0);
	    break;
	case 'l':	/* username */
	    request->username = strdup(optarg);
	    break;
	case 'v':
	    myproxy_debug_set_level(1);
	    verbose = 1;
	    break;
	case 'V': /* print version and exit */
	    printf(version);
	    exit(0);
	    break;
	case 'n':
	    use_empty_passwd = 1;
	    break;
	case 'd':   /* use the certificate subject (DN) as the default
		       username instead of LOGNAME */
	    dn_as_username = 1;
	    break;
	case 'r':   /* retrievers list */
	    if (request->retrievers) {
		fprintf(stderr, "Only one -a or -r option may be specified.\n");
		return -1;
	    }
	    if (expr_type == REGULAR_EXP)  /*copy as is */
	      request->retrievers = strdup (optarg);
	    else
	    {
		request->retrievers = (char *) malloc (strlen (optarg) + 6);
		strcpy (request->retrievers, "*/CN=");
		request->retrievers = strcat (request->retrievers,optarg);
		myproxy_debug("authorized retriever %s", request->retrievers);
	    }
	    break;
	case 'Z':   /* trusted_retrievers list */
	    if (request->trusted_retrievers) {
		fprintf(stderr, "Only one -Z option may be specified.\n");
		return -1;
	    }
	    if (expr_type == REGULAR_EXP)  /*copy as is */
	      request->trusted_retrievers = strdup (optarg);
	    else
	    {
		request->trusted_retrievers =
		    (char *) malloc (strlen (optarg) + 6);
		strcpy (request->trusted_retrievers, "*/CN=");
		request->trusted_retrievers =
		    strcat (request->trusted_retrievers,optarg);
		myproxy_debug("trusted retriever %s",
			      request->trusted_retrievers);
	    }
	    use_empty_passwd = 1;
	    break;
	case 'R':   /* renewers list */
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
	    if (request->retrievers) {
		fprintf(stderr, "Only one -a or -r option may be specified.\n");
		return -1;
	    }
	    request->retrievers = strdup ("*");
	    myproxy_debug("anonymous retrievers allowed");
	    break;
	case 'A':  /*allow anonymous renewers*/
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
	case 'L':
	    create_local_proxy = 1;
	    break;
	case 'm':
	    voms = strdup(optarg);
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
grid_proxy_init(int seconds,
		const char *cert, const char *key, const char *outfile) {

    int rc;
    char *command;
    int cmdlen;
    int hours;
    char *proxy_mode;
    int old=0;
      
    hours = seconds / SECONDS_PER_HOUR;

    proxy_mode = getenv("GT_PROXY_MODE");
    if (proxy_mode && strcmp(proxy_mode, "old") == 0) {
	old=1;
    }
    
    cmdlen = 250;
    if (cert) cmdlen += strlen(cert);
    if (key) cmdlen += strlen(key);
    if (outfile) cmdlen += strlen(outfile);
    if (voms) cmdlen += strlen(voms);
    command = (char *)malloc(cmdlen);

    snprintf(command, cmdlen, "%s%s -verify -hours %d "
	    "-bits %d%s%s%s%s%s%s%s%s%s",
        voms ? "voms-proxy-init -voms " : "grid-proxy-init",
        voms ? voms : "",
	    hours, MYPROXY_DEFAULT_KEYBITS,
	    cert ? " -cert " : "",
	    cert ? cert : "",
	    key ? " -key " : "",
	    key ? key : "",
	    outfile ? " -out " : "",
	    outfile ? outfile : "",
	    read_passwd_from_stdin ? " -pwstdin" : "",
	    verbose ? " -debug" : "", old ? " -old" : "");
    rc = system(command);
    free(command);

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

