/*
 * myproxy-store
 *
 * Client program to store a end-entity credential to a myproxy-server
 */

#include "myproxy_common.h"	/* all needed headers included here */

/* Location of default proxy */
#define MYPROXY_DEFAULT_PROXY	  "/tmp/myproxy-proxy"
#define MYPROXY_DEFAULT_USERCERT  "usercert.pem"
#define MYPROXY_DEFAULT_USERKEY   "userkey.pem"
#define MYPROXY_DEFAULT_DIRECTORY ".globus"

static char usage[] =
    "\n"
    "Syntax: myproxy-store [-c #hours] [-t #hours] [-l username] [-r retrievers] [-w renewers] ...\n"
    "        myproxy-store [-usage|-help] [-version]\n"
    "\n"
    "   Options\n"
    "       -h | --help                       Displays usage\n"
    "       -u | --usage                                    \n"
    "                                                      \n"
    "       -v | --verbose                    Display debugging messages\n"
    "       -V | --version                    Displays version\n"
    "       -s | --pshost         <hostname>  Hostname of the myproxy-server\n"
    "                                         Can also set MYPROXY_SERVER env. var.\n"
    "       -p | --psport         <port #>    Port of the myproxy-server\n"
    "       -c | --certfile       <filename>  Certificate file name\n"
    "       -y | --keyfile        <filename>  Key file name\n"
    "       -l | --username       <username>  Username for the delegated proxy\n"
    "       -t | --proxy_lifetime <hours>     Lifetime of proxies delegated by\n"
    "                                         server (default 12 hours).\n"
    "       -a | --allow_anonymous_retrievers Allow credentials to be retrieved\n"
    "                                         with just username/passphrase\n"
    "       -A | --allow_anonymous_renewers   Allow credentials to be renewed by\n"
    "                                         any client (not recommended)\n"
    "       -x | --regex_dn_match             Set regular expression matching mode\n"
    "                                         for following policy options\n"
    "       -X | --match_cn_only              Set CN matching mode (default)\n"
    "                                         for following policy options\n"
    "       -r | --retrievable_by <dn>        Allow specified entity to retrieve\n"
    "                                         credential\n"
    "       -R | --renewable_by   <dn>        Allow specified entity to renew\n"
    "                                         credential\n"
    "       -E | --retrieve_key <dn>          Allow specified entity to retrieve\n"
    "                                         credential key\n"
    "       -d | --dn_as_username             Use the proxy certificate subject\n"
    "                                         (DN) as the default username,\n"
    "                                         instead of the LOGNAME env. var.\n"
    "       -k | --credname       <name>      Specifies credential name\n"
    "       -K | --creddesc       <desc>      Specifies credential description\n"
    "\n";

struct option long_options[] = {
    {"help",                             no_argument, NULL, 'h'},
    {"usage",                            no_argument, NULL, 'u'},
    {"certfile",                   required_argument, NULL, 'c'},
    {"keyfile",                    required_argument, NULL, 'y'},
    {"proxy_lifetime",             required_argument, NULL, 't'},
    {"pshost",                     required_argument, NULL, 's'},
    {"psport",                     required_argument, NULL, 'p'},
    {"directory",                  required_argument, NULL, 'd'},
    {"username",                   required_argument, NULL, 'l'},
    {"verbose",                          no_argument, NULL, 'v'},
    {"version",                          no_argument, NULL, 'V'},
    {"dn_as_username",                   no_argument, NULL, 'D'},
    {"allow_anonymous_retrievers",       no_argument, NULL, 'a'},
    {"allow_anonymous_renewers",         no_argument, NULL, 'A'},
    {"retrievable_by",             required_argument, NULL, 'r'},
    {"renewable_by",               required_argument, NULL, 'R'},
    {"retrieve_key",               required_argument, NULL, 'E'},
    {"regex_dn_match",                   no_argument, NULL, 'x'},
    {"match_cn_only",                    no_argument, NULL, 'X'},
    {"credname",                   required_argument, NULL, 'k'},
    {"creddesc",                   required_argument, NULL, 'K'},
    {0, 0, 0, 0}
};

/*colon following an option indicates option takes an argument */
static char short_options[] = "uhl:vVdr:R:xXaAk:K:t:c:y:s:p:E:";

static char version[] =
    "myproxy-init version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "
    "\n";

static char *certfile               = NULL;	/* certificate file name */
static char *keyfile                = NULL;	/* key file name */
static int   dn_as_username         = 0;
static int   verbose                = 0;

/* Function declarations */
int 
init_arguments(    int                      argc,
	           char                    *argv[],
	           myproxy_socket_attrs_t  *attrs,
                   myproxy_request_t       *request);

int 
makecertfile(      const char               certfile[],
	           const char               keyfile[],
                   char                   **credbuf);

#define		SECONDS_PER_HOUR			(60 * 60)

int 
main(int   argc, 
     char *argv[])
{
    char                   *credkeybuf         = NULL;

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

    myproxy_log_use_stream(stderr);

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
    client_request->command_type = MYPROXY_STORE_CERT;

    if( myproxy_init( socket_attrs,
                      client_request,
                      MYPROXY_STORE_CERT ) < 0 )
    {
      return( 1 );
    }

    globus_module_activate(GLOBUS_GSI_SYSCONFIG_MODULE);
    GLOBUS_GSI_SYSCONFIG_GET_USER_CERT_FILENAME( &certfile,
						 &keyfile );

    client_request->proxy_lifetime = SECONDS_PER_HOUR *
                                     MYPROXY_DEFAULT_DELEG_HOURS;

    /* Initialize client arguments and create client request object */

    if (init_arguments(argc, argv, socket_attrs, client_request) != 0) {
        goto cleanup;
    }

    if (!certfile && !keyfile) {
	fprintf(stderr, "Credentials not found in default location.\n"
		"Use --certfile and --keyfile options.\n");
	goto cleanup;
    } else if (!certfile) {
	fprintf(stderr, "Certificate not found in default location.\n"
		"Use --certfile option.\n");
	goto cleanup;
    } else if (!keyfile) {
	fprintf(stderr, "Private key not found in default location.\n"
		"Use --keyfile option.\n");
	goto cleanup;
    }

    /*
     ** Read Credential and Key files
     */
    if( makecertfile(certfile, keyfile, &credkeybuf) < 0 )
    {
      fprintf( stderr, "makecertfile failed\n" );
      goto cleanup;
    }

    other_stuff->dn_as_username = dn_as_username;
    other_stuff->credkeybuf     = credkeybuf;

    if( myproxy_failover( socket_attrs,
                          client_request,
                          server_response,
                          other_stuff ) != 0 )
    {
      goto cleanup;
    }

    return 0;

 cleanup:
    return 1;
}

int
init_arguments(int                     argc,
	       char                   *argv[],
	       myproxy_socket_attrs_t *attrs, 
               myproxy_request_t      * request)
{
    extern char *optarg;
    int expr_type = MATCH_CN_ONLY;	/*default */
    int arg;

    while ((arg = getopt_long(argc,
				  argv,
				  short_options,
				  long_options, NULL)) != EOF) {
	switch (arg) {
	case 's':		/* pshost name */
	    attrs->pshost = strdup(optarg);
	    break;

	case 'p':		/* psport */
	    attrs->psport = atoi(optarg);
	    break;

	case 'c':		/* credential file name */
	    certfile = strdup(optarg);
	    break;

	case 'y':		/* key file name */
	    keyfile = strdup(optarg);
	    break;

	case 'u':		/* print help and exit */
	    fprintf(stderr, usage);
	    exit(1);
	    break;

	case 't':		/* Specify proxy lifetime in hours */
	    request->proxy_lifetime = SECONDS_PER_HOUR * atoi(optarg);
	    break;

	case 'h':		/* print help and exit */
	    fprintf(stderr, usage);
	    exit(1);
	    break;

	case 'l':		/* username */
	    request->username = strdup(optarg);
	    break;

	case 'v':		/* verbose */
	    myproxy_debug_set_level(1);
	    verbose = 1;
	    break;

	case 'V':		/* print version and exit */
	    fprintf(stderr, version);
	    exit(1);
	    break;


	case 'r':		/* retrievers list */
	    if (request->renewers) {
		fprintf(stderr,
			"-r is incompatible with -A and -R.  A credential may not be used for both\nretrieval and renewal.  If both are desired, upload multiple credentials with\ndifferent names, using the -k option.\n");
		exit(1);
	    }

	    if (request->retrievers) {
		fprintf(stderr,
			"Only one -a or -r option may be specified.\n");
		exit(1);
	    }

	    if (expr_type == REGULAR_EXP) {
		
                /* Copy as is */
		request->retrievers = strdup(optarg);
	    } else {
		request->retrievers =
		    (char *) malloc(strlen(optarg) + 5);
		strcpy(request->retrievers, "*/CN=");
		myproxy_debug("authorized retriever %s",
			      request->retrievers);
		request->retrievers =
		    strcat(request->retrievers, optarg);
	    }
	    break;

	case 'R':		/* renewers list */
            /*
            ** This needs to be readdressed.  Right now, the private key is
            ** being stored encrypted.  This is a problem if the user calls
            ** /myproxy-get-delegation with the -a option.  The call will
            ** fail because an unencrypted password is being looked for.
            ** So, do we want to add code to unencrypt the private key if
            ** this option is used?
            */
	    if (request->retrievers) {
		fprintf(stderr,
			"-R is incompatible with -a and -r.  A credential may not be used for both\nretrieval and renewal.  If both are desired, upload multiple credentials with\ndifferent names, using the -k option.\n");
		exit(1);
	    }

	    if (request->renewers) {
		fprintf(stderr,
			"Only one -A or -R option may be specified.\n");
		exit(1);
	    }

	    if (expr_type == REGULAR_EXP) {
		/* Copy as is */
		request->renewers = strdup(optarg);
	    } else {
		request->renewers =
		    (char *) malloc(strlen(optarg) + 6);
		strcpy(request->renewers, "*/CN=");
		myproxy_debug("authorized renewer %s", request->renewers);
		request->renewers = strcat(request->renewers, optarg);
	    }
	    break;

        case 'E' :              /* key retriever list */ 
	    if (expr_type == REGULAR_EXP) {
		/* Copy as is */
		request->keyretrieve = strdup(optarg);
	    } else {
		request->keyretrieve =
		    (char *) malloc(strlen(optarg) + 5);
		strcpy(request->keyretrieve, "*/CN=");
		myproxy_debug("authorized key retriever %s",
			      request->keyretrieve);
		request->keyretrieve =
		    strcat(request->keyretrieve, optarg);
	    }
	    break;

	case 'd':		/* 
				 ** use the certificate subject (DN) as the 
				 ** default username instead of LOGNAME 
				 */
	    dn_as_username = 1;
	    break;

	case 'x':		/*set expression type to regex */
	    expr_type = REGULAR_EXP;
	    myproxy_debug("expr-type = regex");
	    break;

	case 'X':		/*set expression type to common name */
	    expr_type = MATCH_CN_ONLY;
	    myproxy_debug("expr-type = CN");
	    break;

	case 'a':		/*allow anonymous retrievers */
	    if (request->renewers) {
		fprintf(stderr,
			"-a is incompatible with -A and -R.  A credential may not be used for both\nretrieval and renewal.  If both are desired, upload multiple credentials with\ndifferent names, using the -k option.\n");
		exit(1);
	    }

	    if (request->retrievers) {
		fprintf(stderr,
			"Only one -a or -r option may be specified.\n");
		exit(1);
	    }

	    request->retrievers = strdup("*");
	    myproxy_debug("anonymous retrievers allowed");
	    break;

	case 'A':		/*allow anonymous renewers */
	    if (request->retrievers) {
		fprintf(stderr,
			"-A is incompatible with -a and -r.  A credential may not be used for both\nretrieval and renewal.  If both are desired, upload multiple credentials with\ndifferent names, using the -k option.\n");
		exit(1);
	    }

	    if (request->renewers) {
		fprintf(stderr,
			"Only one -A or -R option may be specified.\n");
		exit(1);
	    }

	    request->renewers = strdup("*");
	    myproxy_debug("anonymous renewers allowed");
	    break;

	case 'k':		/*credential name */
	    request->credname = strdup(optarg);
	    break;

	case 'K':		/*credential description */
	    request->creddesc = strdup(optarg);
	    break;

	default:		/* print usage and exit */
	    fprintf(stderr, usage);
	    exit(1);
	    break;
	}
    }

    /* Check to see if myproxy-server specified */
    if (attrs->pshost == NULL) {
	fprintf(stderr, usage);
	fprintf(stderr,
		"Unspecified myproxy-server! Either set the MYPROXY_SERVER environment variable or explicitly set the myproxy-server via the -s flag\n");
	return -1;
    }

    return 0;
}

int 
makecertfile(const char   certfile[],
             const char   keyfile[],
             char       **credbuf)
{
    unsigned char *certbuf = NULL;
    unsigned char *keybuf  = NULL;
    int         retval  = -1;
    struct stat s;
    int         bytes;
    static char BEGINCERT[] = "-----BEGIN CERTIFICATE-----";
    static char ENDCERT[] = "-----END CERTIFICATE-----";
    static char BEGINKEY[] = "-----BEGIN RSA PRIVATE KEY-----";
    static char ENDKEY[] = "-----END RSA PRIVATE KEY-----";
    char        *certstart; 
    char        *certend;
    int          size;
    char        *keystart; 
    char        *keyend;


    /* Figure out how much memory we are going to need */
    stat( certfile, &s );
    bytes = s.st_size;
    stat( keyfile, &s );
    bytes += s.st_size;

    *credbuf = malloc( bytes + 1 );
    memset(*credbuf, 0, (bytes + 1));

    /* Read the certificate(s) into a buffer. */
    if (buffer_from_file(certfile, &certbuf, NULL) < 0) {
	fprintf(stderr, "Failed to read %s\n", certfile);
	goto cleanup;
    }

    /* Read the key into a buffer. */
    if (buffer_from_file(keyfile, &keybuf, NULL) < 0) {
        fprintf(stderr, "Failed to read %s\n", keyfile);
        goto cleanup;
    }

    if ((certstart = strstr((const char *)certbuf, BEGINCERT)) == NULL)
    {
      fprintf(stderr, "%s doesn't contain '%s'.\n",  certfile, BEGINCERT);
      goto cleanup;
    }

    if ((certend = strstr(certstart, ENDCERT)) == NULL)
    {
      fprintf(stderr, "%s doesn't contain '%s'.\n", certfile, ENDCERT);
      goto cleanup;
    }
    certend += strlen(ENDCERT);
    size = certend-certstart;

    strncat( *credbuf, certstart, size ); 
    strcat( *credbuf, "\n" );
    certstart += size;

    /* Write the key. */
    if ((keystart = strstr((const char *)keybuf, BEGINKEY)) == NULL) {
	fprintf(stderr, "%s doesn't contain '%s'.\n", keyfile, BEGINKEY);
	goto cleanup;
    }

    if ((keyend = strstr(keystart, ENDKEY)) == NULL) {
	fprintf(stderr, "%s doesn't contain '%s'.\n", keyfile, ENDKEY);
	goto cleanup;
    }
    keyend += strlen(ENDKEY);
    size = keyend-keystart;

    strncat( *credbuf, keystart, size );
    strcat( *credbuf, "\n" );

    /* Write any remaining certificates. */
    while ((certstart = strstr(certstart, BEGINCERT)) != NULL) {

        if ((certend = strstr(certstart, ENDCERT)) == NULL) {
            fprintf(stderr, "Can't find matching '%s' in %s.\n", ENDCERT,
                    certfile);
            goto cleanup;
        }
        certend += strlen(ENDCERT);
        size = certend-certstart;

        strncat( *credbuf, certstart, size ); 
        strcat( *credbuf, "\n" ); 
        certstart += size;
    }

    retval = 0;

  cleanup:
    if (certbuf) free(certbuf);
    if (keybuf) free(keybuf);

    return (retval);
}

