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
    "       -d | --directory      <directory> Specifies the credential storage directory\n"
    "       -c | --certfile       <filename>  Certificate file name\n"
    "       -y | --keyfile        <filename>  Key file name\n"
    "       -l | --username       <username>  Username for the delegated proxy\n"
    "       -t | --proxy_lifetime <hours>     Lifetime of proxies delegated by\n"
    "                                         server (default 12 hours)\n"
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
    "       -D | --dn_as_username             Use the proxy certificate subject\n"
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
    {"regex_dn_match",                   no_argument, NULL, 'x'},
    {"match_cn_only",                    no_argument, NULL, 'X'},
    {"credname",                   required_argument, NULL, 'k'},
    {"creddesc",                   required_argument, NULL, 'K'},
    {0, 0, 0, 0}
};

/*colon following an option indicates option takes an argument */
static char short_options[] = "uhl:vVdr:R:xXaAk:K:t:c:y:s:";

static char version[] =
    "myproxy-init version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "
    "\n";

static char *certfile               = NULL;	/* certificate file name */
static char *keyfile                = NULL;	/* key file name */
static char *creddir                = NULL;	/* key file name */
static int   dn_as_username         = 0;
static int   use_empty_passwd       = 0;
static int   read_passwd_from_stdin = 0;
static int   verbose                = 0;

/* Function declarations */
int 
init_arguments(    int                      argc,
	           char                    *argv[],
	           myproxy_socket_attrs_t  *attrs,
                   myproxy_request_t       *request);

void 
error_exit(        char                    *msg);

int 
file2buf(          const char               filename[], 
                   char                   **buf);

int 
makecertfile(      const char               certfile[],
	           const char               keyfile[],
	           const char               creddir[], 
                   char                   **credbuf);

int 
grid_proxy_init(   int                      hours, 
                   const char              *proxyfile);

int 
grid_proxy_destroy(const char              *proxyfile);


#define		SECONDS_PER_HOUR			(60 * 60)

int 
main(int   argc, 
     char *argv[])
{
    char                   *pshost;
    char                    proxyfile[64];
    char                    request_buffer[1024];
    char                   *credkeybuf         = NULL;
    int                     requestlen;
    int                     cred_lifetime;
    int                     cleanup_user_proxy = 0;

    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;

    myproxy_log_use_stream(stderr);

    socket_attrs = malloc(sizeof(*socket_attrs));
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    client_request = malloc(sizeof(*client_request));
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    memset(server_response, 0, sizeof(*server_response));

    /* setup defaults */
    client_request->version = malloc(strlen(MYPROXY_VERSION) + 1);
    strcpy(client_request->version, MYPROXY_VERSION);
    client_request->command_type = MYPROXY_STORE_CERT;

    pshost = getenv("MYPROXY_SERVER");

    if (pshost != NULL) {
	socket_attrs->pshost = strdup(pshost);
    }

    if (getenv("MYPROXY_SERVER_PORT")) {
	socket_attrs->psport = atoi(getenv("MYPROXY_SERVER_PORT"));
    } else {
	socket_attrs->psport = MYPROXY_SERVER_PORT;
    }

    certfile = strdup(MYPROXY_DEFAULT_USERCERT);
    keyfile = strdup(MYPROXY_DEFAULT_USERKEY);

    creddir = malloc(strlen(getenv("HOME")) + 1 +
		     strlen(MYPROXY_DEFAULT_DIRECTORY) + 1);
    sprintf(creddir, "%s/%s", getenv("HOME"), MYPROXY_DEFAULT_DIRECTORY);

    /* Initialize client arguments and create client request object */
    if (init_arguments(argc, argv, socket_attrs, client_request) != 0) {
        goto cleanup;
    }

    /*
     ** Read Credential and Key files
     */
    makecertfile(certfile, keyfile, creddir, &credkeybuf);

    /* Set up client socket attributes */
    if (myproxy_init_client(socket_attrs) < 0) {
        fprintf(stderr, "%s\n",
                verror_get_string());
        goto cleanup;
    }

/*
** DO I NEED TO DO THIS?????
*/
    /* the lifetime of the proxy */
    cred_lifetime = SECONDS_PER_HOUR * MYPROXY_DEFAULT_HOURS;

    /* client_request stores the lifetime of proxies delegated by the server */
    client_request->proxy_lifetime = SECONDS_PER_HOUR *
	MYPROXY_DEFAULT_DELEG_HOURS;


    /* Create a proxy by running [grid-proxy-init] */
    sprintf(proxyfile, "%s.%u", MYPROXY_DEFAULT_PROXY,
	    (unsigned) getuid());

    /* Run grid-proxy-init to create a proxy */
    if (grid_proxy_init(cred_lifetime, proxyfile) != 0) {
        fprintf(stderr, "grid-proxy-init failed\n"); 
        goto cleanup;
    }

    /* Be sure to delete the user proxy on abnormal exit */
    cleanup_user_proxy = 1;
/*
**
*/
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


/*
** MORE DO I NEED TO DO STUFF??????
*/
    /* Allow user to provide a passphrase */
    if (use_empty_passwd) {
        int rval;
        if (read_passwd_from_stdin) {
            rval = myproxy_read_passphrase_stdin(client_request->passphrase, sizeof(client_request->passphrase), NULL);
        } else {
            rval = myproxy_read_verified_passphrase(client_request->passphrase, sizeof(client_request->passphrase), NULL);
        }
        if (rval == -1) {
            fprintf(stderr, "%s\n", verror_get_string());
            goto cleanup;
        }
    }
/*
**
*/

    /* Authenticate client to server */
    if (myproxy_authenticate_init(socket_attrs, proxyfile) < 0) {
        fprintf(stderr, "%s\n",
                verror_get_string());
        goto cleanup;
    }

    /* Serialize client request object */
    requestlen = myproxy_serialize_request(client_request,
					   request_buffer,
					   sizeof(request_buffer));

    if (requestlen < 0) {
        fprintf(stderr, "%s\n",verror_get_string());
        goto cleanup;
    }

    /* Send request to the myproxy-server */
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
        fprintf(stderr, "%s\n",
                verror_get_string());
        goto cleanup;
    }

    /* Continue unless the response is not OK */
    if (myproxy_recv_response_ex(socket_attrs,
				 server_response, client_request) != 0) {
        fprintf(stderr, "%s\n", verror_get_string());
        goto cleanup;
    }

    /* Send end-entity credentials to server. */
    if (myproxy_init_credentials(socket_attrs,
				 credkeybuf,
				 cred_lifetime,
				 NULL /* no passphrase */ ) < 0) {
        fprintf(stderr, "%s\n",
                verror_get_string());
        goto cleanup;
    }

    /* Get final response from server */
    if (myproxy_recv_response(socket_attrs, server_response) != 0) {
        fprintf(stderr, "%s\n", verror_get_string());
        goto cleanup;
    }

/*
** DO I NEED TO DO THIS?
*/
    /* Delete proxy file */
    if (grid_proxy_destroy(proxyfile) != 0) {
        fprintf(stderr, "Failed to remove temporary proxy credential.\n");
        goto cleanup;
    }
    cleanup_user_proxy = 0;
/*
**
*/

    return 0;

 cleanup:
    if (cleanup_user_proxy) {
        grid_proxy_destroy(proxyfile);
    }
    return 1;
}

int
init_arguments(int                     argc,
	       char                   *argv[],
	       myproxy_socket_attrs_t *attrs, 
               myproxy_request_t      * request)
{
    extern char *gnu_optarg;
    int expr_type = MATCH_CN_ONLY;	/*default */
    int arg;

    while ((arg = gnu_getopt_long(argc,
				  argv,
				  short_options,
				  long_options, NULL)) != EOF) {
	switch (arg) {
	case 's':		/* pshost name */
	    attrs->pshost = strdup(gnu_optarg);
	    break;

	case 'p':		/* psport */
	    attrs->psport = atoi(gnu_optarg);
	    break;

	case 'd':		/* set the credential storage directory */
	    myproxy_set_storage_dir(gnu_optarg);
	    break;

	case 'c':		/* credential file name */
	    certfile = strdup(gnu_optarg);
	    break;

	case 'y':		/* key file name */
	    keyfile = strdup(gnu_optarg);
	    break;

	case 'u':		/* print help and exit */
	    fprintf(stderr, usage);
	    exit(1);
	    break;

	case 't':		/* Specify proxy lifetime in hours */
	    request->proxy_lifetime = SECONDS_PER_HOUR * atoi(gnu_optarg);
	    break;

	case 'h':		/* print help and exit */
	    fprintf(stderr, usage);
	    exit(1);
	    break;

	case 'l':		/* username */
	    request->username = strdup(gnu_optarg);
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
		//Copy as is
		request->retrievers = strdup(gnu_optarg);
	    } else {
		request->retrievers =
		    (char *) malloc(strlen(gnu_optarg) + 5);
		strcpy(request->retrievers, "*/CN=");
		myproxy_debug("authorized retriever %s",
			      request->retrievers);
		request->retrievers =
		    strcat(request->retrievers, gnu_optarg);
	    }
	    break;

	case 'R':		/* renewers list */
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
		// Copy as is
		request->renewers = strdup(gnu_optarg);
	    } else {
		request->renewers =
		    (char *) malloc(strlen(gnu_optarg) + 6);
		strcpy(request->renewers, "*/CN=");
		myproxy_debug("authorized renewer %s", request->renewers);
		request->renewers = strcat(request->renewers, gnu_optarg);
	    }
	    break;

	case 'D':		/* 
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
	    request->credname = strdup(gnu_optarg);
	    break;

	case 'K':		/*credential description */
	    request->creddesc = strdup(gnu_optarg);
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
file2buf(const char   filename[], 
         char       **buf)
{
    int fd, size, rval;
    char *b;

    if ((fd = open(filename, O_RDONLY)) < 0) {
	perror("open");
	return -1;
    }

    if ((size = (int) lseek(fd, 0, SEEK_END)) < 0) {
	perror("lseek");
	return -1;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
	perror("lseek");
	return -1;
    }

    *buf = b = (char *) malloc(size + 1);
    if (b == NULL) {
	perror("malloc");
	return -1;
    }

    while (size) {
	if ((rval = read(fd, b, size)) < 0) {
	    perror("read");
	    return -1;
	}

	size -= rval;
	b += rval;
    }
    *b = '\0';

    return 0;
}


int 
makecertfile(const char   certfile[],
             const char   keyfile[],
	     const char   creddir[], 
             char       **credbuf)
{
    char *certbuf = NULL;
    char *keybuf  = NULL;
    char *cert    = NULL;
    char *key     = NULL;
    int   retval  = -1;

    cert = malloc(strlen(certfile) + 1 + strlen(creddir) + 1);
    key  = malloc(strlen(keyfile)  + 1 + strlen(creddir) + 1);

    sprintf(cert, "%s/%s", creddir, certfile);
    sprintf(key, "%s/%s", creddir, keyfile);

    /* Read the certificate(s) into a buffer. */
    if (file2buf(cert, &certbuf) < 0) {
	fprintf(stderr, "Failed to read %s\n", certfile);
	goto cleanup;
    }

    static char  BEGINCERT[] = "-----BEGIN CERTIFICATE-----";
    static char  ENDCERT[] = "-----END CERTIFICATE-----";
    char        *certstart; 
    char        *certend;
    int          size;

    if ((certstart = strstr(certbuf, BEGINCERT)) == NULL)
    {
      fprintf(stderr, "CRED doesn't contain '%s'.\n",  BEGINCERT);
      goto cleanup;
    }

    if ((certend = strstr(certstart, ENDCERT)) == NULL)
    {
      fprintf(stderr, "CRED doesn't contain '%s'.\n", ENDCERT);
      goto cleanup;
    }
    certend += strlen(ENDCERT);
    size = certend-certstart;

    char *newcert = malloc( size );
    strncpy( newcert, certstart, size );

    /* Read the key into a buffer. */
    if (file2buf(key, &keybuf) < 0) {
	fprintf(stderr, "Failed to read %s\n", keyfile);
	goto cleanup;
    }

    *credbuf = malloc(size + strlen(keybuf) + 1);
    sprintf(*credbuf, "%s\n%s", newcert, keybuf);

    retval = 0;

  cleanup:
    if (certbuf)
	free(certbuf);
    if (keybuf)
	free(keybuf);
    if (cert)
	free(cert);
    if (key)
	free(key);

    return (retval);
}

/* grid_proxy_init()
 *
 * Uses the system() call to run grid-proxy-init to create a user proxy
 *
 * returns grid-proxy-init status 0 if OK, -1 on error
 */
int 
grid_proxy_init(int         seconds, 
                const char *proxyfile)
{
    int  rc;
    char command[128];
    int  hours;

    assert(proxyfile != NULL);

    hours = seconds / SECONDS_PER_HOUR;

    sprintf(command,
	    "grid-proxy-init -verify -valid %d:0 -out %s%s%s",
	    hours,
	    proxyfile,
	    read_passwd_from_stdin ? " -pwstdin" : "",
	    verbose ? " -debug" : "");

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
	fprintf(stderr, "%s\n", verror_get_string());
	return -1;
    }

    return 0;
}
