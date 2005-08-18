/*
 * myproxy-get-credential
 *
 * Webserver program to retrieve a end-entity credential from a myproxy-server
 */

#include "myproxy_common.h"	/* all needed headers included here */

static char usage[] = \
"\n"
"Syntax: myproxy-retrieve [-l username] ...\n"
"        myproxy-retrieve [-usage|-help] [-version]\n"
"\n"
"   Options\n"
"       -h | --help                       Displays usage\n"
"       -u | --usage                                    \n"
"                                                      \n"
"       -v | --verbose                    Display debugging messages\n"
"       -V | --version                    Displays version\n"
"       -l | --username        <username> Username for the delegated proxy\n"
"       -s | --pshost          <hostname> Hostname of the myproxy-server\n"
"       -p | --psport          <port #>   Port of the myproxy-server\n"
"       -a | --authorization   <path>     Use credential for authorization\n"
"                                         (instead of passphrase)\n"
"       -d | --dn_as_username             Use subject of the authorization\n"
"                                         credential (or default credential\n"
"                                         if -a not used) as the default\n"
"                                         username instead of $LOGNAME\n"
"       -k | --credname        <name>     Specify credential name\n"
"       -c | --certfile        <filename> Certificate file name\n"
"       -y | --keyfile         <filename> Key file name\n"
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
    {"usage",                  no_argument, NULL, 'u'},
    {"username",         required_argument, NULL, 'l'},
    {"verbose",                no_argument, NULL, 'v'},
    {"version",                no_argument, NULL, 'V'},
    {"authorization",    required_argument, NULL, 'r'},
    {"dn_as_username",         no_argument, NULL, 'd'},
    {"credname",	 required_argument, NULL, 'k'},
    {"stdin_pass",             no_argument, NULL, 'S'},
    {"no_passphrase",          no_argument, NULL, 'n'},
    {"certfile",         required_argument, NULL, 'c'},
    {"keyfile",          required_argument, NULL, 'y'},
    {"trustroots",             no_argument, NULL, 'T'},
    {0, 0, 0, 0}
};

static char short_options[] = "hus:p:l:t:c:y:vVa:dk:SnT";

static char version[] =
"myproxy-retrieve version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

void 
init_arguments(int argc, char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request);
 
int
store_credential( char *delegfile,
                  char *certfile,
                  char *keyfile );

int
buffer2file( char *buffer,
             int   size,
             int   fd );

int
write_cert( char       *path,
            const char *buffer );

int
write_key( char       *path,
           const char *buffer );

int
mkpath( char *path );

/*
 * Use setvbuf() instead of setlinebuf() since cygwin doesn't support
 * setlinebuf().
 */
#define my_setlinebuf(stream)	setvbuf((stream), (char *) NULL, _IOLBF, 0)

/* location of delegated proxy */
static char *certfile               = NULL;     /* certificate file name */
static char *keyfile                = NULL;     /* key file name */
static int   dn_as_username         = 0;
static int   read_passwd_from_stdin = 0;
static int   use_empty_passwd       = 0;

int
main(int argc, char *argv[]) 
{    
    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;
    myproxy_data_parameters_t  *data_parameters;
    int                     retval     = -1;

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

    data_parameters = malloc(sizeof(*data_parameters));
    memset(data_parameters, 0, sizeof(*data_parameters));

    /* Setup defaults */
    client_request->version = strdup(MYPROXY_VERSION);
    client_request->proxy_lifetime = 60*60*MYPROXY_DEFAULT_DELEG_HOURS;

    if( myproxy_init( socket_attrs,
                      client_request,
                      MYPROXY_RETRIEVE_CERT ) < 0 )
    {
      return( 1 );
    }

    get_user_credential_filenames( &certfile, &keyfile ); 

    /* Initialize client arguments and create client request object */
    init_arguments(argc, argv, socket_attrs, client_request);

    if (!certfile && !keyfile) {
	fprintf(stderr, "Unable to determine credential output locations.\n"
		"Use --certfile and --keyfile options.\n");
	goto error;
    } else if (!certfile) {
	fprintf(stderr, "Unable to determine certificate output location.\n"
		"Use --certfile option.\n");
	goto error;
    } else if (!keyfile) {
	fprintf(stderr, "Unable to determine private key output location.\n"
		"Use --keyfile option.\n");
	goto error;
    }

    if (access(certfile, F_OK) == 0) {
	fprintf(stderr, "%s exists.\n", certfile);
	goto error;
    }

    if (access(keyfile, F_OK) == 0) {
	fprintf(stderr, "%s exists.\n", keyfile);
	goto error;
    }

    data_parameters->use_empty_passwd = use_empty_passwd;
    data_parameters->read_passwd_from_stdin = read_passwd_from_stdin;
    data_parameters->dn_as_username = dn_as_username;

    if( myproxy_failover( socket_attrs,
                          client_request,
                          server_response,
                          data_parameters ) != 0 )
    {
      goto error;
    }

    if( data_parameters->outputfile )
    {
      if( store_credential( data_parameters->outputfile, certfile, keyfile ) < 0 )
      {
        fprintf( stderr, "Problem storing to: %s and %s\n", certfile, keyfile );
        goto error;
      }

      ssl_proxy_file_destroy(data_parameters->outputfile);

      printf("Credentials for %s have been stored in\n%s and\n%s.\n",
             client_request->username, certfile, keyfile);
    }
    else
    {
      printf( "No credentials returned.\n" );
      goto error;
    }

    /* Store file in trusted directory if requested and returned */
    if (client_request->want_trusted_certs) {
        if (server_response->trusted_certs != NULL) {
            if (myproxy_install_trusted_cert_files(server_response->trusted_certs) != 0) {       
		verror_print_error(stderr);
		goto error;
            } else {
		printf("Trust roots have been installed in %s.\n",
		       get_trusted_certs_path());
	    }
        } else {
            myproxy_debug("Requested trusted certs but didn't get any.\n");
        }
    }
    
    retval = 0;

error:
    if (certfile) free(certfile);
    if (keyfile) free(keyfile);
    verror_clear();

    /* free memory allocated */
    myproxy_free(socket_attrs, client_request, server_response);



    if( data_parameters->outputfile )
    {
      ssl_proxy_file_destroy(data_parameters->outputfile);
    }

    return retval;
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
	case 'd':       /* use the certificate subject (DN) as the default
		           username instead of LOGNAME */
	    dn_as_username = 1;
	    break;
	case 'k':       /* credential name */
	    request->credname = strdup (optarg);
	    break;
	case 'S':
	    read_passwd_from_stdin = 1;
	    break;
	case 'T':
	    request->want_trusted_certs = 1;
            myproxy_debug("Requesting trusted certificates.\n");
	    break;
        case 'c':       /* credential file name */
	    if (certfile) free(certfile);
            certfile = strdup(optarg);
            break;
        case 'y':       /* key file name */
	    if (keyfile) free(keyfile);
            keyfile = strdup(optarg);
            break;
        default:        /* print usage and exit */ 
	    fprintf(stderr, usage);
	    exit(1);
	    break;	
        }
    }

    /* Check to see if myproxy-server specified */
    if (attrs->pshost == NULL) {
	fprintf(stderr, "Unspecified myproxy-server.  Set the MYPROXY_SERVER environment variable to\nthe hostname of the myproxy-server or run with '-s server-hostname'.\n");
	exit(1);
    }

    return;
}

int
store_credential( char *delegfile, 
                  char *certfile, 
                  char *keyfile )
{
    unsigned char       *input_buffer       = NULL;
    int                 retval              = -1;


    assert(delegfile != NULL);
    assert(certfile != NULL);
    assert(keyfile != NULL);

    if (buffer_from_file(delegfile, &input_buffer, NULL) < 0)
    {
      fprintf(stderr, "open(%s) failed: %s\n", delegfile, strerror(errno));
      goto error;
    }

    if (write_cert(certfile, (const char *)input_buffer) < 0)
    {
      goto error;
    }

    if (write_key(keyfile, (const char *)input_buffer) < 0)
    {
      goto error;
    }

    retval = 0;
error:
    return(retval);
}

int
write_cert( char       *path, 
            const char *buffer )
{
    int          fd;
    static char  BEGINCERT[] = "-----BEGIN CERTIFICATE-----";
    static char  ENDCERT[]   = "-----END CERTIFICATE-----";
    char        *certstart,
                *certend;
    int          retval      = -1;
    int          size;

    assert(path != NULL);
    assert(buffer != NULL);

    if( make_path( path ) < 0 )
    {
        verror_print_error(stderr);
        goto error;
    }

    /* Open the output file. */
    if ((fd = open(path, O_CREAT | O_EXCL | O_WRONLY,
                 S_IRUSR | S_IWUSR)) < 0)
    {
      if( errno == EEXIST )
      {
        fprintf(stderr, "open(%s) failed: This file already exists.\nmyproxy-retrieve will not overwrite end-entity credentials.\n", path );
        goto error;
      }

      fprintf(stderr, "Open(%s) failed: %s\n", path, strerror(errno));
      goto error;
    }

    if ((certstart = strstr(buffer, BEGINCERT)) == NULL)
    {
      fprintf(stderr, "CRED doesn't contain '%s'.\n",  BEGINCERT);
      goto error;
    }

    if ((certend = strstr(certstart, ENDCERT)) == NULL)
    {
      fprintf(stderr, "CRED doesn't contain '%s'.\n", ENDCERT);
      goto error;
    }
    certend += strlen(ENDCERT);
    size = certend-certstart;

    if( buffer2file( certstart, size, fd ) != 0 )
    {
      fprintf(stderr, "Could not write cert to: '%s'.\n", path);
      goto error;
    }

    certstart += size;

    while ((certstart = strstr(certstart, BEGINCERT)) != NULL) {

        if ((certend = strstr(certstart, ENDCERT)) == NULL) {
            fprintf(stderr, "Can't find matching '%s' in %s.\n", ENDCERT,
                    certfile);
            goto error;
        }
        certend += strlen(ENDCERT);
        size = certend-certstart;

        buffer2file( certstart, size, fd );
        certstart += size;
    }

    retval = 0;

error:
    if( fd )
    {
      close( fd );
    }

    return( retval );
}

int
write_key( char       *path, 
           const char *buffer )
{
    int          fd;
    static char  BEGINKEY[] = "-----BEGIN RSA PRIVATE KEY-----";
    static char  ENDKEY[]   = "-----END RSA PRIVATE KEY-----";
    char        *keystart,
                *keyend;
    int          retval     = -1;
    int          size;

    if( make_path( path ) < 0 )
    {
        verror_print_error(stderr);
        goto error;
    }

    /* Open the output file. */
    if ((fd = open(path, O_CREAT | O_EXCL | O_WRONLY,
                 S_IRUSR | S_IWUSR)) < 0)
    {
      if( errno == EEXIST )
      {
        fprintf(stderr, "open(%s) failed: This file already exists.\nmyproxy-retrieve will not overwrite end-entity credentials.\n", path );
        goto error;
      }

      fprintf(stderr, "open(%s) failed: %s\n", path, strerror(errno));
      goto error;
    }

    /* Write the key. */
    if ((keystart = strstr(buffer, BEGINKEY)) == NULL)
    {
      fprintf(stderr, "CREDKEY doesn't contain '%s'.\n", BEGINKEY);
      goto error;
    }

    if ((keyend = strstr(keystart, ENDKEY)) == NULL)
    {
      fprintf(stderr, "CREDKEY doesn't contain '%s'.\n", ENDKEY);
      goto error;
    }
    keyend += strlen(ENDKEY);
    size = keyend-keystart;

    if( buffer2file( keystart, size, fd ) != 0 )
    {
      fprintf(stderr, "Could not write key to: '%s'.\n", path);
      goto error;
    }

    retval = 0;

error:
    if( fd )
    {
      close( fd );
    }

    return( retval );
}

int
buffer2file( char *buffer,
             int   size,
             int   fd )
{
    int   rval;
    char *certstart;

    certstart = buffer;

    while (size)
    {
      if ((rval = write(fd, certstart, size)) < 0)
      {
          perror("write");
          return( -1 );
      }
      size -= rval;
      certstart += rval;
    }

    if (write(fd, "\n", 1) < 0)
    {
      perror("write");
      return(-1);
    }

    return( 0 );
}
